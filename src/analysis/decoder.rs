use std::io::Read;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use flate2::read::{GzDecoder, ZlibDecoder};

use super::EncodingKind;

const MAX_DECOMPRESSED_BYTES: u64 = 16 * 1024 * 1024;
const MAX_COMPRESSION_LAYERS: usize = 4;
/// Single-byte XOR is only attempted on decoded payloads in this size range.
const MIN_XOR_BYTES: usize = 16;
const MAX_XOR_BYTES: usize = 64 * 1024;
const MIN_XOR_TEXT_SCORE: f32 = 0.75;
const MIN_UTF16_BYTES: usize = 4;

pub(super) struct DecodeResult {
    pub output: String,
    pub compression_layers: Vec<CompressionLayer>,
}

/// A byte-level layer found after an outer text encoding: decompression,
/// UTF-16LE text, or a single-byte XOR key.
pub(super) struct CompressionLayer {
    pub kind: EncodingKind,
    pub input_preview: String,
    pub output_preview: String,
    pub detail: Option<String>,
    pub confidence: f32,
}

/// Which byte-level transforms `decode_binary` may try beyond decompression.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum BinaryTransforms {
    CompressionOnly,
    EncodedPayload,
}

pub(super) fn decode(kind: EncodingKind, input: &str) -> Option<DecodeResult> {
    match kind {
        EncodingKind::Base64 => decode_base64(input),
        EncodingKind::Hex => decode_hex(input),
        EncodingKind::UrlEncoding => text_result(decode_url(input)?),
        EncodingKind::HtmlEntity => {
            text_result(html_escape::decode_html_entities(input).into_owned())
        }
        EncodingKind::UnicodeEscape => text_result(crate::codec::decode_unicode(input).ok()?),
        EncodingKind::Gzip | EncodingKind::Zlib | EncodingKind::Utf16Le | EncodingKind::Xor => None,
    }
}

fn decode_base64(input: &str) -> Option<DecodeResult> {
    let compact: String = input
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(&compact).ok())
        .and_then(|bytes| decode_binary(bytes, BinaryTransforms::EncodedPayload))
}

fn decode_hex(input: &str) -> Option<DecodeResult> {
    let compact: String = input
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if !compact.len().is_multiple_of(2) {
        return None;
    }

    let bytes = compact
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect::<Option<Vec<_>>>()?;

    decode_binary(bytes, BinaryTransforms::EncodedPayload)
}

fn decode_url(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
                output.push(u8::from_str_radix(hex, 16).ok()?);
                index += 3;
            }
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8(output).ok()
}

fn text_result(output: String) -> Option<DecodeResult> {
    Some(DecodeResult {
        output,
        compression_layers: Vec::new(),
    })
}

pub(super) fn decode_binary(
    mut bytes: Vec<u8>,
    transforms: BinaryTransforms,
) -> Option<DecodeResult> {
    let mut compression_layers = Vec::new();
    let mut xor_applied = false;
    for _ in 0..MAX_COMPRESSION_LAYERS {
        if let Some(kind) = compression_kind(&bytes) {
            let input_preview = format!("<{} payload: {} bytes>", kind, bytes.len());
            bytes = decompress(&bytes, kind)?;
            let output_preview = String::from_utf8(bytes.clone())
                .unwrap_or_else(|_| format!("<decompressed binary: {} bytes>", bytes.len()));
            compression_layers.push(CompressionLayer {
                kind,
                input_preview,
                output_preview,
                detail: None,
                confidence: 0.99,
            });
            continue;
        }
        if transforms == BinaryTransforms::CompressionOnly {
            break;
        }
        if let Some(text) = decode_utf16le(&bytes) {
            compression_layers.push(CompressionLayer {
                kind: EncodingKind::Utf16Le,
                input_preview: format!("<UTF-16LE payload: {} bytes>", bytes.len()),
                output_preview: text.clone(),
                detail: None,
                confidence: 0.95,
            });
            return Some(DecodeResult {
                output: text,
                compression_layers,
            });
        }
        if xor_applied || is_printable_text(&bytes) {
            break;
        }
        let Some((key, decoded, score)) = single_byte_xor(&bytes) else {
            break;
        };
        compression_layers.push(CompressionLayer {
            kind: EncodingKind::Xor,
            input_preview: format!("<XOR payload: {} bytes>", bytes.len()),
            output_preview: String::from_utf8_lossy(&decoded).into_owned(),
            detail: Some(format!("single-byte key 0x{key:02x}")),
            confidence: xor_confidence(score),
        });
        bytes = decoded;
        xor_applied = true;
    }
    let output = String::from_utf8(bytes).ok()?;
    Some(DecodeResult {
        output,
        compression_layers,
    })
}

/// Confidence that decoded bytes hold a byte-level layer `decode_binary`
/// would unwrap, so detection and decoding cannot disagree.
pub(super) fn encoded_payload_confidence(bytes: &[u8]) -> Option<f32> {
    if compression_kind(bytes).is_some() {
        return Some(0.99);
    }
    if decode_utf16le(bytes).is_some() {
        return Some(0.95);
    }
    if is_printable_text(bytes) {
        return None;
    }
    single_byte_xor(bytes).map(|(_, _, score)| xor_confidence(score))
}

fn xor_confidence(score: f32) -> f32 {
    // Brute-forced keys are heuristic; never report them as certain.
    (0.5 + score * 0.3).min(0.8)
}

/// Recognizes little-endian UTF-16 text such as PowerShell `-EncodedCommand`
/// payloads: a byte-order mark, or ASCII-range text with zero high bytes.
fn decode_utf16le(bytes: &[u8]) -> Option<String> {
    let (body, has_bom) = match bytes.strip_prefix(&[0xFF, 0xFE]) {
        Some(body) => (body, true),
        None => (bytes, false),
    };
    if body.len() < MIN_UTF16_BYTES || !body.len().is_multiple_of(2) {
        return None;
    }
    let (units, _) = body.as_chunks::<2>();
    if !has_bom {
        let ascii_units = units
            .iter()
            .filter(|unit| unit[1] == 0 && unit[0] != 0)
            .count();
        if ascii_units * 10 < units.len() * 9 {
            return None;
        }
    }
    let text = char::decode_utf16(units.iter().map(|unit| u16::from_le_bytes(*unit)))
        .collect::<Result<String, _>>()
        .ok()?;
    is_printable_text(text.as_bytes()).then_some(text)
}

fn is_printable_text(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| {
        text.chars()
            .all(|character| !character.is_control() || matches!(character, '\t' | '\n' | '\r'))
    })
}

/// Returns the key whose output is entirely printable ASCII and most resembles
/// text. Ties keep the lowest key so results are deterministic.
fn single_byte_xor(bytes: &[u8]) -> Option<(u8, Vec<u8>, f32)> {
    if !(MIN_XOR_BYTES..=MAX_XOR_BYTES).contains(&bytes.len()) {
        return None;
    }
    let mut best: Option<(u8, usize)> = None;
    for key in 1..=u8::MAX {
        let mut text_like = 0;
        let printable = bytes.iter().all(|byte| {
            let value = byte ^ key;
            if value.is_ascii_alphanumeric() || value == b' ' {
                text_like += 1;
            }
            matches!(value, 0x20..=0x7E | b'\t' | b'\n' | b'\r')
        });
        if printable && best.is_none_or(|(_, current)| text_like > current) {
            best = Some((key, text_like));
        }
    }
    let (key, text_like) = best?;
    let score = text_like as f32 / bytes.len() as f32;
    if score < MIN_XOR_TEXT_SCORE {
        return None;
    }
    Some((key, bytes.iter().map(|byte| byte ^ key).collect(), score))
}

pub(super) fn compression_kind(bytes: &[u8]) -> Option<EncodingKind> {
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return Some(EncodingKind::Gzip);
    }
    if bytes.len() >= 2
        && bytes[0] & 0x0f == 8
        && (u16::from(bytes[0]) << 8 | u16::from(bytes[1])).is_multiple_of(31)
    {
        return Some(EncodingKind::Zlib);
    }
    None
}

fn decompress(bytes: &[u8], kind: EncodingKind) -> Option<Vec<u8>> {
    let reader: Box<dyn Read> = match kind {
        EncodingKind::Gzip => Box::new(GzDecoder::new(bytes)),
        EncodingKind::Zlib => Box::new(ZlibDecoder::new(bytes)),
        _ => return None,
    };
    let mut output = Vec::new();
    reader
        .take(MAX_DECOMPRESSED_BYTES + 1)
        .read_to_end(&mut output)
        .ok()?;
    if output.len() as u64 > MAX_DECOMPRESSED_BYTES {
        return None;
    }
    Some(output)
}

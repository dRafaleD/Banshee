use std::io::Read;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use flate2::read::{GzDecoder, ZlibDecoder};

use super::EncodingKind;

const MAX_DECOMPRESSED_BYTES: u64 = 16 * 1024 * 1024;
const MAX_COMPRESSION_LAYERS: usize = 4;

pub(super) struct DecodeResult {
    pub output: String,
    pub compression_layers: Vec<CompressionLayer>,
}

pub(super) struct CompressionLayer {
    pub kind: EncodingKind,
    pub input_preview: String,
    pub output_preview: String,
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
        EncodingKind::Gzip | EncodingKind::Zlib => None,
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
        .and_then(decode_binary)
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

    decode_binary(bytes)
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

pub(super) fn decode_binary(mut bytes: Vec<u8>) -> Option<DecodeResult> {
    let mut compression_layers = Vec::new();
    for _ in 0..MAX_COMPRESSION_LAYERS {
        let Some(kind) = compression_kind(&bytes) else {
            break;
        };
        let input_preview = format!("<{} payload: {} bytes>", kind, bytes.len());
        bytes = decompress(&bytes, kind)?;
        let output_preview = String::from_utf8(bytes.clone())
            .unwrap_or_else(|_| format!("<decompressed binary: {} bytes>", bytes.len()));
        compression_layers.push(CompressionLayer {
            kind,
            input_preview,
            output_preview,
        });
    }
    let output = String::from_utf8(bytes).ok()?;
    Some(DecodeResult {
        output,
        compression_layers,
    })
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

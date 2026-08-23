use std::fmt::Write as _;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use clap::ValueEnum;
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, percent_encode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Codec {
    Base64,
    Base64url,
    Base32,
    Base85,
    Hex,
    Binary,
    Octal,
    Rot13,
    Punycode,
    Url,
    Html,
    Unicode,
}

pub fn encode(input: &str, codec: Codec) -> String {
    encode_bytes(input.as_bytes(), codec).expect("UTF-8 text supports every codec")
}

pub fn encode_bytes(input: &[u8], codec: Codec) -> Result<String> {
    match codec {
        Codec::Base64 => Ok(STANDARD.encode(input)),
        Codec::Base64url => Ok(URL_SAFE_NO_PAD.encode(input)),
        Codec::Base32 => Ok(encode_base32(input)),
        Codec::Base85 => Ok(encode_ascii85(input)),
        Codec::Hex => {
            let mut output = String::with_capacity(input.len() * 2);
            for byte in input {
                write!(output, "{byte:02x}").expect("writing to String cannot fail");
            }
            Ok(output)
        }
        Codec::Binary => Ok(input
            .iter()
            .map(|byte| format!("{byte:08b}"))
            .collect::<Vec<_>>()
            .join(" ")),
        Codec::Octal => Ok(input
            .iter()
            .map(|byte| format!("{byte:03o}"))
            .collect::<Vec<_>>()
            .join(" ")),
        Codec::Rot13 => {
            let input = std::str::from_utf8(input).context("ROT13 encoding requires UTF-8 text")?;
            Ok(rot13(input))
        }
        Codec::Punycode => {
            let input =
                std::str::from_utf8(input).context("Punycode encoding requires UTF-8 text")?;
            idna::domain_to_ascii(input).context("invalid internationalized domain name")
        }
        Codec::Url => Ok(percent_encode(input, NON_ALPHANUMERIC).to_string()),
        Codec::Html => {
            let input = std::str::from_utf8(input).context("HTML encoding requires UTF-8 text")?;
            Ok(html_escape::encode_text(input).into_owned())
        }
        Codec::Unicode => {
            let input =
                std::str::from_utf8(input).context("Unicode encoding requires UTF-8 text")?;
            Ok(encode_unicode(input))
        }
    }
}

pub fn decode(input: &str, codec: Codec) -> Result<Vec<u8>> {
    match codec {
        Codec::Base64 => [STANDARD, STANDARD_NO_PAD]
            .iter()
            .find_map(|engine| engine.decode(input.trim()).ok())
            .context("invalid Base64"),
        Codec::Base64url => URL_SAFE_NO_PAD
            .decode(input.trim().trim_end_matches('='))
            .context("invalid Base64URL"),
        Codec::Base32 => decode_base32(input),
        Codec::Base85 => decode_ascii85(input),
        Codec::Hex => decode_hex(input),
        Codec::Binary => decode_radix_bytes(input, 2, 8, "binary"),
        Codec::Octal => decode_radix_bytes(input, 8, 3, "octal"),
        Codec::Rot13 => Ok(rot13(input).into_bytes()),
        Codec::Punycode => {
            let (decoded, status) = idna::domain_to_unicode(input.trim());
            status
                .context("invalid Punycode domain name")
                .map(|()| decoded.into_bytes())
        }
        Codec::Url => percent_decode_str(&input.replace('+', " "))
            .decode_utf8()
            .context("URL-decoded value is not UTF-8")
            .map(|value| value.into_owned().into_bytes()),
        Codec::Html => Ok(html_escape::decode_html_entities(input)
            .into_owned()
            .into_bytes()),
        Codec::Unicode => decode_unicode(input).map(String::into_bytes),
    }
}

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn encode_base32(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len().div_ceil(5) * 8);
    let mut buffer = 0_u64;
    let mut bits = 0_u8;

    for byte in input {
        buffer = (buffer << 8) | u64::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(char::from(
                BASE32_ALPHABET[((buffer >> bits) & 0x1F) as usize],
            ));
        }
    }
    if bits > 0 {
        output.push(char::from(
            BASE32_ALPHABET[((buffer << (5 - bits)) & 0x1F) as usize],
        ));
    }
    while !output.len().is_multiple_of(8) {
        output.push('=');
    }
    output
}

fn decode_base32(input: &str) -> Result<Vec<u8>> {
    let compact: Vec<u8> = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let body_len = compact
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(compact.len());
    if compact[body_len..].iter().any(|byte| *byte != b'=') {
        bail!("invalid Base32 padding");
    }
    let remainder = body_len % 8;
    if !matches!(remainder, 0 | 2 | 4 | 5 | 7) {
        bail!("invalid Base32 length");
    }
    if body_len != compact.len() {
        let expected_padding = (8 - remainder) % 8;
        if !compact.len().is_multiple_of(8) || compact.len() - body_len != expected_padding {
            bail!("invalid Base32 padding");
        }
    }

    let mut output = Vec::with_capacity(body_len * 5 / 8);
    let mut buffer = 0_u64;
    let mut bits = 0_u8;
    for byte in &compact[..body_len] {
        let value = match byte.to_ascii_uppercase() {
            b'A'..=b'Z' => byte.to_ascii_uppercase() - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => bail!("invalid Base32 character"),
        };
        buffer = (buffer << 5) | u64::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    if bits > 0 && buffer & ((1_u64 << bits) - 1) != 0 {
        bail!("invalid non-zero Base32 padding bits");
    }
    Ok(output)
}

fn encode_ascii85(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len().div_ceil(4) * 5);
    for chunk in input.chunks(4) {
        let mut padded = [0_u8; 4];
        padded[..chunk.len()].copy_from_slice(chunk);
        let value = u32::from_be_bytes(padded);
        if chunk.len() == 4 && value == 0 {
            output.push('z');
            continue;
        }
        let encoded = ascii85_group(value);
        let take = if chunk.len() == 4 { 5 } else { chunk.len() + 1 };
        for byte in &encoded[..take] {
            output.push(char::from(*byte));
        }
    }
    output
}

fn ascii85_group(mut value: u32) -> [u8; 5] {
    let mut encoded = [b'!'; 5];
    for byte in encoded.iter_mut().rev() {
        *byte = (value % 85) as u8 + b'!';
        value /= 85;
    }
    encoded
}

fn decode_ascii85(input: &str) -> Result<Vec<u8>> {
    let trimmed = input.trim();
    let wrapped = trimmed.starts_with("<~") || trimmed.ends_with("~>");
    let source = if wrapped {
        trimmed
            .strip_prefix("<~")
            .and_then(|value| value.strip_suffix("~>"))
            .context("invalid Ascii85 wrapper")?
    } else {
        trimmed
    };

    let mut output = Vec::with_capacity(source.len() * 4 / 5);
    let mut group = Vec::with_capacity(5);
    for byte in source.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        if byte == b'z' {
            if !group.is_empty() {
                bail!("Ascii85 'z' shorthand must appear between groups");
            }
            output.extend_from_slice(&[0; 4]);
            continue;
        }
        if !(b'!'..=b'u').contains(&byte) {
            bail!("invalid Ascii85 character");
        }
        group.push(byte);
        if group.len() == 5 {
            output.extend_from_slice(&decode_ascii85_group(&group)?.to_be_bytes());
            group.clear();
        }
    }
    if group.len() == 1 {
        bail!("invalid one-character Ascii85 tail");
    }
    if !group.is_empty() {
        let output_bytes = group.len() - 1;
        group.resize(5, b'u');
        output.extend_from_slice(&decode_ascii85_group(&group)?.to_be_bytes()[..output_bytes]);
    }
    Ok(output)
}

fn decode_ascii85_group(group: &[u8]) -> Result<u32> {
    let mut value = 0_u64;
    for byte in group {
        value = value * 85 + u64::from(byte - b'!');
    }
    u32::try_from(value).context("Ascii85 group exceeds 32-bit range")
}

fn decode_radix_bytes(input: &str, radix: u32, width: usize, name: &str) -> Result<Vec<u8>> {
    let compact: String = input
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if compact.is_empty() {
        return Ok(Vec::new());
    }
    if !compact.len().is_multiple_of(width) || !compact.is_ascii() {
        bail!("invalid {name} byte sequence");
    }
    compact
        .as_bytes()
        .chunks_exact(width)
        .map(|chunk| {
            let token = std::str::from_utf8(chunk).expect("radix input is ASCII");
            u8::from_str_radix(token, radix)
                .with_context(|| format!("invalid {name} byte '{token}'"))
        })
        .collect()
}

fn rot13(input: &str) -> String {
    input
        .chars()
        .map(|character| match character {
            'a'..='m' | 'A'..='M' => char::from_u32(u32::from(character) + 13).unwrap(),
            'n'..='z' | 'N'..='Z' => char::from_u32(u32::from(character) - 13).unwrap(),
            _ => character,
        })
        .collect()
}

fn decode_hex(input: &str) -> Result<Vec<u8>> {
    let compact = input.trim();
    if !compact.len().is_multiple_of(2) || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid hexadecimal input");
    }
    compact
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("hex is ASCII");
            u8::from_str_radix(pair, 16).context("invalid hexadecimal input")
        })
        .collect()
}

fn encode_unicode(input: &str) -> String {
    let mut output = String::new();
    for character in input.chars() {
        let code = u32::from(character);
        if character.is_ascii() && !character.is_ascii_control() {
            output.push(character);
        } else if code <= 0xFFFF {
            write!(output, "\\u{code:04X}").expect("writing to String cannot fail");
        } else {
            let adjusted = code - 0x1_0000;
            let high = 0xD800 + (adjusted >> 10);
            let low = 0xDC00 + (adjusted & 0x3FF);
            write!(output, "\\u{high:04X}\\u{low:04X}").expect("writing to String cannot fail");
        }
    }
    output
}

pub(crate) fn decode_unicode(input: &str) -> Result<String> {
    let mut output = String::new();
    let mut index = 0;
    while index < input.len() {
        let remaining = &input[index..];
        if let Some(hex) = remaining.strip_prefix("\\u{").and_then(|value| {
            let end = value.find('}')?;
            Some((&value[..end], end + 4))
        }) {
            let code = u32::from_str_radix(hex.0, 16).context("invalid Unicode escape")?;
            output.push(char::from_u32(code).context("invalid Unicode code point")?);
            index += hex.1;
            continue;
        }
        if remaining.starts_with("\\u") && remaining.len() >= 6 {
            let high =
                u16::from_str_radix(&remaining[2..6], 16).context("invalid \\u Unicode escape")?;
            if (0xD800..=0xDBFF).contains(&high) {
                if remaining.len() < 12 || &remaining[6..8] != "\\u" {
                    bail!("high surrogate is missing its low surrogate");
                }
                let low =
                    u16::from_str_radix(&remaining[8..12], 16).context("invalid low surrogate")?;
                if !(0xDC00..=0xDFFF).contains(&low) {
                    bail!("invalid low surrogate");
                }
                let code =
                    0x1_0000 + ((u32::from(high) - 0xD800) << 10) + (u32::from(low) - 0xDC00);
                output.push(char::from_u32(code).context("invalid surrogate pair")?);
                index += 12;
            } else {
                output.push(char::from_u32(u32::from(high)).context("invalid Unicode code point")?);
                index += 6;
            }
            continue;
        }

        let character = remaining.chars().next().expect("non-empty remainder");
        output.push(character);
        index += character.len_utf8();
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{Codec, decode, encode, encode_bytes};

    #[test]
    fn round_trips_unicode_surrogate_pairs() {
        let encoded = encode("Banshee 👻", Codec::Unicode);
        assert_eq!(encoded, "Banshee \\uD83D\\uDC7B");
        assert_eq!(
            decode(&encoded, Codec::Unicode).expect("decode"),
            "Banshee 👻".as_bytes()
        );
    }

    #[test]
    fn decodes_binary_base64() {
        assert_eq!(decode("AP8=", Codec::Base64).expect("decode"), [0, 255]);
    }

    #[test]
    fn supports_base32_known_vector_and_unpadded_input() {
        assert_eq!(encode("foo", Codec::Base32), "MZXW6===");
        assert_eq!(decode("mzxw6", Codec::Base32).expect("decode"), b"foo");
    }

    #[test]
    fn round_trips_ascii85_with_wrapper_and_zero_shorthand() {
        let bytes = b"hello\0\0\0\0world";
        let encoded = encode_bytes(bytes, Codec::Base85).expect("encode");
        assert_eq!(decode(&encoded, Codec::Base85).expect("decode"), bytes);
        assert_eq!(decode("<~z~>", Codec::Base85).expect("decode"), [0; 4]);
    }

    #[test]
    fn supports_binary_and_octal_bytes() {
        assert_eq!(
            encode_bytes(&[0, 255], Codec::Binary).unwrap(),
            "00000000 11111111"
        );
        assert_eq!(decode("0000000011111111", Codec::Binary).unwrap(), [0, 255]);
        assert_eq!(encode_bytes(&[0, 255], Codec::Octal).unwrap(), "000 377");
        assert_eq!(decode("000 377", Codec::Octal).unwrap(), [0, 255]);
    }

    #[test]
    fn rot13_is_symmetric() {
        let encoded = encode("Hello, Banshee!", Codec::Rot13);
        assert_eq!(encoded, "Uryyb, Onafurr!");
        assert_eq!(decode(&encoded, Codec::Rot13).unwrap(), b"Hello, Banshee!");
    }

    #[test]
    fn converts_internationalized_domains() {
        let encoded = encode("bücher.de", Codec::Punycode);
        assert_eq!(encoded, "xn--bcher-kva.de");
        assert_eq!(
            decode(&encoded, Codec::Punycode).unwrap(),
            "bücher.de".as_bytes()
        );
    }
}

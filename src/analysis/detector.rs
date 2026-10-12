use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use regex::Regex;
use std::sync::OnceLock;

use super::EncodingKind;
use super::decoder::encoded_payload_confidence;

#[derive(Debug, Clone, Copy)]
pub(super) struct Detection {
    pub kind: EncodingKind,
    pub confidence: f32,
}

pub(super) fn detect_best(input: &str) -> Option<Detection> {
    let mut candidates = [
        detect_html(input),
        detect_unicode(input),
        detect_url(input),
        detect_hex(input),
        detect_base64(input),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();

    candidates.sort_by(|left, right| right.confidence.total_cmp(&left.confidence));
    candidates.into_iter().next()
}

fn detect_unicode(input: &str) -> Option<Detection> {
    static UNICODE_ESCAPE: OnceLock<Regex> = OnceLock::new();
    let pattern = UNICODE_ESCAPE.get_or_init(|| {
        Regex::new(r"\\u(?:[0-9A-Fa-f]{4}|\{[0-9A-Fa-f]{1,6}\})").expect("valid regex")
    });
    let count = pattern.find_iter(input).count();
    if count == 0 {
        return None;
    }
    Some(Detection {
        kind: EncodingKind::UnicodeEscape,
        confidence: (0.86 + count.min(5) as f32 * 0.02).min(0.98),
    })
}

fn detect_base64(input: &str) -> Option<Detection> {
    let compact: String = input
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if compact.len() < 8 || compact.len() % 4 == 1 {
        return None;
    }

    if !compact.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'_' | b'-' | b'=')
    }) {
        return None;
    }

    let decoded = [STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(&compact).ok())?;
    if let Some(confidence) = encoded_payload_confidence(&decoded) {
        return Some(Detection {
            kind: EncodingKind::Base64,
            confidence,
        });
    }
    let text = std::str::from_utf8(&decoded).ok()?;
    let printable = printable_ratio(text);
    if printable < 0.85 {
        return None;
    }

    let padding_bonus = if compact.ends_with('=') { 0.05 } else { 0.0 };
    Some(Detection {
        kind: EncodingKind::Base64,
        confidence: (0.72_f32 + printable * 0.2 + padding_bonus).min(0.99_f32),
    })
}

fn detect_hex(input: &str) -> Option<Detection> {
    let compact: String = input
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if compact.len() < 4
        || !compact.len().is_multiple_of(2)
        || !compact.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }

    let decoded = compact
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect::<Option<Vec<_>>>()?;
    if let Some(confidence) = encoded_payload_confidence(&decoded) {
        return Some(Detection {
            kind: EncodingKind::Hex,
            confidence,
        });
    }
    let text = std::str::from_utf8(&decoded).ok()?;
    let printable = printable_ratio(text);
    if printable < 0.85 {
        return None;
    }

    Some(Detection {
        kind: EncodingKind::Hex,
        confidence: 0.78 + printable * 0.18,
    })
}

fn detect_url(input: &str) -> Option<Detection> {
    static PERCENT_ESCAPE: OnceLock<Regex> = OnceLock::new();
    let pattern =
        PERCENT_ESCAPE.get_or_init(|| Regex::new(r"%[0-9A-Fa-f]{2}").expect("valid regex"));
    let count = pattern.find_iter(input).count();
    if count == 0 {
        return None;
    }

    Some(Detection {
        kind: EncodingKind::UrlEncoding,
        confidence: (0.8 + count.min(5) as f32 * 0.03).min(0.97),
    })
}

fn detect_html(input: &str) -> Option<Detection> {
    static HTML_ENTITY: OnceLock<Regex> = OnceLock::new();
    let pattern = HTML_ENTITY.get_or_init(|| {
        Regex::new(r"&(?:#\d{1,7}|#x[0-9A-Fa-f]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")
            .expect("valid regex")
    });
    let count = pattern.find_iter(input).count();
    if count == 0 {
        return None;
    }

    Some(Detection {
        kind: EncodingKind::HtmlEntity,
        confidence: (0.84 + count.min(5) as f32 * 0.025).min(0.98),
    })
}

fn printable_ratio(value: &str) -> f32 {
    if value.is_empty() {
        return 0.0;
    }

    let printable = value
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .count();
    printable as f32 / value.chars().count() as f32
}

//! Script-level deobfuscation: character-code arrays, `\xNN` escapes, string
//! concatenation, format operators and reversed literals.
//!
//! Each transform rewrites only the recognized construct and keeps the
//! surrounding code, so later layers (and IOC extraction) see the result in
//! context. Nothing is evaluated; every pattern is a bounded regular expression.

use std::sync::OnceLock;

use regex::{Captures, Regex};

use super::EncodingKind;
use super::decoder::{BinaryTransforms, DecodeResult, decode_binary};
use super::detector::Detection;

/// Character-code constructs must decode to at least this many characters.
const MIN_CHAR_CODES: usize = 3;
/// How far after a character-code array a `-bxor`/`^` key may appear.
const XOR_KEY_WINDOW: usize = 160;
const MIN_HEX_ESCAPES: usize = 4;

struct Patterns {
    from_char_code: Regex,
    ps_char_array: Regex,
    ps_pipeline: Regex,
    ps_char_run: Regex,
    vb_chr_run: Regex,
    xor_key: Regex,
    number: Regex,
    hex_escape: Regex,
    concat: Regex,
    literal: Regex,
    format: Regex,
    js_reverse: Regex,
    ps_reverse: Regex,
}

fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    const NUMBER: &str = r"(?:0x[0-9a-f]+|&h[0-9a-f]+|\d+)";
    const LITERAL: &str = r#"(?:'(?:[^'\r\n]|'')*'|"(?:[^"\\\r\n]|\\.)*")"#;
    PATTERNS.get_or_init(|| Patterns {
        from_char_code: Regex::new(&format!(
            r"(?i)String\.fromCharCode\s*\(\s*({NUMBER}(?:\s*,\s*{NUMBER})*)\s*\)"
        ))
        .expect("valid fromCharCode regex"),
        ps_char_array: Regex::new(&format!(
            r"(?i)\[char\[\]\]\s*@?\(\s*({NUMBER}(?:\s*,\s*{NUMBER})+)\s*\)(?:\s*-join\s*(?:''|\x22\x22))?"
        ))
        .expect("valid PowerShell char array regex"),
        ps_pipeline: Regex::new(&format!(
            r"(?i)@?\(\s*({NUMBER}(?:\s*,\s*{NUMBER}){{2,}})\s*\)\s*\|\s*(?:%|foreach(?:-object)?)\s*\{{\s*\[char\]\s*\(?\s*\$_\s*(?:-bxor\s*({NUMBER}))?\s*\)?\s*\}}"
        ))
        .expect("valid PowerShell pipeline regex"),
        ps_char_run: Regex::new(&format!(
            // Parentheses around a code must balance so an enclosing `)` is kept.
            r"(?i)\[char\]\s*(?:\(\s*{NUMBER}\s*\)|{NUMBER})(?:\s*\+\s*\[char\]\s*(?:\(\s*{NUMBER}\s*\)|{NUMBER}))+"
        ))
        .expect("valid PowerShell char run regex"),
        vb_chr_run: Regex::new(&format!(
            r"(?i)\bchrw?\$?\s*\(\s*{NUMBER}\s*\)(?:\s*[&+]\s*chrw?\$?\s*\(\s*{NUMBER}\s*\))+"
        ))
        .expect("valid VBScript Chr run regex"),
        xor_key: Regex::new(&format!(r"(?i)(?:-bxor|\^)\s*({NUMBER})"))
            .expect("valid XOR key regex"),
        number: Regex::new(&format!(r"(?i){NUMBER}")).expect("valid number regex"),
        hex_escape: Regex::new(r"\\x[0-9A-Fa-f]{2}").expect("valid hex escape regex"),
        concat: Regex::new(&format!(r"{LITERAL}(?:\s*[+&]\s*{LITERAL})+"))
            .expect("valid concatenation regex"),
        literal: Regex::new(LITERAL).expect("valid literal regex"),
        format: Regex::new(&format!(
            r#"(?i)"((?:[^"\r\n]*\{{\d+\}}[^"\r\n]*)+)"\s*-f\s*({LITERAL}(?:\s*,\s*{LITERAL})*)"#
        ))
        .expect("valid format operator regex"),
        js_reverse: Regex::new(&format!(
            r#"({LITERAL})\s*\.split\(\s*(?:''|"")\s*\)\s*\.reverse\(\s*\)\s*\.join\(\s*(?:''|"")\s*\)"#
        ))
        .expect("valid JavaScript reverse regex"),
        ps_reverse: Regex::new(&format!(
            r#"(?i)({LITERAL})\s*\[\s*-1\s*\.\.\s*-\s*[^\]\r\n]{{1,64}}\]\s*-join\s*(?:''|"")"#
        ))
        .expect("valid PowerShell reverse regex"),
    })
}

pub(super) fn detect(input: &str) -> Option<Detection> {
    let patterns = patterns();
    let candidates = [
        (EncodingKind::CharCodes, 0.94, has_char_codes(input)),
        (
            EncodingKind::HexEscape,
            0.9,
            patterns
                .hex_escape
                .find_iter(input)
                .nth(MIN_HEX_ESCAPES - 1)
                .is_some(),
        ),
        (
            EncodingKind::ReversedString,
            0.92,
            patterns.js_reverse.is_match(input) || patterns.ps_reverse.is_match(input),
        ),
        (
            EncodingKind::FormatString,
            0.9,
            patterns.format.is_match(input),
        ),
        (
            EncodingKind::StringConcat,
            0.86,
            patterns.concat.is_match(input),
        ),
    ];
    candidates
        .into_iter()
        .find(|(_, _, present)| *present)
        .map(|(kind, confidence, _)| Detection { kind, confidence })
}

fn has_char_codes(input: &str) -> bool {
    let patterns = patterns();
    [
        &patterns.from_char_code,
        &patterns.ps_char_array,
        &patterns.ps_pipeline,
        &patterns.ps_char_run,
        &patterns.vb_chr_run,
    ]
    .iter()
    .any(|pattern| pattern.is_match(input))
}

pub(super) fn decode(kind: EncodingKind, input: &str) -> Option<DecodeResult> {
    let (output, detail) = match kind {
        EncodingKind::CharCodes => decode_char_codes(input)?,
        EncodingKind::HexEscape => return decode_hex_escapes(input),
        EncodingKind::StringConcat => (join_concatenations(input), None),
        EncodingKind::FormatString => (apply_format_operators(input), None),
        EncodingKind::ReversedString => (reverse_literals(input), None),
        _ => return None,
    };
    (output != input).then(|| DecodeResult {
        output,
        compression_layers: Vec::new(),
        detail,
    })
}

fn decode_char_codes(input: &str) -> Option<(String, Option<String>)> {
    let patterns = patterns();
    let mut keys = Vec::new();
    let mut output = input.to_owned();

    // Arrays may be followed by a `-bxor`/`^` key in a nearby script block.
    for pattern in [&patterns.from_char_code, &patterns.ps_char_array] {
        output = replace_valid(pattern, &output, |captures, whole, text| {
            let mut codes = parse_numbers(&captures[1])?;
            let window_end = (whole.end() + XOR_KEY_WINDOW).min(text.len());
            let window = text.get(whole.end()..window_end).unwrap_or_default();
            if let Some(key) = patterns
                .xor_key
                .captures(window)
                .and_then(|key| parse_number(&key[1]))
            {
                codes.iter_mut().for_each(|code| *code ^= key);
                keys.push(key);
            }
            quoted(&codes)
        });
    }
    output = replace_valid(&patterns.ps_pipeline, &output, |captures, _, _| {
        let mut codes = parse_numbers(&captures[1])?;
        if let Some(key) = captures.get(2).and_then(|key| parse_number(key.as_str())) {
            codes.iter_mut().for_each(|code| *code ^= key);
            keys.push(key);
        }
        quoted(&codes)
    });
    for pattern in [&patterns.ps_char_run, &patterns.vb_chr_run] {
        output = replace_valid(pattern, &output, |captures, _, _| {
            let codes = patterns
                .number
                .find_iter(&captures[0])
                .map(|number| parse_number(number.as_str()))
                .collect::<Option<Vec<_>>>()?;
            quoted(&codes)
        });
    }
    if output == input {
        return None;
    }
    keys.sort_unstable();
    keys.dedup();
    let detail = (!keys.is_empty()).then(|| {
        format!(
            "XOR key {}",
            keys.iter()
                .map(|key| format!("0x{key:02x}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    });
    Some((output, detail))
}

/// Replaces each match for which `build` succeeds; failed matches stay intact.
fn replace_valid(
    pattern: &Regex,
    text: &str,
    mut build: impl FnMut(&Captures<'_>, regex::Match<'_>, &str) -> Option<String>,
) -> String {
    pattern
        .replace_all(text, |captures: &Captures<'_>| {
            let whole = captures.get(0).expect("whole match");
            build(captures, whole, text).unwrap_or_else(|| whole.as_str().to_owned())
        })
        .into_owned()
}

fn parse_numbers(list: &str) -> Option<Vec<u32>> {
    patterns()
        .number
        .find_iter(list)
        .map(|number| parse_number(number.as_str()))
        .collect()
}

fn parse_number(value: &str) -> Option<u32> {
    let lower = value.to_ascii_lowercase();
    if let Some(hex) = lower
        .strip_prefix("0x")
        .or_else(|| lower.strip_prefix("&h"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else {
        lower.parse().ok()
    }
}

/// Builds a single-quoted literal from character codes, or `None` when the
/// codes are too few, invalid, or would produce control characters.
fn quoted(codes: &[u32]) -> Option<String> {
    if codes.len() < MIN_CHAR_CODES {
        return None;
    }
    let text = codes
        .iter()
        .map(|code| char::from_u32(*code))
        .collect::<Option<String>>()?;
    printable(&text).then(|| quote(&text))
}

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

fn printable(text: &str) -> bool {
    text.chars()
        .all(|character| !character.is_control() || matches!(character, '\t' | '\n' | '\r'))
}

fn decode_hex_escapes(input: &str) -> Option<DecodeResult> {
    let pattern = &patterns().hex_escape;
    let mut bytes = Vec::with_capacity(input.len());
    let mut last = 0;
    for escape in pattern.find_iter(input) {
        bytes.extend_from_slice(&input.as_bytes()[last..escape.start()]);
        bytes.push(u8::from_str_radix(&escape.as_str()[2..], 16).ok()?);
        last = escape.end();
    }
    bytes.extend_from_slice(&input.as_bytes()[last..]);
    if let Ok(text) = std::str::from_utf8(&bytes)
        && printable(text)
    {
        return Some(DecodeResult {
            output: text.to_owned(),
            compression_layers: Vec::new(),
            detail: None,
        });
    }
    // Escaped shellcode-like bytes may still wrap compression, UTF-16 or XOR.
    decode_binary(bytes, BinaryTransforms::EncodedPayload)
}

fn literal_value(literal: &str) -> String {
    let inner = &literal[1..literal.len() - 1];
    if literal.starts_with('\'') {
        inner.replace("''", "'")
    } else {
        inner.to_owned()
    }
}

fn join_concatenations(input: &str) -> String {
    let patterns = patterns();
    patterns
        .concat
        .replace_all(input, |captures: &Captures<'_>| {
            let joined = patterns
                .literal
                .find_iter(&captures[0])
                .map(|literal| literal_value(literal.as_str()))
                .collect::<String>();
            quote(&joined)
        })
        .into_owned()
}

fn apply_format_operators(input: &str) -> String {
    let patterns = patterns();
    patterns
        .format
        .replace_all(input, |captures: &Captures<'_>| {
            let arguments = patterns
                .literal
                .find_iter(&captures[2])
                .map(|literal| literal_value(literal.as_str()))
                .collect::<Vec<_>>();
            let mut output = String::new();
            let mut rest = &captures[1];
            while let Some(open) = rest.find('{') {
                output.push_str(&rest[..open]);
                let after = &rest[open + 1..];
                let Some(close) = after.find('}') else {
                    output.push_str(&rest[open..]);
                    rest = "";
                    break;
                };
                match after[..close]
                    .parse::<usize>()
                    .ok()
                    .and_then(|index| arguments.get(index))
                {
                    Some(argument) => output.push_str(argument),
                    // An unknown index means this is not a plain format string.
                    None => return captures[0].to_owned(),
                }
                rest = &after[close + 1..];
            }
            output.push_str(rest);
            quote(&output)
        })
        .into_owned()
}

fn reverse_literals(input: &str) -> String {
    let patterns = patterns();
    let mut output = input.to_owned();
    for pattern in [&patterns.js_reverse, &patterns.ps_reverse] {
        output = pattern
            .replace_all(&output, |captures: &Captures<'_>| {
                quote(
                    &literal_value(&captures[1])
                        .chars()
                        .rev()
                        .collect::<String>(),
                )
            })
            .into_owned();
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{EncodingKind, decode, detect};

    fn run(kind: EncodingKind, input: &str) -> String {
        assert_eq!(
            detect(input).map(|detection| detection.kind),
            Some(kind),
            "{input}"
        );
        decode(kind, input).expect("decodes").output
    }

    #[test]
    fn decodes_character_code_constructs() {
        assert_eq!(
            run(
                EncodingKind::CharCodes,
                "eval(String.fromCharCode(104,105,0x21))"
            ),
            "eval('hi!')"
        );
        assert_eq!(
            run(
                EncodingKind::CharCodes,
                "iex ([char]105+[char]0x65+[char]120)"
            ),
            "iex ('iex')"
        );
        assert_eq!(
            run(
                EncodingKind::CharCodes,
                "[char[]](104,116,116,112) -join ''"
            ),
            "'http'"
        );
        assert_eq!(
            run(
                EncodingKind::CharCodes,
                "x = Chr(87) & ChrW(&H53) & Chr(72)"
            ),
            "x = 'WSH'"
        );
    }

    #[test]
    fn applies_nearby_xor_keys_and_reports_them() {
        let key = 0x5a;
        let codes = "http"
            .bytes()
            .map(|byte| (byte ^ key).to_string())
            .collect::<Vec<_>>()
            .join(",");
        let pipeline = format!("-join (({codes}) | % {{[char]($_ -bxor 0x5a)}})");
        let result = decode(EncodingKind::CharCodes, &pipeline).expect("decodes");
        assert_eq!(result.output, "-join ('http')");
        assert_eq!(result.detail.as_deref(), Some("XOR key 0x5a"));
    }

    #[test]
    fn decodes_hex_escapes_concatenation_format_and_reversal() {
        assert_eq!(
            run(EncodingKind::HexEscape, r"var u = '\x68\x74\x74\x70';"),
            "var u = 'http';"
        );
        assert_eq!(
            run(
                EncodingKind::StringConcat,
                "$u = 'ht'+'tp:'+ \"//ex\" + 'ample.test'"
            ),
            "$u = 'http://example.test'"
        );
        assert_eq!(
            run(
                EncodingKind::FormatString,
                r#"("{2}{0}{1}" -f 'tp://','x.test','ht')"#
            ),
            "('http://x.test')"
        );
        assert_eq!(
            run(
                EncodingKind::ReversedString,
                "'tset.elpmaxe'.split('').reverse().join('')"
            ),
            "'example.test'"
        );
        assert_eq!(
            run(EncodingKind::ReversedString, "'tset.x'[-1..-6] -join ''"),
            "'x.test'"
        );
    }

    #[test]
    fn leaves_plain_or_invalid_code_alone() {
        assert!(detect("plain text with 1, 2, 3 numbers").is_none());
        // Too few codes and control characters are not decoded.
        assert!(decode(EncodingKind::CharCodes, "String.fromCharCode(1,2,3)").is_none());
        assert!(decode(EncodingKind::CharCodes, "String.fromCharCode(65,66)").is_none());
        // Unknown format indexes keep the original expression.
        assert!(decode(EncodingKind::FormatString, r#""{0}{5}" -f 'a','b'"#).is_none());
    }
}

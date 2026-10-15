//! Printable string extraction, like the classic `strings` tool: ASCII and
//! UTF-16LE runs with their byte offsets. Results are bounded so a large or
//! hostile input cannot exhaust memory; the total count is kept even when the
//! list is cut short.

use serde::Serialize;

/// Longest value kept per string; longer runs are cut and flagged.
const MAX_VALUE_CHARS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum StringEncoding {
    Ascii,
    Utf16le,
}

impl std::fmt::Display for StringEncoding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Ascii => "ascii",
            Self::Utf16le => "utf16le",
        })
    }
}

/// Which encodings to search for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum EncodingChoice {
    All,
    Ascii,
    Utf16le,
}

#[derive(Debug, Clone, Serialize)]
pub struct FoundString {
    pub offset: usize,
    pub encoding: StringEncoding,
    pub value: String,
    /// True when the run was longer than the kept value.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub value_truncated: bool,
    /// What the string looks like (url, ipv4, path, ...), when notable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<&'static str>,
}

/// Classifies a string as an analyst would skim `strings` output. The first
/// matching category wins; `None` means nothing stands out.
pub fn category(value: &str) -> Option<&'static str> {
    use std::sync::OnceLock;

    use regex::Regex;

    static PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        [
            ("url", r"(?i)\b(?:https?|ftp)://[^\s]{3,}"),
            (
                "email",
                r"(?i)\b[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})*\.[a-z]{2,24}\b",
            ),
            (
                "ipv4",
                r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b",
            ),
            (
                "registry",
                r"(?i)\bHKEY_[A-Z_]+|\bHK(?:LM|CU|CR|U)\\|software\\microsoft\\windows\\currentversion",
            ),
            (
                "path",
                r"(?i)\b[a-z]:\\[^\s]|%(?:appdata|localappdata|temp|tmp|programdata|userprofile|windir|systemroot)%|\\\\[a-z0-9.-]+\\",
            ),
            (
                "command",
                r"(?i)\b(?:cmd\.exe|powershell|pwsh|rundll32|regsvr32|mshta|wscript|cscript|schtasks|bitsadmin|certutil|vssadmin|wmic|bcdedit|netsh)\b",
            ),
            ("user-agent", r"(?i)\bmozilla/\d"),
            ("base64", r"^[A-Za-z0-9+/]{40,}={0,2}$"),
        ]
        .into_iter()
        .map(|(name, pattern)| (name, Regex::new(pattern).expect("valid category pattern")))
        .collect()
    });
    if let Some((name, _)) = patterns.iter().find(|(_, pattern)| pattern.is_match(value)) {
        return Some(name);
    }
    // Domains: dotted labels ending in a known IANA top-level domain.
    static DOMAIN: OnceLock<Regex> = OnceLock::new();
    let domain = DOMAIN.get_or_init(|| {
        Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b")
            .expect("valid domain pattern")
    });
    domain
        .find_iter(value)
        .any(|found| crate::tld::has_known_tld(found.as_str()))
        .then_some("domain")
}

#[derive(Debug, Clone, Serialize)]
pub struct StringsReport {
    pub input_bytes: usize,
    pub min_length: usize,
    /// Strings found, including those beyond `max_strings`.
    pub total: usize,
    /// True when more strings were found than are listed.
    pub truncated: bool,
    pub strings: Vec<FoundString>,
}

#[derive(Debug, Clone, Copy)]
pub struct StringsOptions {
    pub min_length: usize,
    pub encoding: EncodingChoice,
    pub max_strings: usize,
    /// Keep only strings with a category.
    pub interesting: bool,
}

fn printable(byte: u8) -> bool {
    byte == b'\t' || (0x20..=0x7e).contains(&byte)
}

/// Collects runs of at least `min_length` characters for one encoding.
/// `step` is the width of one character in bytes (1 or 2).
fn runs(bytes: &[u8], encoding: StringEncoding, min_length: usize) -> Vec<(usize, usize, String)> {
    let step = match encoding {
        StringEncoding::Ascii => 1,
        StringEncoding::Utf16le => 2,
    };
    let character = |index: usize| -> Option<u8> {
        match encoding {
            StringEncoding::Ascii => bytes.get(index).copied().filter(|byte| printable(*byte)),
            StringEncoding::Utf16le => match (bytes.get(index), bytes.get(index + 1)) {
                (Some(&low), Some(&0)) if printable(low) => Some(low),
                _ => None,
            },
        }
    };
    let mut found = Vec::new();
    // UTF-16 text may start at an even or an odd offset.
    let starts: &[usize] = if step == 2 { &[0, 1] } else { &[0] };
    for &first in starts {
        let mut index = first;
        let mut start = None;
        let mut length = 0usize;
        let mut value = String::new();
        while index < bytes.len() + step {
            match character(index) {
                Some(byte) => {
                    start.get_or_insert(index);
                    length += 1;
                    if value.len() < MAX_VALUE_CHARS {
                        value.push(char::from(byte));
                    }
                }
                None => {
                    if let Some(offset) = start.take()
                        && length >= min_length
                    {
                        found.push((offset, length, std::mem::take(&mut value)));
                    }
                    value.clear();
                    length = 0;
                }
            }
            index += step;
        }
    }
    found
}

pub fn extract(bytes: &[u8], options: StringsOptions) -> StringsReport {
    let min_length = options.min_length.max(1);
    let mut found: Vec<(usize, usize, StringEncoding, String)> = Vec::new();
    let wanted = |encoding| match options.encoding {
        EncodingChoice::All => true,
        EncodingChoice::Ascii => encoding == StringEncoding::Ascii,
        EncodingChoice::Utf16le => encoding == StringEncoding::Utf16le,
    };
    for encoding in [StringEncoding::Ascii, StringEncoding::Utf16le] {
        if wanted(encoding) {
            found.extend(
                runs(bytes, encoding, min_length)
                    .into_iter()
                    .map(|(offset, length, value)| (offset, length, encoding, value)),
            );
        }
    }
    // A UTF-16 string is also a run of one-character ASCII strings; those are
    // shorter than any useful minimum, so no extra de-duplication is needed.
    found.sort_by_key(|(offset, _, encoding, _)| (*offset, *encoding as u8));
    let mut total = 0;
    let mut strings = Vec::new();
    for (offset, length, encoding, value) in found {
        let category = category(&value);
        if options.interesting && category.is_none() {
            continue;
        }
        total += 1;
        if strings.len() < options.max_strings {
            strings.push(FoundString {
                offset,
                encoding,
                value_truncated: length > value.len(),
                value,
                category,
            });
        }
    }
    StringsReport {
        input_bytes: bytes.len(),
        min_length,
        total,
        truncated: total > options.max_strings,
        strings,
    }
}

#[cfg(test)]
mod tests {
    use super::{EncodingChoice, StringEncoding, StringsOptions, extract};

    fn options(min_length: usize, encoding: EncodingChoice) -> StringsOptions {
        StringsOptions {
            min_length,
            encoding,
            max_strings: 100,
            interesting: false,
        }
    }

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn finds_ascii_runs_with_offsets_and_skips_short_ones() {
        let data = b"\x00\x01hello\x00ab\x00world!\xff";
        let report = extract(data, options(4, EncodingChoice::Ascii));
        let values: Vec<(usize, &str)> = report
            .strings
            .iter()
            .map(|found| (found.offset, found.value.as_str()))
            .collect();
        assert_eq!(values, [(2, "hello"), (11, "world!")]);
        assert_eq!(report.total, 2);
    }

    #[test]
    fn finds_utf16le_at_even_and_odd_offsets() {
        let mut data = vec![0xff];
        data.extend(utf16("kernel32.dll"));
        data.extend([0xff, 0xff]);
        data.extend(utf16("cmd.exe"));
        let report = extract(&data, options(4, EncodingChoice::Utf16le));
        let values: Vec<(usize, &str)> = report
            .strings
            .iter()
            .map(|found| (found.offset, found.value.as_str()))
            .collect();
        assert_eq!(values, [(1, "kernel32.dll"), (27, "cmd.exe")]);
        assert!(
            report
                .strings
                .iter()
                .all(|found| found.encoding == StringEncoding::Utf16le)
        );
    }

    #[test]
    fn all_merges_both_encodings_in_offset_order() {
        let mut data = b"ASCIItext".to_vec();
        data.push(0xff);
        data.extend(utf16("WideText"));
        let report = extract(&data, options(4, EncodingChoice::All));
        let kinds: Vec<StringEncoding> =
            report.strings.iter().map(|found| found.encoding).collect();
        assert_eq!(kinds, [StringEncoding::Ascii, StringEncoding::Utf16le]);
    }

    #[test]
    fn a_string_at_the_very_end_is_kept() {
        let report = extract(b"\x00tail", options(4, EncodingChoice::Ascii));
        assert_eq!(report.strings[0].value, "tail");
        let report = extract(&utf16("tail"), options(4, EncodingChoice::Utf16le));
        assert_eq!(report.strings[0].value, "tail");
    }

    #[test]
    fn the_list_is_bounded_but_the_total_is_kept() {
        let data = b"aaaa\x00bbbb\x00cccc\x00dddd".repeat(5);
        let report = extract(
            &data,
            StringsOptions {
                min_length: 4,
                encoding: EncodingChoice::Ascii,
                max_strings: 3,
                interesting: false,
            },
        );
        assert_eq!(report.strings.len(), 3);
        assert_eq!(report.total, 16);
        assert!(report.truncated);
    }

    #[test]
    fn very_long_runs_are_cut_and_flagged() {
        let data = vec![b'A'; super::MAX_VALUE_CHARS + 10];
        let report = extract(&data, options(4, EncodingChoice::Ascii));
        assert_eq!(report.strings[0].value.len(), super::MAX_VALUE_CHARS);
        assert!(report.strings[0].value_truncated);
    }

    #[test]
    fn empty_input_and_zero_minimum_are_handled() {
        assert_eq!(extract(b"", options(4, EncodingChoice::All)).total, 0);
        assert_eq!(
            extract(b"ab", options(0, EncodingChoice::Ascii)).min_length,
            1
        );
    }
}

#[cfg(test)]
mod category_tests {
    use super::{EncodingChoice, StringsOptions, category, extract};

    #[test]
    fn classifies_common_indicators() {
        for (value, expected) in [
            ("http://203.0.113.9/gate.php", Some("url")),
            ("admin@example.test", Some("email")),
            ("connect 198.51.100.23 now", Some("ipv4")),
            (
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                Some("registry"),
            ),
            (r"HKLM\SYSTEM", Some("registry")),
            (r"C:\Users\Public\a.exe", Some("path")),
            (r"%APPDATA%\svc.exe", Some("path")),
            ("cmd.exe /c whoami", Some("command")),
            ("Mozilla/5.0 (Windows NT 10.0)", Some("user-agent")),
            ("update.microsoft.com", Some("domain")),
            (
                "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAA",
                Some("base64"),
            ),
            ("GetProcAddress", None),
            ("s@I9.t", None),
            ("System.Net.WebClient", None),
            ("999.1.1.1", None),
        ] {
            assert_eq!(category(value), expected, "{value}");
        }
    }

    #[test]
    fn interesting_keeps_only_categorized_strings() {
        let data = b"\x00GetProcAddress\x00http://x.example.test/a\x00LoadLibraryA\x00";
        let report = extract(
            data,
            StringsOptions {
                min_length: 4,
                encoding: EncodingChoice::All,
                max_strings: 100,
                interesting: true,
            },
        );
        assert_eq!(report.total, 1);
        assert_eq!(report.strings[0].value, "http://x.example.test/a");
        assert_eq!(report.strings[0].category, Some("url"));
    }
}

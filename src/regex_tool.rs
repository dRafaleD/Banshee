use anyhow::{Context, Result};
use regex::RegexBuilder;
use serde::Serialize;

const MAX_PATTERN_BYTES: usize = 32 * 1024;
const MAX_MATCHES: usize = 10_000;
const MAX_CAPTURE_GROUPS: usize = 20;
const MAX_CAPTURE_TEXT_CHARS: usize = 4_096;
const REGEX_SIZE_LIMIT: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct RegexTestReport {
    pub pattern: String,
    pub total: usize,
    pub truncated: bool,
    pub matches: Vec<RegexMatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegexMatch {
    pub start: usize,
    pub end: usize,
    pub value: String,
    pub value_truncated: bool,
    pub captures: Vec<Option<String>>,
    pub captures_truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PatternCatalog {
    pub patterns: Vec<BuiltinPattern>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuiltinPattern {
    pub name: &'static str,
    pub pattern: &'static str,
    pub description: &'static str,
}

pub fn test(
    pattern: &str,
    input: &str,
    case_insensitive: bool,
    multiline: bool,
) -> Result<RegexTestReport> {
    if pattern.len() > MAX_PATTERN_BYTES {
        anyhow::bail!("regular expression exceeds the 32 KiB safety limit");
    }
    let regex = RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .multi_line(multiline)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build()
        .with_context(|| format!("invalid regular expression '{pattern}'"))?;

    let mut matches = Vec::new();
    let mut truncated = false;
    for captures in regex.captures_iter(input) {
        if matches.len() == MAX_MATCHES {
            truncated = true;
            break;
        }
        let Some(whole) = captures.get(0) else {
            continue;
        };
        let (value, value_truncated) = bounded_text(whole.as_str());
        let captures_truncated = captures.len().saturating_sub(1) > MAX_CAPTURE_GROUPS;
        let captures = captures
            .iter()
            .skip(1)
            .take(MAX_CAPTURE_GROUPS)
            .map(|capture| capture.map(|value| bounded_text(value.as_str()).0))
            .collect();
        matches.push(RegexMatch {
            start: whole.start(),
            end: whole.end(),
            value,
            value_truncated,
            captures,
            captures_truncated,
        });
    }

    Ok(RegexTestReport {
        pattern: pattern.to_owned(),
        total: matches.len(),
        truncated,
        matches,
    })
}

fn bounded_text(value: &str) -> (String, bool) {
    let mut chars = value.chars();
    let preview: String = chars.by_ref().take(MAX_CAPTURE_TEXT_CHARS).collect();
    let truncated = chars.next().is_some();
    (preview, truncated)
}

pub fn patterns() -> PatternCatalog {
    PatternCatalog {
        patterns: vec![
            BuiltinPattern {
                name: "ipv4-candidate",
                pattern: r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                description: "IPv4 candidate; validate octets after matching",
            },
            BuiltinPattern {
                name: "domain",
                pattern: r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
                description: "DNS-style domain name",
            },
            BuiltinPattern {
                name: "url",
                pattern: r#"https?://[^\s<>\"']+"#,
                description: "HTTP or HTTPS URL candidate",
            },
            BuiltinPattern {
                name: "jwt",
                pattern: r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
                description: "JWT compact serialization candidate",
            },
            BuiltinPattern {
                name: "sha256",
                pattern: r"(?i)\b[0-9a-f]{64}\b",
                description: "SHA-256 hexadecimal digest",
            },
            BuiltinPattern {
                name: "email",
                pattern: r"(?i)\b[a-z0-9.!#$%&'*+/?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b",
                description: "Email address candidate",
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_CAPTURE_TEXT_CHARS, MAX_MATCHES, test};

    #[test]
    fn reports_offsets_and_capture_groups() {
        let report = test(r"user=(\w+)", "user=alice user=bob", false, false).expect("valid regex");
        assert_eq!(report.total, 2);
        assert!(!report.truncated);
        assert_eq!(report.matches[0].captures[0].as_deref(), Some("alice"));
        assert_eq!((report.matches[1].start, report.matches[1].end), (11, 19));
    }

    #[test]
    fn bounds_match_collection_and_capture_text() {
        let input = "a".repeat(MAX_MATCHES + 1);
        let report = test("a", &input, false, false).expect("valid regex");
        assert_eq!(report.total, MAX_MATCHES);
        assert!(report.truncated);

        let long = "a".repeat(MAX_CAPTURE_TEXT_CHARS + 1);
        let report = test("(a+)", &long, false, false).expect("valid regex");
        assert!(report.matches[0].value_truncated);
        assert_eq!(
            report.matches[0].value.chars().count(),
            MAX_CAPTURE_TEXT_CHARS
        );
    }
}

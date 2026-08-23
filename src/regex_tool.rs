use anyhow::{Context, Result};
use regex::RegexBuilder;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct RegexTestReport {
    pub pattern: String,
    pub total: usize,
    pub matches: Vec<RegexMatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegexMatch {
    pub start: usize,
    pub end: usize,
    pub value: String,
    pub captures: Vec<Option<String>>,
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
    let regex = RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .multi_line(multiline)
        .build()
        .with_context(|| format!("invalid regular expression '{pattern}'"))?;

    let matches = regex
        .captures_iter(input)
        .filter_map(|captures| {
            let whole = captures.get(0)?;
            Some(RegexMatch {
                start: whole.start(),
                end: whole.end(),
                value: whole.as_str().to_owned(),
                captures: captures
                    .iter()
                    .skip(1)
                    .map(|capture| capture.map(|value| value.as_str().to_owned()))
                    .collect(),
            })
        })
        .collect::<Vec<_>>();

    Ok(RegexTestReport {
        pattern: pattern.to_owned(),
        total: matches.len(),
        matches,
    })
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
    use super::test;

    #[test]
    fn reports_offsets_and_capture_groups() {
        let report = test(r"user=(\w+)", "user=alice user=bob", false, false).expect("valid regex");
        assert_eq!(report.total, 2);
        assert_eq!(report.matches[0].captures[0].as_deref(), Some("alice"));
        assert_eq!((report.matches[1].start, report.matches[1].end), (11, 19));
    }
}

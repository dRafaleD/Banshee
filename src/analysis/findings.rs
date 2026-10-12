use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

use super::{Finding, FindingKind};

pub(super) fn extract_findings(input: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    extract_jwts(input, &mut findings);
    extract_urls(input, &mut findings);
    extract_ips(input, &mut findings);
    extract_hashes(input, &mut findings);
    extract_domains(input, &mut findings);
    findings
}

fn extract_jwts(input: &str, findings: &mut Vec<Finding>) {
    static JWT: OnceLock<Regex> = OnceLock::new();
    let pattern = JWT.get_or_init(|| {
        Regex::new(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b").expect("valid regex")
    });

    for token in pattern.find_iter(input).map(|matched| matched.as_str()) {
        let mut segments = token.split('.');
        let header = segments.next().and_then(decode_json_segment);
        let payload = segments.next().and_then(decode_json_segment);
        if header.is_some() && payload.is_some() {
            findings.push(Finding {
                kind: FindingKind::Jwt,
                value: token.to_owned(),
                confidence: 0.99,
                detail: header
                    .as_ref()
                    .and_then(|value| value.get("alg"))
                    .and_then(Value::as_str)
                    .map(|algorithm| format!("algorithm: {algorithm}")),
            });
        }
    }
}

fn decode_json_segment(segment: &str) -> Option<Value> {
    let bytes = URL_SAFE_NO_PAD.decode(segment).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn extract_urls(input: &str, findings: &mut Vec<Finding>) {
    static URL: OnceLock<Regex> = OnceLock::new();
    let pattern = URL.get_or_init(|| Regex::new(r#"https?://[^\s<>\"']+"#).expect("valid regex"));
    findings.extend(pattern.find_iter(input).map(|matched| Finding {
        kind: FindingKind::Url,
        value: trim_punctuation(matched.as_str()).to_owned(),
        confidence: 0.98,
        detail: None,
    }));
}

fn extract_ips(input: &str, findings: &mut Vec<Finding>) {
    static IPV4: OnceLock<Regex> = OnceLock::new();
    let pattern =
        IPV4.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("valid regex"));

    findings.extend(pattern.find_iter(input).filter_map(|matched| {
        matched.as_str().parse::<std::net::Ipv4Addr>().ok()?;
        Some(Finding {
            kind: FindingKind::Ip,
            value: matched.as_str().to_owned(),
            confidence: 0.99,
            detail: Some("IPv4".to_owned()),
        })
    }));
}

fn extract_hashes(input: &str, findings: &mut Vec<Finding>) {
    static HASH: OnceLock<Regex> = OnceLock::new();
    let pattern = HASH.get_or_init(|| Regex::new(r"\b[0-9A-Fa-f]{32,128}\b").expect("valid regex"));

    for value in pattern.find_iter(input).map(|matched| matched.as_str()) {
        let algorithm = match value.len() {
            32 => Some("MD5 or NTLM"),
            40 => Some("SHA-1"),
            56 => Some("SHA-224"),
            64 => Some("SHA-256"),
            96 => Some("SHA-384"),
            128 => Some("SHA-512"),
            _ => None,
        };
        if let Some(algorithm) = algorithm {
            findings.push(Finding {
                kind: FindingKind::Hash,
                value: value.to_ascii_lowercase(),
                confidence: 0.9,
                detail: Some(format!("probable {algorithm}")),
            });
        }
    }
}

fn extract_domains(input: &str, findings: &mut Vec<Finding>) {
    static DOMAIN: OnceLock<Regex> = OnceLock::new();
    let pattern = DOMAIN.get_or_init(|| {
        Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b")
            .expect("valid regex")
    });

    findings.extend(
        pattern
            .find_iter(input)
            .filter(|matched| crate::tld::has_known_tld(matched.as_str()))
            .map(|matched| Finding {
                kind: FindingKind::Domain,
                value: matched.as_str().to_ascii_lowercase(),
                confidence: 0.9,
                detail: None,
            }),
    );
}

fn trim_punctuation(value: &str) -> &str {
    value.trim_end_matches(['.', ',', ';', ':', ')', ']', '}'])
}

#[cfg(test)]
mod tests {
    use super::extract_findings;
    use crate::analysis::FindingKind;

    #[test]
    fn validates_ipv4_octets() {
        let findings = extract_findings("good 8.8.8.8 bad 999.1.1.1");
        assert!(findings.iter().any(|item| item.value == "8.8.8.8"));
        assert!(!findings.iter().any(|item| item.value == "999.1.1.1"));
    }

    #[test]
    fn identifies_common_hash_lengths() {
        let findings = extract_findings("d41d8cd98f00b204e9800998ecf8427e");
        let hash = findings
            .iter()
            .find(|item| item.kind == FindingKind::Hash)
            .expect("hash finding");
        assert_eq!(hash.detail.as_deref(), Some("probable MD5 or NTLM"));
    }
}

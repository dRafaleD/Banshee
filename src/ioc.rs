use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use clap::ValueEnum;
use regex::Regex;
use serde::Serialize;
use url::Url;

#[derive(Debug, Clone, Default)]
pub struct ExtractOptions {
    pub include_ip: bool,
    pub include_domain: bool,
    pub include_url: bool,
    pub include_hash: bool,
    pub include_email: bool,
    pub include_mac: bool,
    pub allowlist: PatternList,
    pub denylist: PatternList,
    pub sort: IocSort,
}

#[derive(Debug, Clone, Default)]
pub struct PatternList {
    patterns: Vec<String>,
}

impl PatternList {
    pub fn from_files(paths: &[impl AsRef<Path>]) -> Result<Self> {
        let mut patterns = Vec::new();
        for path in paths {
            let path = path.as_ref();
            let contents = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read IOC list '{}'", path.display()))?;
            for line in contents.lines() {
                let value = line.trim();
                if !value.is_empty() && !value.starts_with('#') {
                    patterns.push(value.to_ascii_lowercase());
                }
            }
        }
        Ok(Self { patterns })
    }

    fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    fn matches(&self, value: &str) -> bool {
        self.patterns
            .iter()
            .any(|pattern| wildcard_matches(pattern, &value.to_ascii_lowercase()))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum IocSort {
    #[default]
    Kind,
    Value,
    Count,
}

impl ExtractOptions {
    fn includes(&self, kind: IocKind) -> bool {
        if !self.include_ip
            && !self.include_domain
            && !self.include_url
            && !self.include_hash
            && !self.include_email
            && !self.include_mac
        {
            return true;
        }

        match kind {
            IocKind::Ipv4 | IocKind::Ipv6 => self.include_ip,
            IocKind::Domain => self.include_domain,
            IocKind::Url => self.include_url,
            IocKind::Hash => self.include_hash,
            IocKind::Email => self.include_email,
            IocKind::Mac => self.include_mac,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    Domain,
    Email,
    Hash,
    Ipv4,
    Ipv6,
    Mac,
    Url,
}

impl std::fmt::Display for IocKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Domain => "domain",
            Self::Email => "email",
            Self::Hash => "hash",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Mac => "mac",
            Self::Url => "url",
        };
        formatter.write_str(label)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ioc {
    pub kind: IocKind,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub occurrences: usize,
    pub first_line: usize,
    pub last_line: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct IocReport {
    pub input_bytes: usize,
    pub total: usize,
    pub total_occurrences: usize,
    pub iocs: Vec<Ioc>,
}

pub fn extract(input: &str, options: ExtractOptions) -> IocReport {
    let refanged = refang(input);
    let mut collector = IocCollector::default();

    extract_urls(&refanged, &mut collector);
    extract_ips(&refanged, &mut collector);
    extract_hashes(&refanged, &mut collector);
    extract_emails(&refanged, &mut collector);
    extract_macs(&refanged, &mut collector);
    extract_domains(&refanged, &mut collector);

    let mut iocs = collector
        .into_values()
        .filter(|ioc| {
            options.includes(ioc.kind)
                && !options.allowlist.matches(&ioc.value)
                && (options.denylist.is_empty() || options.denylist.matches(&ioc.value))
        })
        .collect::<Vec<_>>();
    match options.sort {
        IocSort::Kind => {}
        IocSort::Value => iocs.sort_by(|left, right| {
            left.value
                .cmp(&right.value)
                .then(left.kind.cmp(&right.kind))
        }),
        IocSort::Count => iocs.sort_by(|left, right| {
            right
                .occurrences
                .cmp(&left.occurrences)
                .then(left.kind.cmp(&right.kind))
                .then(left.value.cmp(&right.value))
        }),
    }
    let total_occurrences = iocs.iter().map(|ioc| ioc.occurrences).sum();

    IocReport {
        input_bytes: input.len(),
        total: iocs.len(),
        total_occurrences,
        iocs,
    }
}

pub fn defang(ioc: &Ioc) -> String {
    match ioc.kind {
        IocKind::Url => ioc
            .value
            .replace("https://", "hxxps://")
            .replace("http://", "hxxp://")
            .replace('.', "[.]"),
        IocKind::Domain | IocKind::Ipv4 => ioc.value.replace('.', "[.]"),
        IocKind::Email => ioc.value.replace('@', "[@]").replace('.', "[.]"),
        IocKind::Ipv6 | IocKind::Hash | IocKind::Mac => ioc.value.clone(),
    }
}

fn refang(input: &str) -> String {
    static DEFANGED_SCHEME: OnceLock<Regex> = OnceLock::new();
    let scheme = DEFANGED_SCHEME
        .get_or_init(|| Regex::new(r"(?i)\b(hxxps?)(?:\[:\]//|\[://\]|://)").expect("valid regex"));
    let schemes_fixed = scheme.replace_all(input, |captures: &regex::Captures<'_>| {
        if captures[1].eq_ignore_ascii_case("hxxps") {
            "https://"
        } else {
            "http://"
        }
    });

    schemes_fixed
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
        .replace("[@]", "@")
        .replace("(@)", "@")
}

#[derive(Debug, Default)]
struct IocCollector {
    iocs: BTreeMap<(IocKind, String), Ioc>,
}

impl IocCollector {
    fn record(
        &mut self,
        input: &str,
        offset: usize,
        kind: IocKind,
        value: String,
        detail: Option<String>,
    ) {
        let line = input[..offset]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        let key = (kind, value.clone());
        match self.iocs.get_mut(&key) {
            Some(ioc) => {
                ioc.occurrences += 1;
                ioc.last_line = line;
            }
            None => {
                self.iocs.insert(
                    key,
                    Ioc {
                        kind,
                        value,
                        detail,
                        occurrences: 1,
                        first_line: line,
                        last_line: line,
                    },
                );
            }
        }
    }

    fn into_values(self) -> impl Iterator<Item = Ioc> {
        self.iocs.into_values()
    }
}

fn extract_urls(input: &str, iocs: &mut IocCollector) {
    static URL_CANDIDATE: OnceLock<Regex> = OnceLock::new();
    let pattern = URL_CANDIDATE
        .get_or_init(|| Regex::new(r#"(?i)\bhttps?://[^\s<>\"']+"#).expect("valid regex"));

    for matched in pattern.find_iter(input) {
        let candidate = trim_punctuation(matched.as_str());
        let Ok(url) = Url::parse(candidate) else {
            continue;
        };
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            continue;
        }
        iocs.record(input, matched.start(), IocKind::Url, url.into(), None);
    }
}

fn extract_ips(input: &str, iocs: &mut IocCollector) {
    static IPV4: OnceLock<Regex> = OnceLock::new();
    let ipv4 =
        IPV4.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("valid regex"));
    for matched in ipv4.find_iter(input) {
        let candidate = matched.as_str();
        if candidate.parse::<Ipv4Addr>().is_ok() {
            iocs.record(
                input,
                matched.start(),
                IocKind::Ipv4,
                candidate.to_owned(),
                None,
            );
        }
    }

    let mut search_start = 0;
    for candidate in
        input.split(|character: char| !character.is_ascii_hexdigit() && character != ':')
    {
        if !candidate.contains(':') {
            continue;
        }
        let Ok(IpAddr::V6(address)) = candidate.parse::<IpAddr>() else {
            continue;
        };
        let offset = input[search_start..]
            .find(candidate)
            .map(|index| search_start + index)
            .expect("split candidate originates from input");
        search_start = offset + candidate.len();
        iocs.record(input, offset, IocKind::Ipv6, address.to_string(), None);
    }
}

fn extract_hashes(input: &str, iocs: &mut IocCollector) {
    static HASH: OnceLock<Regex> = OnceLock::new();
    let pattern = HASH.get_or_init(|| Regex::new(r"\b[0-9A-Fa-f]{32,128}\b").expect("valid regex"));

    for matched in pattern.find_iter(input) {
        let candidate = matched.as_str();
        let detail = match candidate.len() {
            32 => Some("MD5 or NTLM"),
            40 => Some("SHA-1"),
            56 => Some("SHA-224"),
            64 => Some("SHA-256"),
            96 => Some("SHA-384"),
            128 => Some("SHA-512"),
            _ => None,
        };
        if let Some(detail) = detail {
            iocs.record(
                input,
                matched.start(),
                IocKind::Hash,
                candidate.to_ascii_lowercase(),
                Some(detail.to_owned()),
            );
        }
    }
}

fn extract_emails(input: &str, iocs: &mut IocCollector) {
    static EMAIL: OnceLock<Regex> = OnceLock::new();
    let pattern = EMAIL.get_or_init(|| {
        Regex::new(r"(?i)\b[a-z0-9.!#$%&'*+/?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b")
            .expect("valid regex")
    });
    for matched in pattern.find_iter(input) {
        iocs.record(
            input,
            matched.start(),
            IocKind::Email,
            matched.as_str().to_ascii_lowercase(),
            None,
        );
    }
}

fn extract_macs(input: &str, iocs: &mut IocCollector) {
    static MAC: OnceLock<Regex> = OnceLock::new();
    let pattern = MAC.get_or_init(|| {
        Regex::new(r"(?i)\b(?:(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|(?:[0-9a-f]{4}\.){2}[0-9a-f]{4})\b")
            .expect("valid regex")
    });
    for matched in pattern.find_iter(input) {
        let candidate = matched.as_str();
        let compact = candidate
            .chars()
            .filter(|character| character.is_ascii_hexdigit())
            .collect::<String>()
            .to_ascii_lowercase();
        let normalized = compact
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| std::str::from_utf8(pair).expect("MAC is ASCII"))
            .collect::<Vec<_>>()
            .join(":");
        iocs.record(input, matched.start(), IocKind::Mac, normalized, None);
    }
}

fn extract_domains(input: &str, iocs: &mut IocCollector) {
    static DOMAIN: OnceLock<Regex> = OnceLock::new();
    let pattern = DOMAIN.get_or_init(|| {
        Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b")
            .expect("valid regex")
    });

    for matched in pattern.find_iter(input) {
        iocs.record(
            input,
            matched.start(),
            IocKind::Domain,
            matched.as_str().to_ascii_lowercase(),
            None,
        );
    }
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let mut pattern_index = 0;
    let mut value_index = 0;
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut wildcard = None;
    let mut retry_index = 0;

    while value_index < value.len() {
        if pattern_index < pattern.len() && pattern[pattern_index] == value[value_index] {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            wildcard = Some(pattern_index);
            pattern_index += 1;
            retry_index = value_index;
        } else if let Some(star) = wildcard {
            pattern_index = star + 1;
            retry_index += 1;
            value_index = retry_index;
        } else {
            return false;
        }
    }
    pattern[pattern_index..].iter().all(|byte| *byte == b'*')
}

fn trim_punctuation(value: &str) -> &str {
    value.trim_end_matches(['.', ',', ';', ':', ')', ']', '}'])
}

#[cfg(test)]
mod tests {
    use super::{ExtractOptions, IocKind, IocSort, PatternList, defang, extract};

    const DIRTY_LOG: &str = "request hxxps[://]EVIL[.]Example[.]COM/a, source=8[.]8[.]8[.]8 ipv6=2001:4860:4860::8888 hash=D41D8CD98F00B204E9800998ECF8427E alt=cdn(.)example(.)net mail=SOC[@]Example[.]COM mac=AA-BB-CC-DD-EE-FF";

    #[test]
    fn extracts_and_normalizes_defanged_iocs() {
        let report = extract(DIRTY_LOG, ExtractOptions::default());

        assert!(
            report
                .iocs
                .iter()
                .any(|ioc| ioc.kind == IocKind::Url && ioc.value == "https://evil.example.com/a")
        );
        assert!(
            report
                .iocs
                .iter()
                .any(|ioc| ioc.kind == IocKind::Ipv4 && ioc.value == "8.8.8.8")
        );
        assert!(
            report
                .iocs
                .iter()
                .any(|ioc| ioc.kind == IocKind::Ipv6 && ioc.value == "2001:4860:4860::8888")
        );
        assert!(report.iocs.iter().any(
            |ioc| ioc.kind == IocKind::Hash && ioc.value == "d41d8cd98f00b204e9800998ecf8427e"
        ));
        assert!(
            report
                .iocs
                .iter()
                .any(|ioc| ioc.kind == IocKind::Domain && ioc.value == "cdn.example.net")
        );
        assert!(
            report
                .iocs
                .iter()
                .any(|ioc| ioc.kind == IocKind::Email && ioc.value == "soc@example.com")
        );
        assert!(
            report
                .iocs
                .iter()
                .any(|ioc| ioc.kind == IocKind::Mac && ioc.value == "aa:bb:cc:dd:ee:ff")
        );
    }

    #[test]
    fn applies_type_filters() {
        let report = extract(
            DIRTY_LOG,
            ExtractOptions {
                include_hash: true,
                ..ExtractOptions::default()
            },
        );
        assert_eq!(report.total, 1);
        assert_eq!(report.iocs[0].kind, IocKind::Hash);
    }

    #[test]
    fn defangs_text_output() {
        let report = extract(DIRTY_LOG, ExtractOptions::default());
        let url = report
            .iocs
            .iter()
            .find(|ioc| ioc.kind == IocKind::Url)
            .expect("URL IOC");
        assert_eq!(defang(url), "hxxps://evil[.]example[.]com/a");
    }

    #[test]
    fn counts_occurrences_and_tracks_lines() {
        let report = extract(
            "8.8.8.8\nexample.com 8.8.8.8\n8.8.8.8",
            ExtractOptions::default(),
        );
        let ip = report
            .iocs
            .iter()
            .find(|ioc| ioc.kind == IocKind::Ipv4)
            .expect("IPv4 IOC");
        assert_eq!(ip.occurrences, 3);
        assert_eq!((ip.first_line, ip.last_line), (1, 3));
        assert_eq!(report.total_occurrences, 4);
    }

    #[test]
    fn applies_lists_and_sorts_by_descending_count() {
        let report = extract(
            "8.8.8.8 safe.example.com evil.example.com 8.8.8.8",
            ExtractOptions {
                allowlist: PatternList {
                    patterns: vec!["safe.*".to_owned()],
                },
                denylist: PatternList {
                    patterns: vec!["*.example.com".to_owned(), "8.8.8.8".to_owned()],
                },
                sort: IocSort::Count,
                ..ExtractOptions::default()
            },
        );
        assert_eq!(report.total, 2);
        assert_eq!(report.iocs[0].value, "8.8.8.8");
        assert_eq!(report.iocs[0].occurrences, 2);
        assert!(
            report
                .iocs
                .iter()
                .all(|ioc| ioc.value != "safe.example.com")
        );
    }
}

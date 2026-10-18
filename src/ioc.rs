use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::OnceLock;

use anyhow::Result;
use clap::ValueEnum;
use regex::Regex;
use serde::Serialize;
use url::Url;

const DEFAULT_MAX_LOCATIONS: usize = 20;
const DEFAULT_MAX_MATCHES: usize = 10_000;
const DEFAULT_MAX_CONTEXT_CHARS: usize = 240;
const MAX_PATTERN_LIST_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ExtractOptions {
    pub include_ip: bool,
    pub include_domain: bool,
    pub include_url: bool,
    pub include_hash: bool,
    pub include_email: bool,
    pub include_mac: bool,
    pub include_secret: bool,
    pub allowlist: PatternList,
    pub denylist: PatternList,
    pub sort: IocSort,
    pub source: String,
    pub context_lines: u8,
    pub max_context_chars: usize,
    pub max_locations: usize,
    pub max_matches: usize,
    pub reveal_secrets: bool,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            include_ip: false,
            include_domain: false,
            include_url: false,
            include_hash: false,
            include_email: false,
            include_mac: false,
            include_secret: false,
            allowlist: PatternList::default(),
            denylist: PatternList::default(),
            sort: IocSort::default(),
            source: "input".to_owned(),
            context_lines: 0,
            max_context_chars: DEFAULT_MAX_CONTEXT_CHARS,
            max_locations: DEFAULT_MAX_LOCATIONS,
            max_matches: DEFAULT_MAX_MATCHES,
            reveal_secrets: false,
        }
    }
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
            let contents = crate::input::read_regular_text_file_limited(
                path,
                MAX_PATTERN_LIST_BYTES,
                "IOC list",
            )?;
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
            && !self.include_secret
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
            IocKind::Secret | IocKind::PrivateKey => self.include_secret,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    Domain,
    Email,
    Hash,
    Ipv4,
    Ipv6,
    Mac,
    PrivateKey,
    Secret,
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
            Self::PrivateKey => "private_key",
            Self::Secret => "secret",
            Self::Url => "url",
        };
        formatter.write_str(label)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ioc {
    pub kind: IocKind,
    pub value: String,
    pub source: String,
    pub redacted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub occurrences: usize,
    pub first_line: Option<usize>,
    pub last_line: Option<usize>,
    pub first_column: Option<usize>,
    pub locations_truncated: bool,
    pub locations: Vec<IocLocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IocLocation {
    pub line: usize,
    pub column: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<ContextLine>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContextLine {
    pub line: usize,
    pub matched: bool,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IocReport {
    pub input_bytes: usize,
    pub source: String,
    pub positions_available: bool,
    pub total: usize,
    pub total_occurrences: usize,
    pub match_limit_reached: bool,
    pub iocs: Vec<Ioc>,
}

pub fn extract(input: &str, options: ExtractOptions) -> IocReport {
    let mapped = refang_with_map(input);
    let mut collector = IocCollector::new(input, &mapped.offsets, &options);

    extract_secrets(&mapped.text, &mut collector);
    if !collector.is_full() {
        extract_urls(&mapped.text, &mut collector);
    }
    if !collector.is_full() {
        extract_ips(&mapped.text, &mut collector);
    }
    if !collector.is_full() {
        extract_hashes(&mapped.text, &mut collector);
    }
    if !collector.is_full() {
        extract_emails(&mapped.text, &mut collector);
    }
    if !collector.is_full() {
        extract_macs(&mapped.text, &mut collector);
    }
    if !collector.is_full() {
        extract_domains(&mapped.text, &mut collector);
    }

    let match_limit_reached = collector.match_limit_reached;
    let mut iocs = collector
        .into_values()
        .filter(|ioc| {
            options.includes(ioc.kind)
                && !options.allowlist.matches(&ioc.value)
                && (options.denylist.is_empty() || options.denylist.matches(&ioc.value))
        })
        .collect::<Vec<_>>();
    if !options.reveal_secrets {
        for ioc in &mut iocs {
            if matches!(ioc.kind, IocKind::Secret | IocKind::PrivateKey) {
                ioc.value = mask_secret(&ioc.value, ioc.kind);
                ioc.redacted = true;
            }
        }
    }
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
        source: options.source,
        positions_available: true,
        total: iocs.len(),
        total_occurrences,
        match_limit_reached,
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
        IocKind::Ipv6 | IocKind::Hash | IocKind::Mac | IocKind::PrivateKey | IocKind::Secret => {
            ioc.value.clone()
        }
    }
}

struct MappedText {
    text: String,
    offsets: Vec<usize>,
}

fn refang_with_map(input: &str) -> MappedText {
    let replacements = [
        ("hxxps[:]//", "https://", true),
        ("hxxps[://]", "https://", true),
        ("hxxps://", "https://", true),
        ("hxxp[:]//", "http://", true),
        ("hxxp[://]", "http://", true),
        ("hxxp://", "http://", true),
        ("[.]", ".", false),
        ("(.)", ".", false),
        ("{.}", ".", false),
        ("[@]", "@", false),
        ("(@)", "@", false),
    ];
    let mut text = String::with_capacity(input.len());
    let mut offsets = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        let remaining = &input[index..];
        let replacement = replacements.iter().find(|(pattern, _, insensitive)| {
            remaining.len() >= pattern.len()
                && if *insensitive {
                    remaining.as_bytes()[..pattern.len()].eq_ignore_ascii_case(pattern.as_bytes())
                } else {
                    remaining.as_bytes().starts_with(pattern.as_bytes())
                }
        });
        if let Some((pattern, value, _)) = replacement {
            text.push_str(value);
            offsets.extend(std::iter::repeat_n(index, value.len()));
            index += pattern.len();
            continue;
        }
        let character = remaining
            .chars()
            .next()
            .expect("remaining text is non-empty");
        text.push(character);
        offsets.extend((0..character.len_utf8()).map(|offset| index + offset));
        index += character.len_utf8();
    }
    MappedText { text, offsets }
}

#[derive(Debug)]
struct IocCollector<'a> {
    iocs: BTreeMap<(IocKind, String), Ioc>,
    seen: HashSet<(IocKind, String, usize)>,
    original: &'a str,
    normalized_offsets: &'a [usize],
    line_starts: Vec<usize>,
    private_key_ranges: Vec<(usize, usize)>,
    source: String,
    context_lines: u8,
    max_context_chars: usize,
    max_locations: usize,
    max_matches: usize,
    matches_seen: usize,
    match_limit_reached: bool,
    reveal_secrets: bool,
}

impl<'a> IocCollector<'a> {
    fn new(original: &'a str, normalized_offsets: &'a [usize], options: &ExtractOptions) -> Self {
        let mut line_starts = vec![0];
        line_starts.extend(
            original
                .bytes()
                .enumerate()
                .filter_map(|(index, byte)| (byte == b'\n').then_some(index + 1)),
        );
        Self {
            iocs: BTreeMap::new(),
            seen: HashSet::new(),
            original,
            normalized_offsets,
            line_starts,
            private_key_ranges: private_key_ranges(original),
            source: options.source.clone(),
            context_lines: options.context_lines,
            max_context_chars: options.max_context_chars.max(32),
            max_locations: options.max_locations.max(1),
            max_matches: options.max_matches.max(1),
            matches_seen: 0,
            match_limit_reached: false,
            reveal_secrets: options.reveal_secrets,
        }
    }

    fn record(&mut self, offset: usize, kind: IocKind, value: String, detail: Option<String>) {
        let original_offset = self
            .normalized_offsets
            .get(offset)
            .copied()
            .unwrap_or(self.original.len());
        if !self.seen.insert((kind, value.clone(), original_offset)) {
            return;
        }
        if self.matches_seen >= self.max_matches {
            self.match_limit_reached = true;
            return;
        }
        self.matches_seen += 1;
        let line_index = self
            .line_starts
            .partition_point(|start| *start <= original_offset)
            - 1;
        let line = line_index + 1;
        let column = self.original[self.line_starts[line_index]..original_offset]
            .chars()
            .count()
            + 1;
        let location = IocLocation {
            line,
            column,
            context: self.context(line_index),
        };
        let key = (kind, value.clone());
        match self.iocs.get_mut(&key) {
            Some(ioc) => {
                ioc.occurrences += 1;
                ioc.last_line = Some(line);
                if ioc.locations.len() < self.max_locations {
                    ioc.locations.push(location);
                } else {
                    ioc.locations_truncated = true;
                }
            }
            None => {
                self.iocs.insert(
                    key,
                    Ioc {
                        kind,
                        value,
                        source: self.source.clone(),
                        redacted: false,
                        detail,
                        occurrences: 1,
                        first_line: Some(line),
                        last_line: Some(line),
                        first_column: Some(column),
                        locations_truncated: false,
                        locations: vec![location],
                    },
                );
            }
        }
    }

    fn is_full(&mut self) -> bool {
        if self.matches_seen >= self.max_matches {
            self.match_limit_reached = true;
            true
        } else {
            false
        }
    }

    fn context(&self, matched_line_index: usize) -> Vec<ContextLine> {
        if self.context_lines == 0 {
            return Vec::new();
        }
        let radius = usize::from(self.context_lines);
        let start = matched_line_index.saturating_sub(radius);
        let end = (matched_line_index + radius + 1).min(self.line_starts.len());
        (start..end)
            .map(|line_index| {
                let line_start = self.line_starts[line_index];
                let line_end = self
                    .line_starts
                    .get(line_index + 1)
                    .copied()
                    .unwrap_or(self.original.len());
                let raw = self.original[line_start..line_end].trim_end_matches(['\r', '\n']);
                let private_key_material = self
                    .private_key_ranges
                    .iter()
                    .any(|(start, end)| line_start < *end && line_end > *start);
                let safe = if private_key_material && !self.reveal_secrets {
                    "[PRIVATE KEY MATERIAL REDACTED]".to_owned()
                } else if self.reveal_secrets {
                    raw.to_owned()
                } else {
                    redact_secrets(raw)
                };
                ContextLine {
                    line: line_index + 1,
                    matched: line_index == matched_line_index,
                    text: truncate_chars(&safe, self.max_context_chars),
                }
            })
            .collect()
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
        if iocs.is_full() {
            break;
        }
        let candidate = trim_punctuation(matched.as_str());
        let Ok(url) = Url::parse(candidate) else {
            continue;
        };
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            continue;
        }
        iocs.record(matched.start(), IocKind::Url, url.into(), None);
    }
}

fn extract_ips(input: &str, iocs: &mut IocCollector) {
    static IPV4: OnceLock<Regex> = OnceLock::new();
    let ipv4 =
        IPV4.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("valid regex"));
    for matched in ipv4.find_iter(input) {
        if iocs.is_full() {
            break;
        }
        let candidate = matched.as_str();
        if candidate.parse::<Ipv4Addr>().is_ok() {
            iocs.record(matched.start(), IocKind::Ipv4, candidate.to_owned(), None);
        }
    }

    let mut search_start = 0;
    for candidate in
        input.split(|character: char| !character.is_ascii_hexdigit() && character != ':')
    {
        if iocs.is_full() {
            break;
        }
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
        iocs.record(offset, IocKind::Ipv6, address.to_string(), None);
    }
}

fn extract_hashes(input: &str, iocs: &mut IocCollector) {
    static HASH: OnceLock<Regex> = OnceLock::new();
    let pattern = HASH.get_or_init(|| Regex::new(r"\b[0-9A-Fa-f]{32,128}\b").expect("valid regex"));

    for matched in pattern.find_iter(input) {
        if iocs.is_full() {
            break;
        }
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
        if iocs.is_full() {
            break;
        }
        iocs.record(
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
        if iocs.is_full() {
            break;
        }
        let candidate = matched.as_str();
        let compact = candidate
            .chars()
            .filter(|character| character.is_ascii_hexdigit())
            .collect::<String>()
            .to_ascii_lowercase();
        let normalized = compact
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| std::str::from_utf8(pair).expect("MAC is ASCII"))
            .collect::<Vec<_>>()
            .join(":");
        iocs.record(matched.start(), IocKind::Mac, normalized, None);
    }
}

fn extract_domains(input: &str, iocs: &mut IocCollector) {
    static DOMAIN: OnceLock<Regex> = OnceLock::new();
    let pattern = DOMAIN.get_or_init(|| {
        Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b")
            .expect("valid regex")
    });

    for matched in pattern.find_iter(input) {
        if iocs.is_full() {
            break;
        }
        let domain = matched.as_str().to_ascii_lowercase();
        if !crate::tld::has_known_tld(&domain) {
            continue;
        }
        // Punycode labels are checked in their Unicode form.
        let detail = domain
            .split('.')
            .any(|label| label.starts_with("xn--"))
            .then(|| idna::domain_to_unicode(&domain))
            .and_then(|(unicode, status)| status.ok().and(crate::homoglyph::assess(&unicode)));
        iocs.record(matched.start(), IocKind::Domain, domain, detail);
    }

    // Domains written with non-ASCII letters are recorded in their ASCII
    // (Punycode) form, which is what DNS, proxies and blocklists use.
    static UNICODE_DOMAIN: OnceLock<Regex> = OnceLock::new();
    let pattern = UNICODE_DOMAIN.get_or_init(|| {
        Regex::new(r"\b(?:[\p{L}\p{N}](?:[\p{L}\p{N}\p{M}-]{0,61}[\p{L}\p{N}\p{M}])?\.)+[\p{L}\p{M}]{2,63}\b")
            .expect("valid regex")
    });
    for matched in pattern.find_iter(input) {
        if iocs.is_full() {
            break;
        }
        let candidate = matched.as_str();
        if candidate.is_ascii() {
            continue;
        }
        let Ok(ascii) = idna::domain_to_ascii(candidate) else {
            continue;
        };
        if !crate::tld::has_known_tld(&ascii) {
            continue;
        }
        let (unicode, _) = idna::domain_to_unicode(&ascii);
        let detail = crate::homoglyph::assess(&unicode);
        iocs.record(matched.start(), IocKind::Domain, ascii, detail);
    }
}

struct SecretPatterns {
    cloud_access_key: Regex,
    github_token: Regex,
    slack_token: Regex,
    bearer_token: Regex,
    assignment: Regex,
    database_password: Regex,
    private_key_begin: Regex,
    private_key_end: Regex,
}

fn secret_patterns() -> &'static SecretPatterns {
    static PATTERNS: OnceLock<SecretPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| SecretPatterns {
        cloud_access_key: Regex::new(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
            .expect("valid cloud access key regex"),
        github_token: Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b")
            .expect("valid GitHub token regex"),
        slack_token: Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,512}\b")
            .expect("valid Slack token regex"),
        bearer_token: Regex::new(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{16,4096})")
            .expect("valid bearer token regex"),
        assignment: Regex::new(
            r#"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret)\s*[:=]\s*["']?([^\s"',;]{8,4096})"#,
        )
        .expect("valid secret assignment regex"),
        database_password: Regex::new(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:@/]+:([^@\s/]{1,512})@",
        )
        .expect("valid database credential regex"),
        private_key_begin: Regex::new(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        )
        .expect("valid private key begin regex"),
        private_key_end: Regex::new(
            r"-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        )
        .expect("valid private key end regex"),
    })
}

fn extract_secrets(input: &str, iocs: &mut IocCollector<'_>) {
    let patterns = secret_patterns();
    record_secret_matches(
        input,
        &patterns.cloud_access_key,
        0,
        "cloud access key candidate",
        IocKind::Secret,
        iocs,
    );
    record_secret_matches(
        input,
        &patterns.github_token,
        0,
        "GitHub token candidate",
        IocKind::Secret,
        iocs,
    );
    record_secret_matches(
        input,
        &patterns.slack_token,
        0,
        "Slack token candidate",
        IocKind::Secret,
        iocs,
    );
    record_secret_matches(
        input,
        &patterns.bearer_token,
        1,
        "bearer token candidate",
        IocKind::Secret,
        iocs,
    );
    record_secret_matches(
        input,
        &patterns.assignment,
        2,
        "credential assignment candidate",
        IocKind::Secret,
        iocs,
    );
    record_secret_matches(
        input,
        &patterns.database_password,
        1,
        "database URI password candidate",
        IocKind::Secret,
        iocs,
    );
    record_secret_matches(
        input,
        &patterns.private_key_begin,
        0,
        "private key material marker",
        IocKind::PrivateKey,
        iocs,
    );
}

fn record_secret_matches(
    input: &str,
    pattern: &Regex,
    capture_index: usize,
    detail: &str,
    kind: IocKind,
    iocs: &mut IocCollector<'_>,
) {
    for captures in pattern.captures_iter(input) {
        if iocs.is_full() {
            break;
        }
        let Some(matched) = captures.get(capture_index) else {
            continue;
        };
        iocs.record(
            matched.start(),
            kind,
            matched.as_str().to_owned(),
            Some(detail.to_owned()),
        );
    }
}

fn sensitive_ranges(input: &str) -> Vec<(usize, usize)> {
    let patterns = secret_patterns();
    let specifications = [
        (&patterns.cloud_access_key, 0),
        (&patterns.github_token, 0),
        (&patterns.slack_token, 0),
        (&patterns.bearer_token, 1),
        (&patterns.assignment, 2),
        (&patterns.database_password, 1),
    ];
    let mut ranges = specifications
        .into_iter()
        .flat_map(|(pattern, capture_index)| {
            pattern
                .captures_iter(input)
                .filter_map(move |captures| captures.get(capture_index).map(|item| item.range()))
        })
        .map(|range| (range.start, range.end))
        .collect::<Vec<_>>();
    ranges.sort_unstable();
    ranges
}

fn redact_secrets(input: &str) -> String {
    let ranges = sensitive_ranges(input);
    if ranges.is_empty() {
        return input.to_owned();
    }
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    for (start, end) in ranges {
        if start < cursor {
            continue;
        }
        output.push_str(&input[cursor..start]);
        output.push_str(&mask_secret(&input[start..end], IocKind::Secret));
        cursor = end;
    }
    output.push_str(&input[cursor..]);
    output
}

pub(crate) fn redact_sensitive_text(input: &str) -> String {
    let mut ranges = sensitive_ranges(input);
    ranges.extend(private_key_ranges(input));
    if ranges.is_empty() {
        return input.to_owned();
    }
    ranges.sort_unstable();
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    for (start, end) in ranges {
        if end <= cursor {
            continue;
        }
        let start = start.max(cursor);
        output.push_str(&input[cursor..start]);
        for character in input[start..end].chars() {
            if matches!(character, '\r' | '\n') {
                output.push(character);
            } else {
                output.push('*');
            }
        }
        cursor = end;
    }
    output.push_str(&input[cursor..]);
    output
}

fn private_key_ranges(input: &str) -> Vec<(usize, usize)> {
    let patterns = secret_patterns();
    patterns
        .private_key_begin
        .find_iter(input)
        .map(|begin| {
            let end = patterns
                .private_key_end
                .find_at(input, begin.end())
                .map_or(input.len(), |end| end.end());
            (begin.start(), end)
        })
        .collect()
}

fn mask_secret(value: &str, kind: IocKind) -> String {
    if kind == IocKind::PrivateKey {
        return "[PRIVATE KEY MATERIAL REDACTED]".to_owned();
    }
    let characters = value.chars().collect::<Vec<_>>();
    if characters.len() < 12 {
        return "********".to_owned();
    }
    let prefix = characters.iter().take(4).collect::<String>();
    let suffix = characters
        .iter()
        .skip(characters.len() - 4)
        .collect::<String>();
    format!("{prefix}…{suffix} [REDACTED]")
}

fn truncate_chars(value: &str, maximum: usize) -> String {
    if value.chars().count() <= maximum {
        return value.to_owned();
    }
    let mut output = value
        .chars()
        .take(maximum.saturating_sub(1))
        .collect::<String>();
    output.push('…');
    output
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
    use super::{ExtractOptions, IocKind, IocSort, PatternList, defang, extract, mask_secret};

    const DIRTY_LOG: &str = "request hxxps[://]EVIL[.]Example[.]COM/a, source=8[.]8[.]8[.]8 ipv6=2001:4860:4860::8888 hash=D41D8CD98F00B204E9800998ECF8427E alt=cdn(.)example(.)net mail=SOC[@]Example[.]COM mac=AA-BB-CC-DD-EE-FF";

    #[test]
    fn file_names_with_non_tld_extensions_are_not_domains() {
        let report = extract(
            "GET /gate.php, payload.exe and System.Net.WebClient, but tool.py and example.test are hosts",
            ExtractOptions::default(),
        );
        let domains = report
            .iocs
            .iter()
            .filter(|ioc| ioc.kind == IocKind::Domain)
            .map(|ioc| ioc.value.as_str())
            .collect::<Vec<_>>();
        assert_eq!(domains, ["example.test", "tool.py"]);
    }

    #[test]
    fn unicode_and_punycode_domains_are_normalized_and_assessed() {
        // Cyrillic р and а in front of "ypal", and its Punycode spelling.
        let report = extract(
            "login at \u{0440}\u{0430}ypal.com or xn--ypal-43d9g.com, see münchen.de",
            ExtractOptions::default(),
        );
        let domains = report
            .iocs
            .iter()
            .filter(|ioc| ioc.kind == IocKind::Domain)
            .map(|ioc| {
                (
                    ioc.value.as_str(),
                    ioc.detail.as_deref().unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();
        let lookalike = domains
            .iter()
            .find(|(value, _)| *value == "xn--ypal-43d9g.com")
            .unwrap_or_else(|| panic!("{domains:?}"));
        assert!(
            lookalike.1.starts_with(crate::homoglyph::LOOKALIKE_PREFIX),
            "{domains:?}"
        );
        assert!(lookalike.1.contains("reads as paypal.com"), "{domains:?}");
        assert_eq!(
            domains
                .iter()
                .filter(|(value, _)| value.starts_with("xn--ypal"))
                .count(),
            1,
            "the Unicode and Punycode spellings are one IOC: {domains:?}"
        );
        assert!(
            domains
                .iter()
                .any(|(value, detail)| *value == "xn--mnchen-3ya.de"
                    && detail.starts_with("internationalized domain")),
            "{domains:?}"
        );
        assert!(
            !domains.iter().any(|(value, _)| *value == "nchen.de"),
            "{domains:?}"
        );
    }

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
        assert_eq!((ip.first_line, ip.last_line), (Some(1), Some(3)));
        assert_eq!(report.total_occurrences, 4);
    }

    #[test]
    fn tracks_original_columns_for_defanged_values() {
        let report = extract(
            "prefix hxxps[://]evil[.]example/path",
            ExtractOptions {
                source: "sample.log".to_owned(),
                ..ExtractOptions::default()
            },
        );
        let url = report
            .iocs
            .iter()
            .find(|ioc| ioc.kind == IocKind::Url)
            .expect("URL IOC");
        assert_eq!(url.source, "sample.log");
        assert_eq!(url.first_line, Some(1));
        assert_eq!(url.first_column, Some(8));
        assert_eq!(url.locations[0].column, 8);
    }

    #[test]
    fn masks_short_and_long_secret_candidates() {
        assert_eq!(mask_secret("short123", IocKind::Secret), "********");
        assert_eq!(
            mask_secret("AKIA1234567890ABCDEF", IocKind::Secret),
            "AKIA…CDEF [REDACTED]"
        );
    }

    #[test]
    fn redacts_secrets_and_private_key_material_from_context() {
        let secret = "AKIA1234567890ABCDEF";
        let input = format!(
            "before\napi_key={secret}\n-----BEGIN PRIVATE KEY-----\nVERYSECRETKEYBODY\n-----END PRIVATE KEY-----\nafter"
        );
        let report = extract(
            &input,
            ExtractOptions {
                include_secret: true,
                context_lines: 1,
                ..ExtractOptions::default()
            },
        );
        let serialized = serde_json::to_string(&report).expect("serialize report");
        assert!(!serialized.contains(secret));
        assert!(!serialized.contains("VERYSECRETKEYBODY"));
        assert!(serialized.contains("REDACTED"));
        assert!(report.iocs.iter().all(|ioc| ioc.redacted));
    }

    #[test]
    fn reveal_option_is_explicit_and_locations_are_bounded() {
        let secret = "AKIA1234567890ABCDEF";
        let input = format!("api_key={secret}\napi_key={secret}\napi_key={secret}");
        let report = extract(
            &input,
            ExtractOptions {
                include_secret: true,
                reveal_secrets: true,
                max_locations: 2,
                ..ExtractOptions::default()
            },
        );
        let candidate = report
            .iocs
            .iter()
            .find(|ioc| ioc.kind == IocKind::Secret && ioc.value == secret)
            .expect("revealed candidate");
        assert!(!candidate.redacted);
        assert_eq!(candidate.occurrences, 3);
        assert_eq!(candidate.locations.len(), 2);
        assert!(candidate.locations_truncated);
    }

    #[test]
    fn match_collection_has_a_global_limit() {
        let report = extract(
            "8.8.8.8 1.1.1.1 example.com",
            ExtractOptions {
                max_matches: 1,
                ..ExtractOptions::default()
            },
        );
        assert!(report.match_limit_reached);
        assert_eq!(report.total_occurrences, 1);
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

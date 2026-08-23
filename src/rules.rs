use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use regex::bytes::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

const MAX_RULE_FILE_BYTES: u64 = 1024 * 1024;
const MAX_SCAN_BYTES: usize = 64 * 1024 * 1024;
const MAX_RULES: usize = 1_000;
const MAX_PATTERN_BYTES: usize = 32 * 1024;
const MAX_MATCHES_PER_RULE: usize = 10_000;
const MAX_SAMPLES_PER_RULE: usize = 20;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    #[default]
    Regex,
    Literal,
    Hex,
}

impl std::fmt::Display for RuleKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Regex => "regex",
            Self::Literal => "literal",
            Self::Hex => "hex",
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSet {
    #[serde(default = "default_version")]
    version: u8,
    rules: Vec<RuleDefinition>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDefinition {
    id: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    severity: Severity,
    #[serde(default)]
    kind: RuleKind,
    pattern: String,
    #[serde(default)]
    case_insensitive: bool,
    #[serde(default = "default_min_matches")]
    min_matches: usize,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidationReport {
    pub valid: bool,
    pub version: u8,
    pub rule_count: usize,
    pub rules: Vec<ValidatedRule>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatedRule {
    pub id: String,
    pub description: String,
    pub severity: Severity,
    pub kind: RuleKind,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub input_bytes: usize,
    pub rules_loaded: usize,
    pub matched_rules: usize,
    pub matches: Vec<RuleMatchReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleMatchReport {
    pub id: String,
    pub description: String,
    pub severity: Severity,
    pub kind: RuleKind,
    pub tags: Vec<String>,
    pub total_matches: usize,
    pub truncated: bool,
    pub samples: Vec<MatchSample>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MatchSample {
    pub offset: usize,
    pub length: usize,
    pub preview: String,
}

enum Matcher {
    Regex(Regex),
    Hex(Vec<Option<u8>>),
}

struct CompiledRule {
    definition: RuleDefinition,
    matcher: Matcher,
}

struct CompiledRuleSet {
    version: u8,
    rules: Vec<CompiledRule>,
}

pub fn validate_file(path: &Path) -> Result<ValidationReport> {
    let rules = load_and_compile(path)?;
    Ok(ValidationReport {
        valid: true,
        version: rules.version,
        rule_count: rules.rules.len(),
        rules: rules
            .rules
            .into_iter()
            .map(|rule| ValidatedRule {
                id: rule.definition.id,
                description: rule.definition.description,
                severity: rule.definition.severity,
                kind: rule.definition.kind,
                tags: rule.definition.tags,
            })
            .collect(),
    })
}

pub fn scan(path: &Path, input: &[u8]) -> Result<ScanReport> {
    if input.len() > MAX_SCAN_BYTES {
        bail!("rule scan input exceeds the 64 MiB safety limit");
    }
    let rules = load_and_compile(path)?;
    let rules_loaded = rules.rules.len();
    let mut matches = Vec::new();
    for rule in rules.rules {
        if let Some(report) = scan_rule(rule, input) {
            matches.push(report);
        }
    }
    Ok(ScanReport {
        input_bytes: input.len(),
        rules_loaded,
        matched_rules: matches.len(),
        matches,
    })
}

fn load_and_compile(path: &Path) -> Result<CompiledRuleSet> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to inspect rule file '{}'", path.display()))?;
    if !metadata.is_file() {
        bail!("'{}' is not a regular rule file", path.display());
    }
    if metadata.len() > MAX_RULE_FILE_BYTES {
        bail!("rule file exceeds the 1 MiB safety limit");
    }
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read UTF-8 rule file '{}'", path.display()))?;
    compile_source(&source).with_context(|| format!("invalid rule file '{}'", path.display()))
}

fn compile_source(source: &str) -> Result<CompiledRuleSet> {
    let rule_set: RuleSet = toml::from_str(source).context("invalid TOML syntax or schema")?;
    if rule_set.version != 1 {
        bail!(
            "unsupported rule schema version {}; expected 1",
            rule_set.version
        );
    }
    if rule_set.rules.is_empty() {
        bail!("rule file must contain at least one [[rules]] entry");
    }
    if rule_set.rules.len() > MAX_RULES {
        bail!("rule file exceeds the {MAX_RULES}-rule safety limit");
    }

    let mut ids = HashSet::new();
    let mut compiled = Vec::with_capacity(rule_set.rules.len());
    for definition in rule_set.rules {
        validate_definition(&definition, &mut ids)?;
        let matcher = compile_matcher(&definition)
            .with_context(|| format!("rule '{}' has an invalid pattern", definition.id))?;
        compiled.push(CompiledRule {
            definition,
            matcher,
        });
    }
    Ok(CompiledRuleSet {
        version: rule_set.version,
        rules: compiled,
    })
}

fn validate_definition(rule: &RuleDefinition, ids: &mut HashSet<String>) -> Result<()> {
    if rule.id.is_empty()
        || rule.id.len() > 128
        || !rule
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!(
            "rule ID '{}' must contain 1-128 ASCII letters, digits, dots, underscores, or hyphens",
            rule.id
        );
    }
    if !ids.insert(rule.id.to_ascii_lowercase()) {
        bail!("duplicate rule ID '{}'", rule.id);
    }
    if rule.pattern.is_empty() {
        bail!("rule '{}' has an empty pattern", rule.id);
    }
    if rule.pattern.len() > MAX_PATTERN_BYTES {
        bail!("rule '{}' pattern exceeds 32 KiB", rule.id);
    }
    if !(1..=MAX_MATCHES_PER_RULE).contains(&rule.min_matches) {
        bail!(
            "rule '{}' min_matches must be between 1 and {MAX_MATCHES_PER_RULE}",
            rule.id
        );
    }
    if rule.kind == RuleKind::Hex && rule.case_insensitive {
        bail!(
            "rule '{}' cannot use case_insensitive with a hex pattern",
            rule.id
        );
    }
    Ok(())
}

fn compile_matcher(rule: &RuleDefinition) -> Result<Matcher> {
    if rule.kind == RuleKind::Hex {
        return Ok(Matcher::Hex(parse_hex_pattern(&rule.pattern)?));
    }
    let pattern = if rule.kind == RuleKind::Literal {
        regex::escape(&rule.pattern)
    } else {
        rule.pattern.clone()
    };
    let regex = RegexBuilder::new(&pattern)
        .case_insensitive(rule.case_insensitive)
        .size_limit(10 * 1024 * 1024)
        .dfa_size_limit(10 * 1024 * 1024)
        .build()
        .context("regex compilation failed")?;
    Ok(Matcher::Regex(regex))
}

fn parse_hex_pattern(pattern: &str) -> Result<Vec<Option<u8>>> {
    let compact: String = pattern
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if compact.is_empty() || !compact.len().is_multiple_of(2) || !compact.is_ascii() {
        bail!("hex patterns require complete byte pairs such as '4D 5A ?? 00'");
    }
    compact
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            if pair == b"??" {
                return Ok(None);
            }
            let pair = std::str::from_utf8(pair).expect("hex pattern is ASCII");
            u8::from_str_radix(pair, 16)
                .map(Some)
                .with_context(|| format!("invalid hex byte '{pair}'"))
        })
        .collect()
}

fn scan_rule(rule: CompiledRule, input: &[u8]) -> Option<RuleMatchReport> {
    let mut samples = Vec::new();
    let mut total_matches = 0_usize;
    let mut truncated = false;
    match &rule.matcher {
        Matcher::Regex(regex) => {
            for found in regex.find_iter(input) {
                if total_matches == MAX_MATCHES_PER_RULE {
                    truncated = true;
                    break;
                }
                if samples.len() < MAX_SAMPLES_PER_RULE {
                    samples.push(sample(input, found.start(), found.end() - found.start()));
                }
                total_matches += 1;
            }
        }
        Matcher::Hex(pattern) => {
            for (offset, window) in input.windows(pattern.len()).enumerate() {
                if pattern
                    .iter()
                    .zip(window)
                    .all(|(expected, actual)| expected.is_none_or(|byte| byte == *actual))
                {
                    if total_matches == MAX_MATCHES_PER_RULE {
                        truncated = true;
                        break;
                    }
                    if samples.len() < MAX_SAMPLES_PER_RULE {
                        samples.push(sample(input, offset, pattern.len()));
                    }
                    total_matches += 1;
                }
            }
        }
    }
    if total_matches < rule.definition.min_matches {
        return None;
    }
    Some(RuleMatchReport {
        id: rule.definition.id,
        description: rule.definition.description,
        severity: rule.definition.severity,
        kind: rule.definition.kind,
        tags: rule.definition.tags,
        total_matches,
        truncated,
        samples,
    })
}

fn sample(input: &[u8], offset: usize, length: usize) -> MatchSample {
    let context_start = offset.saturating_sub(12);
    let context_end = input
        .len()
        .min(offset.saturating_add(length).saturating_add(12));
    let preview = input[context_start..context_end]
        .iter()
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .map(char::from)
        .take(120)
        .collect();
    MatchSample {
        offset,
        length,
        preview,
    }
}

const fn default_version() -> u8 {
    1
}

const fn default_min_matches() -> usize {
    1
}

#[cfg(test)]
mod tests {
    use super::{RuleKind, compile_source, parse_hex_pattern, scan_rule};

    #[test]
    fn compiles_and_scans_regex_literal_and_wildcard_hex_rules() {
        let source = r#"
version = 1

[[rules]]
id = "suspicious-command"
description = "PowerShell encoded command"
severity = "high"
kind = "regex"
pattern = '(?i)powershell(?:\.exe)?\s+-enc'

[[rules]]
id = "marker"
kind = "literal"
pattern = "BANSHEE"
case_insensitive = true

[[rules]]
id = "mz-like"
kind = "hex"
pattern = "4D 5A ?? 00"
"#;
        let rules = compile_source(source).expect("compile");
        let input = b"powershell.exe -enc AAA banshee \x4D\x5A\x90\x00";
        let matched = rules
            .rules
            .into_iter()
            .filter_map(|rule| scan_rule(rule, input))
            .collect::<Vec<_>>();
        assert_eq!(matched.len(), 3);
        assert_eq!(matched[2].kind, RuleKind::Hex);
        assert_eq!(matched[2].samples[0].offset, 32);
    }

    #[test]
    fn rejects_duplicate_rule_ids() {
        let source = r#"
[[rules]]
id = "same"
pattern = "one"
[[rules]]
id = "SAME"
pattern = "two"
"#;
        assert!(
            compile_source(source)
                .err()
                .expect("duplicate error")
                .to_string()
                .contains("duplicate rule ID")
        );
    }

    #[test]
    fn parses_contiguous_and_spaced_hex_patterns() {
        assert_eq!(parse_hex_pattern("4D5A??00").unwrap().len(), 4);
        assert_eq!(parse_hex_pattern("4D 5A ?? 00").unwrap().len(), 4);
        assert!(parse_hex_pattern("4D 5").is_err());
    }
}

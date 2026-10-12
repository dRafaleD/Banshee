use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use regex::bytes::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

pub mod yara;

const MAX_RULE_FILE_BYTES: u64 = 1024 * 1024;
const MAX_SCAN_BYTES: usize = 64 * 1024 * 1024;
const MAX_RULES: usize = 1_000;
const MAX_PATTERN_BYTES: usize = 32 * 1024;
const MAX_MATCHES_PER_RULE: usize = 10_000;
const MAX_SAMPLES_PER_RULE: usize = 20;
const MAX_CONDITIONS_PER_GROUP: usize = 16;
const MAX_TOTAL_MATCHERS: usize = 4_096;
const MAX_REFERENCES_PER_RULE: usize = 16;
const MAX_REFERENCE_BYTES: usize = 512;
const MAX_TAGS_PER_RULE: usize = 32;
const MAX_ATTACK_IDS_PER_RULE: usize = 16;
const MAX_METADATA_BYTES: usize = 4_096;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleFileType {
    Text,
    Binary,
    Elf,
    Pe,
    Zip,
    Tar,
    Gzip,
    Xz,
    Bzip2,
}

impl std::fmt::Display for RuleFileType {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Text => "text",
            Self::Binary => "binary",
            Self::Elf => "elf",
            Self::Pe => "pe",
            Self::Zip => "zip",
            Self::Tar => "tar",
            Self::Gzip => "gzip",
            Self::Xz => "xz",
            Self::Bzip2 => "bzip2",
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
    #[serde(default = "default_max_matches")]
    max_matches: usize,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    confidence: Option<Confidence>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    attack: Vec<String>,
    #[serde(default)]
    file_types: Vec<RuleFileType>,
    #[serde(default)]
    min_entropy: Option<f64>,
    #[serde(default)]
    max_entropy: Option<f64>,
    #[serde(default)]
    all: Vec<RuleCondition>,
    #[serde(default)]
    any: Vec<RuleCondition>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleCondition {
    #[serde(default)]
    kind: RuleKind,
    pattern: String,
    #[serde(default)]
    case_insensitive: bool,
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
    pub category: Option<String>,
    pub confidence: Option<Confidence>,
    pub references: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attack: Vec<String>,
    pub file_types: Vec<RuleFileType>,
    pub min_entropy: Option<f64>,
    pub max_entropy: Option<f64>,
    pub min_matches: usize,
    pub max_matches: usize,
    pub all_conditions: usize,
    pub any_conditions: usize,
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
    pub category: Option<String>,
    pub confidence: Option<Confidence>,
    pub references: Vec<String>,
    /// MITRE ATT&CK tactic/technique identifiers declared by the rule author.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attack: Vec<String>,
    pub detected_file_type: RuleFileType,
    pub entropy: f64,
    pub conditions: ConditionReport,
    pub total_matches: usize,
    pub truncated: bool,
    pub samples: Vec<MatchSample>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConditionReport {
    pub all_required: usize,
    pub all_matched: usize,
    pub any_required: usize,
    pub any_matched: usize,
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
    all: Vec<Matcher>,
    any: Vec<Matcher>,
}

struct CompiledRuleSet {
    version: u8,
    rules: Vec<CompiledRule>,
}

pub fn validate_file(path: &Path) -> Result<ValidationReport> {
    Ok(validation_report(load_and_compile(path)?))
}

/// Validates TOML rule source already held in memory.
pub fn validate_source(source: &str) -> Result<ValidationReport> {
    Ok(validation_report(compile_in_memory(source)?))
}

fn validation_report(rules: CompiledRuleSet) -> ValidationReport {
    ValidationReport {
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
                category: rule.definition.category,
                confidence: rule.definition.confidence,
                references: rule.definition.references,
                attack: rule.definition.attack,
                file_types: rule.definition.file_types,
                min_entropy: rule.definition.min_entropy,
                max_entropy: rule.definition.max_entropy,
                min_matches: rule.definition.min_matches,
                max_matches: rule.definition.max_matches,
                all_conditions: rule.all.len(),
                any_conditions: rule.any.len(),
            })
            .collect(),
    }
}

pub fn scan(path: &Path, input: &[u8]) -> Result<ScanReport> {
    ensure_scan_size(input)?;
    scan_compiled(load_and_compile(path)?, input)
}

/// Scans `input` with TOML rule source already held in memory.
pub fn scan_source(source: &str, input: &[u8]) -> Result<ScanReport> {
    ensure_scan_size(input)?;
    scan_compiled(compile_in_memory(source)?, input)
}

fn ensure_scan_size(input: &[u8]) -> Result<()> {
    if input.len() > MAX_SCAN_BYTES {
        bail!("rule scan input exceeds the 64 MiB safety limit");
    }
    Ok(())
}

fn compile_in_memory(source: &str) -> Result<CompiledRuleSet> {
    if source.len() as u64 > MAX_RULE_FILE_BYTES {
        bail!("rule file exceeds the 1 MiB safety limit");
    }
    compile_source(source)
}

fn scan_compiled(rules: CompiledRuleSet, input: &[u8]) -> Result<ScanReport> {
    let rules_loaded = rules.rules.len();
    let file_type = detect_file_type(input);
    let entropy = crate::analysis::entropy::analyze_bytes(input).bits_per_byte;
    let mut matches = Vec::new();
    for rule in rules.rules {
        if let Some(report) = scan_rule(rule, input, file_type, entropy) {
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
    let source =
        crate::input::read_regular_text_file_limited(path, MAX_RULE_FILE_BYTES, "rule file")?;
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
    let mut total_matchers = 0_usize;
    for definition in rule_set.rules {
        validate_definition(&definition, &mut ids)?;
        let matcher = compile_matcher(&definition)
            .with_context(|| format!("rule '{}' has an invalid pattern", definition.id))?;
        let all = definition
            .all
            .iter()
            .enumerate()
            .map(|(index, condition)| {
                compile_condition(condition).with_context(|| {
                    format!(
                        "rule '{}' all condition {} is invalid",
                        definition.id,
                        index + 1
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let any = definition
            .any
            .iter()
            .enumerate()
            .map(|(index, condition)| {
                compile_condition(condition).with_context(|| {
                    format!(
                        "rule '{}' any condition {} is invalid",
                        definition.id,
                        index + 1
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        total_matchers = total_matchers
            .saturating_add(1)
            .saturating_add(all.len())
            .saturating_add(any.len());
        if total_matchers > MAX_TOTAL_MATCHERS {
            bail!("rule file exceeds the {MAX_TOTAL_MATCHERS}-matcher safety limit");
        }
        compiled.push(CompiledRule {
            definition,
            matcher,
            all,
            any,
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
    if !(1..=MAX_MATCHES_PER_RULE).contains(&rule.max_matches) {
        bail!(
            "rule '{}' max_matches must be between 1 and {MAX_MATCHES_PER_RULE}",
            rule.id
        );
    }
    if rule.min_matches > rule.max_matches {
        bail!("rule '{}' min_matches cannot exceed max_matches", rule.id);
    }
    if rule.kind == RuleKind::Hex && rule.case_insensitive {
        bail!(
            "rule '{}' cannot use case_insensitive with a hex pattern",
            rule.id
        );
    }
    if rule.description.len() > MAX_METADATA_BYTES {
        bail!("rule '{}' description exceeds 4 KiB", rule.id);
    }
    if rule.tags.len() > MAX_TAGS_PER_RULE {
        bail!(
            "rule '{}' exceeds the {MAX_TAGS_PER_RULE}-tag safety limit",
            rule.id
        );
    }
    for tag in &rule.tags {
        validate_metadata_value(rule, "tag", tag, 128)?;
    }
    if let Some(category) = &rule.category {
        validate_metadata_value(rule, "category", category, 128)?;
    }
    if rule.references.len() > MAX_REFERENCES_PER_RULE {
        bail!(
            "rule '{}' exceeds the {MAX_REFERENCES_PER_RULE}-reference safety limit",
            rule.id
        );
    }
    for reference in &rule.references {
        validate_metadata_value(rule, "reference", reference, MAX_REFERENCE_BYTES)?;
    }
    if rule.attack.len() > MAX_ATTACK_IDS_PER_RULE {
        bail!(
            "rule '{}' exceeds the {MAX_ATTACK_IDS_PER_RULE}-ATT&CK-identifier safety limit",
            rule.id
        );
    }
    let mut attack_ids = HashSet::new();
    for identifier in &rule.attack {
        if !is_attack_identifier(identifier) {
            bail!(
                "rule '{}' attack value '{}' must be a tactic (TA0002) or technique \
                 (T1059, T1059.001) identifier",
                rule.id,
                identifier.escape_debug()
            );
        }
        if !attack_ids.insert(identifier.as_str()) {
            bail!("rule '{}' repeats attack value '{identifier}'", rule.id);
        }
    }
    if rule.file_types.len() > 9 {
        bail!("rule '{}' has too many file_types", rule.id);
    }
    let mut file_types = HashSet::new();
    for file_type in &rule.file_types {
        if !file_types.insert(*file_type as u8) {
            bail!("rule '{}' contains a duplicate file_type", rule.id);
        }
    }
    validate_entropy(rule.id.as_str(), "min_entropy", rule.min_entropy)?;
    validate_entropy(rule.id.as_str(), "max_entropy", rule.max_entropy)?;
    if let (Some(minimum), Some(maximum)) = (rule.min_entropy, rule.max_entropy)
        && minimum > maximum
    {
        bail!("rule '{}' min_entropy cannot exceed max_entropy", rule.id);
    }
    if rule.all.len() > MAX_CONDITIONS_PER_GROUP || rule.any.len() > MAX_CONDITIONS_PER_GROUP {
        bail!(
            "rule '{}' all/any groups are limited to {MAX_CONDITIONS_PER_GROUP} conditions each",
            rule.id
        );
    }
    for (group, conditions) in [("all", &rule.all), ("any", &rule.any)] {
        for (index, condition) in conditions.iter().enumerate() {
            validate_condition(rule, group, index, condition)?;
        }
    }
    Ok(())
}

/// Accepts `TA0000` tactics, `T0000` techniques and `T0000.000` sub-techniques.
fn is_attack_identifier(value: &str) -> bool {
    let digits = |part: &str, length: usize| {
        part.len() == length && part.bytes().all(|byte| byte.is_ascii_digit())
    };
    if let Some(tactic) = value.strip_prefix("TA") {
        return digits(tactic, 4);
    }
    let Some(technique) = value.strip_prefix('T') else {
        return false;
    };
    match technique.split_once('.') {
        Some((base, sub)) => digits(base, 4) && digits(sub, 3),
        None => digits(technique, 4),
    }
}

fn validate_metadata_value(
    rule: &RuleDefinition,
    field: &str,
    value: &str,
    maximum: usize,
) -> Result<()> {
    if value.trim().is_empty() || value.len() > maximum {
        bail!(
            "rule '{}' {field} values must contain 1-{maximum} bytes",
            rule.id
        );
    }
    Ok(())
}

fn validate_entropy(rule_id: &str, field: &str, value: Option<f64>) -> Result<()> {
    if value.is_some_and(|value| !value.is_finite() || !(0.0..=8.0).contains(&value)) {
        bail!("rule '{rule_id}' {field} must be between 0.0 and 8.0");
    }
    Ok(())
}

fn validate_condition(
    rule: &RuleDefinition,
    group: &str,
    index: usize,
    condition: &RuleCondition,
) -> Result<()> {
    if condition.pattern.is_empty() || condition.pattern.len() > MAX_PATTERN_BYTES {
        bail!(
            "rule '{}' {group} condition {} pattern must contain 1-{} bytes",
            rule.id,
            index + 1,
            MAX_PATTERN_BYTES
        );
    }
    if condition.kind == RuleKind::Hex && condition.case_insensitive {
        bail!(
            "rule '{}' {group} condition {} cannot use case_insensitive with hex",
            rule.id,
            index + 1
        );
    }
    Ok(())
}

fn compile_matcher(rule: &RuleDefinition) -> Result<Matcher> {
    compile_pattern(rule.kind, &rule.pattern, rule.case_insensitive)
}

fn compile_condition(condition: &RuleCondition) -> Result<Matcher> {
    compile_pattern(
        condition.kind,
        &condition.pattern,
        condition.case_insensitive,
    )
}

fn compile_pattern(kind: RuleKind, source: &str, case_insensitive: bool) -> Result<Matcher> {
    if kind == RuleKind::Hex {
        return Ok(Matcher::Hex(parse_hex_pattern(source)?));
    }
    let pattern = if kind == RuleKind::Literal {
        regex::escape(source)
    } else {
        source.to_owned()
    };
    let regex = RegexBuilder::new(&pattern)
        .case_insensitive(case_insensitive)
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

fn scan_rule(
    rule: CompiledRule,
    input: &[u8],
    file_type: RuleFileType,
    entropy: f64,
) -> Option<RuleMatchReport> {
    if !rule.definition.file_types.is_empty() && !rule.definition.file_types.contains(&file_type) {
        return None;
    }
    if rule
        .definition
        .min_entropy
        .is_some_and(|minimum| entropy < minimum)
        || rule
            .definition
            .max_entropy
            .is_some_and(|maximum| entropy > maximum)
    {
        return None;
    }
    let all_matched = rule
        .all
        .iter()
        .filter(|matcher| matcher_has_match(matcher, input))
        .count();
    if all_matched != rule.all.len() {
        return None;
    }
    let any_matched = rule
        .any
        .iter()
        .filter(|matcher| matcher_has_match(matcher, input))
        .count();
    if !rule.any.is_empty() && any_matched == 0 {
        return None;
    }

    let (total_matches, samples, truncated) =
        collect_matches(&rule.matcher, input, rule.definition.max_matches);
    if total_matches < rule.definition.min_matches {
        return None;
    }
    Some(RuleMatchReport {
        id: rule.definition.id,
        description: rule.definition.description,
        severity: rule.definition.severity,
        kind: rule.definition.kind,
        tags: rule.definition.tags,
        category: rule.definition.category,
        confidence: rule.definition.confidence,
        references: rule.definition.references,
        attack: rule.definition.attack,
        detected_file_type: file_type,
        entropy,
        conditions: ConditionReport {
            all_required: rule.all.len(),
            all_matched,
            any_required: rule.any.len(),
            any_matched,
        },
        total_matches,
        truncated,
        samples,
    })
}

fn collect_matches(
    matcher: &Matcher,
    input: &[u8],
    maximum: usize,
) -> (usize, Vec<MatchSample>, bool) {
    let mut samples = Vec::new();
    let mut total_matches = 0_usize;
    let mut truncated = false;
    match matcher {
        Matcher::Regex(regex) => {
            for found in regex.find_iter(input) {
                if total_matches == maximum {
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
                    if total_matches == maximum {
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
    (total_matches, samples, truncated)
}

fn matcher_has_match(matcher: &Matcher, input: &[u8]) -> bool {
    match matcher {
        Matcher::Regex(regex) => regex.is_match(input),
        Matcher::Hex(pattern) => input.windows(pattern.len()).any(|window| {
            pattern
                .iter()
                .zip(window)
                .all(|(expected, actual)| expected.is_none_or(|byte| byte == *actual))
        }),
    }
}

fn detect_file_type(input: &[u8]) -> RuleFileType {
    if input.starts_with(b"\x7FELF") {
        RuleFileType::Elf
    } else if input.starts_with(b"MZ") {
        RuleFileType::Pe
    } else if matches!(
        input.get(..4),
        Some(b"PK\x03\x04" | b"PK\x05\x06" | b"PK\x07\x08")
    ) {
        RuleFileType::Zip
    } else if matches!(input.get(257..262), Some(b"ustar")) {
        RuleFileType::Tar
    } else if input.starts_with(&[0x1f, 0x8b]) {
        RuleFileType::Gzip
    } else if input.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        RuleFileType::Xz
    } else if input.starts_with(b"BZh") {
        RuleFileType::Bzip2
    } else if std::str::from_utf8(input).is_ok() {
        RuleFileType::Text
    } else {
        RuleFileType::Binary
    }
}

fn sample(input: &[u8], offset: usize, length: usize) -> MatchSample {
    const REDACTION_LOOKBEHIND: usize = 4096 + 128;
    const MAX_VISIBLE_MATCH_BYTES: usize = 256;
    const PREVIEW_CHARS: usize = 120;

    let context_start = offset.saturating_sub(REDACTION_LOOKBEHIND);
    let context_end = input.len().min(
        offset
            .saturating_add(length.min(MAX_VISIBLE_MATCH_BYTES))
            .saturating_add(12),
    );
    let escaped = input[context_start..context_end]
        .iter()
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .map(char::from)
        .collect::<String>();
    let redacted = crate::ioc::redact_sensitive_text(&escaped);
    let mut tail = redacted
        .chars()
        .rev()
        .take(PREVIEW_CHARS)
        .collect::<Vec<_>>();
    tail.reverse();
    let preview = tail.into_iter().collect();
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

const fn default_max_matches() -> usize {
    MAX_MATCHES_PER_RULE
}

#[cfg(test)]
mod tests {
    use super::{RuleFileType, RuleKind, compile_source, parse_hex_pattern, scan_rule};

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
            .filter_map(|rule| scan_rule(rule, input, RuleFileType::Binary, 4.0))
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

    #[test]
    fn supports_metadata_predicates_compound_conditions_and_per_rule_limits() {
        let source = r#"
version = 1

[[rules]]
id = "compound-pe"
description = "Bounded compound rule"
severity = "high"
kind = "literal"
pattern = "MARK"
min_matches = 2
max_matches = 2
tags = ["executable"]
category = "execution"
confidence = "medium"
references = ["internal-playbook-7"]
attack = ["TA0002", "T1059.001"]
file_types = ["pe"]
min_entropy = 0.0
max_entropy = 8.0

[[rules.all]]
kind = "hex"
pattern = "4D 5A"

[[rules.any]]
kind = "literal"
pattern = "PowerShell"
case_insensitive = true
"#;
        let rules = compile_source(source).expect("compile compound rule");
        let rule = &rules.rules[0];
        assert_eq!(rule.all.len(), 1);
        assert_eq!(rule.any.len(), 1);

        let input = b"MZ powershell MARK MARK MARK";
        let report = scan_rule(
            rules.rules.into_iter().next().expect("rule"),
            input,
            RuleFileType::Pe,
            3.5,
        )
        .expect("matched rule");
        assert_eq!(report.category.as_deref(), Some("execution"));
        assert_eq!(report.references, ["internal-playbook-7"]);
        assert_eq!(report.attack, ["TA0002", "T1059.001"]);
        assert_eq!(report.detected_file_type, RuleFileType::Pe);
        assert_eq!(report.total_matches, 2);
        assert!(report.truncated);
        assert_eq!(report.conditions.all_matched, 1);
        assert_eq!(report.conditions.any_matched, 1);
    }

    #[test]
    fn compound_and_file_predicates_gate_rule_matches() {
        let source = r#"
[[rules]]
id = "gated"
pattern = "MARK"
file_types = ["elf"]
min_entropy = 3.0

[[rules.all]]
kind = "literal"
pattern = "required"

[[rules.any]]
kind = "literal"
pattern = "choice-a"
"#;
        let rules = compile_source(source).expect("compile gated rule");
        let input = b"MARK required choice-a";
        assert!(
            scan_rule(
                rules.rules.into_iter().next().expect("rule"),
                input,
                RuleFileType::Text,
                2.0,
            )
            .is_none()
        );
        let rules = compile_source(source).expect("compile gated rule again");
        assert!(
            scan_rule(
                rules.rules.into_iter().next().expect("rule"),
                input,
                RuleFileType::Elf,
                2.0,
            )
            .is_none()
        );
    }

    #[test]
    fn rejects_invalid_new_limits_with_actionable_errors() {
        let invalid_matches = r#"
[[rules]]
id = "bad-matches"
pattern = "x"
min_matches = 3
max_matches = 2
"#;
        assert!(
            compile_source(invalid_matches)
                .err()
                .expect("invalid match limits")
                .to_string()
                .contains("min_matches cannot exceed max_matches")
        );

        let invalid_entropy = r#"
[[rules]]
id = "bad-entropy"
pattern = "x"
min_entropy = 8.1
"#;
        assert!(
            compile_source(invalid_entropy)
                .err()
                .expect("invalid entropy limit")
                .to_string()
                .contains("min_entropy must be between 0.0 and 8.0")
        );

        let excessive_conditions = format!(
            "[[rules]]\nid = \"too-many\"\npattern = \"x\"\n{}",
            "[[rules.all]]\nkind = \"literal\"\npattern = \"x\"\n".repeat(17)
        );
        assert!(
            compile_source(&excessive_conditions)
                .err()
                .expect("condition limit")
                .to_string()
                .contains("all/any groups are limited to 16")
        );
    }

    #[test]
    fn validates_attack_identifiers_strictly() {
        for valid in ["TA0002", "T1059", "T1059.001"] {
            assert!(super::is_attack_identifier(valid), "{valid}");
        }
        for invalid in [
            "t1059",
            "T105",
            "T1059.1",
            "T1059.0011",
            "TA002",
            "T1059.",
            "X1059",
            "",
        ] {
            assert!(!super::is_attack_identifier(invalid), "{invalid}");
        }
        let rule = |attack: &str| {
            format!(
                "version = 1\n[[rules]]\nid = 'r'\nkind = 'literal'\npattern = 'x'\nattack = {attack}\n"
            )
        };
        assert!(compile_source(&rule(r#"["T1059.001"]"#)).is_ok());
        let error = format!(
            "{:#}",
            compile_source(&rule(r#"["T1059.1"]"#))
                .err()
                .expect("invalid id")
        );
        assert!(error.contains("must be a tactic"), "{error}");
        let error = format!(
            "{:#}",
            compile_source(&rule(r#"["T1059", "T1059"]"#))
                .err()
                .expect("duplicate id")
        );
        assert!(error.contains("repeats attack value"), "{error}");
    }
}

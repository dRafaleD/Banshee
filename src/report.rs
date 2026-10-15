use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use serde::Serialize;

use crate::analysis::entropy::EntropyReport;
use crate::batch::{BatchReport, TokenAnalysis};
use crate::file_inspect::FileReport;
use crate::hash::HashAlgorithm;
use crate::ioc::Ioc;
use crate::rules::{RuleMatchReport, ScanReport, Severity};

pub const REPORT_SCHEMA_VERSION: u8 = 1;
const MAX_REPORT_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Read the wire version without assuming that the schema is supported.
pub fn schema_version(value: &serde_json::Value) -> Result<u8> {
    let object = value
        .as_object()
        .context("report root must be a JSON object")?;
    let version = object
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .context("report is missing an integer schema_version")?;
    u8::try_from(version).context("report schema_version is out of range")
}

/// Validate saved JSON against its version's compatibility contract.
/// Optional historical fields remain missing; unknown additions are ignored.
/// Errors identify schema locations, never values from the saved report.
pub fn validate_compatibility(value: &serde_json::Value) -> Result<u8> {
    let version = schema_version(value)?;
    match version {
        1 => validate_v1(value)?,
        _ => bail!("unsupported report schema version {version}; expected 1"),
    }
    Ok(version)
}

#[derive(Clone, Copy)]
enum SchemaType {
    Object,
    Array,
    String,
    Unsigned,
    Number,
    Boolean,
}

impl SchemaType {
    fn accepts(self, value: &serde_json::Value) -> bool {
        match self {
            Self::Object => value.is_object(),
            Self::Array => value.is_array(),
            Self::String => value.is_string(),
            Self::Unsigned => value.is_u64(),
            Self::Number => value.is_number(),
            Self::Boolean => value.is_boolean(),
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Object => "an object",
            Self::Array => "an array",
            Self::String => "a string",
            Self::Unsigned => "a non-negative integer",
            Self::Number => "a number",
            Self::Boolean => "a boolean",
        }
    }
}

fn schema_field(
    value: &serde_json::Value,
    pointer: &str,
    kind: SchemaType,
    required: bool,
) -> Result<()> {
    match value.pointer(pointer).filter(|value| !value.is_null()) {
        Some(value) if kind.accepts(value) => Ok(()),
        None if !required => Ok(()),
        _ => bail!("report field '{pointer}' must be {}", kind.description()),
    }
}

fn schema_collection(
    value: &serde_json::Value,
    pointer: &str,
    fields: &[(&str, SchemaType, bool)],
) -> Result<()> {
    schema_field(value, pointer, SchemaType::Array, false)?;
    if let Some(items) = value.pointer(pointer).and_then(serde_json::Value::as_array) {
        for (index, item) in items.iter().enumerate() {
            if !item.is_object() {
                bail!("report item '{pointer}/{index}' must be an object");
            }
            for (name, kind, required) in fields {
                schema_field(item, &format!("/{name}"), *kind, *required)
                    .with_context(|| format!("invalid report item '{pointer}/{index}'"))?;
            }
        }
    }
    Ok(())
}

fn validate_v1(value: &serde_json::Value) -> Result<()> {
    use SchemaType::{Array, Boolean, Number, Object, String, Unsigned};
    for field in [
        "file",
        "hashes",
        "entropy",
        "content_analysis",
        "rule_analysis",
        "summary",
    ] {
        schema_field(value, &format!("/{field}"), Object, true)?;
    }
    schema_field(value, "/findings", Array, true)?;
    for pointer in [
        "/file/path",
        "/file/format",
        "/hashes/md5",
        "/hashes/sha1",
        "/hashes/sha256",
    ] {
        schema_field(value, pointer, String, true)?;
    }
    schema_field(value, "/file/size", Unsigned, true)?;
    schema_field(value, "/entropy/bits_per_byte", Number, true)?;

    // The v1 reader permits these sections and attributes to be omitted. Do
    // not invent values or turn unavailable collections into [].
    for pointer in [
        "/file/executable",
        "/file/archive",
        "/content_analysis/report",
        "/content_analysis/report/iocs",
        "/rule_analysis/report",
    ] {
        schema_field(value, pointer, Object, false)?;
    }
    for pointer in [
        "/content_analysis/status",
        "/content_analysis/mode",
        "/rule_analysis/status",
        "/rule_analysis/rule_file",
        "/file/executable/format",
        "/file/executable/architecture",
        "/file/executable/kind",
        "/file/executable/entry_point",
    ] {
        schema_field(value, pointer, String, false)?;
    }
    for pointer in [
        "/file/executable/bits",
        "/file/archive/total_entries",
        "/file/archive/total_size",
        "/summary/total_findings",
        "/summary/file_findings",
        "/summary/content_findings",
        "/summary/iocs",
        "/summary/matched_rules",
    ] {
        schema_field(value, pointer, Unsigned, false)?;
    }
    schema_collection(
        value,
        "/content_analysis/report/iocs/iocs",
        &[
            ("kind", String, true),
            ("value", String, true),
            ("occurrences", Unsigned, false),
        ],
    )?;
    schema_collection(
        value,
        "/findings",
        &[
            ("source", String, true),
            ("kind", String, true),
            ("value", String, true),
            ("detail", String, true),
            ("severity", String, false),
        ],
    )?;
    schema_collection(
        value,
        "/rule_analysis/report/matches",
        &[
            ("id", String, true),
            ("description", String, false),
            ("severity", String, false),
            ("kind", String, false),
            ("category", String, false),
            ("confidence", String, false),
            ("total_matches", Unsigned, false),
            ("truncated", Boolean, false),
            ("conditions", Object, false),
        ],
    )?;
    schema_collection(
        value,
        "/file/archive/entries",
        &[
            ("name", String, true),
            ("kind", String, false),
            ("size", Unsigned, false),
            ("compressed_size", Unsigned, false),
            ("encrypted", Boolean, false),
            ("path_safe", Boolean, false),
        ],
    )?;
    schema_collection(
        value,
        "/file/executable/section_details",
        &[
            ("name", String, true),
            ("virtual_address", String, false),
            ("file_offset", Unsigned, false),
            ("file_size", Unsigned, false),
            ("memory_size", Unsigned, false),
            ("readable", Boolean, false),
            ("allocated", Boolean, false),
            ("writable", Boolean, false),
            ("executable", Boolean, false),
        ],
    )?;
    if let Some(items) = value
        .pointer("/rule_analysis/report/matches")
        .and_then(serde_json::Value::as_array)
    {
        for (index, item) in items.iter().enumerate() {
            for name in ["all_required", "all_matched", "any_required", "any_matched"] {
                schema_field(item, &format!("/conditions/{name}"), Unsigned, false)
                    .with_context(|| format!("invalid rule conditions at item {index}"))?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    Text,
    Json,
    Markdown,
    /// Self-contained, script-free HTML page.
    Html,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnifiedReport {
    pub schema_version: u8,
    pub file: FileReport,
    pub hashes: FileHashes,
    pub entropy: EntropyReport,
    pub content_analysis: ContentAnalysis,
    pub rule_analysis: RuleAnalysis,
    pub findings: Vec<ReportFinding>,
    pub summary: ReportSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileHashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    /// ssdeep fuzzy hash for similarity between related samples.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssdeep: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentMode {
    Utf8Text,
    ExtractedPrintableStrings,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentAnalysis {
    pub status: SectionStatus,
    pub mode: ContentMode,
    pub report: BatchReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleAnalysis {
    pub status: SectionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<ScanReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SectionStatus {
    Completed,
    NotRequested,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSource {
    FileInspection,
    ContentAnalysis,
    IocExtraction,
    LocalRule,
}

impl std::fmt::Display for FindingSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::FileInspection => "file inspection",
            Self::ContentAnalysis => "content analysis",
            Self::IocExtraction => "IOC extraction",
            Self::LocalRule => "local rule",
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportFinding {
    pub source: FindingSource,
    pub severity: Severity,
    pub kind: String,
    pub value: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportSummary {
    pub total_findings: usize,
    pub file_findings: usize,
    pub content_findings: usize,
    pub iocs: usize,
    pub matched_rules: usize,
}

pub fn generate(
    path: &Path,
    rule_file: Option<&Path>,
    max_entries: usize,
    max_depth: u8,
    max_tokens: usize,
) -> Result<UnifiedReport> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to inspect '{}'", path.display()))?;
    if !metadata.is_file() {
        bail!("'{}' is not a regular file", path.display());
    }
    if metadata.len() > MAX_REPORT_FILE_BYTES {
        bail!("file exceeds the 256 MiB report limit");
    }
    let bytes =
        crate::input::read_regular_file_limited(path, MAX_REPORT_FILE_BYTES, "report input")?;
    generate_from_bytes(
        &bytes,
        &path.display().to_string(),
        rule_file.map(RuleSource::File),
        max_entries,
        max_depth,
        max_tokens,
    )
}

/// Where local rules for a report come from.
#[derive(Debug, Clone, Copy)]
pub enum RuleSource<'a> {
    File(&'a Path),
    /// TOML rule source already in memory, with a label shown in reports.
    Inline {
        label: &'a str,
        source: &'a str,
    },
}

/// Builds a report for bytes already in memory, for example in a browser
/// build where no file system is available. `name` labels the sample.
pub fn generate_from_bytes(
    bytes: &[u8],
    name: &str,
    rules: Option<RuleSource<'_>>,
    max_entries: usize,
    max_depth: u8,
    max_tokens: usize,
) -> Result<UnifiedReport> {
    if bytes.len() as u64 > MAX_REPORT_FILE_BYTES {
        bail!("file exceeds the 256 MiB report limit");
    }
    let file = crate::file_inspect::inspect_bytes(bytes, name.to_owned(), max_entries)?;
    let hashes = FileHashes {
        md5: digest(bytes, HashAlgorithm::Md5)?,
        sha1: digest(bytes, HashAlgorithm::Sha1)?,
        sha256: file.sha256.clone(),
        ssdeep: Some(crate::fuzzy::ssdeep(bytes)),
    };
    let mut content_report =
        crate::batch::analyze_bytes_with_source(bytes, max_depth, max_tokens, name);
    if let Some(document) = &file.document {
        // Shortcut arguments and package relationships are UTF-16 or compressed,
        // so printable-string extraction alone would miss their indicators.
        crate::batch::merge_supplementary_text(
            &mut content_report,
            &document.analysis_text(),
            max_depth,
            max_tokens,
            &format!("{name} (document metadata)"),
        );
    }
    let content_analysis = ContentAnalysis {
        status: SectionStatus::Completed,
        mode: if content_report.binary.is_some() {
            ContentMode::ExtractedPrintableStrings
        } else {
            ContentMode::Utf8Text
        },
        report: content_report,
    };
    let rule_analysis = match rules {
        Some(RuleSource::File(rule_file)) => RuleAnalysis {
            status: SectionStatus::Completed,
            rule_file: Some(rule_file.display().to_string()),
            report: Some(crate::rules::scan(rule_file, bytes)?),
        },
        Some(RuleSource::Inline { label, source }) => RuleAnalysis {
            status: SectionStatus::Completed,
            rule_file: Some(label.to_owned()),
            report: Some(crate::rules::scan_source(source, bytes)?),
        },
        None => RuleAnalysis {
            status: SectionStatus::NotRequested,
            rule_file: None,
            report: None,
        },
    };

    let findings = collect_findings(&file, &content_analysis.report, &rule_analysis);
    let summary = ReportSummary {
        total_findings: findings.len(),
        file_findings: file.findings.len(),
        content_findings: content_analysis.report.analyses.len(),
        iocs: content_analysis.report.iocs.total,
        matched_rules: rule_analysis
            .report
            .as_ref()
            .map_or(0, |report| report.matched_rules),
    };

    Ok(UnifiedReport {
        schema_version: REPORT_SCHEMA_VERSION,
        file,
        hashes,
        entropy: content_analysis.report.entropy.clone(),
        content_analysis,
        rule_analysis,
        findings,
        summary,
    })
}

fn digest(bytes: &[u8], algorithm: HashAlgorithm) -> Result<String> {
    Ok(crate::hash::calculate_bytes(bytes, algorithm)?.digest)
}

fn collect_findings(
    file: &FileReport,
    content: &BatchReport,
    rules: &RuleAnalysis,
) -> Vec<ReportFinding> {
    let mut findings = Vec::new();
    findings.extend(file.findings.iter().map(|finding| ReportFinding {
        source: FindingSource::FileInspection,
        severity: Severity::Medium,
        kind: "file_property".to_owned(),
        value: file.path.clone(),
        detail: finding.clone(),
    }));
    findings.extend(content.analyses.iter().map(content_finding));
    findings.extend(content.iocs.iocs.iter().map(ioc_finding));
    if let Some(report) = &rules.report {
        findings.extend(report.matches.iter().map(rule_finding));
    }
    findings
}

fn content_finding(item: &TokenAnalysis) -> ReportFinding {
    let kind = item
        .report
        .layers
        .first()
        .map(|layer| layer.kind.to_string())
        .unwrap_or_else(|| "structured_indicator".to_owned());
    ReportFinding {
        source: FindingSource::ContentAnalysis,
        severity: Severity::Info,
        kind,
        value: item.token.clone(),
        detail: item.line.map_or_else(
            || {
                "interesting token extracted from binary content; source position unavailable"
                    .to_owned()
            },
            |line| format!("interesting token on line {line}"),
        ),
    }
}

fn ioc_finding(ioc: &Ioc) -> ReportFinding {
    ReportFinding {
        source: FindingSource::IocExtraction,
        severity: Severity::Info,
        kind: ioc.kind.to_string(),
        value: ioc.value.clone(),
        detail: match (ioc.first_line, ioc.last_line) {
            (Some(first), Some(last)) => format!(
                "{} occurrence{}; lines {first}-{last}",
                ioc.occurrences,
                if ioc.occurrences == 1 { "" } else { "s" },
            ),
            _ => format!(
                "{} occurrence{}; source position unavailable",
                ioc.occurrences,
                if ioc.occurrences == 1 { "" } else { "s" },
            ),
        },
    }
}

fn rule_finding(rule: &RuleMatchReport) -> ReportFinding {
    ReportFinding {
        source: FindingSource::LocalRule,
        severity: rule.severity,
        kind: rule.kind.to_string(),
        value: rule.id.clone(),
        detail: {
            let detail = if rule.description.is_empty() {
                format!("{} matches", rule.total_matches)
            } else {
                rule.description.clone()
            };
            if rule.attack.is_empty() {
                detail
            } else {
                format!("{detail} [ATT&CK {}]", rule.attack.join(", "))
            }
        },
    }
}

pub fn print(report: &UnifiedReport, format: ReportFormat) -> Result<()> {
    crate::output::with_output(|output| write_to(output, report, format))
}

pub fn write_to(
    output: &mut dyn Write,
    report: &UnifiedReport,
    format: ReportFormat,
) -> Result<()> {
    match format {
        ReportFormat::Text => write_text(output, report),
        ReportFormat::Json => {
            serde_json::to_writer_pretty(&mut *output, report)
                .context("failed to serialize unified report")?;
            writeln!(output).context("failed to write unified report")
        }
        ReportFormat::Markdown => write_markdown(output, report),
        ReportFormat::Html => crate::report_html::write_html(output, report),
    }
}

fn write_text(output: &mut dyn Write, report: &UnifiedReport) -> Result<()> {
    writeln!(output, "Banshee unified report")?;
    writeln!(output, "Path: {}", safe(&report.file.path))?;
    writeln!(output, "Format: {}", safe(&report.file.format))?;
    writeln!(output, "Size: {} bytes", report.file.size)?;
    writeln!(output, "MD5: {}", report.hashes.md5)?;
    writeln!(output, "SHA-1: {}", report.hashes.sha1)?;
    writeln!(output, "SHA-256: {}", report.hashes.sha256)?;
    if let Some(ssdeep) = &report.hashes.ssdeep {
        writeln!(output, "ssdeep: {ssdeep}")?;
    }
    if let Some(compression) = &report.file.compression {
        writeln!(
            output,
            "Compression: {} ({} -> {} bytes; payload: {})",
            safe(&compression.algorithm),
            compression.compressed_bytes,
            compression.decompressed_bytes,
            safe(&compression.payload_format)
        )?;
    }
    if let Some(executable) = &report.file.executable {
        let import_symbols: usize = executable
            .imports
            .iter()
            .map(|library| library.symbols.len())
            .sum();
        writeln!(
            output,
            "Executable: {} {}-bit {}; entry {}; {} sections",
            safe(&executable.architecture),
            executable.bits,
            safe(&executable.kind),
            safe(&executable.entry_point),
            executable.sections
        )?;
        writeln!(
            output,
            "Executable details: {} parsed sections{}; {} import libraries / {} symbols{}; {} named exports{}",
            executable.section_details.len(),
            if executable.sections_truncated {
                " (truncated)"
            } else {
                ""
            },
            executable.imports.len(),
            import_symbols,
            if executable.imports_truncated {
                " (truncated)"
            } else {
                ""
            },
            executable.exports.len(),
            if executable.exports_truncated {
                " (truncated)"
            } else {
                ""
            }
        )?;
        crate::output::write_pe_metadata(output, executable, "")?;
        if let Some(present) = executable.signature_present {
            writeln!(
                output,
                "{}: {present} (signature not verified)",
                executable.signature_label()
            )?;
        }
        if let Some(interpreter) = &executable.interpreter {
            writeln!(
                output,
                "{}: {}",
                executable.interpreter_label(),
                safe(interpreter)
            )?;
        }
        if !executable.needed_libraries.is_empty() || executable.needed_libraries_truncated {
            writeln!(
                output,
                "{}: {}{}",
                executable.dependencies_label(),
                executable.needed_libraries.len(),
                if executable.needed_libraries_truncated {
                    " (truncated)"
                } else {
                    ""
                }
            )?;
        }
        if let Some(stripped) = executable.stripped {
            writeln!(output, "ELF stripped indicator: {stripped}")?;
        }
        if !executable.parse_warnings.is_empty() {
            writeln!(
                output,
                "Executable parser warnings: {} (not suspicious findings)",
                executable.parse_warnings.len()
            )?;
        }
    }
    if let Some(document) = &report.file.document {
        crate::output::write_document(output, document)?;
    }
    if let Some(archive) = &report.file.archive {
        writeln!(
            output,
            "Archive: {} entries; {} declared bytes{}",
            archive.total_entries,
            archive.total_size,
            if archive.truncated {
                "; entry list truncated"
            } else {
                ""
            }
        )?;
    }
    writeln!(
        output,
        "Entropy: {:.2} bits/byte; score {}/100 ({})",
        report.entropy.bits_per_byte,
        report.entropy.suspicion_score,
        report.entropy.suspicion_level
    )?;
    writeln!(
        output,
        "Content mode: {}",
        match report.content_analysis.mode {
            ContentMode::Utf8Text => "UTF-8 text",
            ContentMode::ExtractedPrintableStrings => "bounded printable-string extraction",
        }
    )?;
    writeln!(output, "IOCs: {}", report.summary.iocs)?;
    writeln!(
        output,
        "Interesting content tokens: {}",
        report.summary.content_findings
    )?;
    match &report.rule_analysis.report {
        Some(rules) => writeln!(
            output,
            "Local rules: {} loaded; {} matched",
            rules.rules_loaded, rules.matched_rules
        )?,
        None => writeln!(output, "Local rules: not requested")?,
    }
    writeln!(output, "Total findings: {}", report.summary.total_findings)?;
    for finding in &report.findings {
        writeln!(
            output,
            "[{}] {} / {}: {} ({})",
            finding.severity,
            finding.source,
            safe(&finding.kind),
            safe(&finding.value),
            safe(&finding.detail)
        )?;
    }
    Ok(())
}

fn write_markdown(output: &mut dyn Write, report: &UnifiedReport) -> Result<()> {
    writeln!(output, "# Banshee unified report\n")?;
    writeln!(output, "## File\n")?;
    writeln!(output, "- Path: `{}`", markdown(&report.file.path))?;
    writeln!(output, "- Format: {}", markdown(&report.file.format))?;
    writeln!(output, "- Size: {} bytes", report.file.size)?;
    writeln!(output, "- MD5: `{}`", report.hashes.md5)?;
    writeln!(output, "- SHA-1: `{}`", report.hashes.sha1)?;
    writeln!(output, "- SHA-256: `{}`", report.hashes.sha256)?;
    if let Some(ssdeep) = &report.hashes.ssdeep {
        writeln!(output, "- ssdeep: `{ssdeep}`")?;
    }
    writeln!(output)?;
    if let Some(compression) = &report.file.compression {
        writeln!(
            output,
            "- Compression: {} ({} to {} bytes; payload: {})",
            markdown(&compression.algorithm),
            compression.compressed_bytes,
            compression.decompressed_bytes,
            markdown(&compression.payload_format)
        )?;
    }
    if let Some(executable) = &report.file.executable {
        let import_symbols: usize = executable
            .imports
            .iter()
            .map(|library| library.symbols.len())
            .sum();
        writeln!(
            output,
            "- Executable: {} {}-bit {}; entry `{}`; {} sections",
            markdown(&executable.architecture),
            executable.bits,
            markdown(&executable.kind),
            markdown(&executable.entry_point),
            executable.sections
        )?;
        writeln!(
            output,
            "- Parsed executable details: {} sections{}; {} import libraries / {} symbols{}; {} named exports{}",
            executable.section_details.len(),
            if executable.sections_truncated {
                " (truncated)"
            } else {
                ""
            },
            executable.imports.len(),
            import_symbols,
            if executable.imports_truncated {
                " (truncated)"
            } else {
                ""
            },
            executable.exports.len(),
            if executable.exports_truncated {
                " (truncated)"
            } else {
                ""
            }
        )?;
        crate::output::write_pe_metadata(output, executable, "- ")?;
        if let Some(present) = executable.signature_present {
            writeln!(
                output,
                "- {}: {present} (signature not verified)",
                executable.signature_label()
            )?;
        }
        if let Some(interpreter) = &executable.interpreter {
            writeln!(
                output,
                "- {}: `{}`",
                executable.interpreter_label(),
                markdown(interpreter)
            )?;
        }
        if !executable.needed_libraries.is_empty() || executable.needed_libraries_truncated {
            writeln!(
                output,
                "- {}: {}{}",
                executable.dependencies_label(),
                executable.needed_libraries.len(),
                if executable.needed_libraries_truncated {
                    " (truncated)"
                } else {
                    ""
                }
            )?;
        }
        if let Some(stripped) = executable.stripped {
            writeln!(output, "- ELF stripped indicator: {stripped}")?;
        }
        if !executable.parse_warnings.is_empty() {
            writeln!(
                output,
                "- Executable parser warnings: {} (not suspicious findings)",
                executable.parse_warnings.len()
            )?;
        }
    }
    if let Some(document) = &report.file.document {
        writeln!(output, "- Document: {}", markdown(&document.kind))?;
        if let Some(macros) = document.macros_present {
            writeln!(output, "- Macros present: {macros}")?;
        }
        for property in &document.properties {
            writeln!(
                output,
                "- {}: `{}`",
                markdown(&property.name),
                markdown(&property.value)
            )?;
        }
        for target in &document.external_targets {
            writeln!(
                output,
                "- External {}: `{}`",
                markdown(&target.relationship),
                markdown(&target.target)
            )?;
        }
    }
    if let Some(archive) = &report.file.archive {
        writeln!(
            output,
            "- Archive: {} entries; {} declared bytes{}",
            archive.total_entries,
            archive.total_size,
            if archive.truncated {
                "; entry list truncated"
            } else {
                ""
            }
        )?;
    }
    writeln!(output)?;
    writeln!(output, "## Analysis\n")?;
    writeln!(
        output,
        "- Entropy: {:.2} bits per byte",
        report.entropy.bits_per_byte
    )?;
    writeln!(
        output,
        "- Entropy classification: {}",
        markdown(&report.entropy.classification.to_string())
    )?;
    writeln!(
        output,
        "- Suspicion score: {}/100 ({})",
        report.entropy.suspicion_score, report.entropy.suspicion_level
    )?;
    writeln!(output, "- IOCs: {}", report.summary.iocs)?;
    writeln!(
        output,
        "- Interesting content tokens: {}",
        report.summary.content_findings
    )?;
    writeln!(
        output,
        "- Matched local rules: {}\n",
        report.summary.matched_rules
    )?;
    writeln!(output, "## Findings\n")?;
    if report.findings.is_empty() {
        writeln!(output, "No findings were produced by the enabled analyses.")?;
    } else {
        for finding in &report.findings {
            writeln!(
                output,
                "- **{}** — {} / {}: `{}` — {}",
                finding.severity,
                finding.source,
                markdown(&finding.kind),
                markdown(&finding.value),
                markdown(&finding.detail)
            )?;
        }
    }
    writeln!(
        output,
        "\n> Findings are analyst-assistance signals, not a malware verdict."
    )?;
    Ok(())
}

fn safe(value: &str) -> String {
    crate::output::terminal_safe(value)
}

fn markdown(value: &str) -> String {
    safe(value)
        .replace('\\', "\\\\")
        .replace('`', "\\`")
        .replace('*', "\\*")
        .replace('_', "\\_")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::{SectionStatus, generate};

    #[test]
    fn builds_report_without_optional_rules() {
        let path =
            std::env::temp_dir().join(format!("banshee-report-unit-{}.txt", std::process::id()));
        std::fs::write(&path, b"source=8.8.8.8 aGVsbG8=").expect("write fixture");

        let report = generate(&path, None, 100, 8, 100).expect("generate report");
        assert_eq!(report.schema_version, 1);
        assert_eq!(report.summary.iocs, 1);
        assert!(report.summary.content_findings >= 1);
        assert_eq!(report.rule_analysis.status, SectionStatus::NotRequested);
        assert_eq!(report.hashes.sha256, report.file.sha256);
        std::fs::remove_file(path).expect("remove fixture");
    }
}

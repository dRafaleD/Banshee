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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    Text,
    Json,
    Markdown,
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
        std::fs::read(path).with_context(|| format!("failed to read '{}'", path.display()))?;

    let file = crate::file_inspect::inspect_bytes(&bytes, path.display().to_string(), max_entries)?;
    let hashes = FileHashes {
        md5: digest(&bytes, HashAlgorithm::Md5)?,
        sha1: digest(&bytes, HashAlgorithm::Sha1)?,
        sha256: file.sha256.clone(),
    };
    let content_report = crate::batch::analyze_bytes_with_source(
        &bytes,
        max_depth,
        max_tokens,
        &path.display().to_string(),
    );
    let content_analysis = ContentAnalysis {
        status: SectionStatus::Completed,
        mode: if content_report.binary.is_some() {
            ContentMode::ExtractedPrintableStrings
        } else {
            ContentMode::Utf8Text
        },
        report: content_report,
    };
    let rule_analysis = match rule_file {
        Some(rule_file) => RuleAnalysis {
            status: SectionStatus::Completed,
            rule_file: Some(rule_file.display().to_string()),
            report: Some(crate::rules::scan(rule_file, &bytes)?),
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
        detail: if rule.description.is_empty() {
            format!("{} matches", rule.total_matches)
        } else {
            rule.description.clone()
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
        if let Some(present) = executable.signature_present {
            writeln!(
                output,
                "PE certificate table present: {present} (signature not verified)"
            )?;
        }
        if let Some(interpreter) = &executable.interpreter {
            writeln!(output, "ELF interpreter: {}", safe(interpreter))?;
        }
        if !executable.needed_libraries.is_empty() || executable.needed_libraries_truncated {
            writeln!(
                output,
                "ELF dynamic dependencies: {}{}",
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
    writeln!(output, "- SHA-256: `{}`\n", report.hashes.sha256)?;
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
        if let Some(present) = executable.signature_present {
            writeln!(
                output,
                "- PE certificate table present: {present} (signature not verified)"
            )?;
        }
        if let Some(interpreter) = &executable.interpreter {
            writeln!(output, "- ELF interpreter: `{}`", markdown(interpreter))?;
        }
        if !executable.needed_libraries.is_empty() || executable.needed_libraries_truncated {
            writeln!(
                output,
                "- ELF dynamic dependencies: {}{}",
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

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use regex::{Regex, RegexBuilder};
use serde::Serialize;

use crate::report::UnifiedReport;

const SCAN_SCHEMA_VERSION: u8 = 1;
const MAX_GLOB_PATTERNS: usize = 128;
const MAX_GLOB_BYTES: usize = 1024;
const MAX_TRAVERSAL_DEPTH: usize = 128;
const MAX_DISCOVERED_ENTRIES: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScanFormat {
    Text,
    Json,
    Jsonl,
}

#[derive(Debug, Clone, Copy)]
pub struct ScanOptions<'a> {
    pub recursive: bool,
    pub rule_file: Option<&'a Path>,
    pub includes: &'a [String],
    pub excludes: &'a [String],
    pub max_files: usize,
    pub max_file_size: u64,
    pub max_total_size: u64,
    pub max_entries: usize,
    pub max_depth: u8,
    pub max_tokens: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DirectoryScanReport {
    pub schema_version: u8,
    pub root: String,
    pub recursive: bool,
    pub limits: ScanLimits,
    pub filters: ScanFilters,
    pub results: Vec<FileScanResult>,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanLimits {
    pub max_files: usize,
    pub max_file_size: u64,
    pub max_total_size: u64,
    pub max_entries_per_archive: usize,
    pub max_tokens_per_file: usize,
    pub max_decode_depth: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanFilters {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileScanStatus {
    Analyzed,
    Skipped,
    Unreadable,
    Unsupported,
    Failed,
}

impl std::fmt::Display for FileScanStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Analyzed => "analyzed",
            Self::Skipped => "skipped",
            Self::Unreadable => "unreadable",
            Self::Unsupported => "unsupported",
            Self::Failed => "failed",
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FileScanResult {
    pub path: String,
    pub status: FileScanStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<UnifiedReport>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanSummary {
    pub discovered_files: usize,
    pub analyzed: usize,
    pub skipped: usize,
    pub unreadable: usize,
    pub unsupported: usize,
    pub failed: usize,
    pub files_omitted_by_limit: usize,
    pub bytes_analyzed: u64,
    pub total_findings: usize,
    pub file_limit_reached: bool,
    pub total_size_limit_reached: bool,
    pub traversal_entry_limit_reached: bool,
}

struct CompiledFilters {
    includes: Vec<Regex>,
    excludes: Vec<Regex>,
}

#[derive(Debug)]
struct DiscoveredEntry {
    path: PathBuf,
    relative: String,
    kind: DiscoveredKind,
}

#[derive(Debug)]
enum DiscoveredKind {
    File(u64),
    Symlink,
    Unsupported(String),
    Unreadable(String),
}

pub fn scan(root: &Path, options: ScanOptions<'_>) -> Result<DirectoryScanReport> {
    let filters = CompiledFilters::new(options.includes, options.excludes)?;
    if let Some(rule_file) = options.rule_file {
        crate::rules::validate_file(rule_file)?;
    }

    let traversal_limit = options
        .max_files
        .saturating_mul(16)
        .clamp(1024, MAX_DISCOVERED_ENTRIES);
    let (mut entries, traversal_entry_limit_reached) =
        discover(root, options.recursive, traversal_limit)?;
    entries.sort_by(|left, right| left.relative.cmp(&right.relative));

    let discovered_files = entries
        .iter()
        .filter(|entry| matches!(entry.kind, DiscoveredKind::File(_)))
        .count();
    let files_omitted_by_limit = discovered_files.saturating_sub(options.max_files);
    let mut files_considered = 0_usize;
    let mut bytes_analyzed = 0_u64;
    let mut results = Vec::new();
    let mut total_size_limit_reached = false;

    for entry in entries {
        match entry.kind {
            DiscoveredKind::File(size) => {
                if files_considered >= options.max_files {
                    continue;
                }
                files_considered += 1;
                if !filters.selected(&entry.relative) {
                    results.push(result(
                        entry.relative,
                        FileScanStatus::Skipped,
                        Some("path excluded by include/exclude filters".to_owned()),
                        Some(size),
                    ));
                    continue;
                }
                if size > options.max_file_size {
                    results.push(result(
                        entry.relative,
                        FileScanStatus::Skipped,
                        Some(format!(
                            "file size {size} exceeds per-file limit {}",
                            options.max_file_size
                        )),
                        Some(size),
                    ));
                    continue;
                }
                if size > options.max_total_size.saturating_sub(bytes_analyzed) {
                    total_size_limit_reached = true;
                    results.push(result(
                        entry.relative,
                        FileScanStatus::Skipped,
                        Some("combined scan size limit reached".to_owned()),
                        Some(size),
                    ));
                    continue;
                }

                match crate::report::generate(
                    &entry.path,
                    options.rule_file,
                    options.max_entries,
                    options.max_depth,
                    options.max_tokens,
                ) {
                    Ok(report) => {
                        bytes_analyzed = bytes_analyzed.saturating_add(report.file.size as u64);
                        results.push(FileScanResult {
                            path: entry.relative,
                            status: FileScanStatus::Analyzed,
                            reason: None,
                            size: Some(report.file.size as u64),
                            report: Some(report),
                        });
                    }
                    Err(error) => {
                        let status = if error
                            .chain()
                            .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
                            .any(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
                        {
                            FileScanStatus::Unreadable
                        } else {
                            FileScanStatus::Failed
                        };
                        results.push(result(
                            entry.relative,
                            status,
                            Some(format!("{error:#}")),
                            Some(size),
                        ));
                    }
                }
            }
            DiscoveredKind::Symlink => results.push(result(
                entry.relative,
                FileScanStatus::Skipped,
                Some("symbolic link not followed".to_owned()),
                None,
            )),
            DiscoveredKind::Unsupported(reason) => results.push(result(
                entry.relative,
                FileScanStatus::Unsupported,
                Some(reason),
                None,
            )),
            DiscoveredKind::Unreadable(reason) => results.push(result(
                entry.relative,
                FileScanStatus::Unreadable,
                Some(reason),
                None,
            )),
        }
    }

    let mut summary = ScanSummary {
        discovered_files,
        files_omitted_by_limit,
        bytes_analyzed,
        file_limit_reached: files_omitted_by_limit > 0,
        total_size_limit_reached,
        traversal_entry_limit_reached,
        ..ScanSummary::default()
    };
    for item in &results {
        match item.status {
            FileScanStatus::Analyzed => {
                summary.analyzed += 1;
                summary.total_findings += item
                    .report
                    .as_ref()
                    .map_or(0, |report| report.summary.total_findings);
            }
            FileScanStatus::Skipped => summary.skipped += 1,
            FileScanStatus::Unreadable => summary.unreadable += 1,
            FileScanStatus::Unsupported => summary.unsupported += 1,
            FileScanStatus::Failed => summary.failed += 1,
        }
    }

    Ok(DirectoryScanReport {
        schema_version: SCAN_SCHEMA_VERSION,
        root: root.display().to_string(),
        recursive: options.recursive,
        limits: ScanLimits {
            max_files: options.max_files,
            max_file_size: options.max_file_size,
            max_total_size: options.max_total_size,
            max_entries_per_archive: options.max_entries,
            max_tokens_per_file: options.max_tokens,
            max_decode_depth: options.max_depth,
        },
        filters: ScanFilters {
            include: options.includes.to_vec(),
            exclude: options.excludes.to_vec(),
        },
        results,
        summary,
    })
}

fn discover(
    root: &Path,
    recursive: bool,
    traversal_limit: usize,
) -> Result<(Vec<DiscoveredEntry>, bool)> {
    let metadata = std::fs::symlink_metadata(root)
        .with_context(|| format!("failed to inspect scan root '{}'", root.display()))?;
    if metadata.file_type().is_symlink() {
        return Ok((
            vec![DiscoveredEntry {
                path: root.to_path_buf(),
                relative: display_name(root),
                kind: DiscoveredKind::Symlink,
            }],
            false,
        ));
    }
    if metadata.is_file() {
        return Ok((
            vec![DiscoveredEntry {
                path: root.to_path_buf(),
                relative: display_name(root),
                kind: DiscoveredKind::File(metadata.len()),
            }],
            false,
        ));
    }
    if !metadata.is_dir() {
        return Ok((
            vec![DiscoveredEntry {
                path: root.to_path_buf(),
                relative: display_name(root),
                kind: DiscoveredKind::Unsupported(
                    "not a regular file, directory, or symbolic link".to_owned(),
                ),
            }],
            false,
        ));
    }

    let mut output = Vec::new();
    let mut directories = vec![(root.to_path_buf(), 0_usize)];
    let mut discovered_entries = 0_usize;
    let mut entry_limit_reached = false;
    while let Some((directory, depth)) = directories.pop() {
        let read_dir = match std::fs::read_dir(&directory) {
            Ok(read_dir) => read_dir,
            Err(error) => {
                output.push(DiscoveredEntry {
                    relative: relative_path(root, &directory),
                    path: directory,
                    kind: DiscoveredKind::Unreadable(format!("failed to read directory: {error}")),
                });
                continue;
            }
        };
        let mut children = Vec::new();
        for entry in read_dir {
            match entry {
                Ok(entry) => children.push(entry.path()),
                Err(error) => output.push(DiscoveredEntry {
                    relative: relative_path(root, &directory),
                    path: directory.clone(),
                    kind: DiscoveredKind::Unreadable(format!(
                        "failed while reading directory entry: {error}"
                    )),
                }),
            }
        }
        children.sort();
        for path in children {
            if discovered_entries >= traversal_limit {
                entry_limit_reached = true;
                break;
            }
            discovered_entries += 1;
            let relative = relative_path(root, &path);
            match std::fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    output.push(DiscoveredEntry {
                        path,
                        relative,
                        kind: DiscoveredKind::Symlink,
                    });
                }
                Ok(metadata) if metadata.is_file() => output.push(DiscoveredEntry {
                    path,
                    relative,
                    kind: DiscoveredKind::File(metadata.len()),
                }),
                Ok(metadata) if metadata.is_dir() => {
                    if recursive && depth < MAX_TRAVERSAL_DEPTH {
                        directories.push((path, depth + 1));
                    } else if recursive {
                        output.push(DiscoveredEntry {
                            path,
                            relative,
                            kind: DiscoveredKind::Unsupported(format!(
                                "directory depth exceeds safety limit {MAX_TRAVERSAL_DEPTH}"
                            )),
                        });
                    }
                }
                Ok(_) => output.push(DiscoveredEntry {
                    path,
                    relative,
                    kind: DiscoveredKind::Unsupported(
                        "not a regular file, directory, or symbolic link".to_owned(),
                    ),
                }),
                Err(error) => output.push(DiscoveredEntry {
                    path,
                    relative,
                    kind: DiscoveredKind::Unreadable(format!("failed to inspect entry: {error}")),
                }),
            }
        }
        if entry_limit_reached {
            break;
        }
        directories.sort_by(|left, right| right.0.cmp(&left.0));
    }
    Ok((output, entry_limit_reached))
}

fn result(
    path: String,
    status: FileScanStatus,
    reason: Option<String>,
    size: Option<u64>,
) -> FileScanResult {
    FileScanResult {
        path,
        status,
        reason,
        size,
        report: None,
    }
}

fn display_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn relative_path(root: &Path, path: &Path) -> String {
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    if relative.is_empty() {
        ".".to_owned()
    } else {
        relative
    }
}

impl CompiledFilters {
    fn new(includes: &[String], excludes: &[String]) -> Result<Self> {
        if includes.len() + excludes.len() > MAX_GLOB_PATTERNS {
            bail!("scan accepts at most {MAX_GLOB_PATTERNS} include/exclude patterns");
        }
        Ok(Self {
            includes: compile_globs(includes)?,
            excludes: compile_globs(excludes)?,
        })
    }

    fn selected(&self, path: &str) -> bool {
        let included =
            self.includes.is_empty() || self.includes.iter().any(|pattern| pattern.is_match(path));
        included && !self.excludes.iter().any(|pattern| pattern.is_match(path))
    }
}

fn compile_globs(patterns: &[String]) -> Result<Vec<Regex>> {
    patterns
        .iter()
        .map(|pattern| {
            if pattern.is_empty() || pattern.len() > MAX_GLOB_BYTES {
                bail!("glob patterns must contain between 1 and {MAX_GLOB_BYTES} bytes");
            }
            let expression = glob_expression(pattern);
            RegexBuilder::new(&expression)
                .size_limit(1024 * 1024)
                .build()
                .with_context(|| format!("invalid glob pattern '{pattern}'"))
        })
        .collect()
}

fn glob_expression(pattern: &str) -> String {
    let normalized = pattern.replace('\\', "/");
    let match_name_only = !normalized.contains('/');
    let mut expression = if match_name_only {
        "^(?:.*/)?".to_owned()
    } else {
        "^".to_owned()
    };
    let characters = normalized.chars().collect::<Vec<_>>();
    let mut index = 0;
    while index < characters.len() {
        match characters[index] {
            '*' if characters.get(index + 1) == Some(&'*') => {
                if characters.get(index + 2) == Some(&'/') {
                    expression.push_str("(?:.*/)?");
                    index += 3;
                } else {
                    expression.push_str(".*");
                    index += 2;
                }
            }
            '*' => {
                expression.push_str("[^/]*");
                index += 1;
            }
            '?' => {
                expression.push_str("[^/]");
                index += 1;
            }
            character => {
                expression.push_str(&regex::escape(&character.to_string()));
                index += 1;
            }
        }
    }
    expression.push('$');
    expression
}

pub fn print(report: &DirectoryScanReport, format: ScanFormat) -> Result<()> {
    crate::output::with_output(|output| match format {
        ScanFormat::Text => write_text(output, report),
        ScanFormat::Json => {
            serde_json::to_writer_pretty(&mut *output, report)
                .context("failed to serialize directory scan")?;
            writeln!(output).context("failed to write directory scan")
        }
        ScanFormat::Jsonl => write_jsonl(output, report),
    })
}

fn write_text(output: &mut dyn Write, report: &DirectoryScanReport) -> Result<()> {
    writeln!(output, "Banshee bounded scan")?;
    writeln!(
        output,
        "Root: {}",
        crate::output::terminal_safe(&report.root)
    )?;
    writeln!(output, "Recursive: {}", report.recursive)?;
    for item in &report.results {
        write!(
            output,
            "[{}] {}",
            item.status,
            crate::output::terminal_safe(&item.path)
        )?;
        if let Some(file_report) = &item.report {
            write!(
                output,
                " — {}; {} bytes; {} findings",
                crate::output::terminal_safe(&file_report.file.format),
                file_report.file.size,
                file_report.summary.total_findings
            )?;
        }
        if let Some(reason) = &item.reason {
            write!(output, " — {}", crate::output::terminal_safe(reason))?;
        }
        writeln!(output)?;
    }
    writeln!(
        output,
        "Summary: {} discovered; {} analyzed; {} skipped; {} unreadable; {} unsupported; {} failed; {} bytes; {} findings",
        report.summary.discovered_files,
        report.summary.analyzed,
        report.summary.skipped,
        report.summary.unreadable,
        report.summary.unsupported,
        report.summary.failed,
        report.summary.bytes_analyzed,
        report.summary.total_findings
    )?;
    if report.summary.file_limit_reached {
        writeln!(
            output,
            "File limit reached: {} regular files omitted",
            report.summary.files_omitted_by_limit
        )?;
    }
    if report.summary.total_size_limit_reached {
        writeln!(output, "Combined scan size limit reached")?;
    }
    if report.summary.traversal_entry_limit_reached {
        writeln!(output, "Traversal entry safety limit reached")?;
    }
    Ok(())
}

#[derive(Serialize)]
struct JsonlStart<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    schema_version: u8,
    root: &'a str,
    recursive: bool,
    limits: &'a ScanLimits,
    filters: &'a ScanFilters,
}

#[derive(Serialize)]
struct JsonlFile<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    result: &'a FileScanResult,
}

#[derive(Serialize)]
struct JsonlSummary<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    summary: &'a ScanSummary,
}

fn write_jsonl(output: &mut dyn Write, report: &DirectoryScanReport) -> Result<()> {
    write_json_line(
        output,
        &JsonlStart {
            record_type: "scan_start",
            schema_version: report.schema_version,
            root: &report.root,
            recursive: report.recursive,
            limits: &report.limits,
            filters: &report.filters,
        },
    )?;
    for item in &report.results {
        write_json_line(
            output,
            &JsonlFile {
                record_type: "file",
                result: item,
            },
        )?;
    }
    write_json_line(
        output,
        &JsonlSummary {
            record_type: "summary",
            summary: &report.summary,
        },
    )
}

fn write_json_line(output: &mut dyn Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *output, value).context("failed to serialize JSONL record")?;
    writeln!(output).context("failed to write JSONL record")
}

#[cfg(test)]
mod tests {
    use super::{CompiledFilters, glob_expression};

    #[test]
    fn glob_patterns_match_names_and_paths() {
        let filters = CompiledFilters::new(&["*.txt".to_owned()], &["private/**".to_owned()])
            .expect("compile filters");
        assert!(filters.selected("notes.txt"));
        assert!(filters.selected("nested/notes.txt"));
        assert!(!filters.selected("nested/image.png"));
        assert!(!filters.selected("private/notes.txt"));
        assert_eq!(glob_expression("a?.txt"), "^(?:.*/)?a[^/]\\.txt$");
        assert_eq!(glob_expression("**/*.txt"), "^(?:.*/)?[^/]*\\.txt$");
    }
}

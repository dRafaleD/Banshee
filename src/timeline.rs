//! Case timelines: timestamped facts from local files, merged and sorted.
//! Each file is inspected (never executed) and contributes its file-system
//! modification time plus any times its format records: PE build stamps,
//! email Date headers, shortcut target times, event log and capture ranges,
//! and minidump times. Embedded times can be forged; the source of every
//! event is named so that analysts can judge it.

use std::path::PathBuf;

use anyhow::{Result, bail};
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::{Rfc2822, Rfc3339};

use crate::file_inspect::FileReport;

pub const SCHEMA_VERSION: u8 = 1;
const MAX_ARCHIVE_ENTRIES: usize = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum TimelineFormat {
    Text,
    Json,
    Csv,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelineEvent {
    /// RFC 3339 UTC time.
    pub time: String,
    pub event: String,
    pub source: String,
    pub detail: String,
    #[serde(skip)]
    sort_key: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelineError {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelineReport {
    pub schema_version: u8,
    pub files: usize,
    pub files_limit_reached: bool,
    pub events: Vec<TimelineEvent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<TimelineError>,
}

/// Whole seconds in UTC, so that every source lines up; sorting still uses
/// the full precision.
fn utc(time: OffsetDateTime) -> String {
    let time = time.to_offset(time::UtcOffset::UTC);
    time.replace_nanosecond(0)
        .unwrap_or(time)
        .format(&Rfc3339)
        .unwrap_or_else(|_| time.to_string())
}

/// Parses RFC 3339 or RFC 2822 (email) dates; a trailing `(comment)`, as
/// in `+0000 (UTC)`, is ignored.
fn parse_time(value: &str) -> Option<OffsetDateTime> {
    let value = value.split('(').next().unwrap_or(value).trim();
    OffsetDateTime::parse(value, &Rfc3339)
        .or_else(|_| OffsetDateTime::parse(value, &Rfc2822))
        .ok()
}

struct Collector<'a> {
    source: &'a str,
    events: Vec<TimelineEvent>,
}

impl Collector<'_> {
    fn push(&mut self, time: OffsetDateTime, event: &str, detail: impl Into<String>) {
        self.events.push(TimelineEvent {
            time: utc(time),
            event: event.to_owned(),
            source: self.source.to_owned(),
            detail: detail.into(),
            sort_key: time,
        });
    }
}

/// Timestamped facts recorded inside an inspected file.
fn embedded_events(report: &FileReport, collector: &mut Collector<'_>) {
    if let Some(executable) = &report.executable
        && executable.format.starts_with("PE")
        && let Some(stamp) = executable.timestamp.filter(|stamp| *stamp != 0)
        && let Ok(time) = OffsetDateTime::from_unix_timestamp(i64::from(stamp))
    {
        collector.push(
            time,
            "PE build time",
            "COFF TimeDateStamp; reproducible builds and packers may set any value",
        );
    }
    let Some(document) = &report.document else {
        return;
    };
    let (first, last) = if document.kind.contains("event log") {
        ("first event record", "last event record")
    } else {
        ("first packet", "last packet")
    };
    for property in &document.properties {
        match property.name.as_str() {
            "date" => {
                if let Some(time) = parse_time(&property.value) {
                    collector.push(time, "email Date header", property.value.clone());
                }
            }
            "Dump time (UTC)" => {
                if let Some(time) = parse_time(&property.value) {
                    collector.push(time, "minidump written", "MINIDUMP_HEADER TimeDateStamp");
                }
            }
            "Time range (UTC)" => {
                if let Some((start, end)) = property.value.split_once(" to ") {
                    for (value, event) in [(start, first), (end, last)] {
                        if let Some(time) = parse_time(value) {
                            collector.push(time, event, document.kind.clone());
                        }
                    }
                }
            }
            "Target created (UTC)" | "Target accessed (UTC)" | "Target modified (UTC)" => {
                if let Some(time) = parse_time(&property.value) {
                    let event = match property.name.as_str() {
                        "Target created (UTC)" => "shortcut target created",
                        "Target accessed (UTC)" => "shortcut target accessed",
                        _ => "shortcut target modified",
                    };
                    collector.push(time, event, "times copied into the LNK header");
                }
            }
            _ => {}
        }
    }
}

/// Regular files under the given paths, sorted, without following links.
fn discover(paths: &[PathBuf], recursive: bool, max_files: usize) -> (Vec<PathBuf>, bool) {
    let mut files = Vec::new();
    let mut pending: Vec<PathBuf> = paths.to_vec();
    let mut reached = false;
    let mut directories_left = 100_000_usize;
    while let Some(path) = pending.pop() {
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            files.push(path);
            continue;
        };
        if metadata.is_file() {
            if files.len() >= max_files {
                reached = true;
                break;
            }
            files.push(path);
        } else if metadata.is_dir() && (recursive || paths.contains(&path)) {
            if directories_left == 0 {
                reached = true;
                break;
            }
            directories_left -= 1;
            if let Ok(entries) = std::fs::read_dir(&path) {
                let mut children: Vec<PathBuf> = entries
                    .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                    .collect();
                children.sort();
                children.reverse();
                pending.extend(children);
            }
        }
    }
    files.sort();
    (files, reached)
}

pub fn build(paths: &[PathBuf], recursive: bool, max_files: usize) -> Result<TimelineReport> {
    if paths.is_empty() {
        bail!("timeline needs at least one file or directory");
    }
    let (files, files_limit_reached) = discover(paths, recursive, max_files);
    let mut events = Vec::new();
    let mut errors = Vec::new();
    for path in &files {
        let source = path.display().to_string();
        let mut collector = Collector {
            source: &source,
            events: Vec::new(),
        };
        match std::fs::metadata(path).and_then(|metadata| metadata.modified()) {
            Ok(modified) => collector.push(
                OffsetDateTime::from(modified),
                "file modified",
                "file-system modification time",
            ),
            Err(error) => {
                errors.push(TimelineError {
                    path: source.clone(),
                    reason: error.to_string(),
                });
                continue;
            }
        }
        match crate::file_inspect::inspect_file(path, MAX_ARCHIVE_ENTRIES) {
            Ok(report) => embedded_events(&report, &mut collector),
            Err(error) => errors.push(TimelineError {
                path: source.clone(),
                reason: format!("{error:#}"),
            }),
        }
        events.extend(collector.events);
    }
    events.sort_by(|left, right| {
        left.sort_key
            .cmp(&right.sort_key)
            .then_with(|| left.source.cmp(&right.source))
            .then_with(|| left.event.cmp(&right.event))
    });
    Ok(TimelineReport {
        schema_version: SCHEMA_VERSION,
        files: files.len(),
        files_limit_reached,
        events,
        errors,
    })
}

pub fn print(report: &TimelineReport, format: TimelineFormat) -> Result<()> {
    crate::output::with_output(|output| {
        match format {
            TimelineFormat::Json => {
                serde_json::to_writer_pretty(&mut *output, report)?;
                writeln!(output)?;
            }
            TimelineFormat::Csv => {
                writeln!(output, "time,event,source,detail")?;
                for event in &report.events {
                    writeln!(
                        output,
                        "{},{},{},{}",
                        crate::export::csv_field(&event.time),
                        crate::export::csv_field(&event.event),
                        crate::export::csv_field(&event.source),
                        crate::export::csv_field(&event.detail)
                    )?;
                }
            }
            TimelineFormat::Text => {
                let safe = crate::output::terminal_safe;
                for event in &report.events {
                    writeln!(
                        output,
                        "{}  {:<26} {}  ({})",
                        event.time,
                        event.event,
                        safe(&event.source),
                        safe(&event.detail)
                    )?;
                }
                writeln!(
                    output,
                    "Timeline: {} events from {} files",
                    report.events.len(),
                    report.files
                )?;
                if report.files_limit_reached {
                    writeln!(output, "File limit reached; later files were not read")?;
                }
                for error in &report.errors {
                    writeln!(
                        output,
                        "Unreadable: {} — {}",
                        safe(&error.path),
                        safe(&error.reason)
                    )?;
                }
            }
        }
        Ok(())
    })
}

impl std::fmt::Display for TimelineFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Text => "text",
            Self::Json => "json",
            Self::Csv => "csv",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{build, parse_time};

    #[test]
    fn parses_rfc3339_and_email_dates() {
        let email = parse_time("Fri, 16 Oct 2026 09:12:44 +0200 (CEST)").unwrap();
        assert_eq!(super::utc(email), "2026-10-16T07:12:44Z");
        assert!(parse_time("2026-10-16T07:12:44Z").is_some());
        assert!(parse_time("yesterday").is_none());
    }

    #[test]
    fn merges_and_sorts_events_from_several_files() {
        let root = std::env::temp_dir().join(format!("banshee-timeline-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(
            root.join("mail.eml"),
            "From: a@example.com\r\nTo: b@example.com\r\nSubject: s\r\nDate: Fri, 16 Oct 2026 09:12:44 +0000\r\n\r\nbody\r\n",
        )
        .unwrap();
        std::fs::write(root.join("nested").join("note.txt"), "plain").unwrap();

        let shallow = build(std::slice::from_ref(&root), false, 100).unwrap();
        assert_eq!(shallow.files, 1);
        let events: Vec<&str> = shallow
            .events
            .iter()
            .map(|event| event.event.as_str())
            .collect();
        // The 2026 Date header sorts before the file's own (later) mtime.
        assert_eq!(
            events,
            ["email Date header", "file modified"],
            "{:?}",
            shallow.events
        );
        assert_eq!(shallow.events[0].time, "2026-10-16T09:12:44Z");

        let deep = build(std::slice::from_ref(&root), true, 100).unwrap();
        assert_eq!(deep.files, 2);
        let limited = build(std::slice::from_ref(&root), true, 1).unwrap();
        assert!(limited.files_limit_reached);
        std::fs::remove_dir_all(root).unwrap();
    }
}

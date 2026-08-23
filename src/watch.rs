use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::batch::{self, BatchReport};

const MAX_APPENDED_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PENDING_LINE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct WatchOptions {
    pub from_start: bool,
    pub max_depth: u8,
    pub max_tokens: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct WatchEvent {
    pub path: String,
    pub input_bytes: usize,
    pub partial_line_flushed: bool,
    pub rotation_detected: bool,
    pub report: BatchReport,
}

pub struct FileWatcher {
    path: PathBuf,
    offset: u64,
    pending: Vec<u8>,
    options: WatchOptions,
    rotation_detected: bool,
}

impl FileWatcher {
    pub fn new(path: &Path, options: WatchOptions) -> Result<Self> {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("failed to inspect watched file '{}'", path.display()))?;
        if !metadata.is_file() {
            bail!("watched path '{}' is not a regular file", path.display());
        }
        Ok(Self {
            path: path.to_path_buf(),
            offset: if options.from_start {
                0
            } else {
                metadata.len()
            },
            pending: Vec::new(),
            options,
            rotation_detected: false,
        })
    }

    /// Reads at most one bounded appended chunk. Set `flush_partial` for one-shot scans.
    pub fn poll(&mut self, flush_partial: bool) -> Result<Option<WatchEvent>> {
        let size = std::fs::metadata(&self.path)
            .with_context(|| format!("failed to inspect watched file '{}'", self.path.display()))?
            .len();
        if size < self.offset {
            self.offset = 0;
            self.pending.clear();
            self.rotation_detected = true;
        }

        if size > self.offset {
            let available = (size - self.offset).min(MAX_APPENDED_BYTES);
            let mut file = File::open(&self.path).with_context(|| {
                format!("failed to open watched file '{}'", self.path.display())
            })?;
            file.seek(SeekFrom::Start(self.offset)).with_context(|| {
                format!("failed to seek watched file '{}'", self.path.display())
            })?;
            let mut appended = Vec::with_capacity(available as usize);
            file.take(available)
                .read_to_end(&mut appended)
                .with_context(|| {
                    format!("failed to read watched file '{}'", self.path.display())
                })?;
            self.offset += appended.len() as u64;
            self.pending.extend_from_slice(&appended);
        }

        let (input, partial_line_flushed) = self.take_complete_lines(flush_partial);
        if input.is_empty() {
            return Ok(None);
        }

        let event = WatchEvent {
            path: self.path.display().to_string(),
            input_bytes: input.len(),
            partial_line_flushed,
            rotation_detected: std::mem::take(&mut self.rotation_detected),
            report: batch::analyze_bytes(&input, self.options.max_depth, self.options.max_tokens),
        };
        Ok(Some(event))
    }

    fn take_complete_lines(&mut self, flush_partial: bool) -> (Vec<u8>, bool) {
        if flush_partial && !self.pending.is_empty() {
            let partial_line_flushed = !self.pending.ends_with(b"\n");
            return (std::mem::take(&mut self.pending), partial_line_flushed);
        }
        let last_newline = self.pending.iter().rposition(|byte| *byte == b'\n');
        match (last_newline, self.pending.len() > MAX_PENDING_LINE_BYTES) {
            (Some(index), _) => (self.pending.drain(..=index).collect(), false),
            (None, true) if !self.pending.is_empty() => (std::mem::take(&mut self.pending), true),
            _ => (Vec::new(), false),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::{FileWatcher, WatchOptions};

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("banshee-watch-{}-{name}", std::process::id()))
    }

    fn options() -> WatchOptions {
        WatchOptions {
            from_start: true,
            max_depth: 8,
            max_tokens: 100,
        }
    }

    #[test]
    fn analyzes_complete_lines_and_keeps_partial_lines() {
        let path = fixture_path("partial.log");
        std::fs::write(&path, b"source=8.8.8.8\npartial").expect("write fixture");
        let mut watcher = FileWatcher::new(&path, options()).expect("watcher");

        let first = watcher.poll(false).expect("poll").expect("event");
        assert_eq!(first.report.iocs.total, 1);
        assert!(watcher.poll(false).expect("poll").is_none());

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open fixture");
        writeln!(file, "-line domain=example.com").expect("append fixture");
        let second = watcher.poll(false).expect("poll").expect("event");
        assert!(
            second
                .report
                .iocs
                .iocs
                .iter()
                .any(|ioc| ioc.value == "example.com")
        );

        std::fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn detects_truncation_and_restarts_from_beginning() {
        let path = fixture_path("rotate.log");
        std::fs::write(&path, b"old-message=8.8.8.8\n").expect("write fixture");
        let mut watcher = FileWatcher::new(&path, options()).expect("watcher");
        watcher
            .poll(false)
            .expect("first poll")
            .expect("first event");

        std::fs::write(&path, b"new=1.1.1.1\n").expect("truncate fixture");
        let event = watcher.poll(false).expect("second poll").expect("event");
        assert!(event.rotation_detected);
        assert!(
            event
                .report
                .iocs
                .iocs
                .iter()
                .any(|ioc| ioc.value == "1.1.1.1")
        );

        std::fs::remove_file(path).expect("remove fixture");
    }
}

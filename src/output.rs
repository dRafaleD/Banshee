use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard};

use anyhow::{Context, Result};
use clap::ValueEnum;
use serde::Serialize;

use crate::analysis::AnalysisReport;
use crate::analysis::entropy::EntropyReport;
use crate::ioc::{IocReport, defang};
use crate::jwt::JwtReport;
use crate::watch::WatchEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Jsonl,
    Csv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy)]
enum Tone {
    Heading,
    Good,
    Warning,
    Danger,
    Info,
}

static COLOR_ENABLED: AtomicBool = AtomicBool::new(false);
static QUIET: AtomicBool = AtomicBool::new(false);
static OUTPUT_STATE: LazyLock<Mutex<OutputState>> =
    LazyLock::new(|| Mutex::new(OutputState::default()));

#[derive(Debug, Default)]
struct OutputState {
    target: Option<OutputTarget>,
    file: Option<File>,
}

#[derive(Debug)]
struct OutputTarget {
    path: PathBuf,
    force: bool,
}

enum OutputWriter {
    Stdout(io::Stdout),
    File(MutexGuard<'static, OutputState>),
    Sink(io::Sink),
}

impl Write for OutputWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Stdout(stdout) => stdout.write(buffer),
            Self::File(state) => state
                .file
                .as_mut()
                .expect("output file initialized")
                .write(buffer),
            Self::Sink(sink) => sink.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Stdout(stdout) => stdout.flush(),
            Self::File(state) => state
                .file
                .as_mut()
                .expect("output file initialized")
                .flush(),
            Self::Sink(sink) => sink.flush(),
        }
    }
}

pub fn configure_destination(path: Option<PathBuf>, force: bool) -> Result<()> {
    let mut state = OUTPUT_STATE
        .lock()
        .map_err(|_| anyhow::anyhow!("output state lock was poisoned"))?;
    *state = OutputState {
        target: path.map(|path| OutputTarget { path, force }),
        file: None,
    };
    Ok(())
}

pub fn configure_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

fn output_writer() -> Result<OutputWriter> {
    if QUIET.load(Ordering::Relaxed) {
        return Ok(OutputWriter::Sink(io::sink()));
    }
    let mut state = OUTPUT_STATE
        .lock()
        .map_err(|_| anyhow::anyhow!("output state lock was poisoned"))?;
    let Some(target) = state.target.as_ref() else {
        drop(state);
        return Ok(OutputWriter::Stdout(io::stdout()));
    };

    if state.file.is_none() {
        let path = target.path.clone();
        let force = target.force;
        let mut options = OpenOptions::new();
        options.write(true);
        if force {
            options.create(true).truncate(true);
        } else {
            options.create_new(true);
        }
        let file = options.open(&path).with_context(|| {
            format!(
                "failed to create output file '{}'{}",
                path.display(),
                if force {
                    ""
                } else {
                    "; target may already exist (use --force to overwrite)"
                }
            )
        })?;
        state.file = Some(file);
    }
    Ok(OutputWriter::File(state))
}

pub fn configure_color(mode: ColorMode, no_color: bool) {
    let redirected = OUTPUT_STATE
        .lock()
        .map(|state| state.target.is_some())
        .unwrap_or(true);
    let enabled = !no_color
        && match mode {
            ColorMode::Auto => !redirected && io::stdout().is_terminal(),
            ColorMode::Always => true,
            ColorMode::Never => false,
        };
    COLOR_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn selected_format(format: Option<OutputFormat>, json: bool) -> OutputFormat {
    format.unwrap_or(if json {
        OutputFormat::Json
    } else {
        OutputFormat::Text
    })
}

pub fn print_report(report: &AnalysisReport, json: bool) -> Result<()> {
    let mut output = output_writer()?;

    if json {
        serde_json::to_writer_pretty(&mut output, report).context("failed to serialize report")?;
        writeln!(output)?;
        return Ok(());
    }

    if report.layers.is_empty() {
        writeln!(
            output,
            "{}",
            paint("No supported encoding layer detected.", Tone::Info)
        )?;
    } else {
        writeln!(output, "{}", paint("Layers:", Tone::Heading))?;
        for layer in &report.layers {
            writeln!(
                output,
                "  [{}] {} ({:.0}% confidence)",
                layer.depth,
                paint(&layer.kind.to_string(), Tone::Info),
                layer.confidence * 100.0
            )?;
            writeln!(output, "      -> {}", preview(&layer.output, 160))?;
        }
    }

    writeln!(output, "\n{}", paint("Final result:", Tone::Heading))?;
    writeln!(output, "{}", report.final_value)?;
    writeln!(
        output,
        "\n{} {:.0}%",
        paint("Overall confidence:", Tone::Heading),
        report.confidence * 100.0
    )?;

    if !report.findings.is_empty() {
        writeln!(output, "\n{}", paint("Findings:", Tone::Danger))?;
        for finding in &report.findings {
            write!(
                output,
                "  - {}: {}",
                paint(&finding.kind.to_string(), Tone::Danger),
                finding.value
            )?;
            if let Some(detail) = &finding.detail {
                write!(output, " ({detail})")?;
            }
            writeln!(output)?;
        }
    }

    Ok(())
}

pub fn print_entropy_report(report: &EntropyReport, json: bool) -> Result<()> {
    let mut output = output_writer()?;

    if json {
        serde_json::to_writer_pretty(&mut output, report).context("failed to serialize report")?;
        writeln!(output)?;
        return Ok(());
    }

    writeln!(
        output,
        "{} {:.2} bits per byte",
        paint("Entropy:", Tone::Heading),
        report.bits_per_byte
    )?;
    writeln!(
        output,
        "Normalized entropy: {:.0}%",
        report.normalized_entropy * 100.0
    )?;
    writeln!(
        output,
        "Input: {} bytes, {} unique byte values",
        report.byte_length, report.unique_bytes
    )?;
    writeln!(
        output,
        "Classification: {}",
        paint(&report.classification.to_string(), Tone::Info)
    )?;
    writeln!(
        output,
        "{} {}/100 ({})",
        paint("Suspicion score:", Tone::Warning),
        report.suspicion_score,
        report.suspicion_level
    )?;
    writeln!(output, "{}", paint("Signals:", Tone::Heading))?;
    for signal in &report.signals {
        writeln!(output, "  - {signal}")?;
    }

    Ok(())
}

pub fn print_jwt_report(report: &JwtReport, json: bool) -> Result<()> {
    let mut output = output_writer()?;

    if json {
        serde_json::to_writer_pretty(&mut output, report).context("failed to serialize report")?;
        writeln!(output)?;
        return Ok(());
    }

    writeln!(output, "{}", paint("Header:", Tone::Heading))?;
    writeln!(output, "{}", serde_json::to_string_pretty(&report.header)?)?;
    writeln!(output, "\n{}", paint("Payload:", Tone::Heading))?;
    writeln!(output, "{}", serde_json::to_string_pretty(&report.payload)?)?;
    writeln!(
        output,
        "\n{} {} ({} encoded characters); verified: no",
        paint("Signature:", Tone::Heading),
        if report.signature.present {
            "present"
        } else {
            "empty"
        },
        report.signature.encoded_length
    )?;

    if !report.time_claims.is_empty() {
        writeln!(
            output,
            "\n{}",
            paint("Time claims (Unix seconds):", Tone::Heading)
        )?;
        for claim in &report.time_claims {
            writeln!(output, "  - {}: {}", claim.name, claim.unix_seconds)?;
        }
    }

    writeln!(output, "\n{}", paint("Security notes:", Tone::Warning))?;
    for note in &report.security_notes {
        writeln!(output, "  - [{}] {}", note.severity, note.message)?;
    }

    Ok(())
}

pub fn print_ioc_report(
    report: &IocReport,
    format: OutputFormat,
    defanged: bool,
    summary: bool,
) -> Result<()> {
    let mut output = output_writer()?;

    match format {
        OutputFormat::Text => {
            if summary {
                writeln!(
                    output,
                    "Summary: {} unique IOC(s), {} occurrence(s)",
                    report.total, report.total_occurrences
                )?;
            }
            for ioc in &report.iocs {
                let value = if defanged {
                    defang(ioc)
                } else {
                    ioc.value.clone()
                };
                writeln!(
                    output,
                    "{}\t{}\tcount={}\tlines={}-{}",
                    paint(&ioc.kind.to_string(), ioc_tone(ioc.kind)),
                    value,
                    ioc.occurrences,
                    ioc.first_line,
                    ioc.last_line
                )?;
            }
        }
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut output, report)
                .context("failed to serialize report")?;
            writeln!(output)?;
        }
        OutputFormat::Jsonl => {
            for ioc in &report.iocs {
                write_json_line(&mut output, ioc)?;
            }
        }
        OutputFormat::Csv => {
            write_csv_record(
                &mut output,
                [
                    "kind",
                    "value",
                    "detail",
                    "occurrences",
                    "first_line",
                    "last_line",
                ],
            )?;
            for ioc in &report.iocs {
                write_csv_record(
                    &mut output,
                    [
                        ioc.kind.to_string(),
                        ioc.value.clone(),
                        ioc.detail.clone().unwrap_or_default(),
                        ioc.occurrences.to_string(),
                        ioc.first_line.to_string(),
                        ioc.last_line.to_string(),
                    ],
                )?;
            }
        }
    }

    Ok(())
}

pub fn print_batch_jsonl(report: &crate::batch::BatchReport) -> Result<()> {
    let mut output = output_writer()?;
    for analysis in &report.analyses {
        write_json_line(&mut output, analysis)?;
    }
    for ioc in &report.iocs.iocs {
        write_json_line(&mut output, ioc)?;
    }
    Ok(())
}

pub fn print_batch_csv(report: &crate::batch::BatchReport) -> Result<()> {
    let mut output = output_writer()?;
    write_csv_record(
        &mut output,
        [
            "record_type",
            "line",
            "kind",
            "value",
            "detail",
            "occurrences",
            "first_line",
            "last_line",
        ],
    )?;
    for analysis in &report.analyses {
        let kind = analysis
            .report
            .layers
            .first()
            .map(|layer| layer.kind.to_string())
            .unwrap_or_else(|| "structured_indicator".to_owned());
        write_csv_record(
            &mut output,
            [
                "analysis".to_owned(),
                analysis.line.to_string(),
                kind,
                analysis.report.final_value.clone(),
                analysis.token.clone(),
                String::new(),
                String::new(),
                String::new(),
            ],
        )?;
    }
    for ioc in &report.iocs.iocs {
        write_csv_record(
            &mut output,
            [
                "ioc".to_owned(),
                String::new(),
                ioc.kind.to_string(),
                ioc.value.clone(),
                ioc.detail.clone().unwrap_or_default(),
                ioc.occurrences.to_string(),
                ioc.first_line.to_string(),
                ioc.last_line.to_string(),
            ],
        )?;
    }
    Ok(())
}

pub fn print_watch_jsonl(event: &WatchEvent) -> Result<()> {
    let mut output = output_writer()?;
    write_json_line(&mut output, event)?;
    Ok(())
}

pub fn print_watch_csv(event: &WatchEvent) -> Result<()> {
    let mut output = output_writer()?;
    write_csv_record(
        &mut output,
        [
            "path",
            "input_bytes",
            "iocs",
            "interesting_tokens",
            "partial_line_flushed",
            "rotation_detected",
        ],
    )?;
    write_csv_record(
        &mut output,
        [
            event.path.clone(),
            event.input_bytes.to_string(),
            event.report.iocs.total.to_string(),
            event.report.analyses.len().to_string(),
            event.partial_line_flushed.to_string(),
            event.rotation_detected.to_string(),
        ],
    )?;
    Ok(())
}

fn preview(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let preview: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{preview}…")
    } else {
        preview
    }
}

fn ioc_tone(kind: crate::ioc::IocKind) -> Tone {
    match kind {
        crate::ioc::IocKind::Hash => Tone::Danger,
        crate::ioc::IocKind::Url | crate::ioc::IocKind::Domain => Tone::Warning,
        crate::ioc::IocKind::Ipv4 | crate::ioc::IocKind::Ipv6 => Tone::Info,
        crate::ioc::IocKind::Email | crate::ioc::IocKind::Mac => Tone::Good,
    }
}

fn paint(value: &str, tone: Tone) -> String {
    paint_with(value, tone, COLOR_ENABLED.load(Ordering::Relaxed))
}

fn paint_with(value: &str, tone: Tone, enabled: bool) -> String {
    if !enabled {
        return value.to_owned();
    }
    let code = match tone {
        Tone::Heading => "1;36",
        Tone::Good => "32",
        Tone::Warning => "33",
        Tone::Danger => "31",
        Tone::Info => "34",
    };
    format!("\x1b[{code}m{value}\x1b[0m")
}

pub fn print_json_or<T, F>(report: &T, json: bool, human: F) -> Result<()>
where
    T: Serialize,
    F: FnOnce(&mut dyn Write) -> io::Result<()>,
{
    let mut output = output_writer()?;
    if json {
        serde_json::to_writer_pretty(&mut output, report).context("failed to serialize report")?;
        writeln!(output)?;
        Ok(())
    } else {
        human(&mut output).context("failed to write output")
    }
}

pub fn write_raw(bytes: &[u8]) -> Result<()> {
    output_writer()?
        .write_all(bytes)
        .context("failed to write raw output")
}

pub fn write_line(value: &str) -> Result<()> {
    writeln!(output_writer()?, "{value}").context("failed to write output")
}

pub fn with_output<T>(callback: impl FnOnce(&mut dyn Write) -> Result<T>) -> Result<T> {
    let mut output = output_writer()?;
    callback(&mut output)
}

fn write_json_line<T: Serialize>(output: &mut dyn Write, value: &T) -> io::Result<()> {
    serde_json::to_writer(&mut *output, value).map_err(io::Error::other)?;
    writeln!(output)
}

fn write_csv_record<I, S>(output: &mut dyn Write, fields: I) -> io::Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut first = true;
    for field in fields {
        if !first {
            write!(output, ",")?;
        }
        first = false;
        let value = field.as_ref();
        if value.contains([',', '"', '\n', '\r']) {
            write!(output, "\"{}\"", value.replace('"', "\"\""))?;
        } else {
            write!(output, "{value}")?;
        }
    }
    writeln!(output)
}

#[cfg(test)]
mod tests {
    use super::{Tone, paint_with};

    #[test]
    fn styles_only_when_enabled() {
        assert_eq!(paint_with("Banshee", Tone::Heading, false), "Banshee");
        assert_eq!(
            paint_with("Banshee", Tone::Heading, true),
            "\x1b[1;36mBanshee\x1b[0m"
        );
    }
}

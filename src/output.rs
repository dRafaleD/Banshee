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
use crate::i18n::t;
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

/// Whether human-readable output may use colors (see `configure_color`).
pub(crate) fn color_enabled() -> bool {
    COLOR_ENABLED.load(Ordering::Relaxed)
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
            paint(
                t(
                    "No supported encoding layer detected.",
                    "Desteklenen kodlama katmanı bulunamadı."
                ),
                Tone::Info
            )
        )?;
    } else {
        writeln!(
            output,
            "{}",
            paint(t("Layers:", "Katmanlar:"), Tone::Heading)
        )?;
        for layer in &report.layers {
            let detail = layer
                .detail
                .as_deref()
                .map(|detail| format!(", {}", terminal_safe(detail)))
                .unwrap_or_default();
            writeln!(
                output,
                "  [{}] {} ({:.0}% {}{detail})",
                layer.depth,
                paint(&layer.kind.to_string(), Tone::Info),
                layer.confidence * 100.0,
                t("confidence", "güven")
            )?;
            writeln!(
                output,
                "      -> {}",
                terminal_safe(&preview(&layer.output, 160))
            )?;
        }
    }

    writeln!(
        output,
        "\n{}",
        paint(t("Final result:", "Nihai sonuç:"), Tone::Heading)
    )?;
    writeln!(output, "{}", terminal_safe(&report.final_value))?;
    writeln!(
        output,
        "\n{} {:.0}%",
        paint(t("Overall confidence:", "Genel güven:"), Tone::Heading),
        report.confidence * 100.0
    )?;

    if !report.findings.is_empty() {
        writeln!(
            output,
            "\n{}",
            paint(t("Findings:", "Bulgular:"), Tone::Danger)
        )?;
        for finding in &report.findings {
            write!(
                output,
                "  - {}: {}",
                paint(&finding.kind.to_string(), Tone::Danger),
                terminal_safe(&finding.value)
            )?;
            if let Some(detail) = &finding.detail {
                write!(output, " ({})", terminal_safe(detail))?;
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
        "{} {:.2} {}",
        paint(t("Entropy:", "Entropi:"), Tone::Heading),
        report.bits_per_byte,
        t("bits per byte", "bit/bayt")
    )?;
    writeln!(
        output,
        "{} {:.0}%",
        t("Normalized entropy:", "Normalize entropi:"),
        report.normalized_entropy * 100.0
    )?;
    writeln!(
        output,
        "{}",
        if crate::i18n::is_turkish() {
            format!(
                "Girdi: {} bayt, {} benzersiz bayt değeri",
                report.byte_length, report.unique_bytes
            )
        } else {
            format!(
                "Input: {} bytes, {} unique byte values",
                report.byte_length, report.unique_bytes
            )
        }
    )?;
    writeln!(
        output,
        "{} {}",
        t("Classification:", "Sınıflandırma:"),
        paint(&classification_label(report.classification), Tone::Info)
    )?;
    writeln!(
        output,
        "{} {}/100 ({})",
        paint(t("Suspicion score:", "Şüphe skoru:"), Tone::Warning),
        report.suspicion_score,
        suspicion_label(report.suspicion_level)
    )?;
    writeln!(
        output,
        "{}",
        paint(t("Signals:", "Sinyaller:"), Tone::Heading)
    )?;
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

    writeln!(output, "{}", paint(t("Header:", "Başlık:"), Tone::Heading))?;
    writeln!(output, "{}", serde_json::to_string_pretty(&report.header)?)?;
    writeln!(output, "\n{}", paint(t("Payload:", "Yük:"), Tone::Heading))?;
    writeln!(output, "{}", serde_json::to_string_pretty(&report.payload)?)?;
    writeln!(
        output,
        "\n{} {} ({} {}); {}",
        paint(t("Signature:", "İmza:"), Tone::Heading),
        if report.signature.present {
            t("present", "var")
        } else {
            t("empty", "boş")
        },
        report.signature.encoded_length,
        t("encoded characters", "kodlanmış karakter"),
        t("verified: no", "doğrulandı: hayır")
    )?;

    if !report.time_claims.is_empty() {
        writeln!(
            output,
            "\n{}",
            paint(
                t(
                    "Time claims (Unix seconds):",
                    "Zaman iddiaları (Unix saniye):"
                ),
                Tone::Heading
            )
        )?;
        for claim in &report.time_claims {
            writeln!(output, "  - {}: {}", claim.name, claim.unix_seconds)?;
        }
    }

    writeln!(
        output,
        "\n{}",
        paint(t("Security notes:", "Güvenlik notları:"), Tone::Warning)
    )?;
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
                write!(
                    output,
                    "{}\t{}\tcount={}",
                    paint(&ioc.kind.to_string(), ioc_tone(ioc.kind)),
                    terminal_safe(&value),
                    ioc.occurrences
                )?;
                match (ioc.first_line, ioc.first_column, ioc.last_line) {
                    (Some(first), Some(column), Some(last)) => {
                        write!(
                            output,
                            "\tlines={first}-{last}\tsource={}\tlocation={first}:{column}",
                            terminal_safe(&ioc.source)
                        )?;
                    }
                    _ => write!(
                        output,
                        "\tlines=unavailable\tsource={}\tlocation=unavailable",
                        terminal_safe(&ioc.source)
                    )?,
                }
                if ioc.locations_truncated {
                    write!(output, "\tlocations=truncated")?;
                }
                writeln!(output)?;
                for location in &ioc.locations {
                    for context in &location.context {
                        writeln!(
                            output,
                            "  {} {:>6} | {}",
                            if context.matched { ">" } else { " " },
                            context.line,
                            terminal_safe(&context.text)
                        )?;
                    }
                }
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
                    "source",
                    "redacted",
                    "first_column",
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
                        option_usize(ioc.first_line),
                        option_usize(ioc.last_line),
                        ioc.source.clone(),
                        ioc.redacted.to_string(),
                        option_usize(ioc.first_column),
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
                option_usize(analysis.line),
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
                option_usize(ioc.first_line),
                option_usize(ioc.last_line),
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

/// Classification text in the current language (English comes from `Display`).
fn classification_label(classification: crate::analysis::entropy::Classification) -> String {
    use crate::analysis::entropy::Classification;
    if !crate::i18n::is_turkish() {
        return classification.to_string();
    }
    match classification {
        Classification::PlainText => "düz metin veya düşük entropili veri",
        Classification::Encoded => "kodlanmış veri",
        Classification::Jwt => "JSON Web Token",
        Classification::HashLike => "özet (hash) benzeri değer",
        Classification::HighEntropy => "yüksek entropili veri (rastgele veya şifreli olabilir)",
    }
    .to_owned()
}

fn suspicion_label(level: crate::analysis::entropy::SuspicionLevel) -> String {
    use crate::analysis::entropy::SuspicionLevel;
    if !crate::i18n::is_turkish() {
        return level.to_string();
    }
    match level {
        SuspicionLevel::Low => "düşük",
        SuspicionLevel::Medium => "orta",
        SuspicionLevel::High => "yüksek",
    }
    .to_owned()
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
        crate::ioc::IocKind::PrivateKey | crate::ioc::IocKind::Secret => Tone::Danger,
        crate::ioc::IocKind::Ipv4 | crate::ioc::IocKind::Ipv6 => Tone::Info,
        crate::ioc::IocKind::Email | crate::ioc::IocKind::Mac => Tone::Good,
    }
}

fn option_usize(value: Option<usize>) -> String {
    value.map_or_else(String::new, |value| value.to_string())
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
    writeln!(output_writer()?, "{}", terminal_safe(value)).context("failed to write output")
}

/// Escapes terminal control and bidirectional formatting characters in untrusted text.
/// JSON and raw-output modes intentionally preserve their original bytes.
/// Plain-text lines for PE import hash, Rich header and TLS metadata.
pub fn write_pe_metadata(
    output: &mut dyn Write,
    executable: &crate::file_inspect::ExecutableReport,
    prefix: &str,
) -> io::Result<()> {
    if let Some(imphash) = &executable.imphash {
        writeln!(output, "{prefix}Imphash: {imphash}")?;
    }
    if let Some(rich) = &executable.rich_header {
        writeln!(
            output,
            "{prefix}Rich header: {} entries; checksum {}",
            rich.entries.len(),
            if rich.checksum_valid {
                "valid"
            } else {
                "MISMATCH"
            }
        )?;
    }
    if let Some(callbacks) = executable.tls_callbacks {
        writeln!(output, "{prefix}TLS callbacks: {callbacks}")?;
    }
    write_managed_and_signature(output, executable, prefix)
}

/// .NET metadata and Authenticode lines, as `Label: value`.
pub fn write_managed_and_signature(
    output: &mut dyn Write,
    executable: &crate::file_inspect::ExecutableReport,
    prefix: &str,
) -> io::Result<()> {
    if let Some(dotnet) = &executable.dotnet {
        write_dotnet(output, dotnet, prefix)?;
    }
    if let Some(signature) = &executable.authenticode {
        write_authenticode(output, signature, prefix)?;
    }
    Ok(())
}

fn write_authenticode(
    output: &mut dyn Write,
    signature: &crate::file_inspect::AuthenticodeReport,
    prefix: &str,
) -> io::Result<()> {
    match &signature.signer {
        Some(signer) => writeln!(
            output,
            "{prefix}Authenticode signer: {} (issued by {}); valid {} to {}{}",
            metadata_name(&signer.subject),
            metadata_name(&signer.issuer),
            signer.not_before,
            signer.not_after,
            if signer.self_signed {
                "; self-signed"
            } else {
                ""
            }
        )?,
        None => writeln!(output, "{prefix}Authenticode signer: not identified")?,
    }
    writeln!(
        output,
        "{prefix}Authenticode: digest {}; timestamped {}; {} certificate(s){}; signature NOT verified",
        signature.digest_algorithm,
        if signature.timestamped { "yes" } else { "no" },
        signature.certificates.len(),
        if signature.nested_signatures > 0 {
            format!("; {} nested signature(s)", signature.nested_signatures)
        } else {
            String::new()
        }
    )?;
    for nested in &signature.nested_signers {
        writeln!(
            output,
            "{prefix}Authenticode nested signer: {} (issued by {}); digest {}",
            metadata_name(&nested.signer.subject),
            metadata_name(&nested.signer.issuer),
            nested.digest_algorithm
        )?;
    }
    let chain: Vec<String> = signature
        .certificates
        .iter()
        .map(|certificate| certificate.subject.clone())
        .collect();
    if !chain.is_empty() {
        writeln!(
            output,
            "{prefix}Authenticode certificates: {}",
            joined(&chain, 8)
        )?;
    }
    Ok(())
}

/// Keeps metadata names readable in both terminals and Markdown: anything
/// outside a conservative identifier set becomes `?`.
fn metadata_name(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_alphanumeric() || "._-!+ ,()[]:@$`<>".contains(character) {
                character
            } else {
                '?'
            }
        })
        .collect::<String>()
        .replace('`', "'")
}

fn joined(values: &[String], limit: usize) -> String {
    let mut text = values
        .iter()
        .take(limit)
        .map(|value| metadata_name(value))
        .collect::<Vec<_>>()
        .join(", ");
    if values.len() > limit {
        text.push_str(&format!(", … ({} more)", values.len() - limit));
    }
    text
}

fn write_dotnet(
    output: &mut dyn Write,
    dotnet: &crate::file_inspect::DotNetReport,
    prefix: &str,
) -> io::Result<()> {
    let identity = match (&dotnet.assembly_name, &dotnet.assembly_version) {
        (Some(name), Some(version)) => format!("{} {version}", metadata_name(name)),
        (Some(name), None) => metadata_name(name),
        _ => "(no assembly manifest; module only)".to_owned(),
    };
    writeln!(
        output,
        "{prefix}.NET assembly: {identity}; runtime {}; {} types, {} methods{}",
        metadata_name(&dotnet.runtime_version),
        dotnet.type_count,
        dotnet.method_count,
        if dotnet.flags.is_empty() {
            String::new()
        } else {
            format!("; {}", dotnet.flags.join(", "))
        }
    )?;
    if !dotnet.assembly_references.is_empty() {
        writeln!(
            output,
            "{prefix}.NET assembly references: {}",
            joined(&dotnet.assembly_references, 20)
        )?;
    }
    if !dotnet.pinvoke_imports.is_empty() {
        writeln!(
            output,
            "{prefix}.NET P/Invoke imports ({}): {}",
            dotnet.pinvoke_imports.len(),
            joined(&dotnet.pinvoke_imports, 30)
        )?;
    }
    if !dotnet.notable_references.is_empty() {
        writeln!(
            output,
            "{prefix}.NET notable references: {}",
            joined(&dotnet.notable_references, 20)
        )?;
    }
    if dotnet.lists_truncated {
        writeln!(output, "{prefix}.NET lists truncated at safety limit")?;
    }
    Ok(())
}

/// Plain-text lines for a document section, shared by `file inspect` and reports.
pub fn write_document(
    output: &mut dyn Write,
    document: &crate::file_inspect::DocumentReport,
) -> io::Result<()> {
    writeln!(output, "Document: {}", terminal_safe(&document.kind))?;
    if let Some(macros) = document.macros_present {
        writeln!(output, "Macros present: {macros}")?;
    }
    for property in &document.properties {
        writeln!(
            output,
            "{}: {}",
            terminal_safe(&property.name),
            terminal_safe(&property.value)
        )?;
    }
    for target in &document.external_targets {
        writeln!(
            output,
            "External {}: {}",
            terminal_safe(&target.relationship),
            terminal_safe(&target.target)
        )?;
    }
    if document.targets_truncated {
        writeln!(output, "External target list truncated")?;
    }
    for note in &document.notes {
        writeln!(output, "Note: {}", terminal_safe(note))?;
    }
    Ok(())
}

pub fn terminal_safe(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control()
            || matches!(
                character,
                '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
            )
        {
            safe.extend(character.escape_unicode());
        } else {
            safe.push(character);
        }
    }
    safe
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

    #[test]
    fn escapes_terminal_control_sequences() {
        assert_eq!(
            super::terminal_safe("safe\u{1b}[2J\ntext"),
            "safe\\u{1b}[2J\\u{a}text"
        );
    }
}

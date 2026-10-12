//! Self-contained HTML rendering for unified reports.
//!
//! Report values originate from untrusted samples, so the page carries no
//! script, loads no external resource, and escapes every interpolated value.
//! A restrictive Content-Security-Policy makes that explicit to the browser.

use std::io::Write;

use anyhow::Result;

use crate::report::UnifiedReport;
use crate::rules::Severity;

const MAX_ARCHIVE_ROWS: usize = 500;
const MAX_IOC_ROWS: usize = 2_000;
const MAX_SYMBOLS_PER_LIBRARY: usize = 512;
const MAX_DECODED_ROWS: usize = 200;
const MAX_VALUE_CHARS: usize = 240;

const STYLE: &str = r#"
:root{--bg:#f7f7f5;--panel:#fff;--text:#1c1d1f;--muted:#5f6368;--line:#e2e2df;
--code:#f0f0ec;--info:#3b6fb6;--low:#2f855a;--medium:#b7791f;--high:#c05621;--critical:#c53030}
@media (prefers-color-scheme:dark){:root{--bg:#121314;--panel:#1b1c1e;--text:#e8e8e6;
--muted:#a0a3a8;--line:#2e3033;--code:#25272a;--info:#7aa7e8;--low:#68c18f;--medium:#e0b25a;
--high:#ec8a52;--critical:#f07070}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.1rem;margin:0 0 12px}
.sub{color:var(--muted);margin:0 0 20px}
section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:0 0 16px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:0 0 16px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.stat b{display:block;font-size:1.4rem}.stat span{color:var(--muted);font-size:.85rem}
dl{display:grid;grid-template-columns:minmax(120px,max-content) 1fr;gap:6px 16px;margin:0}
dt{color:var(--muted)}dd{margin:0;min-width:0}
code,.mono{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;font-size:.88em;overflow-wrap:anywhere}
code{background:var(--code);padding:1px 5px;border-radius:4px}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;white-space:nowrap}
table{min-width:640px}td.mono{max-width:420px}
.sev{display:inline-block;padding:1px 8px;border-radius:999px;font-size:.78rem;font-weight:600;
border:1px solid currentColor;white-space:nowrap}
.sev-info{color:var(--info)}.sev-low{color:var(--low)}.sev-medium{color:var(--medium)}
.sev-high{color:var(--high)}.sev-critical{color:var(--critical)}
.muted{color:var(--muted)}details{margin:6px 0}summary{cursor:pointer}
.note{border-left:3px solid var(--medium);padding:8px 12px;color:var(--muted);margin:0}
"#;

pub(crate) fn write_html(output: &mut dyn Write, report: &UnifiedReport) -> Result<()> {
    let file = &report.file;
    writeln!(
        output,
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'\">\n\
         <meta name=\"referrer\" content=\"no-referrer\">\n\
         <meta name=\"generator\" content=\"Banshee {version}\">\n\
         <title>Banshee report — {name}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n<main>",
        version = env!("CARGO_PKG_VERSION"),
        name = escape(&display_name(&file.path)),
    )?;
    writeln!(output, "<h1>Banshee report</h1>")?;
    writeln!(output, "<p class=\"sub mono\">{}</p>", escape(&file.path))?;

    write_summary(output, report)?;
    write_file_section(output, report)?;
    write_findings(output, report)?;
    write_decoded(output, report)?;
    write_iocs(output, report)?;
    write_rules(output, report)?;
    if let Some(executable) = &file.executable {
        write_executable(output, executable)?;
    }
    if let Some(archive) = &file.archive {
        write_archive(output, archive)?;
    }

    writeln!(
        output,
        "<p class=\"note\">Findings are analyst-assistance signals, not a malware verdict. \
         Values are redacted where Banshee detects credentials; review the sample before acting.</p>"
    )?;
    writeln!(output, "</main>\n</body>\n</html>")?;
    Ok(())
}

fn write_summary(output: &mut dyn Write, report: &UnifiedReport) -> Result<()> {
    let highest = report
        .findings
        .iter()
        .map(|finding| finding.severity)
        .max_by_key(|severity| severity_rank(*severity));
    writeln!(output, "<div class=\"stats\">")?;
    stat(
        output,
        &report.summary.total_findings.to_string(),
        "findings",
    )?;
    stat(
        output,
        &highest.map_or_else(|| "none".to_owned(), |severity| severity.to_string()),
        "highest severity",
    )?;
    stat(output, &report.summary.iocs.to_string(), "IOCs")?;
    stat(
        output,
        &report.summary.matched_rules.to_string(),
        "matched rules",
    )?;
    stat(
        output,
        &format!("{:.2}", report.entropy.bits_per_byte),
        "entropy (bits/byte)",
    )?;
    writeln!(output, "</div>")?;
    let attack = attack_coverage(report);
    if !attack.is_empty() {
        writeln!(
            output,
            "<section><h2>ATT&amp;CK coverage</h2><p class=\"muted\">Identifiers declared by \
             matching local rules; they describe rule intent, not confirmed behavior.</p><p>{}</p>\
             </section>",
            attack
                .iter()
                .map(|(identifier, rules)| format!(
                    "<code>{}</code> <span class=\"muted\">×{rules}</span>",
                    escape(identifier)
                ))
                .collect::<Vec<_>>()
                .join(" &nbsp; ")
        )?;
    }
    Ok(())
}

fn attack_coverage(report: &UnifiedReport) -> std::collections::BTreeMap<&str, usize> {
    let mut coverage = std::collections::BTreeMap::new();
    for rule in report
        .rule_analysis
        .report
        .iter()
        .flat_map(|rules| &rules.matches)
    {
        for identifier in &rule.attack {
            *coverage.entry(identifier.as_str()).or_default() += 1;
        }
    }
    coverage
}

fn stat(output: &mut dyn Write, value: &str, label: &str) -> Result<()> {
    writeln!(
        output,
        "<div class=\"stat\"><b>{}</b><span>{}</span></div>",
        escape(value),
        escape(label)
    )?;
    Ok(())
}

fn write_file_section(output: &mut dyn Write, report: &UnifiedReport) -> Result<()> {
    let file = &report.file;
    writeln!(output, "<section><h2>File</h2><dl>")?;
    row(output, "Format", &escape(&file.format))?;
    row(output, "Size", &format!("{} bytes", file.size))?;
    row(output, "MD5", &code(&report.hashes.md5))?;
    row(output, "SHA-1", &code(&report.hashes.sha1))?;
    row(output, "SHA-256", &code(&report.hashes.sha256))?;
    if let Some(compression) = &file.compression {
        row(
            output,
            "Compression",
            &format!(
                "{} ({} → {} bytes; payload: {})",
                escape(&compression.algorithm),
                compression.compressed_bytes,
                compression.decompressed_bytes,
                escape(&compression.payload_format)
            ),
        )?;
    }
    row(
        output,
        "Entropy",
        &format!(
            "{:.2} bits/byte · {} · suspicion {}/100 ({})",
            report.entropy.bits_per_byte,
            escape(&report.entropy.classification.to_string()),
            report.entropy.suspicion_score,
            escape(&report.entropy.suspicion_level.to_string())
        ),
    )?;
    if !report.entropy.signals.is_empty() {
        row(
            output,
            "Entropy signals",
            &escape(&report.entropy.signals.join("; ")),
        )?;
    }
    writeln!(output, "</dl></section>")?;
    Ok(())
}

fn write_findings(output: &mut dyn Write, report: &UnifiedReport) -> Result<()> {
    writeln!(output, "<section><h2>Findings</h2>")?;
    if report.findings.is_empty() {
        writeln!(
            output,
            "<p class=\"muted\">No findings were produced by the enabled analyses.</p></section>"
        )?;
        return Ok(());
    }
    let mut findings = report.findings.iter().collect::<Vec<_>>();
    // Most severe first; the stable sort keeps the report's own order within a level.
    findings.sort_by_key(|finding| std::cmp::Reverse(severity_rank(finding.severity)));
    writeln!(
        output,
        "<div class=\"scroll\"><table><thead><tr><th>Severity</th><th>Source</th>\
         <th>Kind</th><th>Value</th><th>Detail</th></tr></thead><tbody>"
    )?;
    for finding in findings {
        writeln!(
            output,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
            severity_badge(finding.severity),
            escape(&finding.source.to_string()),
            escape(&finding.kind),
            escape(&clip(&finding.value)),
            escape(&finding.detail)
        )?;
    }
    writeln!(output, "</tbody></table></div></section>")?;
    Ok(())
}

fn write_iocs(output: &mut dyn Write, report: &UnifiedReport) -> Result<()> {
    let iocs = &report.content_analysis.report.iocs;
    if iocs.iocs.is_empty() {
        return Ok(());
    }
    writeln!(output, "<section><h2>Indicators ({})</h2>", iocs.iocs.len())?;
    writeln!(
        output,
        "<div class=\"scroll\"><table><thead><tr><th>Kind</th><th>Value</th>\
         <th>Occurrences</th><th>First line</th></tr></thead><tbody>"
    )?;
    for ioc in iocs.iocs.iter().take(MAX_IOC_ROWS) {
        writeln!(
            output,
            "<tr><td>{}</td><td class=\"mono\">{}{}</td><td>{}</td><td>{}</td></tr>",
            escape(&ioc.kind.to_string()),
            escape(&ioc.value),
            if ioc.redacted {
                " <span class=\"muted\">(redacted)</span>"
            } else {
                ""
            },
            ioc.occurrences,
            ioc.first_line
                .map_or_else(|| "—".to_owned(), |line| line.to_string())
        )?;
    }
    writeln!(output, "</tbody></table></div>")?;
    truncation_note(output, iocs.iocs.len(), MAX_IOC_ROWS, "indicators")?;
    if iocs.match_limit_reached {
        writeln!(
            output,
            "<p class=\"muted\">The IOC match limit was reached; the list is incomplete.</p>"
        )?;
    }
    writeln!(output, "</section>")?;
    Ok(())
}

fn write_rules(output: &mut dyn Write, report: &UnifiedReport) -> Result<()> {
    let Some(rules) = &report.rule_analysis.report else {
        return Ok(());
    };
    writeln!(
        output,
        "<section><h2>Local rules</h2><p class=\"muted\">{} of {} rules matched{}.</p>",
        rules.matched_rules,
        rules.rules_loaded,
        report
            .rule_analysis
            .rule_file
            .as_deref()
            .map(|path| format!(" from <code>{}</code>", escape(path)))
            .unwrap_or_default()
    )?;
    for rule in &rules.matches {
        writeln!(
            output,
            "<details><summary>{} <b>{}</b> — {} ({} matches{})</summary><dl>",
            severity_badge(rule.severity),
            escape(&rule.id),
            escape(&rule.description),
            rule.total_matches,
            if rule.truncated { ", truncated" } else { "" }
        )?;
        if let Some(category) = &rule.category {
            row(output, "Category", &escape(category))?;
        }
        if !rule.tags.is_empty() {
            row(output, "Tags", &escape(&rule.tags.join(", ")))?;
        }
        if !rule.attack.is_empty() {
            row(output, "ATT&amp;CK", &escape(&rule.attack.join(", ")))?;
        }
        // References are metadata only; they are shown as text and never linked.
        if !rule.references.is_empty() {
            row(output, "References", &escape(&rule.references.join(" · ")))?;
        }
        for sample in &rule.samples {
            row(
                output,
                &format!("Offset {}", sample.offset),
                &code(&sample.preview),
            )?;
        }
        writeln!(output, "</dl></details>")?;
    }
    writeln!(output, "</section>")?;
    Ok(())
}

fn write_executable(
    output: &mut dyn Write,
    executable: &crate::file_inspect::ExecutableReport,
) -> Result<()> {
    writeln!(output, "<section><h2>Executable</h2><dl>")?;
    row(
        output,
        "Type",
        &format!(
            "{} {} {}-bit {}",
            escape(&executable.format),
            escape(&executable.architecture),
            executable.bits,
            escape(&executable.kind)
        ),
    )?;
    row(output, "Entry point", &code(&executable.entry_point))?;
    if let Some(subsystem) = &executable.subsystem {
        row(output, "Subsystem", &escape(subsystem))?;
    }
    if let Some(present) = executable.signature_present {
        row(
            output,
            "Certificate table",
            &format!("{present} <span class=\"muted\">(signature not verified)</span>"),
        )?;
    }
    if let Some(overlay) = &executable.overlay {
        row(
            output,
            "Overlay",
            &format!("{} bytes at offset {}", overlay.size, overlay.offset),
        )?;
    }
    if let Some(interpreter) = &executable.interpreter {
        row(output, "Interpreter", &code(interpreter))?;
    }
    for (label, value) in [
        ("RPATH", &executable.rpath),
        ("RUNPATH", &executable.runpath),
    ] {
        if let Some(value) = value {
            row(output, label, &code(value))?;
        }
    }
    if !executable.suspicious_properties.is_empty() {
        row(
            output,
            "Notable properties",
            &escape(&executable.suspicious_properties.join("; ")),
        )?;
    }
    if !executable.parse_warnings.is_empty() {
        row(
            output,
            "Parser warnings",
            &format!(
                "{} <span class=\"muted\">(not suspicious findings)</span>",
                escape(&executable.parse_warnings.join("; "))
            ),
        )?;
    }
    writeln!(output, "</dl>")?;

    if !executable.section_details.is_empty() {
        writeln!(
            output,
            "<h2 style=\"margin-top:16px\">Sections{}</h2><div class=\"scroll\"><table><thead><tr>\
             <th>Name</th><th>Address</th><th>File size</th><th>Memory size</th><th>Flags</th>\
             </tr></thead><tbody>",
            if executable.sections_truncated {
                " (truncated)"
            } else {
                ""
            }
        )?;
        for section in &executable.section_details {
            let flags = [
                (section.readable.unwrap_or(false), 'R'),
                (section.writable, 'W'),
                (section.executable, 'X'),
            ]
            .iter()
            .map(|(set, flag)| if *set { *flag } else { '-' })
            .collect::<String>();
            writeln!(
                output,
                "<tr><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td><td>{}</td>\
                 <td class=\"mono\">{}</td></tr>",
                escape(&section.name),
                escape(&section.virtual_address),
                section.file_size,
                section.memory_size,
                flags
            )?;
        }
        writeln!(output, "</tbody></table></div>")?;
    }

    if !executable.imports.is_empty() {
        writeln!(
            output,
            "<h2 style=\"margin-top:16px\">Imports{}</h2>",
            if executable.imports_truncated {
                " (truncated)"
            } else {
                ""
            }
        )?;
        for library in &executable.imports {
            writeln!(
                output,
                "<details><summary><code>{}</code> <span class=\"muted\">{} symbols</span></summary>\
                 <p class=\"mono\">{}</p>",
                escape(&library.name),
                library.symbols.len(),
                escape(
                    &library
                        .symbols
                        .iter()
                        .take(MAX_SYMBOLS_PER_LIBRARY)
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            )?;
            truncation_note(
                output,
                library.symbols.len(),
                MAX_SYMBOLS_PER_LIBRARY,
                "symbols",
            )?;
            writeln!(output, "</details>")?;
        }
    }
    for (title, values, truncated) in [
        ("Exports", &executable.exports, executable.exports_truncated),
        (
            "Dynamic dependencies",
            &executable.needed_libraries,
            executable.needed_libraries_truncated,
        ),
    ] {
        if values.is_empty() {
            continue;
        }
        writeln!(
            output,
            "<details><summary>{} ({}{})</summary><p class=\"mono\">{}</p></details>",
            title,
            values.len(),
            if truncated { ", truncated" } else { "" },
            escape(&values.join(", "))
        )?;
    }
    writeln!(output, "</section>")?;
    Ok(())
}

fn write_archive(
    output: &mut dyn Write,
    archive: &crate::file_inspect::ArchiveReport,
) -> Result<()> {
    writeln!(
        output,
        "<section><h2>Archive ({} entries, {} declared bytes{})</h2>",
        archive.total_entries,
        archive.total_size,
        if archive.truncated {
            "; list truncated"
        } else {
            ""
        }
    )?;
    writeln!(
        output,
        "<div class=\"scroll\"><table><thead><tr><th>Name</th><th>Kind</th><th>Size</th>\
         <th>Compressed</th><th>Notes</th></tr></thead><tbody>"
    )?;
    for entry in archive.entries.iter().take(MAX_ARCHIVE_ROWS) {
        let mut notes = Vec::new();
        if entry.encrypted {
            notes.push("encrypted");
        }
        if !entry.path_safe {
            notes.push("unsafe path");
        }
        writeln!(
            output,
            "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape(&entry.name),
            escape(&entry.kind),
            entry.size,
            entry
                .compressed_size
                .map_or_else(|| "—".to_owned(), |size| size.to_string()),
            notes.join(", ")
        )?;
    }
    writeln!(output, "</tbody></table></div>")?;
    truncation_note(output, archive.entries.len(), MAX_ARCHIVE_ROWS, "entries")?;
    writeln!(output, "</section>")?;
    Ok(())
}

fn write_decoded(output: &mut dyn Write, report: &UnifiedReport) -> Result<()> {
    let decoded = report
        .content_analysis
        .report
        .analyses
        .iter()
        .filter(|item| !item.report.layers.is_empty())
        .collect::<Vec<_>>();
    if decoded.is_empty() {
        return Ok(());
    }
    writeln!(
        output,
        "<section><h2>Decoded content ({})</h2>",
        decoded.len()
    )?;
    writeln!(
        output,
        "<div class=\"scroll\"><table><thead><tr><th>Line</th><th>Layers</th><th>Result</th><th>Confidence</th></tr></thead><tbody>"
    )?;
    for item in decoded.iter().take(MAX_DECODED_ROWS) {
        let layers = item
            .report
            .layers
            .iter()
            .map(|layer| match &layer.detail {
                Some(detail) => format!("{} ({detail})", layer.kind),
                None => layer.kind.to_string(),
            })
            .collect::<Vec<_>>()
            .join(" → ");
        // Content analysis keeps decoded text verbatim; mask credentials here too.
        let result = crate::ioc::redact_sensitive_text(&item.report.final_value);
        writeln!(
            output,
            "<tr><td>{}</td><td>{}</td><td class=\"mono\">{}</td><td>{:.0}%</td></tr>",
            item.line
                .map_or_else(|| "—".to_owned(), |line| line.to_string()),
            escape(&layers),
            escape(&clip(&result)),
            item.report.confidence * 100.0
        )?;
    }
    writeln!(output, "</tbody></table></div>")?;
    truncation_note(output, decoded.len(), MAX_DECODED_ROWS, "decoded values")?;
    writeln!(output, "</section>")?;
    Ok(())
}

/// Shortens long values for display; the JSON report keeps the full value.
fn clip(value: &str) -> String {
    let length = value.chars().count();
    if length <= MAX_VALUE_CHARS {
        return value.to_owned();
    }
    let kept = value.chars().take(MAX_VALUE_CHARS).collect::<String>();
    format!("{kept}… ({length} characters)")
}

fn truncation_note(output: &mut dyn Write, total: usize, shown: usize, noun: &str) -> Result<()> {
    if total > shown {
        writeln!(
            output,
            "<p class=\"muted\">Showing {shown} of {total} {noun}; see the JSON report for all.</p>"
        )?;
    }
    Ok(())
}

fn row(output: &mut dyn Write, label: &str, html_value: &str) -> Result<()> {
    writeln!(output, "<dt>{}</dt><dd>{html_value}</dd>", escape(label))?;
    Ok(())
}

fn code(value: &str) -> String {
    format!("<code>{}</code>", escape(value))
}

fn severity_badge(severity: Severity) -> String {
    format!("<span class=\"sev sev-{severity}\">{severity}</span>")
}

const fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn display_name(path: &str) -> String {
    std::path::Path::new(path).file_name().map_or_else(
        || path.to_owned(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// Escapes text for element and quoted-attribute contexts after removing
/// terminal control and bidirectional-override characters.
fn escape(value: &str) -> String {
    let safe = crate::output::terminal_safe(value);
    let mut escaped = String::with_capacity(safe.len());
    for character in safe.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::escape;

    #[test]
    fn escapes_markup_quotes_and_bidirectional_overrides() {
        assert_eq!(
            escape("<script>alert('x')</script>&\""),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;&quot;"
        );
        let escaped = escape("evil\u{202e}gpj.exe");
        assert!(!escaped.contains('\u{202e}'));
        assert!(escaped.contains("\\u{202e}"));
    }
}

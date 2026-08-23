use std::collections::HashSet;

use serde::Serialize;

use crate::analysis::entropy::{
    EntropyReport, analyze as analyze_entropy, analyze_bytes as entropy_bytes,
};
use crate::analysis::{AnalysisReport, Analyzer, EncodingKind, Layer};
use crate::ioc::{ExtractOptions, IocReport, extract};

const MAX_TOKEN_BYTES: usize = 1024 * 1024;
const MAX_EXTRACTED_TEXT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct BatchReport {
    pub input_bytes: usize,
    pub tokens_scanned: usize,
    pub token_limit_reached: bool,
    pub analyses: Vec<TokenAnalysis>,
    pub iocs: IocReport,
    pub entropy: EntropyReport,
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
    pub line: usize,
    pub token: String,
    pub report: AnalysisReport,
}

pub fn analyze(input: &str, max_depth: u8, max_tokens: usize) -> BatchReport {
    let analyzer = Analyzer::new(max_depth);
    let mut seen = HashSet::new();
    let mut analyses = Vec::new();
    let mut tokens_scanned = 0;
    let mut token_limit_reached = false;

    'lines: for (line_index, line) in input.lines().enumerate() {
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
                    line: line_index + 1,
                    token: token.to_owned(),
                    report,
                });
            }
        }
    }

    BatchReport {
        input_bytes: input.len(),
        tokens_scanned,
        token_limit_reached,
        analyses,
        iocs: extract(input, ExtractOptions::default()),
        entropy: analyze_entropy(input),
        binary: None,
    }
}

pub fn analyze_bytes(input: &[u8], max_depth: u8, max_tokens: usize) -> BatchReport {
    if let Ok(text) = std::str::from_utf8(input) {
        return analyze(text, max_depth, max_tokens);
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
    let mut report = analyze(&analysis_text, max_depth, max_tokens);
    report.input_bytes = input.len();
    report.entropy = entropy_bytes(input);
    report.binary = Some(BinaryInfo {
        detected_format: compression.unwrap_or("unknown").to_owned(),
        extracted_strings,
        container_layers: container.layers,
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
        assert!(report.iocs.iocs.iter().any(|ioc| ioc.value == "8.8.8.8"));
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
    }
}

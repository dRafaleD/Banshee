mod decoder;
mod detector;
pub mod entropy;
mod findings;
mod model;

pub use model::{AnalysisReport, EncodingKind, Finding, FindingKind, Layer, StopReason};

use decoder::{decode, decode_binary};
use detector::detect_best;
use findings::extract_findings;

const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Analyzer {
    max_depth: u8,
}

impl Analyzer {
    pub fn new(max_depth: u8) -> Self {
        Self { max_depth }
    }

    pub fn analyze(&self, input: &str) -> AnalysisReport {
        let original = input.to_owned();
        let mut current = input.to_owned();
        let mut layers = Vec::new();
        let mut seen = std::collections::HashSet::new();
        seen.insert(current.clone());

        let stop_reason = loop {
            if current.len() > MAX_INPUT_BYTES {
                break StopReason::SizeLimit;
            }

            if layers.len() >= usize::from(self.max_depth) {
                break StopReason::DepthLimit;
            }

            let Some(detection) = detect_best(&current) else {
                break StopReason::NoFurtherEncoding;
            };

            let Some(decoded) = decode(detection.kind, &current) else {
                break StopReason::DecodeFailed;
            };

            if decoded.output == current || !seen.insert(decoded.output.clone()) {
                break StopReason::RepeatedValue;
            }

            let first_output = decoded
                .compression_layers
                .first()
                .map(|layer| layer.input_preview.clone())
                .unwrap_or_else(|| decoded.output.clone());
            layers.push(Layer {
                depth: layers.len() + 1,
                kind: detection.kind,
                confidence: detection.confidence,
                input: current,
                output: first_output,
            });

            let mut truncated_at = None;
            for compression in decoded.compression_layers {
                if layers.len() >= usize::from(self.max_depth) {
                    truncated_at = Some(compression.input_preview);
                    break;
                }
                layers.push(Layer {
                    depth: layers.len() + 1,
                    kind: compression.kind,
                    confidence: 0.99,
                    input: compression.input_preview,
                    output: compression.output_preview,
                });
            }
            if let Some(value) = truncated_at {
                current = value;
                break StopReason::DepthLimit;
            }
            current = decoded.output;
            if layers.len() >= usize::from(self.max_depth) {
                break StopReason::DepthLimit;
            }
        };

        let mut findings = extract_findings(&original);
        for layer in &layers {
            findings.extend(extract_findings(&layer.output));
        }
        findings.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.value.cmp(&right.value))
        });
        findings.dedup_by(|left, right| left.kind == right.kind && left.value == right.value);

        let confidence = layers
            .iter()
            .map(|layer| layer.confidence)
            .reduce(f32::min)
            .unwrap_or(if findings.is_empty() { 0.25 } else { 0.85 });

        AnalysisReport {
            original,
            layers,
            final_value: current,
            confidence,
            findings,
            stop_reason,
        }
    }

    pub fn analyze_bytes(&self, input: &[u8]) -> AnalysisReport {
        if let Ok(text) = std::str::from_utf8(input) {
            return self.analyze(text);
        }

        let descriptor = format!("<binary input: {} bytes>", input.len());
        let Some(decoded) = decode_binary(input.to_vec()) else {
            return AnalysisReport {
                original: descriptor,
                layers: Vec::new(),
                final_value: format!("<unrecognized binary data: {} bytes>", input.len()),
                confidence: 0.25,
                findings: Vec::new(),
                stop_reason: StopReason::NoFurtherEncoding,
            };
        };

        let compression_count = decoded.compression_layers.len();
        let mut layers = decoded
            .compression_layers
            .into_iter()
            .take(usize::from(self.max_depth))
            .enumerate()
            .map(|(index, compression)| Layer {
                depth: index + 1,
                kind: compression.kind,
                confidence: 0.99,
                input: compression.input_preview,
                output: compression.output_preview,
            })
            .collect::<Vec<_>>();
        if compression_count > layers.len() || layers.len() >= usize::from(self.max_depth) {
            return AnalysisReport {
                original: descriptor,
                final_value: layers
                    .last()
                    .map(|layer| layer.output.clone())
                    .unwrap_or(decoded.output),
                confidence: 0.99,
                findings: Vec::new(),
                layers,
                stop_reason: StopReason::DepthLimit,
            };
        }

        let remaining = self.max_depth - layers.len() as u8;
        let nested = Analyzer::new(remaining).analyze(&decoded.output);
        let offset = layers.len();
        layers.extend(nested.layers.into_iter().map(|mut layer| {
            layer.depth += offset;
            layer
        }));

        AnalysisReport {
            original: descriptor,
            layers,
            final_value: nested.final_value,
            confidence: nested.confidence.min(0.99),
            findings: nested.findings,
            stop_reason: nested.stop_reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use flate2::Compression;
    use flate2::write::{GzEncoder, ZlibEncoder};

    use super::{Analyzer, EncodingKind};

    #[test]
    fn recursively_decodes_base64_then_url_encoding() {
        let report = Analyzer::new(8).analyze("aGVsbG8lMjB3b3JsZA==");

        assert_eq!(report.layers.len(), 2);
        assert_eq!(report.layers[0].kind, EncodingKind::Base64);
        assert_eq!(report.layers[1].kind, EncodingKind::UrlEncoding);
        assert_eq!(report.final_value, "hello world");
    }

    #[test]
    fn respects_depth_limit() {
        let report = Analyzer::new(1).analyze("WVdKag==");

        assert_eq!(report.layers.len(), 1);
        assert_eq!(report.final_value, "YWJj");
    }

    #[test]
    fn decodes_base64_gzip_and_nested_url_encoding() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"hello%20world").expect("compress");
        let encoded = STANDARD.encode(encoder.finish().expect("finish gzip"));

        let report = Analyzer::new(8).analyze(&encoded);
        assert_eq!(report.layers.len(), 3);
        assert_eq!(report.layers[0].kind, EncodingKind::Base64);
        assert_eq!(report.layers[1].kind, EncodingKind::Gzip);
        assert_eq!(report.layers[2].kind, EncodingKind::UrlEncoding);
        assert_eq!(report.final_value, "hello world");
    }

    #[test]
    fn decodes_hex_wrapped_zlib() {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"banshee").expect("compress");
        let compressed = encoder.finish().expect("finish zlib");
        let encoded = compressed
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        let report = Analyzer::new(8).analyze(&encoded);
        assert_eq!(report.layers[0].kind, EncodingKind::Hex);
        assert_eq!(report.layers[1].kind, EncodingKind::Zlib);
        assert_eq!(report.final_value, "banshee");
    }
}

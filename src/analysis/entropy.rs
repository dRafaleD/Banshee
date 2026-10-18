use std::collections::HashSet;

use serde::Serialize;

use super::{Analyzer, FindingKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    PlainText,
    Encoded,
    Jwt,
    HashLike,
    HighEntropy,
}

impl std::fmt::Display for Classification {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::PlainText => "plain text or low-entropy data",
            Self::Encoded => "encoded data",
            Self::Jwt => "JSON Web Token",
            Self::HashLike => "hash-like value",
            Self::HighEntropy => "high-entropy data (possibly random or encrypted)",
        };
        formatter.write_str(label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspicionLevel {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for SuspicionLevel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        };
        formatter.write_str(label)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EntropyReport {
    pub byte_length: usize,
    pub unique_bytes: usize,
    pub bits_per_byte: f64,
    pub normalized_entropy: f64,
    pub classification: Classification,
    pub suspicion_score: u8,
    pub suspicion_level: SuspicionLevel,
    pub signals: Vec<String>,
}

pub fn analyze(input: &str) -> EntropyReport {
    let bytes = input.as_bytes();
    let byte_length = bytes.len();
    let unique_bytes = bytes.iter().copied().collect::<HashSet<_>>().len();
    let bits_per_byte = shannon_entropy(bytes);
    let normalized_entropy = (bits_per_byte / 8.0).clamp(0.0, 1.0);

    let analysis = Analyzer::new(1).analyze(input);
    let classification = classify(bits_per_byte, byte_length, &analysis);
    let mut signals = Vec::new();
    signals.push(format!("Shannon entropy: {bits_per_byte:.2} bits per byte"));

    if let Some(layer) = analysis.layers.first() {
        signals.push(format!(
            "Detected {} ({:.0}% confidence)",
            layer.kind,
            layer.confidence * 100.0
        ));
    }
    for finding in &analysis.findings {
        match finding.kind {
            FindingKind::Jwt => signals.push("JWT structure detected".to_owned()),
            FindingKind::Hash => signals.push("Common hash length detected".to_owned()),
            _ => {}
        }
    }
    if byte_length < 16 {
        signals.push("Short inputs produce less reliable entropy estimates".to_owned());
    }

    let suspicion_score = score(bits_per_byte, byte_length, classification);
    let suspicion_level = match suspicion_score {
        0..=34 => SuspicionLevel::Low,
        35..=64 => SuspicionLevel::Medium,
        _ => SuspicionLevel::High,
    };

    EntropyReport {
        byte_length,
        unique_bytes,
        bits_per_byte,
        normalized_entropy,
        classification,
        suspicion_score,
        suspicion_level,
        signals,
    }
}

pub fn analyze_bytes(bytes: &[u8]) -> EntropyReport {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return analyze(text);
    }

    let byte_length = bytes.len();
    let unique_bytes = bytes.iter().copied().collect::<HashSet<_>>().len();
    let bits_per_byte = shannon_entropy(bytes);
    let normalized_entropy = (bits_per_byte / 8.0).clamp(0.0, 1.0);
    let classification = if is_high_entropy(bits_per_byte, byte_length) {
        Classification::HighEntropy
    } else {
        Classification::PlainText
    };
    let suspicion_score = score(bits_per_byte, byte_length, classification);
    let suspicion_level = match suspicion_score {
        0..=34 => SuspicionLevel::Low,
        35..=64 => SuspicionLevel::Medium,
        _ => SuspicionLevel::High,
    };

    EntropyReport {
        byte_length,
        unique_bytes,
        bits_per_byte,
        normalized_entropy,
        classification,
        suspicion_score,
        suspicion_level,
        signals: vec![
            format!("Shannon entropy: {bits_per_byte:.2} bits per byte"),
            "Input contains non-UTF-8 binary data".to_owned(),
        ],
    }
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut frequencies = [0_usize; 256];
    for byte in bytes {
        frequencies[usize::from(*byte)] += 1;
    }

    let length = bytes.len() as f64;
    frequencies
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn classify(bits_per_byte: f64, length: usize, analysis: &super::AnalysisReport) -> Classification {
    if analysis
        .findings
        .iter()
        .any(|finding| finding.kind == FindingKind::Jwt)
    {
        return Classification::Jwt;
    }
    if analysis
        .findings
        .iter()
        .any(|finding| finding.kind == FindingKind::Hash)
    {
        return Classification::HashLike;
    }
    if !analysis.layers.is_empty() {
        return Classification::Encoded;
    }
    if is_high_entropy(bits_per_byte, length) {
        return Classification::HighEntropy;
    }
    Classification::PlainText
}

/// Inputs at least this long are judged as documents or files rather than
/// single tokens: ordinary text and executables reach 4.5-6.5 bits per
/// byte there, while compressed or encrypted data comes close to 8.
const DOCUMENT_BYTES: usize = 256;

fn is_high_entropy(bits_per_byte: f64, length: usize) -> bool {
    if length >= DOCUMENT_BYTES {
        bits_per_byte >= 7.2
    } else {
        length >= 32 && bits_per_byte >= 4.5
    }
}

fn score(bits_per_byte: f64, length: usize, classification: Classification) -> u8 {
    let document = length >= DOCUMENT_BYTES
        && matches!(
            classification,
            Classification::PlainText | Classification::HighEntropy
        );
    let entropy_component = if document {
        // Only entropy above typical text and code counts for whole files.
        ((bits_per_byte - 6.0).max(0.0) / 2.0 * 60.0).round() as u8
    } else {
        (bits_per_byte / 8.0 * 60.0).round() as u8
    };
    let length_component = (length.min(64) as f64 / 64.0 * 10.0).round() as u8;
    let classification_component = match classification {
        Classification::PlainText => 0,
        Classification::HashLike => 15,
        Classification::Encoded => 20,
        Classification::Jwt => 20,
        Classification::HighEntropy => 30,
    };

    entropy_component
        .saturating_add(length_component)
        .saturating_add(classification_component)
        .min(100)
}

#[cfg(test)]
mod tests {
    use super::{Classification, SuspicionLevel, analyze};

    #[test]
    fn identifies_low_entropy_text() {
        let report = analyze("aaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(report.bits_per_byte, 0.0);
        assert_eq!(report.classification, Classification::PlainText);
        assert_eq!(report.suspicion_level, SuspicionLevel::Low);
    }

    #[test]
    fn identifies_base64_as_encoded() {
        let report = analyze("aGVsbG8gd29ybGQ=");
        assert_eq!(report.classification, Classification::Encoded);
        assert!(report.suspicion_score >= 20);
    }

    #[test]
    fn ordinary_documents_are_not_high_entropy_but_random_data_is() {
        let text = "Invoice 4471 is overdue. Please review it today and reply to \
                    the accounts team if the amount or the due date looks wrong. "
            .repeat(4);
        let report = analyze(&text);
        assert!(report.bits_per_byte > 4.0, "{}", report.bits_per_byte);
        assert_eq!(report.classification, Classification::PlainText);
        assert_eq!(report.suspicion_level, SuspicionLevel::Low);

        let mut state = 0x2545_f491_u32;
        let random: Vec<u8> = (0..4096)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        let report = super::analyze_bytes(&random);
        assert_eq!(report.classification, Classification::HighEntropy);
        assert_eq!(report.suspicion_level, SuspicionLevel::High);
    }

    #[test]
    fn has_known_entropy_for_balanced_bytes() {
        let report = analyze("abab");
        assert_eq!(report.bits_per_byte, 1.0);
    }
}

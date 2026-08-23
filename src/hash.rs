use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use md4::Md4;
use md5::Md5;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Md5,
    Ntlm,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Md5 => "MD5",
            Self::Ntlm => "NTLM",
            Self::Sha1 => "SHA-1",
            Self::Sha224 => "SHA-224",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CalculateReport {
    pub algorithm: HashAlgorithm,
    pub digest: String,
    pub input_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdentifyReport {
    pub normalized: String,
    pub bit_length: usize,
    pub probable_algorithms: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrackReport {
    pub algorithm: HashAlgorithm,
    pub attempts: u64,
    pub match_value: Option<String>,
}

pub fn calculate(value: &str, algorithm: HashAlgorithm) -> CalculateReport {
    calculate_bytes(value.as_bytes(), algorithm).expect("UTF-8 is valid for every hash algorithm")
}

pub fn calculate_bytes(value: &[u8], algorithm: HashAlgorithm) -> Result<CalculateReport> {
    Ok(CalculateReport {
        algorithm,
        digest: digest_bytes(value, algorithm)?,
        input_bytes: value.len(),
    })
}

pub fn identify(value: &str) -> Result<IdentifyReport> {
    let normalized = normalize_hash(value)?;
    let probable_algorithms = algorithms_for_length(normalized.len())
        .into_iter()
        .map(|algorithm| algorithm.to_string())
        .collect::<Vec<_>>();
    if probable_algorithms.is_empty() {
        bail!(
            "unsupported hash length: {} hexadecimal characters",
            normalized.len()
        );
    }

    Ok(IdentifyReport {
        bit_length: normalized.len() * 4,
        normalized,
        probable_algorithms,
    })
}

pub fn crack(
    target: &str,
    wordlist: &Path,
    algorithm: Option<HashAlgorithm>,
) -> Result<CrackReport> {
    let target = normalize_hash(target)?;
    let algorithm = match algorithm {
        Some(algorithm) => algorithm,
        None => {
            let candidates = algorithms_for_length(target.len());
            match candidates.as_slice() {
                [algorithm] => *algorithm,
                [] => bail!("cannot infer an algorithm for this hash length"),
                _ => bail!(
                    "hash length is ambiguous; specify --algorithm (for example, MD5 and NTLM share 128 bits)"
                ),
            }
        }
    };
    if digest_length(algorithm) != target.len() {
        bail!("target length does not match {algorithm}");
    }

    let file = File::open(wordlist)
        .with_context(|| format!("failed to open wordlist '{}'", wordlist.display()))?;
    let mut attempts = 0_u64;
    for line in BufReader::new(file).lines() {
        let candidate = line.context("failed while reading wordlist")?;
        let candidate = candidate.trim_end_matches('\r');
        attempts += 1;
        if digest(candidate, algorithm).eq_ignore_ascii_case(&target) {
            return Ok(CrackReport {
                algorithm,
                attempts,
                match_value: Some(candidate.to_owned()),
            });
        }
    }

    Ok(CrackReport {
        algorithm,
        attempts,
        match_value: None,
    })
}

fn digest(value: &str, algorithm: HashAlgorithm) -> String {
    digest_bytes(value.as_bytes(), algorithm).expect("UTF-8 input supports NTLM")
}

fn digest_bytes(value: &[u8], algorithm: HashAlgorithm) -> Result<String> {
    let output = match algorithm {
        HashAlgorithm::Md5 => Md5::digest(value).to_vec(),
        HashAlgorithm::Ntlm => {
            let value = std::str::from_utf8(value)
                .context("NTLM input must be UTF-8 text because it hashes UTF-16LE")?;
            let bytes = value
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            Md4::digest(bytes).to_vec()
        }
        HashAlgorithm::Sha1 => Sha1::digest(value).to_vec(),
        HashAlgorithm::Sha224 => Sha224::digest(value).to_vec(),
        HashAlgorithm::Sha256 => Sha256::digest(value).to_vec(),
        HashAlgorithm::Sha384 => Sha384::digest(value).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(value).to_vec(),
    };
    let mut encoded = String::with_capacity(output.len() * 2);
    for byte in output {
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(encoded)
}

fn normalize_hash(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("hash must contain only hexadecimal characters");
    }
    Ok(normalized)
}

fn algorithms_for_length(length: usize) -> Vec<HashAlgorithm> {
    match length {
        32 => vec![HashAlgorithm::Md5, HashAlgorithm::Ntlm],
        40 => vec![HashAlgorithm::Sha1],
        56 => vec![HashAlgorithm::Sha224],
        64 => vec![HashAlgorithm::Sha256],
        96 => vec![HashAlgorithm::Sha384],
        128 => vec![HashAlgorithm::Sha512],
        _ => Vec::new(),
    }
}

fn digest_length(algorithm: HashAlgorithm) -> usize {
    match algorithm {
        HashAlgorithm::Md5 | HashAlgorithm::Ntlm => 32,
        HashAlgorithm::Sha1 => 40,
        HashAlgorithm::Sha224 => 56,
        HashAlgorithm::Sha256 => 64,
        HashAlgorithm::Sha384 => 96,
        HashAlgorithm::Sha512 => 128,
    }
}

#[cfg(test)]
mod tests {
    use super::{HashAlgorithm, calculate, calculate_bytes, identify};

    #[test]
    fn calculates_known_sha256() {
        let report = calculate("hello", HashAlgorithm::Sha256);
        assert_eq!(
            report.digest,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn identifies_sha1_by_length() {
        let report = identify("a9993e364706816aba3e25717850c26c9cd0d89d").expect("valid hash");
        assert_eq!(report.probable_algorithms, ["SHA-1"]);
    }

    #[test]
    fn hashes_arbitrary_binary_bytes() {
        let report = calculate_bytes(&[0, 255], HashAlgorithm::Sha256).expect("binary hash");
        assert_eq!(report.input_bytes, 2);
        assert_eq!(report.digest.len(), 64);
        assert!(calculate_bytes(&[0, 255], HashAlgorithm::Ntlm).is_err());
    }
}

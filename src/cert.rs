use std::fmt::{self, Write as _};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
#[cfg(feature = "crypto-verify")]
use x509_parser::error::X509Error;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::Pem;

const MAX_CERTIFICATE_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CHAIN_CERTIFICATES: usize = 64;

#[derive(Debug, Clone, Serialize)]
pub struct BasicConstraintsReport {
    pub critical: bool,
    pub ca: bool,
    pub path_length_constraint: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertificateReport {
    pub format: String,
    pub version: u32,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub currently_valid: bool,
    pub self_issued: bool,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub public_key_bits: Option<usize>,
    pub basic_constraints: Option<BasicConstraintsReport>,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub subject_alt_names: Vec<String>,
    pub sha256_fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    Valid,
    Invalid,
    Unsupported,
}

impl fmt::Display for SignatureStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Unsupported => "unsupported",
        };
        formatter.write_str(value)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainLinkReport {
    pub child_index: usize,
    pub issuer_index: usize,
    pub issuer_subject_match: bool,
    pub signature_status: SignatureStatus,
    pub issuer_is_ca: bool,
    pub issuer_key_cert_sign: Option<bool>,
    pub issuer_authorized_to_sign: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertificateChainReport {
    pub format: String,
    pub certificates: Vec<CertificateReport>,
    pub links: Vec<ChainLinkReport>,
    pub ordered_leaf_to_root: bool,
    pub all_certificates_currently_valid: bool,
    pub root_self_issued: bool,
    pub root_signature_status: Option<SignatureStatus>,
}

pub fn inspect_file(path: &Path) -> Result<CertificateReport> {
    inspect_bytes(&read_certificate_file(path)?)
}

/// Inspects the first certificate in PEM or DER bytes already held in memory.
pub fn inspect_bytes(input: &[u8]) -> Result<CertificateReport> {
    let certificates = decode_certificates(input)?;
    certificate_report(&certificates[0].1, &certificates[0].0)
}

pub fn inspect_chain_file(path: &Path) -> Result<CertificateChainReport> {
    inspect_chain_bytes(&read_certificate_file(path)?)
}

/// Inspects a PEM chain (or a single DER certificate) already held in memory.
pub fn inspect_chain_bytes(input: &[u8]) -> Result<CertificateChainReport> {
    let encoded = decode_certificates(input)?;
    let mut certificates = Vec::with_capacity(encoded.len());
    for (format, der) in &encoded {
        certificates.push(certificate_report(der, format)?);
    }

    let mut links = Vec::with_capacity(encoded.len().saturating_sub(1));
    for index in 0..encoded.len().saturating_sub(1) {
        let child = parse_certificate(&encoded[index].1)?;
        let issuer = parse_certificate(&encoded[index + 1].1)?;
        let issuer_is_ca = issuer
            .basic_constraints()
            .ok()
            .flatten()
            .is_some_and(|extension| extension.value.ca);
        let issuer_key_cert_sign = issuer
            .key_usage()
            .ok()
            .flatten()
            .map(|extension| extension.value.key_cert_sign());
        links.push(ChainLinkReport {
            child_index: index,
            issuer_index: index + 1,
            issuer_subject_match: child.issuer() == issuer.subject(),
            signature_status: verify_signature(&child, Some(&issuer)),
            issuer_is_ca,
            issuer_key_cert_sign,
            issuer_authorized_to_sign: issuer_is_ca && issuer_key_cert_sign.unwrap_or(true),
        });
    }

    let root = parse_certificate(&encoded.last().expect("non-empty certificate list").1)?;
    let root_self_issued = root.issuer() == root.subject();
    let root_signature_status = root_self_issued.then(|| verify_signature(&root, None));
    let ordered_leaf_to_root = links.iter().all(|link| {
        link.issuer_subject_match
            && link.signature_status == SignatureStatus::Valid
            && link.issuer_authorized_to_sign
    });
    let all_certificates_currently_valid = certificates
        .iter()
        .all(|certificate| certificate.currently_valid);

    Ok(CertificateChainReport {
        format: encoded[0].0.clone(),
        certificates,
        links,
        ordered_leaf_to_root,
        all_certificates_currently_valid,
        root_self_issued,
        root_signature_status,
    })
}

fn read_certificate_file(path: &Path) -> Result<Vec<u8>> {
    crate::input::read_regular_file_limited(path, MAX_CERTIFICATE_FILE_BYTES, "certificate")
}

fn decode_certificates(input: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    if input.len() as u64 > MAX_CERTIFICATE_FILE_BYTES {
        return Err(anyhow!("certificate input exceeds the 4 MiB safety limit"));
    }
    let without_bom = input.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(input);
    let first_content = without_bom
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(0);
    if !without_bom[first_content..].starts_with(b"-----BEGIN") {
        parse_certificate(input)?;
        return Ok(vec![("DER".to_owned(), input.to_vec())]);
    }

    let mut certificates = Vec::new();
    for (index, block) in Pem::iter_from_buffer(input).enumerate() {
        let pem = block.map_err(|error| anyhow!("invalid PEM block {}: {error}", index + 1))?;
        if pem.label == "CERTIFICATE" {
            if certificates.len() == MAX_CHAIN_CERTIFICATES {
                return Err(anyhow!(
                    "PEM input contains more than {MAX_CHAIN_CERTIFICATES} certificates"
                ));
            }
            parse_certificate(&pem.contents)
                .with_context(|| format!("invalid certificate in PEM block {}", index + 1))?;
            certificates.push(("PEM".to_owned(), pem.contents));
        }
    }
    if certificates.is_empty() {
        return Err(anyhow!("PEM input does not contain a CERTIFICATE block"));
    }
    Ok(certificates)
}

fn certificate_report(der: &[u8], format: &str) -> Result<CertificateReport> {
    let certificate = parse_certificate(der)?;
    let mut subject_alt_names = Vec::new();
    if let Some(extension) = certificate
        .subject_alternative_name()
        .map_err(|error| anyhow!("invalid Subject Alternative Name extension: {error}"))?
    {
        for name in &extension.value.general_names {
            let value = match name {
                GeneralName::DNSName(value) => format!("DNS:{value}"),
                GeneralName::IPAddress(bytes) => match *bytes {
                    [a, b, c, d] => format!("IP:{a}.{b}.{c}.{d}"),
                    bytes if bytes.len() == 16 => {
                        let mut octets = [0_u8; 16];
                        octets.copy_from_slice(bytes);
                        format!("IP:{}", std::net::Ipv6Addr::from(octets))
                    }
                    bytes => format!("IP:0x{}", encode_hex(bytes, false)),
                },
                GeneralName::URI(value) => format!("URI:{value}"),
                GeneralName::RFC822Name(value) => format!("EMAIL:{value}"),
                other => format!("{other:?}"),
            };
            subject_alt_names.push(value);
        }
    }

    let basic_constraints = certificate
        .basic_constraints()
        .map_err(|error| anyhow!("invalid Basic Constraints extension: {error}"))?
        .map(|extension| BasicConstraintsReport {
            critical: extension.critical,
            ca: extension.value.ca,
            path_length_constraint: extension.value.path_len_constraint,
        });
    let key_usage = certificate
        .key_usage()
        .map_err(|error| anyhow!("invalid Key Usage extension: {error}"))?
        .map(|extension| key_usage_values(extension.value))
        .unwrap_or_default();
    let extended_key_usage = certificate
        .extended_key_usage()
        .map_err(|error| anyhow!("invalid Extended Key Usage extension: {error}"))?
        .map(|extension| extended_key_usage_values(extension.value))
        .unwrap_or_default();

    let public_key_oid = certificate.public_key().algorithm.algorithm.to_id_string();
    let parsed_key_bits = certificate
        .public_key()
        .parsed()
        .ok()
        .map(|key| key.key_size())
        .filter(|bits| *bits > 0);

    Ok(CertificateReport {
        format: format.to_owned(),
        version: certificate.version().0 + 1,
        subject: certificate.subject().to_string(),
        issuer: certificate.issuer().to_string(),
        serial: certificate.raw_serial_as_string(),
        not_before: certificate.validity().not_before.to_string(),
        not_after: certificate.validity().not_after.to_string(),
        currently_valid: certificate.validity().is_valid(),
        self_issued: certificate.subject() == certificate.issuer(),
        signature_algorithm: describe_signature_algorithm(
            &certificate.signature_algorithm.algorithm.to_id_string(),
        ),
        public_key_algorithm: describe_public_key_algorithm(&public_key_oid),
        public_key_bits: parsed_key_bits.or_else(|| known_key_bits(&public_key_oid)),
        basic_constraints,
        key_usage,
        extended_key_usage,
        subject_alt_names,
        sha256_fingerprint: encode_hex(&Sha256::digest(der), true),
    })
}

fn parse_certificate(der: &[u8]) -> Result<X509Certificate<'_>> {
    let (remaining, certificate) = parse_x509_certificate(der)
        .map_err(|error| anyhow!("invalid X.509 certificate: {error}"))?;
    if !remaining.is_empty() {
        return Err(anyhow!(
            "certificate has {} trailing DER byte(s)",
            remaining.len()
        ));
    }
    Ok(certificate)
}

fn verify_signature(
    certificate: &X509Certificate<'_>,
    issuer: Option<&X509Certificate<'_>>,
) -> SignatureStatus {
    #[cfg(feature = "crypto-verify")]
    {
        let issuer_key = issuer.map(|certificate| certificate.public_key());
        match certificate.verify_signature(issuer_key) {
            Ok(()) => SignatureStatus::Valid,
            Err(X509Error::SignatureUnsupportedAlgorithm) => SignatureStatus::Unsupported,
            Err(_) => SignatureStatus::Invalid,
        }
    }
    // Builds without signature support never claim a valid or invalid chain.
    #[cfg(not(feature = "crypto-verify"))]
    {
        let _ = (certificate, issuer);
        SignatureStatus::Unsupported
    }
}

fn key_usage_values(usage: &x509_parser::extensions::KeyUsage) -> Vec<String> {
    [
        (usage.digital_signature(), "digital_signature"),
        (usage.non_repudiation(), "content_commitment"),
        (usage.key_encipherment(), "key_encipherment"),
        (usage.data_encipherment(), "data_encipherment"),
        (usage.key_agreement(), "key_agreement"),
        (usage.key_cert_sign(), "key_cert_sign"),
        (usage.crl_sign(), "crl_sign"),
        (usage.encipher_only(), "encipher_only"),
        (usage.decipher_only(), "decipher_only"),
    ]
    .into_iter()
    .filter(|(enabled, _)| *enabled)
    .map(|(_, name)| name.to_owned())
    .collect()
}

fn extended_key_usage_values(usage: &x509_parser::extensions::ExtendedKeyUsage<'_>) -> Vec<String> {
    let mut values: Vec<String> = [
        (usage.any, "any"),
        (usage.server_auth, "server_auth"),
        (usage.client_auth, "client_auth"),
        (usage.code_signing, "code_signing"),
        (usage.email_protection, "email_protection"),
        (usage.time_stamping, "time_stamping"),
        (usage.ocsp_signing, "ocsp_signing"),
    ]
    .into_iter()
    .filter(|(enabled, _)| *enabled)
    .map(|(_, name)| name.to_owned())
    .collect();
    values.extend(usage.other.iter().map(ToString::to_string));
    values
}

fn describe_signature_algorithm(oid: &str) -> String {
    let name = match oid {
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        _ => return oid.to_owned(),
    };
    format!("{name} ({oid})")
}

fn describe_public_key_algorithm(oid: &str) -> String {
    let name = match oid {
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.10045.2.1" => "EC",
        "1.2.840.10040.4.1" => "DSA",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        _ => return oid.to_owned(),
    };
    format!("{name} ({oid})")
}

fn known_key_bits(oid: &str) -> Option<usize> {
    match oid {
        "1.3.101.112" => Some(256),
        "1.3.101.113" => Some(448),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8], separated: bool) -> String {
    let extra = if separated {
        bytes.len().saturating_sub(1)
    } else {
        0
    };
    let mut encoded = String::with_capacity(bytes.len() * 2 + extra);
    for (index, byte) in bytes.iter().enumerate() {
        if separated && index > 0 {
            encoded.push(':');
        }
        write!(encoded, "{byte:02X}").expect("writing to String cannot fail");
    }
    encoded
}

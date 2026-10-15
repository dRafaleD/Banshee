//! Authenticode details from a PE certificate table: the PKCS#7 SignedData
//! structure is walked to list the embedded certificates, identify the signer,
//! and note the digest algorithm, timestamps and nested signatures. The
//! signature itself is NOT verified and no certificate is trusted; this is
//! metadata for triage only.

use serde::Serialize;
use x509_parser::parse_x509_certificate;

const MAX_CERTIFICATES: usize = 32;
const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
/// PKCS#9 countersignature (1.2.840.113549.1.9.6).
const OID_COUNTERSIGNATURE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x06];
/// RFC 3161 timestamp token used by Authenticode (1.3.6.1.4.1.311.3.3.1).
const OID_RFC3161_TIMESTAMP: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01];
/// Nested signature (1.3.6.1.4.1.311.2.4.1), used for dual signing.
const OID_NESTED_SIGNATURE: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01];

#[derive(Debug, Clone, Serialize)]
pub struct AuthenticodeReport {
    pub digest_algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<CertificateSummary>,
    pub certificates: Vec<CertificateSummary>,
    pub certificates_truncated: bool,
    /// A countersignature or RFC 3161 timestamp is attached.
    pub timestamped: bool,
    /// Additional (nested) signatures, as used for SHA-1 + SHA-256 dual signing.
    pub nested_signatures: usize,
    /// Signers of those nested signatures. Windows may report one of these
    /// rather than the primary signer.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nested_signers: Vec<NestedSigner>,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct NestedSigner {
    pub digest_algorithm: String,
    pub signer: CertificateSummary,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CertificateSummary {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub self_signed: bool,
}

/// One DER element: tag, content and the remaining input. Only definite
/// lengths of up to four bytes are accepted, as DER requires.
/// (tag, content, whole element, rest of the input)
type Element<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

fn element(data: &[u8]) -> Option<Element<'_>> {
    let tag = *data.first()?;
    let first = *data.get(1)?;
    let (length, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7F);
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for byte in data.get(2..2 + count)? {
            length = (length << 8) | usize::from(*byte);
        }
        (length, 2 + count)
    };
    let end = header.checked_add(length)?;
    let content = data.get(header..end)?;
    Some((tag, content, data.get(..end)?, &data[end..]))
}

/// Iterates the elements of a constructed value.
fn children(mut data: &[u8]) -> impl Iterator<Item = (u8, &[u8], &[u8])> {
    std::iter::from_fn(move || {
        let (tag, content, whole, rest) = element(data)?;
        data = rest;
        Some((tag, content, whole))
    })
}

fn digest_name(oid: &[u8]) -> String {
    match oid {
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05] => "MD5".to_owned(),
        [0x2B, 0x0E, 0x03, 0x02, 0x1A] => "SHA-1".to_owned(),
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => "SHA-256".to_owned(),
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02] => "SHA-384".to_owned(),
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03] => "SHA-512".to_owned(),
        _ => "unknown".to_owned(),
    }
}

fn common_name(name: &x509_parser::x509::X509Name<'_>) -> String {
    name.iter_common_name()
        .next()
        .and_then(|attribute| attribute.as_str().ok())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| name.to_string())
}

fn trim_zeros(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    &value[start..]
}

/// The value SETs of the attributes in `attributes` that have `oid`.
fn attribute_values<'a>(attributes: &'a [u8], oid: &'a [u8]) -> impl Iterator<Item = &'a [u8]> {
    children(attributes).filter_map(move |(_, attribute, _)| {
        let mut parts = children(attribute);
        let (tag, value, _) = parts.next()?;
        if tag != 0x06 || value != oid {
            return None;
        }
        parts.next().map(|(_, values, _)| values)
    })
}

/// Counts the attributes in `attributes` (a SET OF Attribute) with `oid`.
fn has_attribute(attributes: &[u8], oid: &[u8]) -> usize {
    children(attributes)
        .filter(|(_, attribute, _)| {
            children(attribute)
                .next()
                .is_some_and(|(tag, value, _)| tag == 0x06 && value == oid)
        })
        .count()
}

/// Parses the certificate table (one or more WIN_CERTIFICATE entries).
pub(super) fn inspect(table: &[u8], warnings: &mut Vec<String>) -> Option<AuthenticodeReport> {
    let length = u32::from_le_bytes(table.get(0..4)?.try_into().ok()?) as usize;
    let kind = u16::from_le_bytes(table.get(6..8)?.try_into().ok()?);
    if kind != 0x0002 {
        warnings.push(format!(
            "PE certificate table holds type 0x{kind:04X}, not PKCS#7 signed data"
        ));
        return None;
    }
    let Some(pkcs7) = table.get(8..length.min(table.len())) else {
        warnings.push("PE certificate entry is truncated".to_owned());
        return None;
    };
    let report = parse_signed_data(pkcs7, true);
    if report.is_none() {
        warnings.push("Authenticode PKCS#7 structure could not be parsed".to_owned());
    }
    report
}

/// `nested` allows one level of nested signatures to be read as well.
fn parse_signed_data(pkcs7: &[u8], nested: bool) -> Option<AuthenticodeReport> {
    // ContentInfo ::= SEQUENCE { contentType, [0] EXPLICIT content }
    let (_, content_info, _, _) = element(pkcs7)?;
    let mut parts = children(content_info);
    let (_, oid, _) = parts.next()?;
    if oid != OID_SIGNED_DATA {
        return None;
    }
    let (_, explicit, _) = parts.next()?;
    let (_, signed_data, _, _) = element(explicit)?;

    let mut report = AuthenticodeReport {
        digest_algorithm: "unknown".to_owned(),
        signer: None,
        certificates: Vec::new(),
        certificates_truncated: false,
        timestamped: false,
        nested_signatures: 0,
        nested_signers: Vec::new(),
        verified: false,
    };
    // Raw (issuer, serial) of each certificate, to find the signer.
    let mut identities: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut signer_identity = None;
    let mut seen_digest_set = false;
    for (tag, content, _) in children(signed_data) {
        match tag {
            // digestAlgorithms SET OF AlgorithmIdentifier
            0x31 if !seen_digest_set => {
                seen_digest_set = true;
                if let Some((_, algorithm, _)) = children(content).next()
                    && let Some((0x06, oid, _)) = children(algorithm).next()
                {
                    report.digest_algorithm = digest_name(oid);
                }
            }
            // [0] IMPLICIT certificates
            0xA0 => {
                for (_, _, whole) in children(content) {
                    if report.certificates.len() >= MAX_CERTIFICATES {
                        report.certificates_truncated = true;
                        break;
                    }
                    let Ok((_, certificate)) = parse_x509_certificate(whole) else {
                        continue;
                    };
                    let validity = certificate.validity();
                    report.certificates.push(CertificateSummary {
                        subject: common_name(certificate.subject()),
                        issuer: common_name(certificate.issuer()),
                        serial: certificate.tbs_certificate.raw_serial_as_string(),
                        not_before: validity.not_before.to_string(),
                        not_after: validity.not_after.to_string(),
                        self_signed: certificate.subject().as_raw()
                            == certificate.issuer().as_raw(),
                    });
                    identities.push((
                        certificate.issuer().as_raw().to_vec(),
                        trim_zeros(certificate.tbs_certificate.raw_serial()).to_vec(),
                    ));
                }
            }
            // signerInfos SET OF SignerInfo (the last element)
            0x31 => {
                if let Some((_, signer_info, _)) = children(content).next() {
                    let mut fields = children(signer_info).skip(1);
                    if let Some((_, issuer_and_serial, _)) = fields.next() {
                        let mut parts = children(issuer_and_serial);
                        if let (Some((_, _, issuer)), Some((_, serial, _))) =
                            (parts.next(), parts.next())
                        {
                            signer_identity = Some((issuer.to_vec(), trim_zeros(serial).to_vec()));
                        }
                    }
                    for (tag, attributes, _) in fields {
                        if tag == 0xA1 {
                            report.timestamped = has_attribute(attributes, OID_COUNTERSIGNATURE)
                                + has_attribute(attributes, OID_RFC3161_TIMESTAMP)
                                > 0;
                            report.nested_signatures =
                                has_attribute(attributes, OID_NESTED_SIGNATURE);
                            if nested {
                                for values in attribute_values(attributes, OID_NESTED_SIGNATURE) {
                                    for (_, _, whole) in children(values) {
                                        if let Some(inner) = parse_signed_data(whole, false)
                                            && let Some(signer) = inner.signer
                                        {
                                            report.nested_signers.push(NestedSigner {
                                                digest_algorithm: inner.digest_algorithm,
                                                signer,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(identity) = signer_identity
        && let Some(index) = identities.iter().position(|known| *known == identity)
    {
        report.signer = Some(report.certificates[index].clone());
    }
    Some(report)
}

/// Findings for the signer certificate.
pub(super) fn findings(report: &AuthenticodeReport) -> Vec<String> {
    let mut findings = Vec::new();
    match &report.signer {
        Some(signer) if signer.self_signed => findings.push(format!(
            "Authenticode signer certificate is self-signed ({})",
            signer.subject
        )),
        None if !report.certificates.is_empty() => findings.push(
            "Authenticode signer certificate is not among the embedded certificates".to_owned(),
        ),
        _ => {}
    }
    if matches!(report.digest_algorithm.as_str(), "MD5") {
        findings.push("Authenticode signature uses the broken MD5 digest".to_owned());
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::{children, element, has_attribute};

    #[test]
    fn der_elements_with_short_and_long_lengths() {
        let short = [0x04, 0x02, 0xAA, 0xBB, 0xFF];
        let (tag, content, whole, rest) = element(&short).unwrap();
        assert_eq!(
            (tag, content, whole.len(), rest),
            (0x04, &[0xAA, 0xBB][..], 4, &[0xFF][..])
        );
        let mut long = vec![0x04, 0x82, 0x01, 0x00];
        long.extend(vec![0x11; 256]);
        assert_eq!(element(&long).unwrap().1.len(), 256);
        // Indefinite length and lengths past the end are rejected.
        assert!(element(&[0x30, 0x80, 0x00, 0x00]).is_none());
        assert!(element(&[0x04, 0x05, 0x00]).is_none());
        assert!(element(&[0x04, 0x85, 1, 1, 1, 1, 1]).is_none());
    }

    #[test]
    fn children_walk_a_sequence() {
        let sequence = [0x02, 0x01, 0x05, 0x04, 0x01, 0x07];
        let tags: Vec<u8> = children(&sequence).map(|(tag, ..)| tag).collect();
        assert_eq!(tags, [0x02, 0x04]);
    }

    /// DER element with a definite length.
    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if content.len() < 0x80 {
            out.push(content.len() as u8);
        } else {
            let bytes = (content.len() as u32).to_be_bytes();
            let skip = bytes.iter().position(|byte| *byte != 0).unwrap_or(3);
            out.push(0x80 | (4 - skip) as u8);
            out.extend(&bytes[skip..]);
        }
        out.extend(content);
        out
    }

    /// A minimal PKCS#7 SignedData around `certificate`, signed (in structure
    /// only) by it, with an RFC 3161 timestamp attribute.
    fn signed_data(certificate: &[u8], issuer: &[u8], serial: &[u8]) -> Vec<u8> {
        let sha256 = der(
            0x06,
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
        );
        let algorithm = der(0x30, &sha256);
        let timestamp = der(
            0x30,
            &[der(0x06, super::OID_RFC3161_TIMESTAMP), der(0x31, &[])].concat(),
        );
        let signer_info = der(
            0x30,
            &[
                der(0x02, &[1]),
                der(0x30, &[issuer.to_vec(), der(0x02, serial)].concat()),
                algorithm.clone(),
                algorithm.clone(),
                der(0x04, &[0; 8]),
                der(0xA1, &timestamp),
            ]
            .concat(),
        );
        let signed = der(
            0x30,
            &[
                der(0x02, &[1]),
                der(0x31, &algorithm),
                der(
                    0x30,
                    &der(
                        0x06,
                        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01],
                    ),
                ),
                der(0xA0, certificate),
                der(0x31, &signer_info),
            ]
            .concat(),
        );
        der(
            0x30,
            &[der(0x06, super::OID_SIGNED_DATA), der(0xA0, &signed)].concat(),
        )
    }

    #[test]
    fn reads_signer_digest_and_timestamp_from_pkcs7() {
        let key = rcgen::generate_simple_self_signed(vec!["signer.example.test".to_owned()])
            .expect("certificate");
        let certificate = key.cert.der().to_vec();
        let (_, parsed) = x509_parser::parse_x509_certificate(&certificate).expect("parse");
        let pkcs7 = signed_data(
            &certificate,
            parsed.issuer().as_raw(),
            parsed.tbs_certificate.raw_serial(),
        );
        // WIN_CERTIFICATE: length, revision 0x0200, type PKCS_SIGNED_DATA.
        let mut table = Vec::new();
        table.extend(((pkcs7.len() + 8) as u32).to_le_bytes());
        table.extend(0x0200u16.to_le_bytes());
        table.extend(0x0002u16.to_le_bytes());
        table.extend(&pkcs7);
        let mut warnings = Vec::new();
        let report = super::inspect(&table, &mut warnings).expect("Authenticode");
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(report.digest_algorithm, "SHA-256");
        assert!(report.timestamped);
        assert!(!report.verified);
        let signer = report.signer.as_ref().expect("signer");
        assert!(signer.self_signed);
        assert_eq!(report.certificates.len(), 1);
        let findings = super::findings(&report).join(
            "
",
        );
        assert!(findings.contains("self-signed"), "{findings}");
    }

    #[test]
    fn non_pkcs7_tables_and_garbage_are_reported_not_parsed() {
        let mut warnings = Vec::new();
        let mut table = vec![16, 0, 0, 0, 0, 2, 1, 0];
        table.extend([0; 8]);
        assert!(super::inspect(&table, &mut warnings).is_none());
        assert!(warnings[0].contains("not PKCS#7"), "{warnings:?}");
        let mut garbage = vec![40, 0, 0, 0, 0, 2, 2, 0];
        garbage.extend([0x30; 32]);
        warnings.clear();
        assert!(super::inspect(&garbage, &mut warnings).is_none());
        assert!(!warnings.is_empty());
    }

    #[test]
    fn attributes_are_found_by_oid() {
        let oid = [0x2A, 0x03];
        // SET content: Attribute ::= SEQUENCE { OID, SET {...} }
        let attributes = [0x30, 0x06, 0x06, 0x02, 0x2A, 0x03, 0x31, 0x00];
        assert_eq!(has_attribute(&attributes, &oid), 1);
        assert_eq!(has_attribute(&attributes, &[0x2A, 0x04]), 0);
    }
}

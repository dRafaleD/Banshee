//! Export saved report observables to STIX 2.1, MISP or CSV.
//!
//! Exports describe what was observed, never a verdict: STIX output contains
//! cyber-observable objects inside a `grouping` (no `indicator` objects), MISP
//! attributes are not marked for IDS use, and redacted credentials are never
//! exported in any format.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use serde::Serialize;
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Namespace defined by STIX 2.1 for deterministic cyber-observable identifiers.
const STIX_NAMESPACE: [u8; 16] = [
    0x00, 0xab, 0xed, 0xb4, 0xaa, 0x42, 0x46, 0x6c, 0x9c, 0x01, 0xfe, 0xd2, 0x33, 0x15, 0xa9, 0xb7,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    /// STIX 2.1 bundle of observables in a grouping
    Stix,
    /// MISP event JSON with non-IDS attributes
    Misp,
    /// Comma-separated type,value,occurrences rows
    Csv,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportSummary {
    pub exported: usize,
    pub skipped_redacted: usize,
    pub skipped_unsupported: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ObservableKind {
    Domain,
    Email,
    Ipv4,
    Ipv6,
    Mac,
    Url,
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl ObservableKind {
    fn from_ioc(kind: &str, value: &str) -> Option<Self> {
        Some(match kind {
            "domain" => Self::Domain,
            "email" => Self::Email,
            "ipv4" => Self::Ipv4,
            "ipv6" => Self::Ipv6,
            "mac" => Self::Mac,
            "url" => Self::Url,
            "hash" => match value.len() {
                32 => Self::Md5,
                40 => Self::Sha1,
                64 => Self::Sha256,
                128 => Self::Sha512,
                // NTLM shares MD5's length; other lengths have no portable type.
                _ => return None,
            },
            _ => return None,
        })
    }

    const fn csv_type(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Email => "email",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Mac => "mac",
            Self::Url => "url",
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    const fn hash_algorithm(self) -> Option<&'static str> {
        match self {
            Self::Md5 => Some("MD5"),
            Self::Sha1 => Some("SHA-1"),
            Self::Sha256 => Some("SHA-256"),
            Self::Sha512 => Some("SHA-512"),
            _ => None,
        }
    }
}

struct Observable {
    kind: ObservableKind,
    value: String,
    occurrences: u64,
}

struct Sample {
    name: String,
    md5: String,
    sha1: String,
    sha256: String,
}

struct ExportData {
    sample: Sample,
    observables: Vec<Observable>,
    summary: ExportSummary,
}

pub fn export(path: &Path, format: ExportFormat, output: &mut dyn Write) -> Result<ExportSummary> {
    let loaded = crate::diff::load_saved_report(path, "export")?;
    crate::report::validate_compatibility(&loaded.value)
        .context("export input is not a valid Banshee report")?;
    let data = collect(&loaded.value)?;
    match format {
        ExportFormat::Stix => {
            let bundle = stix_bundle(&data, &now_timestamp()?);
            serde_json::to_writer_pretty(&mut *output, &bundle)
                .context("failed to write STIX bundle")?;
            writeln!(output)?;
        }
        ExportFormat::Misp => {
            let event = misp_event(&data, OffsetDateTime::now_utc());
            serde_json::to_writer_pretty(&mut *output, &event)
                .context("failed to write MISP event")?;
            writeln!(output)?;
        }
        ExportFormat::Csv => write_csv(output, &data)?,
    }
    Ok(data.summary)
}

fn collect(report: &Value) -> Result<ExportData> {
    let text = |pointer: &str| {
        report
            .pointer(pointer)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .with_context(|| format!("report is missing '{pointer}'"))
    };
    let path = text("/file/path")?;
    let sample = Sample {
        name: Path::new(&path)
            .file_name()
            .map_or_else(|| path.clone(), |name| name.to_string_lossy().into_owned()),
        md5: text("/hashes/md5")?,
        sha1: text("/hashes/sha1")?,
        sha256: text("/hashes/sha256")?,
    };

    let mut summary = ExportSummary {
        exported: 0,
        skipped_redacted: 0,
        skipped_unsupported: 0,
    };
    let mut seen = BTreeSet::new();
    let mut observables = Vec::new();
    let iocs = report
        .pointer("/content_analysis/report/iocs/iocs")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for ioc in iocs {
        let kind = ioc.get("kind").and_then(Value::as_str).unwrap_or_default();
        let value = ioc.get("value").and_then(Value::as_str).unwrap_or_default();
        let redacted = ioc
            .get("redacted")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if redacted || matches!(kind, "secret" | "private_key") {
            summary.skipped_redacted += 1;
            continue;
        }
        let Some(kind) = ObservableKind::from_ioc(kind, value) else {
            summary.skipped_unsupported += 1;
            continue;
        };
        if value.is_empty() || !seen.insert((kind, value.to_owned())) {
            continue;
        }
        observables.push(Observable {
            kind,
            value: value.to_owned(),
            occurrences: ioc.get("occurrences").and_then(Value::as_u64).unwrap_or(1),
        });
    }
    observables.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.value.cmp(&right.value))
    });
    summary.exported = observables.len();
    Ok(ExportData {
        sample,
        observables,
        summary,
    })
}

fn stix_bundle(data: &ExportData, timestamp: &str) -> Value {
    let mut objects = Vec::new();
    let mut references = Vec::new();

    let sample_hashes = BTreeMap::from([
        ("MD5", data.sample.md5.as_str()),
        ("SHA-1", data.sample.sha1.as_str()),
        ("SHA-256", data.sample.sha256.as_str()),
    ]);
    let sample = json!({
        "type": "file",
        "spec_version": "2.1",
        "id": stix_file_id(&sample_hashes, Some(&data.sample.name)),
        "name": data.sample.name,
        "hashes": sample_hashes,
    });
    references.push(sample["id"].clone());
    objects.push(sample);

    for observable in &data.observables {
        let object = match observable.kind.hash_algorithm() {
            Some(algorithm) => {
                let hashes = BTreeMap::from([(algorithm, observable.value.as_str())]);
                json!({
                    "type": "file",
                    "spec_version": "2.1",
                    "id": stix_file_id(&hashes, None),
                    "hashes": hashes,
                })
            }
            None => {
                let kind = match observable.kind {
                    ObservableKind::Domain => "domain-name",
                    ObservableKind::Email => "email-addr",
                    ObservableKind::Ipv4 => "ipv4-addr",
                    ObservableKind::Ipv6 => "ipv6-addr",
                    ObservableKind::Mac => "mac-addr",
                    _ => "url",
                };
                json!({
                    "type": kind,
                    "spec_version": "2.1",
                    "id": stix_id(kind, &json!({ "value": observable.value })),
                    "value": observable.value,
                })
            }
        };
        references.push(object["id"].clone());
        objects.push(object);
    }

    let grouping_id = format!(
        "grouping--{}",
        uuid_v5(
            &STIX_NAMESPACE,
            format!("banshee-grouping:{}", data.sample.sha256).as_bytes()
        )
    );
    objects.push(json!({
        "type": "grouping",
        "spec_version": "2.1",
        "id": grouping_id,
        "created": timestamp,
        "modified": timestamp,
        "name": format!("Banshee observables for {}", data.sample.name),
        "description": "Values observed by offline Banshee triage. They are analyst-assistance signals, not a maliciousness verdict.",
        "context": "unspecified",
        "object_refs": references,
    }));

    json!({
        "type": "bundle",
        "id": format!(
            "bundle--{}",
            uuid_v5(&STIX_NAMESPACE, format!("banshee-bundle:{}", data.sample.sha256).as_bytes())
        ),
        "objects": objects,
    })
}

/// STIX 2.1 deterministic file identifier: one hash, chosen in the
/// specification's preference order, plus the name when present.
fn stix_file_id(hashes: &BTreeMap<&str, &str>, name: Option<&str>) -> String {
    let mut contributing = serde_json::Map::new();
    if let Some((algorithm, value)) = ["MD5", "SHA-1", "SHA-256", "SHA-512"]
        .iter()
        .find_map(|algorithm| hashes.get(algorithm).map(|value| (*algorithm, *value)))
    {
        contributing.insert("hashes".to_owned(), json!({ algorithm: value }));
    }
    if let Some(name) = name {
        contributing.insert("name".to_owned(), json!(name));
    }
    stix_id("file", &Value::Object(contributing))
}

fn stix_id(kind: &str, contributing: &Value) -> String {
    format!(
        "{kind}--{}",
        uuid_v5(&STIX_NAMESPACE, canonical_json(contributing).as_bytes())
    )
}

/// RFC 8785-compatible serialization for the string-only objects used in
/// identifiers: object keys sorted, no insignificant whitespace.
fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(object) => {
            let sorted = object.iter().collect::<BTreeMap<_, _>>();
            let members = sorted
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("string serializes"),
                        canonical_json(value)
                    )
                })
                .collect::<Vec<_>>();
            format!("{{{}}}", members.join(","))
        }
        other => serde_json::to_string(other).expect("JSON value serializes"),
    }
}

fn uuid_v5(namespace: &[u8; 16], name: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(namespace);
    hasher.update(name);
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

fn misp_event(data: &ExportData, now: OffsetDateTime) -> Value {
    let mut attributes = vec![
        misp_attribute(
            "filename|md5",
            "Payload delivery",
            &format!("{}|{}", data.sample.name, data.sample.md5),
            "analyzed sample",
        ),
        misp_attribute(
            "filename|sha1",
            "Payload delivery",
            &format!("{}|{}", data.sample.name, data.sample.sha1),
            "analyzed sample",
        ),
        misp_attribute(
            "filename|sha256",
            "Payload delivery",
            &format!("{}|{}", data.sample.name, data.sample.sha256),
            "analyzed sample",
        ),
    ];
    for observable in &data.observables {
        let (kind, category, comment) = match observable.kind {
            ObservableKind::Domain => ("domain", "Network activity", "observed in sample content"),
            ObservableKind::Email => ("email", "Network activity", "observed in sample content"),
            ObservableKind::Ipv4 | ObservableKind::Ipv6 => (
                "ip-dst",
                "Network activity",
                "observed in sample content; traffic direction not determined",
            ),
            ObservableKind::Mac => (
                "mac-address",
                "Network activity",
                "observed in sample content",
            ),
            ObservableKind::Url => ("url", "Network activity", "observed in sample content"),
            ObservableKind::Md5 => ("md5", "Payload delivery", "hash string in sample content"),
            ObservableKind::Sha1 => ("sha1", "Payload delivery", "hash string in sample content"),
            ObservableKind::Sha256 => (
                "sha256",
                "Payload delivery",
                "hash string in sample content",
            ),
            ObservableKind::Sha512 => (
                "sha512",
                "Payload delivery",
                "hash string in sample content",
            ),
        };
        attributes.push(misp_attribute(kind, category, &observable.value, comment));
    }
    let date = format!(
        "{:04}-{:02}-{:02}",
        now.year(),
        u8::from(now.month()),
        now.day()
    );
    json!({
        "Event": {
            "info": format!("Banshee triage: {}", data.sample.name),
            "date": date,
            // 4 = undefined threat level, 0 = initial analysis, 0 = organisation only.
            "threat_level_id": "4",
            "analysis": "0",
            "distribution": "0",
            "published": false,
            "Attribute": attributes,
        }
    })
}

fn misp_attribute(kind: &str, category: &str, value: &str, comment: &str) -> Value {
    json!({
        "type": kind,
        "category": category,
        "value": value,
        "to_ids": false,
        "comment": comment,
    })
}

fn write_csv(output: &mut dyn Write, data: &ExportData) -> Result<()> {
    writeln!(output, "type,value,occurrences,source")?;
    for (kind, value) in [
        ("sample_md5", &data.sample.md5),
        ("sample_sha1", &data.sample.sha1),
        ("sample_sha256", &data.sample.sha256),
    ] {
        writeln!(
            output,
            "{kind},{},1,{}",
            csv_field(value),
            csv_field(&data.sample.name)
        )?;
    }
    for observable in &data.observables {
        writeln!(
            output,
            "{},{},{},{}",
            observable.kind.csv_type(),
            csv_field(&observable.value),
            observable.occurrences,
            csv_field(&data.sample.name)
        )?;
    }
    Ok(())
}

/// Quotes CSV fields and neutralizes spreadsheet formula prefixes.
fn csv_field(value: &str) -> String {
    let guarded = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

fn now_timestamp() -> Result<String> {
    let now = OffsetDateTime::now_utc();
    let truncated = now
        .replace_nanosecond(now.millisecond() as u32 * 1_000_000)
        .context("invalid timestamp")?;
    let formatted = truncated
        .format(&Rfc3339)
        .context("failed to format timestamp")?;
    if !formatted.ends_with('Z') {
        bail!("UTC timestamp did not format with a Z suffix");
    }
    Ok(formatted)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{STIX_NAMESPACE, canonical_json, csv_field, stix_id, uuid_v5};

    #[test]
    fn uuid_v5_matches_reference_implementation() {
        // Python: uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), '{"value":"example.com"}')
        assert_eq!(
            uuid_v5(&STIX_NAMESPACE, br#"{"value":"example.com"}"#),
            "bedb4899-d24b-5401-bc86-8f6b4cc18ec7"
        );
    }

    #[test]
    fn canonical_json_sorts_keys_without_whitespace() {
        let value = json!({ "name": "a.exe", "hashes": { "SHA-256": "ab", "MD5": "cd" } });
        assert_eq!(
            canonical_json(&value),
            r#"{"hashes":{"MD5":"cd","SHA-256":"ab"},"name":"a.exe"}"#
        );
        assert!(
            stix_id("domain-name", &json!({ "value": "example.com" })).starts_with("domain-name--")
        );
    }

    #[test]
    fn csv_fields_are_quoted_and_formula_safe() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=HYPERLINK(1)"), "'=HYPERLINK(1)");
        assert_eq!(csv_field("@SUM(A1)"), "'@SUM(A1)");
    }
}

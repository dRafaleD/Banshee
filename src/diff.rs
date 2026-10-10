use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::{Map, Value};

const DIFF_SCHEMA_VERSION: u8 = 1;
const MAX_REPORT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    ReportJson,
    EvidenceBundle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Available,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FieldState {
    pub status: Availability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldChange {
    pub field: String,
    pub left: FieldState,
    pub right: FieldState,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChangedItem {
    pub key: String,
    pub before: Value,
    pub after: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct CollectionDiff {
    pub left_status: Availability,
    pub right_status: Availability,
    pub added: Vec<Value>,
    pub removed: Vec<Value>,
    pub changed: Vec<ChangedItem>,
}

impl CollectionDiff {
    fn has_changes(&self) -> bool {
        self.left_status != self.right_status
            || !self.added.is_empty()
            || !self.removed.is_empty()
            || !self.changed.is_empty()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EntropyDiff {
    pub left: FieldState,
    pub right: FieldState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffSummary {
    pub has_changes: bool,
    pub field_changes: usize,
    pub iocs_added: usize,
    pub iocs_removed: usize,
    pub iocs_changed: usize,
    pub findings_added: usize,
    pub findings_removed: usize,
    pub findings_changed: usize,
    pub rules_added: usize,
    pub rules_removed: usize,
    pub rules_changed: usize,
    pub archive_entries_added: usize,
    pub archive_entries_removed: usize,
    pub archive_entries_changed: usize,
    pub executable_sections_added: usize,
    pub executable_sections_removed: usize,
    pub executable_sections_changed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisDiff {
    pub schema_version: u8,
    pub report_schema_version: u8,
    pub left: DiffInput,
    pub right: DiffInput,
    pub fields: Vec<FieldChange>,
    pub entropy: EntropyDiff,
    pub iocs: CollectionDiff,
    pub findings: CollectionDiff,
    pub rule_matches: CollectionDiff,
    pub archive_entries: CollectionDiff,
    pub executable_sections: CollectionDiff,
    pub summary: DiffSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffInput {
    pub path: String,
    pub kind: InputKind,
}

struct LoadedReport {
    input: DiffInput,
    schema_version: u8,
    value: Value,
}

pub fn compare(left: &Path, right: &Path) -> Result<AnalysisDiff> {
    let left = load_report(left)?;
    let right = load_report(right)?;
    if left.schema_version != right.schema_version {
        bail!(
            "incompatible report schema versions: left is {}, right is {}",
            left.schema_version,
            right.schema_version
        );
    }
    crate::report::validate_compatibility(&left.value)
        .context("left input is not a valid Banshee report")?;
    crate::report::validate_compatibility(&right.value)
        .context("right input is not a valid Banshee report")?;

    let mut fields = Vec::new();
    for (name, pointer) in [
        ("hash.md5", "/hashes/md5"),
        ("hash.sha1", "/hashes/sha1"),
        ("hash.sha256", "/hashes/sha256"),
        ("file.format", "/file/format"),
        ("file.size", "/file/size"),
        ("file.executable.format", "/file/executable/format"),
        (
            "file.executable.architecture",
            "/file/executable/architecture",
        ),
        ("file.executable.bits", "/file/executable/bits"),
        ("file.executable.kind", "/file/executable/kind"),
        (
            "file.executable.entry_point",
            "/file/executable/entry_point",
        ),
        ("file.archive.total_entries", "/file/archive/total_entries"),
        ("file.archive.total_size", "/file/archive/total_size"),
    ] {
        let left_state = field_state(&left.value, pointer);
        let right_state = field_state(&right.value, pointer);
        if left_state != right_state {
            fields.push(FieldChange {
                field: name.to_owned(),
                left: left_state,
                right: right_state,
            });
        }
    }

    let entropy_left = field_state(&left.value, "/entropy/bits_per_byte");
    let entropy_right = field_state(&right.value, "/entropy/bits_per_byte");
    let entropy = EntropyDiff {
        delta: match (
            entropy_left.value.as_ref().and_then(Value::as_f64),
            entropy_right.value.as_ref().and_then(Value::as_f64),
        ) {
            (Some(left), Some(right)) => Some(right - left),
            _ => None,
        },
        left: entropy_left,
        right: entropy_right,
    };

    let iocs = compare_collection(
        &left.value,
        &right.value,
        "/content_analysis/report/iocs/iocs",
        &["kind", "value"],
        &["kind", "value", "occurrences"],
        "IOC",
    )?;
    let findings = compare_collection(
        &left.value,
        &right.value,
        "/findings",
        &["source", "kind", "value", "detail"],
        &["source", "severity", "kind", "value", "detail"],
        "finding",
    )?;
    let rule_matches = compare_collection(
        &left.value,
        &right.value,
        "/rule_analysis/report/matches",
        &["id"],
        &[
            "id",
            "description",
            "severity",
            "kind",
            "category",
            "confidence",
            "total_matches",
            "truncated",
            "conditions",
        ],
        "rule match",
    )?;
    let archive_entries = compare_collection(
        &left.value,
        &right.value,
        "/file/archive/entries",
        &["name"],
        &[
            "name",
            "kind",
            "size",
            "compressed_size",
            "encrypted",
            "path_safe",
        ],
        "archive entry",
    )?;
    let executable_sections = compare_collection(
        &left.value,
        &right.value,
        "/file/executable/section_details",
        &["name"],
        &[
            "name",
            "virtual_address",
            "file_offset",
            "file_size",
            "memory_size",
            "readable",
            "allocated",
            "writable",
            "executable",
        ],
        "executable section",
    )?;

    let entropy_changed = entropy.left != entropy.right;
    let has_changes = !fields.is_empty()
        || entropy_changed
        || iocs.has_changes()
        || findings.has_changes()
        || rule_matches.has_changes()
        || archive_entries.has_changes()
        || executable_sections.has_changes();
    let summary = DiffSummary {
        has_changes,
        field_changes: fields.len(),
        iocs_added: iocs.added.len(),
        iocs_removed: iocs.removed.len(),
        iocs_changed: iocs.changed.len(),
        findings_added: findings.added.len(),
        findings_removed: findings.removed.len(),
        findings_changed: findings.changed.len(),
        rules_added: rule_matches.added.len(),
        rules_removed: rule_matches.removed.len(),
        rules_changed: rule_matches.changed.len(),
        archive_entries_added: archive_entries.added.len(),
        archive_entries_removed: archive_entries.removed.len(),
        archive_entries_changed: archive_entries.changed.len(),
        executable_sections_added: executable_sections.added.len(),
        executable_sections_removed: executable_sections.removed.len(),
        executable_sections_changed: executable_sections.changed.len(),
    };

    Ok(AnalysisDiff {
        schema_version: DIFF_SCHEMA_VERSION,
        report_schema_version: left.schema_version,
        left: left.input,
        right: right.input,
        fields,
        entropy,
        iocs,
        findings,
        rule_matches,
        archive_entries,
        executable_sections,
        summary,
    })
}

pub fn print(report: &AnalysisDiff, json: bool) -> Result<()> {
    crate::output::print_json_or(report, json, |output| write_text(output, report))
}

fn write_text(output: &mut dyn Write, report: &AnalysisDiff) -> std::io::Result<()> {
    writeln!(output, "Banshee analysis diff")?;
    writeln!(
        output,
        "Left: {}",
        crate::output::terminal_safe(&report.left.path)
    )?;
    writeln!(
        output,
        "Right: {}",
        crate::output::terminal_safe(&report.right.path)
    )?;
    writeln!(output, "Report schema: {}", report.report_schema_version)?;
    writeln!(output, "Changes: {}", report.summary.has_changes)?;
    for change in &report.fields {
        writeln!(
            output,
            "Field {}: {} -> {}",
            change.field,
            display_state(&change.left),
            display_state(&change.right)
        )?;
    }
    if report.entropy.left != report.entropy.right {
        writeln!(
            output,
            "Entropy: {} -> {}{}",
            display_state(&report.entropy.left),
            display_state(&report.entropy.right),
            report
                .entropy
                .delta
                .map(|value| format!(" (delta {value:+.4})"))
                .unwrap_or_default()
        )?;
    }
    write_collection(output, "IOCs", &report.iocs)?;
    write_collection(output, "Findings", &report.findings)?;
    write_collection(output, "Rule matches", &report.rule_matches)?;
    write_collection(output, "Archive entries", &report.archive_entries)?;
    write_collection(output, "Executable sections", &report.executable_sections)?;
    Ok(())
}

fn write_collection(
    output: &mut dyn Write,
    name: &str,
    diff: &CollectionDiff,
) -> std::io::Result<()> {
    writeln!(
        output,
        "{name}: left={}; right={}; +{} -{} ~{}",
        availability(diff.left_status),
        availability(diff.right_status),
        diff.added.len(),
        diff.removed.len(),
        diff.changed.len()
    )?;
    for value in &diff.added {
        writeln!(output, "  + {}", compact(value))?;
    }
    for value in &diff.removed {
        writeln!(output, "  - {}", compact(value))?;
    }
    for value in &diff.changed {
        writeln!(
            output,
            "  ~ {}: {} -> {}",
            crate::output::terminal_safe(&value.key),
            compact(&value.before),
            compact(&value.after)
        )?;
    }
    Ok(())
}

fn display_state(state: &FieldState) -> String {
    state
        .value
        .as_ref()
        .map(compact)
        .unwrap_or_else(|| "<missing>".to_owned())
}

fn compact(value: &Value) -> String {
    crate::output::terminal_safe(
        &serde_json::to_string(value).unwrap_or_else(|_| "null".to_owned()),
    )
}

const fn availability(value: Availability) -> &'static str {
    match value {
        Availability::Available => "available",
        Availability::Missing => "missing",
    }
}

fn load_report(path: &Path) -> Result<LoadedReport> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect diff input '{}'", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("diff input '{}' cannot be a symbolic link", path.display());
    }
    let (report_path, kind) = if metadata.is_dir() {
        let verification = crate::evidence::verify(path)?;
        if !verification.valid {
            bail!(
                "evidence bundle '{}' failed verification: {}",
                path.display(),
                verification.errors.join("; ")
            );
        }
        (path.join("report.json"), InputKind::EvidenceBundle)
    } else if metadata.is_file() {
        (path.to_owned(), InputKind::ReportJson)
    } else {
        bail!(
            "diff input '{}' is not a regular report or bundle",
            path.display()
        );
    };
    let report_metadata = fs::metadata(&report_path)
        .with_context(|| format!("failed to inspect report '{}'", report_path.display()))?;
    if report_metadata.len() > MAX_REPORT_BYTES {
        bail!("diff report exceeds the 64 MiB safety limit");
    }
    let source = fs::read_to_string(&report_path)
        .with_context(|| format!("failed to read report '{}'", report_path.display()))?;
    let mut value: Value = serde_json::from_str(&source)
        .with_context(|| format!("invalid report JSON in '{}'", report_path.display()))?;
    let schema_version = crate::report::schema_version(&value)?;
    sanitize_report_value(&mut value);
    Ok(LoadedReport {
        input: DiffInput {
            path: path.display().to_string(),
            kind,
        },
        schema_version,
        value,
    })
}

fn sanitize_report_value(value: &mut Value) {
    match value {
        Value::String(text) => *text = crate::ioc::redact_sensitive_text(text),
        Value::Array(items) => {
            for item in items {
                sanitize_report_value(item);
            }
        }
        Value::Object(object) => {
            for item in object.values_mut() {
                sanitize_report_value(item);
            }
            let sensitive_kind = object
                .get("kind")
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase);
            if let (Some(kind), Some(Value::String(secret))) =
                (sensitive_kind, object.get_mut("value"))
            {
                if kind == "secret" {
                    *secret = "<redacted secret>".to_owned();
                } else if kind == "private_key" {
                    *secret = "<redacted private key>".to_owned();
                }
            }
        }
        _ => {}
    }
}

fn field_state(report: &Value, pointer: &str) -> FieldState {
    match report.pointer(pointer).filter(|value| !value.is_null()) {
        Some(value) => FieldState {
            status: Availability::Available,
            value: Some(value.clone()),
        },
        None => FieldState {
            status: Availability::Missing,
            value: None,
        },
    }
}

fn compare_collection(
    left: &Value,
    right: &Value,
    pointer: &str,
    key_fields: &[&str],
    value_fields: &[&str],
    label: &str,
) -> Result<CollectionDiff> {
    let left = extract_collection(left, pointer, key_fields, value_fields, label)?;
    let right = extract_collection(right, pointer, key_fields, value_fields, label)?;
    let left_status = if left.is_some() {
        Availability::Available
    } else {
        Availability::Missing
    };
    let right_status = if right.is_some() {
        Availability::Available
    } else {
        Availability::Missing
    };
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    if let (Some(left), Some(right)) = (&left, &right) {
        for (key, value) in right {
            match left.get(key) {
                None => added.push(value.clone()),
                Some(before) if before != value => changed.push(ChangedItem {
                    key: key.clone(),
                    before: before.clone(),
                    after: value.clone(),
                }),
                Some(_) => {}
            }
        }
        for (key, value) in left {
            if !right.contains_key(key) {
                removed.push(value.clone());
            }
        }
    }
    Ok(CollectionDiff {
        left_status,
        right_status,
        added,
        removed,
        changed,
    })
}

fn extract_collection(
    report: &Value,
    pointer: &str,
    key_fields: &[&str],
    value_fields: &[&str],
    label: &str,
) -> Result<Option<BTreeMap<String, Value>>> {
    let Some(value) = report.pointer(pointer).filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let items = value
        .as_array()
        .with_context(|| format!("{label} section at {pointer} is not an array"))?;
    let mut grouped = BTreeMap::<String, Vec<Value>>::new();
    for (index, item) in items.iter().enumerate() {
        let object = item
            .as_object()
            .with_context(|| format!("{label} item {index} is not an object"))?;
        let key_value = select_fields(object, key_fields, true, label, index)?;
        let base_key =
            serde_json::to_string(&key_value).context("failed to build comparison key")?;
        let selected = select_fields(object, value_fields, false, label, index)?;
        grouped.entry(base_key).or_default().push(selected);
    }
    let mut result = BTreeMap::new();
    for (base_key, mut values) in grouped {
        values.sort_by_cached_key(|value| serde_json::to_string(value).unwrap_or_default());
        for (index, selected) in values.into_iter().enumerate() {
            let key = if index == 0 {
                base_key.clone()
            } else {
                format!("{base_key} [duplicate {}]", index + 1)
            };
            result.insert(key, selected);
        }
    }
    Ok(Some(result))
}

fn select_fields(
    object: &Map<String, Value>,
    fields: &[&str],
    required: bool,
    label: &str,
    index: usize,
) -> Result<Value> {
    let mut selected = Map::new();
    for field in fields {
        match object.get(*field).filter(|value| !value.is_null()) {
            Some(value) => {
                selected.insert((*field).to_owned(), value.clone());
            }
            None if required => bail!("{label} item {index} is missing key field '{field}'"),
            None => {
                selected.insert((*field).to_owned(), Value::Null);
            }
        }
    }
    Ok(Value::Object(selected))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Availability, compare_collection, field_state};

    #[test]
    fn distinguishes_missing_collections_from_empty_collections() {
        let missing = json!({});
        let empty = json!({"items": []});
        let diff = compare_collection(&missing, &empty, "/items", &["id"], &["id"], "item")
            .expect("compare");
        assert_eq!(diff.left_status, Availability::Missing);
        assert_eq!(diff.right_status, Availability::Available);
        assert!(diff.has_changes());
        assert!(diff.added.is_empty());
    }

    #[test]
    fn tracks_added_removed_and_changed_items_deterministically() {
        let left = json!({"items": [
            {"id": "b", "count": 1},
            {"id": "a", "count": 1}
        ]});
        let right = json!({"items": [
            {"id": "b", "count": 2},
            {"id": "c", "count": 1}
        ]});
        let diff = compare_collection(&left, &right, "/items", &["id"], &["id", "count"], "item")
            .expect("compare");
        assert_eq!(diff.added[0]["id"], "c");
        assert_eq!(diff.removed[0]["id"], "a");
        assert_eq!(diff.changed.len(), 1);
    }

    #[test]
    fn distinguishes_missing_scalar_from_present_zero() {
        let missing = field_state(&json!({}), "/value");
        let zero = field_state(&json!({"value": 0}), "/value");
        assert_ne!(missing, zero);
    }
}

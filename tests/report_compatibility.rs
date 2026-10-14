use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use banshee::diff::{Availability, compare};
use banshee::report::{REPORT_SCHEMA_VERSION, generate, validate_compatibility};
use serde_json::{Value, json};

const MINIMAL: &str = include_str!("fixtures/reports/v1-legacy-minimal.json");
const EXECUTABLE: &str = include_str!("fixtures/reports/v1-legacy-executable.json");
const ARCHIVE: &str = include_str!("fixtures/reports/v1-archive-rules.json");

struct Workspace(PathBuf);

impl Workspace {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "banshee-report-compatibility-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn save(&self, name: &str, value: &Value) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        path
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn fixture(source: &str) -> Value {
    serde_json::from_str(source).unwrap()
}

fn compare_values(left: &Value, right: &Value) -> banshee::diff::AnalysisDiff {
    let workspace = Workspace::new();
    compare(
        &workspace.save("left.json", left),
        &workspace.save("right.json", right),
    )
    .unwrap()
}

#[test]
fn saved_v1_fixtures_validate_and_self_compare_without_samples() {
    assert_eq!(REPORT_SCHEMA_VERSION, 1);
    for source in [MINIMAL, EXECUTABLE, ARCHIVE] {
        let report = fixture(source);
        assert_eq!(validate_compatibility(&report).unwrap(), 1);
        let diff = compare_values(&report, &report);
        assert_eq!(diff.schema_version, 1);
        assert_eq!(diff.report_schema_version, 1);
        assert!(!diff.summary.has_changes);
    }
}

#[test]
fn optional_additions_preserve_missing_versus_empty_and_null() {
    let old = fixture(EXECUTABLE);
    let mut new = old.clone();
    new["file"]["executable"]["section_details"] = json!([]);
    new["rule_analysis"]["report"] = json!({"matches": []});
    let diff = compare_values(&old, &new);
    assert!(diff.summary.has_changes);
    assert_eq!(diff.executable_sections.left_status, Availability::Missing);
    assert_eq!(
        diff.executable_sections.right_status,
        Availability::Available
    );
    assert_eq!(diff.rule_matches.left_status, Availability::Missing);
    assert_eq!(diff.rule_matches.right_status, Availability::Available);
    assert!(diff.executable_sections.added.is_empty());
    assert!(diff.executable_sections.removed.is_empty());
    let mut null = old.clone();
    null["file"]["executable"]["section_details"] = Value::Null;
    null["rule_analysis"]["report"] = Value::Null;
    assert!(!compare_values(&old, &null).summary.has_changes);
}

#[test]
fn unknown_additions_and_incidental_metadata_do_not_change_comparison() {
    let old = fixture(ARCHIVE);
    let mut new = old.clone();
    new["future_extension"] = json!({"enabled": true});
    new["file"]["path"] = json!("different/sample.zip");
    new["content_analysis"]["report"]["iocs"]["iocs"][0]["locations"] = json!([{"line": 99}]);
    new["rule_analysis"]["report"]["matches"][0]["samples"] = json!([{"preview": "ignored"}]);
    assert_eq!(validate_compatibility(&new).unwrap(), 1);
    assert!(!compare_values(&old, &new).summary.has_changes);
}

#[test]
fn saved_collections_track_count_severity_and_archive_changes() {
    let old = fixture(ARCHIVE);
    let mut new = old.clone();
    new["content_analysis"]["report"]["iocs"]["iocs"][0]["occurrences"] = json!(2);
    new["findings"][0]["severity"] = json!("high");
    new["rule_analysis"]["report"]["matches"][0]["total_matches"] = json!(2);
    new["file"]["archive"]["entries"][0]["size"] = json!(8);
    let diff = compare_values(&old, &new);
    assert_eq!(diff.summary.iocs_changed, 1);
    assert_eq!(diff.summary.findings_changed, 1);
    assert_eq!(diff.summary.rules_changed, 1);
    assert_eq!(diff.summary.archive_entries_changed, 1);
    assert!(diff.fields.is_empty());
}

#[test]
fn duplicate_entries_and_collection_order_compare_deterministically() {
    let mut old = fixture(ARCHIVE);
    let entries = old["file"]["archive"]["entries"].as_array_mut().unwrap();
    let mut duplicate = entries[0].clone();
    duplicate["size"] = json!(8);
    entries.push(duplicate);
    let mut new = old.clone();
    new["file"]["archive"]["entries"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert!(!compare_values(&old, &new).summary.has_changes);
    new["file"]["archive"]["entries"][0]["size"] = json!(9);
    let diff = compare_values(&old, &new);
    assert_eq!(diff.summary.archive_entries_changed, 1);
    assert!(diff.archive_entries.changed[0].key.contains("duplicate 2"));
}

#[test]
fn optional_scalar_zero_is_available_and_entropy_delta_is_right_minus_left() {
    let old = fixture(EXECUTABLE);
    let mut new = old.clone();
    new["file"]["archive"] = json!({"total_entries": 0, "total_size": 0});
    new["entropy"]["bits_per_byte"] = json!(2.0);
    let diff = compare_values(&old, &new);
    assert_eq!(diff.fields.len(), 2);
    for field in &diff.fields {
        assert_eq!(field.left.status, Availability::Missing);
        assert_eq!(field.right.value, Some(json!(0)));
    }
    assert_eq!(diff.entropy.delta, Some(0.5));
}

#[test]
fn versions_are_explicit_and_mismatch_error_precedes_shape_validation() {
    let workspace = Workspace::new();
    let valid = workspace.save("valid.json", &fixture(MINIMAL));
    for version in [json!(0), json!(2), json!(255)] {
        let future = json!({"schema_version": version});
        let error = validate_compatibility(&future).unwrap_err().to_string();
        assert!(error.contains("unsupported report schema version"));
        let path = workspace.save("unsupported.json", &future);
        assert!(
            compare(&valid, &path)
                .unwrap_err()
                .to_string()
                .contains("incompatible report schema versions")
        );
        assert!(
            format!("{:#}", compare(&path, &path).unwrap_err())
                .contains("unsupported report schema version")
        );
    }
    for invalid in [
        json!({}),
        json!([]),
        json!({"schema_version": "1"}),
        json!({"schema_version": 1.0}),
        json!({"schema_version": -1}),
        json!({"schema_version": 256}),
        json!({"schema_version": null}),
    ] {
        assert!(validate_compatibility(&invalid).is_err());
    }
}

#[test]
fn malformed_comparison_fields_are_rejected_without_echoing_values() {
    let cases = [
        ("/file", json!("sensitive-sentinel")),
        ("/hashes/md5", json!({"sensitive-sentinel": 1})),
        ("/file/size", json!(-1)),
        ("/entropy/bits_per_byte", json!("sensitive-sentinel")),
        ("/content_analysis/report", json!([])),
        (
            "/content_analysis/report/iocs/iocs",
            json!({"sensitive-sentinel": true}),
        ),
        (
            "/content_analysis/report/iocs/iocs/0/kind",
            json!({"sensitive-sentinel": true}),
        ),
        (
            "/content_analysis/report/iocs/iocs/0/occurrences",
            json!(-1),
        ),
        ("/findings/0/detail", json!(["sensitive-sentinel"])),
        ("/rule_analysis/report/matches/0/id", json!(7)),
        (
            "/rule_analysis/report/matches/0/total_matches",
            json!("sensitive-sentinel"),
        ),
        (
            "/file/archive/entries/0/encrypted",
            json!("sensitive-sentinel"),
        ),
    ];
    let workspace = Workspace::new();
    let valid = workspace.save("valid.json", &fixture(ARCHIVE));
    for (pointer, invalid) in cases {
        let mut report = fixture(ARCHIVE);
        *report.pointer_mut(pointer).unwrap() = invalid;
        let error = format!("{:#}", validate_compatibility(&report).unwrap_err());
        assert!(!error.contains("sensitive-sentinel"), "{pointer}: {error}");
        let path = workspace.save("invalid.json", &report);
        assert!(compare(&valid, &path).is_err(), "{pointer}");
    }
    let mut report = fixture(EXECUTABLE);
    report["file"]["executable"]["section_details"] = json!([{"name": "text", "writable": 1}]);
    assert!(validate_compatibility(&report).is_err());
    let mut report = fixture(ARCHIVE);
    report["rule_analysis"]["report"]["matches"][0]["conditions"] = json!({"all_required": -1});
    assert!(validate_compatibility(&report).is_err());
}

#[test]
fn required_fields_and_collection_keys_cannot_be_missing_or_null() {
    for pointer in [
        "/file",
        "/findings",
        "/file/path",
        "/hashes/sha256",
        "/file/size",
        "/entropy/bits_per_byte",
        "/findings/0/value",
        "/file/archive/entries/0/name",
        "/rule_analysis/report/matches/0/id",
        "/content_analysis/report/iocs/iocs/0/kind",
    ] {
        let mut report = fixture(ARCHIVE);
        *report.pointer_mut(pointer).unwrap() = Value::Null;
        assert!(validate_compatibility(&report).is_err(), "{pointer}");
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        report
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert!(validate_compatibility(&report).is_err(), "{pointer}");
    }
}

#[test]
fn current_generated_text_binary_and_archive_reports_remain_compatible() {
    let workspace = Workspace::new();
    let rules = workspace.0.join("rules.toml");
    std::fs::write(
        &rules,
        "version = 1\n[[rules]]\nid = 'marker'\nkind = 'literal'\npattern = 'fixture'\n",
    )
    .unwrap();
    let mut archive = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(7);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(&mut header, "sample.txt", &b"fixture"[..])
        .unwrap();
    let archive = archive.into_inner().unwrap();
    for (index, bytes) in [
        b"fixture fixture.example".as_slice(),
        b"\xff\0fixture\0".as_slice(),
        archive.as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        let sample = workspace.0.join(format!("sample-{index}"));
        std::fs::write(&sample, bytes).unwrap();
        let current =
            serde_json::to_value(generate(&sample, Some(&rules), 100, 3, 100).unwrap()).unwrap();
        validate_compatibility(&current).unwrap();
        let saved = workspace.save("current.json", &current);
        std::fs::remove_file(&sample).unwrap();
        assert!(!compare(&saved, &saved).unwrap().summary.has_changes);
        let diff = compare(&workspace.save("old.json", &fixture(MINIMAL)), &saved).unwrap();
        assert!(diff.summary.has_changes);
    }
}

#[test]
fn legacy_secrets_and_private_keys_are_redacted_in_json_and_text_diffs() {
    let old = fixture(ARCHIVE);
    let mut new = fixture(ARCHIVE);
    new["content_analysis"]["report"]["iocs"]["iocs"] = json!([
        {"kind": "secret", "value": "synthetic-secret-sentinel", "occurrences": 1},
        {"kind": "private_key", "value": "synthetic-private-key-sentinel", "occurrences": 1}
    ]);
    new["findings"] = json!([
        {"source": "ioc_extraction", "kind": "secret", "value": "synthetic-secret-sentinel", "detail": "Synthetic secret", "severity": "info"},
        {"source": "ioc_extraction", "kind": "private_key", "value": "synthetic-private-key-sentinel", "detail": "Synthetic key", "severity": "info"}
    ]);
    new["rule_analysis"]["report"]["matches"][0]["description"] =
        json!("api_key=abcdefghijklmnopqrstuvwx");
    let workspace = Workspace::new();
    let left = workspace.save("left.json", &old);
    let right = workspace.save("right.json", &new);
    let diff = compare(&left, &right).unwrap();
    assert_eq!(diff.summary.iocs_added, 2);
    assert_eq!(diff.summary.findings_added, 2);
    let serialized = serde_json::to_string(&diff).unwrap();
    assert_redacted(&serialized);
    for json_output in [false, true] {
        let mut command = assert_cmd::Command::cargo_bin("banshee").unwrap();
        command.arg("diff").arg(&left).arg(&right);
        if json_output {
            command.arg("--json");
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert_redacted(&String::from_utf8(output.stdout).unwrap());
    }
    // Comparison reads saved reports; it does not rewrite raw evidence.
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(right).unwrap()).unwrap(),
        new
    );
}

#[test]
fn secret_changes_compare_after_redaction_in_both_directions() {
    let mut old = fixture(ARCHIVE);
    old["content_analysis"]["report"]["iocs"]["iocs"] = json!([
        {"kind": "secret", "value": "synthetic-old-secret", "occurrences": 1},
        {"kind": "private_key", "value": "synthetic-old-key", "occurrences": 1}
    ]);
    old["findings"] = json!([
        {"source": "ioc_extraction", "kind": "secret", "value": "synthetic-old-secret", "detail": "Synthetic secret", "severity": "info"}
    ]);
    let mut new = old.clone();
    new["content_analysis"]["report"]["iocs"]["iocs"][0]["value"] = json!("synthetic-new-secret");
    new["content_analysis"]["report"]["iocs"]["iocs"][1]["value"] = json!("synthetic-new-key");
    new["findings"][0]["value"] = json!("synthetic-new-secret");
    assert!(!compare_values(&old, &new).summary.has_changes);
    new["findings"][0]["severity"] = json!("high");
    new["content_analysis"]["report"]["iocs"]["iocs"][0]["occurrences"] = json!(2);
    for (left, right) in [(&old, &new), (&new, &old)] {
        let diff = compare_values(left, right);
        assert_eq!(diff.summary.iocs_changed, 1);
        assert_eq!(diff.summary.findings_changed, 1);
        let output = serde_json::to_string(&diff).unwrap();
        for sentinel in [
            "synthetic-old-secret",
            "synthetic-new-secret",
            "synthetic-old-key",
            "synthetic-new-key",
        ] {
            assert!(!output.contains(sentinel));
        }
        assert!(diff.findings.changed[0].key.contains("<redacted secret>"));
    }
}

fn assert_redacted(output: &str) {
    for sentinel in [
        "synthetic-secret-sentinel",
        "synthetic-private-key-sentinel",
        "abcdefghijklmnopqrstuvwx",
    ] {
        assert!(
            !output.contains(sentinel),
            "sensitive value appeared in diff"
        );
    }
    assert!(output.contains("<redacted secret>"));
    assert!(output.contains("<redacted private key>"));
}

#[test]
fn cli_version_and_validation_failures_return_operational_error() {
    let workspace = Workspace::new();
    let valid = workspace.save("valid.json", &fixture(MINIMAL));
    let mut malformed = fixture(MINIMAL);
    malformed["file"]["size"] = json!("sensitive-sentinel");
    let invalid = workspace.save("invalid.json", &malformed);
    let unsupported = workspace.save("unsupported.json", &json!({"schema_version": 2}));
    for (left, right) in [
        (&valid, &invalid),
        (&valid, &unsupported),
        (&unsupported, &unsupported),
    ] {
        let output = assert_cmd::Command::cargo_bin("banshee")
            .unwrap()
            .arg("diff")
            .arg(left)
            .arg(right)
            .arg("--json")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(
            !String::from_utf8(output.stderr)
                .unwrap()
                .contains("sensitive-sentinel")
        );
    }
}

#[test]
fn verified_evidence_bundles_use_the_same_report_contract() {
    let workspace = Workspace::new();
    let sample = workspace.0.join("sample.txt");
    let bundle = workspace.0.join("bundle");
    std::fs::write(&sample, b"fixture.example").unwrap();
    banshee::evidence::create(
        &sample,
        &bundle,
        banshee::evidence::CreateOptions {
            rule_file: None,
            include_sample: false,
            max_entries: 100,
            max_depth: 3,
            max_tokens: 100,
            force: false,
        },
    )
    .unwrap();
    std::fs::remove_file(sample).unwrap();
    let diff = compare(&bundle, &bundle.join("report.json")).unwrap();
    assert!(!diff.summary.has_changes);
    assert!(!bundle.join("source-sample.bin").exists());
    std::fs::write(bundle.join("report.json"), MINIMAL).unwrap();
    assert!(
        format!("{:#}", compare(&bundle, Path::new("unused")).unwrap_err())
            .contains("failed verification")
    );
}

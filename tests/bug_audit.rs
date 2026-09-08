//! Regression expectations for the September bug audit; failures expose current bugs.
use assert_cmd::Command;
use serde_json::json;
use std::path::PathBuf;

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "banshee-audit-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, value: serde_json::Value) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Only this test's uniquely created temporary directory is removed.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn evidence_force_preserves_directory_with_invalid_marker() {
    let f = Fixture::new("force");
    let source = f.0.join("sample.txt");
    std::fs::write(&source, b"hello").unwrap();
    let target = f.0.join("ordinary-folder");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("manifest.json"), b"not a manifest").unwrap();
    std::fs::write(target.join("keep.txt"), b"unrelated data").unwrap();
    let output = Command::cargo_bin("banshee")
        .unwrap()
        .args(["evidence", "create"])
        .arg(source)
        .arg("--output")
        .arg(&target)
        .arg("--force")
        .output()
        .unwrap();
    assert!(
        target.join("keep.txt").exists(),
        "Unrelated data deleted; exit={:?}",
        output.status.code()
    );
}

#[test]
fn evidence_accepts_documented_relative_output() {
    let f = Fixture::new("relative");
    std::fs::write(f.0.join("sample.txt"), b"hello").unwrap();
    Command::cargo_bin("banshee")
        .unwrap()
        .current_dir(&f.0)
        .args([
            "evidence",
            "create",
            "sample.txt",
            "--output",
            "case-evidence",
        ])
        .assert()
        .success();
}

#[test]
fn evidence_rejects_empty_manifest_as_incomplete_bundle() {
    let f = Fixture::new("manifest");
    f.write(
        "manifest.json",
        json!({"schema_version":1,"generated_by":"banshee 0.1.0","entries":[]}),
    );
    Command::cargo_bin("banshee")
        .unwrap()
        .args(["evidence", "verify"])
        .arg(&f.0)
        .assert()
        .failure();
}

#[test]
fn diff_rejects_non_report_json() {
    let f = Fixture::new("schema");
    let path = f.write("empty.json", json!({"schema_version":1}));
    Command::cargo_bin("banshee")
        .unwrap()
        .arg("diff")
        .arg(&path)
        .arg(&path)
        .assert()
        .code(2);
}

#[test]
fn diff_detects_executable_section_permission_change() {
    let f = Fixture::new("permissions");
    let source = f.0.join("sample.txt");
    std::fs::write(&source, b"hello").unwrap();
    let output = Command::cargo_bin("banshee")
        .unwrap()
        .arg("report")
        .arg(source)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let mut left: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    left["file"]["executable"] = json!({"format":"PE","section_details":[{"name":".text","writable":false,"executable":true}]});
    let mut right = left.clone();
    right["file"]["executable"]["section_details"][0]["writable"] = json!(true);
    let a = f.write("a.json", left);
    let b = f.write("b.json", right);
    Command::cargo_bin("banshee")
        .unwrap()
        .arg("diff")
        .arg(a)
        .arg(b)
        .assert()
        .code(1);
}

#[test]
fn diff_duplicate_archive_entries_ignore_order() {
    let f = Fixture::new("duplicates");
    let source = f.0.join("sample.txt");
    std::fs::write(&source, b"hello").unwrap();
    let output = Command::cargo_bin("banshee")
        .unwrap()
        .arg("report")
        .arg(source)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let mut left: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    left["file"]["archive"] = json!({"total_entries":2,"total_size":3,"truncated":false,
        "entries":[{"name":"same.txt","kind":"file","size":1},{"name":"same.txt","kind":"file","size":2}]});
    let mut right = left.clone();
    right["file"]["archive"]["entries"]
        .as_array_mut()
        .unwrap()
        .reverse();
    let a = f.write("a.json", left);
    let b = f.write("b.json", right);
    Command::cargo_bin("banshee")
        .unwrap()
        .arg("diff")
        .arg(a)
        .arg(b)
        .assert()
        .success();
}

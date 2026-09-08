use assert_cmd::Command;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "banshee-security-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn clipped_rule_context_must_not_leak_password_fragment() {
    let f = Fixture::new("redaction");
    let rules = f.0.join("rules.toml");
    std::fs::write(
        &rules,
        "version=1\n[[rules]]\nid='marker'\nkind='literal'\npattern='TAILMARK'\n",
    )
    .unwrap();
    // Synthetic credential only. The assignment prefix falls outside the preview window.
    let input = "password = abcdefghijklmnopqrstuvwxyzTAILMARK";
    let report = banshee::rules::scan(&rules, input.as_bytes()).unwrap();
    assert!(
        !report.matches[0].samples[0]
            .preview
            .contains("opqrstuvwxyz"),
        "Password suffix remains in rule preview"
    );
}

#[test]
fn concurrent_target_creation_must_not_be_overwritten_without_force() {
    let f = Fixture::new("publish");
    let source = f.0.join("sample.txt");
    std::fs::write(&source, "hello ".repeat(100_000)).unwrap();
    let target = f.0.join("bundle");
    let binary = assert_cmd::cargo::cargo_bin("banshee");
    let mut child = std::process::Command::new(binary)
        .args(["evidence", "create"])
        .arg(source)
        .arg("--output")
        .arg(&target)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let mut staged = false;
    while start.elapsed() < Duration::from_secs(10) {
        if std::fs::read_dir(&f.0).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".bundle.banshee-staging-")
        }) {
            staged = true;
            break;
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    if !staged {
        let _ = child.kill();
        let _ = child.wait();
        panic!("Could not observe staging; race test inconclusive");
    }
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("keep.txt"), b"concurrently created user data").unwrap();
    let status = child.wait().unwrap();
    assert!(
        target.join("keep.txt").exists(),
        "Concurrent target deleted without --force; exit={:?}",
        status.code()
    );
}

#[test]
fn diff_must_mask_secret_values_from_saved_reports() {
    let f = Fixture::new("diff-secret");
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
    let left: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut right = left.clone();
    right["content_analysis"]["report"]["iocs"]["iocs"] = serde_json::json!([
        {"kind":"secret","value":"password = SyntheticAuditSecret123","occurrences":1}
    ]);
    let a = f.0.join("a.json");
    let b = f.0.join("b.json");
    std::fs::write(&a, serde_json::to_vec(&left).unwrap()).unwrap();
    std::fs::write(&b, serde_json::to_vec(&right).unwrap()).unwrap();
    let output = Command::cargo_bin("banshee")
        .unwrap()
        .arg("diff")
        .arg(a)
        .arg(b)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("SyntheticAuditSecret123"),
        "Diff re-emits secret from input report"
    );
}

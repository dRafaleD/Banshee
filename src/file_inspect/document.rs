//! Structural inspection of documents and shortcuts commonly used to deliver
//! malware: OOXML packages, OLE compound files, PDF and Windows LNK files.
//!
//! Nothing is rendered, executed or extracted to disk. Every list and read is
//! bounded, and each reported property is a triage signal rather than a verdict.

use std::io::{Cursor, Read};
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use regex::bytes::Regex as BytesRegex;
use serde::Serialize;

use super::binary::{read_u16, read_u32};

const MAX_TARGETS: usize = 256;
const MAX_PROPERTY_CHARS: usize = 4_096;
const MAX_RELATIONSHIP_FILES: usize = 256;
const MAX_XML_PART_BYTES: u64 = 8 * 1024 * 1024;
const MAX_OLE_SECTORS: usize = 1 << 20;
const MAX_OLE_DIRECTORY_ENTRIES: usize = 4_096;
const MAX_LNK_PADDING_SPACES: usize = 32;
const MAX_VISIBLE_LNK_ARGUMENTS: usize = 260;

/// Programs frequently abused to launch payloads from documents or shortcuts.
const SCRIPT_HOSTS: &[&str] = &[
    "powershell",
    "pwsh",
    "cmd.exe",
    "mshta",
    "wscript",
    "cscript",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "msiexec",
    "curl.exe",
    "forfiles",
    "conhost",
];

#[derive(Debug, Clone, Serialize)]
pub struct DocumentReport {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub macros_present: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<DocumentProperty>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub external_targets: Vec<ExternalTarget>,
    pub targets_truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub suspicious_properties: Vec<String>,
    /// Analysis limits that apply to this format, kept apart from findings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// Further text for content analysis only, such as event log data.
    #[serde(skip)]
    pub extra_text: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DocumentProperty {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalTarget {
    pub relationship: String,
    pub target: String,
}

impl DocumentReport {
    pub(super) fn new(kind: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            macros_present: None,
            properties: Vec::new(),
            external_targets: Vec::new(),
            targets_truncated: false,
            suspicious_properties: Vec::new(),
            notes: Vec::new(),
            extra_text: Vec::new(),
        }
    }

    pub(super) fn property(&mut self, name: &str, value: impl Into<String>) {
        self.properties.push(DocumentProperty {
            name: name.to_owned(),
            value: clip(&value.into()),
        });
    }

    pub(super) fn target(&mut self, relationship: &str, target: &str) {
        if self.external_targets.len() >= MAX_TARGETS {
            self.targets_truncated = true;
            return;
        }
        self.external_targets.push(ExternalTarget {
            relationship: relationship.to_owned(),
            target: clip(target),
        });
    }

    /// Text worth passing to content analysis: targets and string properties
    /// that file-level printable-string extraction cannot see (for example
    /// UTF-16 shortcut arguments or compressed OOXML relationships).
    pub fn analysis_text(&self) -> String {
        self.external_targets
            .iter()
            .map(|target| target.target.as_str())
            .chain(
                self.properties
                    .iter()
                    .map(|property| property.value.as_str()),
            )
            .chain(self.extra_text.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn clip(value: &str) -> String {
    if value.chars().count() <= MAX_PROPERTY_CHARS {
        return value.to_owned();
    }
    let mut clipped = value.chars().take(MAX_PROPERTY_CHARS).collect::<String>();
    clipped.push('…');
    clipped
}

// ---------------------------------------------------------------------------
// OOXML

/// Inspects a ZIP that carries `[Content_Types].xml`; other ZIPs return `None`.
/// Unreadable parts become notes so one damaged part does not hide the rest.
pub(super) fn inspect_ooxml(bytes: &[u8]) -> Option<DocumentReport> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).ok()?;
    let names = zip
        .file_names()
        .filter_map(Result::ok)
        .map(std::borrow::Cow::into_owned)
        .collect::<Vec<_>>();
    if !names.iter().any(|name| name == "[Content_Types].xml") {
        return None;
    }
    let has_prefix = |prefix: &str| names.iter().any(|name| name.starts_with(prefix));
    let kind = if has_prefix("word/") {
        "Word document (OOXML)"
    } else if has_prefix("xl/") {
        "Excel workbook (OOXML)"
    } else if has_prefix("ppt/") {
        "PowerPoint presentation (OOXML)"
    } else {
        "OOXML package"
    };
    let mut report = DocumentReport::new(kind);

    let lower = names
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let macros = lower.iter().any(|name| name.ends_with("vbaproject.bin"));
    report.macros_present = Some(macros);
    if macros {
        report
            .suspicious_properties
            .push("document contains a VBA macro project (vbaProject.bin)".to_owned());
    }
    let embedded = lower
        .iter()
        .filter(|name| name.contains("/embeddings/") || name.contains("oleobject"))
        .count();
    if embedded > 0 {
        report.property("Embedded objects", embedded.to_string());
        report
            .suspicious_properties
            .push(format!("document embeds {embedded} OLE/package object(s)"));
    }
    let activex = lower
        .iter()
        .filter(|name| name.contains("/activex/") && name.ends_with(".xml"))
        .count();
    if activex > 0 {
        report.property("ActiveX controls", activex.to_string());
        report
            .suspicious_properties
            .push(format!("document declares {activex} ActiveX control(s)"));
    }

    let relationship_files = names
        .iter()
        .filter(|name| name.ends_with(".rels"))
        .take(MAX_RELATIONSHIP_FILES)
        .cloned()
        .collect::<Vec<_>>();
    for name in relationship_files {
        if let Some(xml) = read_part_or_note(&mut zip, &name, &mut report) {
            collect_external_relationships(&xml, &mut report);
        }
    }

    for name in [
        "word/document.xml",
        "word/footnotes.xml",
        "word/endnotes.xml",
    ] {
        if !names.iter().any(|candidate| candidate == name) {
            continue;
        }
        if let Some(xml) = read_part_or_note(&mut zip, name, &mut report)
            && dde_pattern().is_match(&xml)
        {
            report
                .suspicious_properties
                .push(format!("DDE field instruction in {name}"));
        }
    }
    report
        .notes
        .push("macro source code is not decompressed or analyzed".to_owned());
    Some(report)
}

fn read_part_or_note(
    zip: &mut zip::ZipArchive<Cursor<&[u8]>>,
    name: &str,
    report: &mut DocumentReport,
) -> Option<Vec<u8>> {
    match read_zip_part(zip, name) {
        Ok(Some(xml)) => Some(xml),
        Ok(None) => {
            report
                .notes
                .push(format!("OOXML part '{name}' exceeds the 8 MiB limit"));
            None
        }
        Err(error) => {
            report.notes.push(format!("{error:#}"));
            None
        }
    }
}

fn read_zip_part(zip: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str) -> Result<Option<Vec<u8>>> {
    let entry = zip
        .by_name(name)
        .with_context(|| format!("failed to read OOXML part '{name}'"))?;
    let mut data = Vec::new();
    entry
        .take(MAX_XML_PART_BYTES + 1)
        .read_to_end(&mut data)
        .with_context(|| format!("failed to decompress OOXML part '{name}'"))?;
    Ok((data.len() as u64 <= MAX_XML_PART_BYTES).then_some(data))
}

fn collect_external_relationships(xml: &[u8], report: &mut DocumentReport) {
    static RELATIONSHIP: OnceLock<BytesRegex> = OnceLock::new();
    static ATTRIBUTE: OnceLock<BytesRegex> = OnceLock::new();
    let relationship = RELATIONSHIP.get_or_init(|| {
        BytesRegex::new(r"(?i)<(?:\w+:)?Relationship\b[^>]*>").expect("valid relationship regex")
    });
    let attribute = ATTRIBUTE.get_or_init(|| {
        BytesRegex::new(r#"(?i)\b(Target|TargetMode|Type)\s*=\s*(?:"([^"]*)"|'([^']*)')"#)
            .expect("valid attribute regex")
    });
    for element in relationship.find_iter(xml) {
        let (mut target, mut mode, mut kind) = (None, None, None);
        for captures in attribute.captures_iter(element.as_bytes()) {
            let value = captures
                .get(2)
                .or_else(|| captures.get(3))
                .map(|value| xml_unescape(&String::from_utf8_lossy(value.as_bytes())));
            match captures[1].to_ascii_lowercase().as_slice() {
                b"target" => target = value,
                b"targetmode" => mode = value,
                _ => kind = value,
            }
        }
        let (Some(target), Some(mode)) = (target, mode) else {
            continue;
        };
        if !mode.eq_ignore_ascii_case("external") {
            continue;
        }
        let relationship = kind
            .as_deref()
            .and_then(|kind| kind.rsplit('/').next())
            .unwrap_or("unknown")
            .to_owned();
        match relationship.as_str() {
            "attachedTemplate" => report
                .suspicious_properties
                .push(format!("remote template reference: {}", clip(&target))),
            "oleObject" | "frame" | "subDocument" => report.suspicious_properties.push(format!(
                "external {relationship} reference: {}",
                clip(&target)
            )),
            _ => {}
        }
        report.target(&relationship, &target);
    }
}

fn dde_pattern() -> &'static BytesRegex {
    static DDE: OnceLock<BytesRegex> = OnceLock::new();
    DDE.get_or_init(|| {
        BytesRegex::new(r"(?i)<w:instrText[^>]*>\s*(?:DDE|DDEAUTO)\b").expect("valid DDE regex")
    })
}

fn xml_unescape(value: &str) -> String {
    html_escape::decode_html_entities(value).into_owned()
}

// ---------------------------------------------------------------------------
// OLE compound file (CFB)

const OLE_SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const END_OF_CHAIN: u32 = 0xFFFF_FFFE;

pub(super) fn is_ole(bytes: &[u8]) -> bool {
    bytes.starts_with(&OLE_SIGNATURE)
}

pub(super) fn inspect_ole(bytes: &[u8]) -> DocumentReport {
    let (names, parsed) = match ole_directory_names(bytes) {
        Ok(names) => (names, true),
        Err(_) => (ole_name_scan(bytes), false),
    };
    let has = |wanted: &str| names.iter().any(|name| name.eq_ignore_ascii_case(wanted));
    let has_prefix = |prefix: &str| names.iter().any(|name| name.starts_with(prefix));
    let kind = if has("WordDocument") {
        "Word 97-2003 document (OLE)"
    } else if has("Workbook") || has("Book") {
        "Excel 97-2003 workbook (OLE)"
    } else if has("PowerPoint Document") {
        "PowerPoint 97-2003 presentation (OLE)"
    } else if has_prefix("__substg1.0_") {
        "Outlook message (OLE)"
    } else if has("EncryptedPackage") {
        "Encrypted OOXML package (OLE)"
    } else if has_prefix("\u{4840}") {
        // Windows Installer stores its tables under names starting with U+4840.
        "Windows Installer package (OLE)"
    } else {
        "OLE compound file"
    };
    let mut report = DocumentReport::new(kind);
    let macros = has("_VBA_PROJECT") || has("_VBA_PROJECT_CUR") || has("VBA") || has("Macros");
    report.macros_present = Some(macros);
    if macros {
        report
            .suspicious_properties
            .push("compound file contains a VBA macro storage".to_owned());
    }
    if has("\u{1}Ole10Native") {
        report
            .suspicious_properties
            .push("embedded OLE Packager object (Ole10Native)".to_owned());
    }
    if has("ObjectPool") {
        report.property("Embedded object storage", "ObjectPool");
    }
    if has("EncryptedPackage") {
        report
            .suspicious_properties
            .push("password-protected document hides its content from inspection".to_owned());
    }
    report.property("Directory entries", names.len().to_string());
    if !parsed {
        report.notes.push(
            "directory chain could not be parsed; names were found by a bounded UTF-16 scan"
                .to_owned(),
        );
    }
    report
        .notes
        .push("stream contents and macro source code are not analyzed".to_owned());
    report
}

fn ole_directory_names(bytes: &[u8]) -> Result<Vec<String>> {
    if bytes.len() < 512 {
        bail!("truncated compound file header");
    }
    let shift = read_u16(bytes, 0x1E, true).context("missing sector shift")?;
    if !matches!(shift, 9 | 12) {
        bail!("unsupported sector size");
    }
    let sector_size = 1_usize << shift;
    let directory_start = read_u32(bytes, 0x30, true).context("missing directory start")?;
    let fat_sectors = read_u32(bytes, 0x2C, true).context("missing FAT size")? as usize;
    let sector = |index: u32| -> Option<&[u8]> {
        let start = (index as usize).checked_add(1)?.checked_mul(sector_size)?;
        bytes.get(start..start.checked_add(sector_size)?)
    };

    // The header lists the first 109 FAT sectors; that covers files of several
    // MiB, and larger directories fall back to the name scan.
    let mut fat = Vec::new();
    for slot in 0..fat_sectors.min(109) {
        let index = read_u32(bytes, 0x4C + slot * 4, true).context("truncated DIFAT")?;
        let data = sector(index).context("FAT sector outside file")?;
        fat.extend(
            data.as_chunks::<4>()
                .0
                .iter()
                .map(|chunk| u32::from_le_bytes(*chunk)),
        );
        if fat.len() > MAX_OLE_SECTORS {
            bail!("FAT exceeds the sector limit");
        }
    }

    let mut names = Vec::new();
    let mut current = directory_start;
    let mut visited = std::collections::HashSet::new();
    while current != END_OF_CHAIN {
        if !visited.insert(current) || names.len() >= MAX_OLE_DIRECTORY_ENTRIES {
            bail!("directory chain loops or is too long");
        }
        let data = sector(current).context("directory sector outside file")?;
        for entry in data.as_chunks::<128>().0 {
            let name_bytes = usize::from(read_u16(entry, 0x40, true).unwrap_or(0));
            let object_type = entry[0x42];
            if object_type == 0 || !(2..=64).contains(&name_bytes) {
                continue;
            }
            let units = entry[..name_bytes - 2]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|unit| u16::from_le_bytes(*unit));
            names.push(
                char::decode_utf16(units)
                    .map(|unit| unit.unwrap_or('\u{FFFD}'))
                    .collect(),
            );
        }
        current = *fat
            .get(current as usize)
            .context("directory sector missing from FAT")?;
    }
    Ok(names)
}

/// Fallback: finds well-known storage names stored as UTF-16LE anywhere.
fn ole_name_scan(bytes: &[u8]) -> Vec<String> {
    [
        "WordDocument",
        "Workbook",
        "PowerPoint Document",
        "_VBA_PROJECT",
        "_VBA_PROJECT_CUR",
        "Macros",
        "\u{1}Ole10Native",
        "ObjectPool",
        "EncryptedPackage",
    ]
    .iter()
    .filter(|name| {
        let needle = name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        bytes.windows(needle.len()).any(|window| window == needle)
    })
    .map(|name| (*name).to_owned())
    .collect()
}

// ---------------------------------------------------------------------------
// PDF

pub(super) fn is_pdf(bytes: &[u8]) -> bool {
    bytes
        .get(..1024.min(bytes.len()))
        .is_some_and(|head| head.windows(5).any(|window| window == b"%PDF-"))
}

pub(super) fn inspect_pdf(bytes: &[u8]) -> DocumentReport {
    static NAME: OnceLock<BytesRegex> = OnceLock::new();
    static URI: OnceLock<BytesRegex> = OnceLock::new();
    let name = NAME
        .get_or_init(|| BytesRegex::new(r"/([A-Za-z0-9#]{1,64})").expect("valid PDF name regex"));
    let uri = URI.get_or_init(|| {
        BytesRegex::new(r"/URI\s*\(((?:[^()\\]|\\.){1,2048})\)").expect("valid PDF URI regex")
    });

    let mut report = DocumentReport::new("PDF document");
    let mut counts = std::collections::BTreeMap::<&'static str, usize>::new();
    let mut obfuscated = false;
    const INTERESTING: &[&str] = &[
        "JavaScript",
        "JS",
        "OpenAction",
        "AA",
        "Launch",
        "EmbeddedFile",
        "EmbeddedFiles",
        "URI",
        "SubmitForm",
        "GoToR",
        "GoToE",
        "RichMedia",
        "XFA",
        "AcroForm",
        "ObjStm",
        "Encrypt",
        "JBIG2Decode",
    ];
    for captures in name.captures_iter(bytes) {
        let raw = &captures[1];
        let decoded = decode_pdf_name(raw);
        if let Some(known) = INTERESTING.iter().find(|known| known.as_bytes() == decoded) {
            *counts.entry(known).or_default() += 1;
            obfuscated |= raw.contains(&b'#');
        }
    }
    for (name, count) in &counts {
        report.property(&format!("/{name}"), count.to_string());
    }
    let count = |name: &str| counts.get(name).copied().unwrap_or(0);
    if count("JavaScript") + count("JS") > 0 {
        report
            .suspicious_properties
            .push("PDF contains JavaScript".to_owned());
    }
    if count("OpenAction") + count("AA") > 0 {
        report
            .suspicious_properties
            .push("PDF defines automatic actions (/OpenAction or /AA)".to_owned());
    }
    if count("Launch") > 0 {
        report
            .suspicious_properties
            .push("PDF contains a /Launch action".to_owned());
    }
    if count("EmbeddedFile") + count("EmbeddedFiles") > 0 {
        report
            .suspicious_properties
            .push("PDF embeds files".to_owned());
    }
    if obfuscated {
        report
            .suspicious_properties
            .push("PDF names are obfuscated with #xx hex escapes".to_owned());
    }
    for captures in uri.captures_iter(bytes) {
        report.target(
            "URI",
            &String::from_utf8_lossy(&unescape_pdf_string(&captures[1])),
        );
    }
    report.notes.push(
        "streams are not decompressed; names inside compressed object streams are not counted"
            .to_owned(),
    );
    report
}

fn decode_pdf_name(raw: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'#'
            && let Some(byte) = raw
                .get(index + 1..index + 3)
                .and_then(|hex| std::str::from_utf8(hex).ok())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        {
            decoded.push(byte);
            index += 3;
            continue;
        }
        decoded.push(raw[index]);
        index += 1;
    }
    decoded
}

fn unescape_pdf_string(raw: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(raw.len());
    let mut bytes = raw.iter();
    while let Some(byte) = bytes.next() {
        if *byte == b'\\'
            && let Some(next) = bytes.next()
        {
            output.push(match next {
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                other => *other,
            });
            continue;
        }
        output.push(*byte);
    }
    output
}

// ---------------------------------------------------------------------------
// Windows shortcut (MS-SHLLINK)

const LNK_HEADER_SIZE: u32 = 0x4C;
const LNK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

pub(super) fn is_lnk(bytes: &[u8]) -> bool {
    bytes.len() >= 0x4C
        && read_u32(bytes, 0, true) == Some(LNK_HEADER_SIZE)
        && bytes[4..20] == LNK_CLSID
}

pub(super) fn inspect_lnk(bytes: &[u8]) -> Result<DocumentReport> {
    let flags = read_u32(bytes, 0x14, true).context("truncated shortcut header")?;
    let show_command = read_u32(bytes, 0x3C, true).context("truncated shortcut header")?;
    let unicode = flags & 0x80 != 0;
    let mut offset = LNK_HEADER_SIZE as usize;
    let mut report = DocumentReport::new("Windows shortcut (LNK)");

    if flags & 0x1 != 0 {
        let size = read_u16(bytes, offset, true).context("truncated target ID list")?;
        offset = offset
            .checked_add(2 + usize::from(size))
            .filter(|end| *end <= bytes.len())
            .context("target ID list exceeds the file")?;
        report.notes.push(
            "the shell item ID list is skipped; targets come from link info and strings".to_owned(),
        );
    }
    if flags & 0x2 != 0 {
        let size = read_u32(bytes, offset, true).context("truncated link info")? as usize;
        let info = bytes
            .get(offset..offset.checked_add(size).context("link info overflows")?)
            .context("link info exceeds the file")?;
        if let Some(path) = link_info_base_path(info) {
            report.property("Target path", path);
        }
        offset += size;
    }
    for (flag, name) in [
        (0x4, "Description"),
        (0x8, "Relative path"),
        (0x10, "Working directory"),
        (0x20, "Arguments"),
        (0x40, "Icon location"),
    ] {
        if flags & flag == 0 {
            continue;
        }
        let characters =
            usize::from(read_u16(bytes, offset, true).context("truncated string data")?);
        offset += 2;
        let length = if unicode { characters * 2 } else { characters };
        let data = bytes
            .get(offset..offset + length)
            .with_context(|| format!("shortcut {name} exceeds the file"))?;
        let value = if unicode {
            char::decode_utf16(
                data.as_chunks::<2>()
                    .0
                    .iter()
                    .map(|unit| u16::from_le_bytes(*unit)),
            )
            .map(|unit| unit.unwrap_or('\u{FFFD}'))
            .collect::<String>()
        } else {
            data.iter().map(|byte| char::from(*byte)).collect()
        };
        offset += length;
        if name == "Arguments" {
            inspect_lnk_arguments(&value, &mut report);
        }
        report.property(name, value);
    }

    if show_command == 7 {
        report
            .suspicious_properties
            .push("shortcut starts its target minimized (SW_SHOWMINNOACTIVE)".to_owned());
    }
    let launched = report
        .properties
        .iter()
        .filter(|property| {
            matches!(
                property.name.as_str(),
                "Target path" | "Relative path" | "Arguments"
            )
        })
        .map(|property| property.value.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    let mut hosts = SCRIPT_HOSTS
        .iter()
        .filter(|host| launched.contains(*host))
        .copied()
        .collect::<Vec<_>>();
    hosts.dedup();
    if !hosts.is_empty() {
        report.suspicious_properties.push(format!(
            "shortcut launches a script host or system binary: {}",
            hosts.join(", ")
        ));
    }
    let icon = report
        .properties
        .iter()
        .find(|property| property.name == "Icon location")
        .map(|property| property.value.to_ascii_lowercase());
    if let Some(icon) = icon
        && [
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png",
        ]
        .iter()
        .any(|extension| icon.contains(extension))
        && !hosts.is_empty()
    {
        report
            .suspicious_properties
            .push("document-like icon on a shortcut that launches a script host".to_owned());
    }
    Ok(report)
}

fn inspect_lnk_arguments(arguments: &str, report: &mut DocumentReport) {
    let leading = arguments
        .chars()
        .take_while(|character| character.is_whitespace())
        .count();
    if leading >= MAX_LNK_PADDING_SPACES {
        report.suspicious_properties.push(format!(
            "shortcut arguments start with {leading} whitespace characters (hidden from the Properties dialog)"
        ));
    }
    let length = arguments.chars().count();
    if length > MAX_VISIBLE_LNK_ARGUMENTS {
        report.suspicious_properties.push(format!(
            "shortcut arguments are {length} characters long; Explorer shows only the first {MAX_VISIBLE_LNK_ARGUMENTS}"
        ));
    }
}

fn link_info_base_path(info: &[u8]) -> Option<String> {
    let header_size = read_u32(info, 4, true)?;
    let link_flags = read_u32(info, 8, true)?;
    if link_flags & 0x1 == 0 {
        return None;
    }
    if header_size >= 0x24
        && let Some(offset) = read_u32(info, 0x1C, true).filter(|offset| *offset != 0)
    {
        let units = info
            .get(offset as usize..)?
            .as_chunks::<2>()
            .0
            .iter()
            .map(|unit| u16::from_le_bytes(*unit))
            .take_while(|unit| *unit != 0)
            .take(MAX_PROPERTY_CHARS);
        return Some(
            char::decode_utf16(units)
                .map(|unit| unit.unwrap_or('\u{FFFD}'))
                .collect(),
        );
    }
    let offset = read_u32(info, 0x10, true)? as usize;
    let path = info
        .get(offset..)?
        .iter()
        .take_while(|byte| **byte != 0)
        .take(MAX_PROPERTY_CHARS)
        .map(|byte| char::from(*byte))
        .collect::<String>();
    (!path.is_empty()).then_some(path)
}

#[cfg(test)]
mod tests;

//! OneNote (`.one`) inspection. Lures hide an executable, script or shortcut
//! behind a fake "open" button in a notebook, and OneNote stores every
//! attachment as a FileDataStoreObject. Those objects are found by their
//! header GUID, sized, hashed and typed by content; script text is passed to
//! content analysis. Pictures are stored the same way and are not suspicious.

use sha2::{Digest, Sha256};

use super::document::DocumentReport;

/// {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}, the section file header.
const SECTION_GUID: [u8; 16] = [
    0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D, 0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3,
];
/// {43FF2FA1-EFD9-4C76-9EE2-10EA5722765F}, the table-of-contents header.
const TOC_GUID: [u8; 16] = [
    0xA1, 0x2F, 0xFF, 0x43, 0xD9, 0xEF, 0x76, 0x4C, 0x9E, 0xE2, 0x10, 0xEA, 0x57, 0x22, 0x76, 0x5F,
];
/// {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}, FileDataStoreObject header.
const FILE_DATA_GUID: [u8; 16] = [
    0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45, 0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC,
];
/// GUID, cbLength (u64), unused (u32) and reserved (u64) precede the data.
const FILE_DATA_HEADER_BYTES: usize = 16 + 8 + 4 + 8;
const MAX_LISTED: usize = 64;
/// Findings listed one by one; a crafted notebook can hold millions of
/// tiny objects, so the rest are summarized.
const MAX_FLAGGED: usize = 64;
const MAX_TEXT_BYTES: usize = 1024 * 1024;

pub(super) fn is_onenote(bytes: &[u8]) -> bool {
    bytes.starts_with(&SECTION_GUID) || bytes.starts_with(&TOC_GUID)
}

/// What an embedded file is, and whether a lure would use it.
fn classify(data: &[u8]) -> (&'static str, bool) {
    let head = &data[..data.len().min(4096)];
    if data.starts_with(b"MZ") {
        return ("Windows executable (PE)", true);
    }
    if data.starts_with(b"\x7FELF") {
        return ("ELF executable", true);
    }
    if super::document::is_lnk(data) {
        return ("Windows shortcut (LNK)", true);
    }
    if super::document::is_ole(data) {
        return ("OLE compound file (Office document or installer)", true);
    }
    if data.starts_with(b"PK\x03\x04") {
        return ("ZIP archive", true);
    }
    if data.starts_with(b"%PDF-") {
        return ("PDF document", false);
    }
    if data.starts_with(b"\x89PNG")
        || data.starts_with(&[0xFF, 0xD8, 0xFF])
        || data.starts_with(b"GIF8")
        || data.starts_with(b"BM")
    {
        return ("image", false);
    }
    let printable = head
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
        .count();
    if head.is_empty() || printable * 10 < head.len() * 9 {
        return ("binary data", false);
    }
    let text = String::from_utf8_lossy(head).to_ascii_lowercase();
    if text.contains("<hta:application") || text.contains("<script") {
        ("HTML application or script page (HTA)", true)
    } else if text.contains("powershell") || text.contains("invoke-") || text.contains("iex ") {
        ("PowerShell script", true)
    } else if text.contains("wscript") || text.contains("createobject(") {
        ("VBScript or JScript", true)
    } else if text.trim_start().starts_with("@echo") || text.contains("cmd /c") {
        ("batch script", true)
    } else {
        ("text", false)
    }
}

pub(super) fn inspect(bytes: &[u8]) -> DocumentReport {
    let toc = bytes.starts_with(&TOC_GUID);
    let mut report = DocumentReport::new(if toc {
        "OneNote table of contents"
    } else {
        "OneNote section"
    });
    report.notes.push(
        "embedded files are found by their FileDataStoreObject header; their names are \
         stored in property sets that are not decoded"
            .to_owned(),
    );

    let mut found = 0_usize;
    let mut risky = 0_usize;
    let mut overruns = 0_usize;
    let mut text_bytes = 0_usize;
    let mut position = 16;
    while let Some(offset) = bytes
        .get(position..)
        .and_then(|rest| rest.windows(16).position(|window| window == FILE_DATA_GUID))
    {
        let start = position + offset;
        position = start + 16;
        let Some(length) = bytes
            .get(start + 16..start + 24)
            .map(|raw| u64::from_le_bytes(raw.try_into().expect("8 bytes")))
        else {
            break;
        };
        let data_start = start + FILE_DATA_HEADER_BYTES;
        let Some(data) = usize::try_from(length)
            .ok()
            .and_then(|length| bytes.get(data_start..data_start.checked_add(length)?))
        else {
            overruns += 1;
            if overruns <= MAX_FLAGGED {
                report.suspicious_properties.push(format!(
                    "OneNote file data object at offset {start} declares {length} bytes beyond the end of the file"
                ));
            }
            continue;
        };
        position = data_start + data.len();
        found += 1;
        let (kind, suspicious) = classify(data);
        let sha256 = format!("{:x}", Sha256::digest(data));
        if found <= MAX_LISTED {
            report.property(
                &format!("Embedded file {found}"),
                format!("{kind}, {} bytes, SHA-256 {sha256}", data.len()),
            );
        }
        if suspicious {
            risky += 1;
            if risky <= MAX_FLAGGED {
                report.suspicious_properties.push(format!(
                    "OneNote notebook embeds a {kind} ({} bytes, SHA-256 {sha256}); lures hide such files behind fake buttons",
                    data.len()
                ));
            }
            let script =
                kind.contains("script") || kind.starts_with("VBScript") || kind.starts_with("HTML");
            if script && text_bytes + data.len() <= MAX_TEXT_BYTES {
                text_bytes += data.len();
                report
                    .extra_text
                    .push(String::from_utf8_lossy(data).into_owned());
            }
        }
    }
    for (count, what) in [
        (risky, "embedded payloads"),
        (overruns, "truncated file data objects"),
    ] {
        if count > MAX_FLAGGED {
            report.suspicious_properties.push(format!(
                "OneNote notebook has {} more {what} than the {MAX_FLAGGED} listed",
                count - MAX_FLAGGED
            ));
        }
    }
    report.property("Embedded files", found.to_string());
    if found > MAX_LISTED {
        report.notes.push(format!(
            "only the first {MAX_LISTED} embedded files are listed"
        ));
    }
    report.macros_present = Some(false);
    if risky > 0 {
        report.property("Embedded executable content", risky.to_string());
    }
    report
}

#[cfg(test)]
mod tests {
    use super::{FILE_DATA_GUID, SECTION_GUID, inspect, is_onenote};

    fn notebook(blobs: &[&[u8]]) -> Vec<u8> {
        let mut bytes = SECTION_GUID.to_vec();
        bytes.extend([0; 64]);
        for blob in blobs {
            bytes.extend(FILE_DATA_GUID);
            bytes.extend((blob.len() as u64).to_le_bytes());
            bytes.extend([0; 12]);
            bytes.extend(*blob);
            bytes.extend([0; 24]);
        }
        bytes
    }

    #[test]
    fn lists_embedded_files_and_flags_executable_content() {
        let script = b"@echo off\r\ncmd /c start https://files.example.net/a.txt\r\n";
        let bytes = notebook(&[b"\x89PNG\r\n\x1a\nimage", b"MZ\x90\0rest", script]);
        assert!(is_onenote(&bytes));
        let report = inspect(&bytes);
        let property = |name: &str| {
            report
                .properties
                .iter()
                .find(|property| property.name == name)
                .map(|property| property.value.clone())
                .unwrap_or_default()
        };
        assert_eq!(property("Embedded files"), "3");
        assert!(property("Embedded file 1").starts_with("image, 13 bytes"));
        assert!(property("Embedded file 2").starts_with("Windows executable (PE)"));
        assert_eq!(
            report.suspicious_properties.len(),
            2,
            "{:?}",
            report.suspicious_properties
        );
        assert!(report.suspicious_properties[1].contains("batch script"));
        assert!(
            report
                .analysis_text()
                .contains("https://files.example.net/a.txt")
        );
    }

    #[test]
    fn truncated_objects_are_reported_not_trusted() {
        let mut bytes = notebook(&[]);
        bytes.extend(FILE_DATA_GUID);
        bytes.extend(u64::MAX.to_le_bytes());
        let report = inspect(&bytes);
        assert!(report.suspicious_properties[0].contains("beyond the end of the file"));
        assert!(!is_onenote(b"not a notebook at all"));
    }

    #[test]
    fn many_tiny_payloads_are_summarized() {
        let blob: &[u8] = b"MZ";
        let blobs = vec![blob; 10_000];
        let report = inspect(&notebook(&blobs));
        assert_eq!(report.suspicious_properties.len(), 65);
        assert!(
            report.suspicious_properties[64].contains("9936 more embedded payloads"),
            "{}",
            report.suspicious_properties[64]
        );
        assert!(report.properties.len() < 80);
    }
}

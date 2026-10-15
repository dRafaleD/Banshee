use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};
use bzip2::read::MultiBzDecoder;
use flate2::read::MultiGzDecoder;
use serde::Serialize;
use sha2::{Digest, Sha256};
#[cfg(feature = "xz")]
use xz2::read::XzDecoder;

mod archive;
mod authenticode;
mod binary;
mod document;
mod dotnet;
mod elf;
mod macho;
mod ordinals;
mod pe;
mod pe_extra;
mod rtf;
mod script;

use archive::{inspect_tar, inspect_zip, is_tar, is_zip};
pub use authenticode::{AuthenticodeReport, CertificateSummary, NestedSigner};
pub use document::{DocumentProperty, DocumentReport, ExternalTarget};
pub use dotnet::DotNetReport;
use elf::inspect_elf;
use macho::inspect_macho;
use pe::inspect_pe;
pub use pe_extra::{RichEntry, RichHeader};

const MAX_INPUT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EXECUTABLE_SECTIONS: usize = 256;
const MAX_IMPORT_LIBRARIES: usize = 256;
const MAX_IMPORT_SYMBOLS: usize = 4_096;
const MAX_EXPORTS: usize = 4_096;
const MAX_EXECUTABLE_STRING_BYTES: usize = 1_024;

#[derive(Debug, Clone, Serialize)]
pub struct FileReport {
    pub path: String,
    pub size: usize,
    pub format: String,
    pub sha256: String,
    pub compression: Option<CompressionReport>,
    pub archive: Option<ArchiveReport>,
    pub executable: Option<ExecutableReport>,
    /// Office, PDF or shortcut structure; omitted for other formats.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<DocumentReport>,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompressionReport {
    pub algorithm: String,
    pub compressed_bytes: usize,
    pub decompressed_bytes: usize,
    pub payload_format: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveReport {
    pub total_entries: usize,
    pub total_size: u64,
    pub truncated: bool,
    pub entries: Vec<ArchiveEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveEntry {
    pub name: String,
    pub kind: String,
    pub size: u64,
    pub compressed_size: Option<u64>,
    pub encrypted: bool,
    pub path_safe: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExecutableReport {
    pub format: String,
    pub architecture: String,
    pub bits: u8,
    pub endianness: Option<String>,
    pub kind: String,
    pub entry_point: String,
    pub sections: u16,
    pub subsystem: Option<String>,
    pub timestamp: Option<u32>,
    pub section_details: Vec<ExecutableSection>,
    pub sections_truncated: bool,
    pub imports: Vec<ImportLibrary>,
    pub imports_truncated: bool,
    pub exports: Vec<String>,
    pub exports_truncated: bool,
    pub overlay: Option<OverlayReport>,
    pub signature_present: Option<bool>,
    pub interpreter: Option<String>,
    pub needed_libraries: Vec<String>,
    pub needed_libraries_truncated: bool,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
    pub stripped: Option<bool>,
    pub debug_info_present: Option<bool>,
    pub parse_warnings: Vec<String>,
    pub suspicious_properties: Vec<String>,
    /// pefile-compatible import hash; omitted when imports are incomplete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imphash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rich_header: Option<RichHeader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_callbacks: Option<usize>,
    /// Architectures of a Mach-O universal binary; details describe the first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub universal_architectures: Vec<String>,
    /// CLI metadata of a managed (.NET) PE file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dotnet: Option<DotNetReport>,
    /// Authenticode certificate details (not verified).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticode: Option<AuthenticodeReport>,
}

impl ExecutableReport {
    fn is_macho(&self) -> bool {
        self.format == "Mach-O"
    }

    /// Label for `signature_present`, which means different things per format.
    pub fn signature_label(&self) -> &'static str {
        if self.is_macho() {
            "Code signature present"
        } else {
            "PE certificate table present"
        }
    }

    /// Label for `interpreter`.
    pub fn interpreter_label(&self) -> &'static str {
        if self.is_macho() {
            "Dynamic linker"
        } else {
            "ELF interpreter"
        }
    }

    /// Label for the `needed_libraries` count.
    pub fn dependencies_label(&self) -> &'static str {
        if self.is_macho() {
            "Mach-O linked libraries"
        } else {
            "ELF dynamic dependencies"
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ExecutableSection {
    pub name: String,
    pub virtual_address: String,
    pub file_offset: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub readable: Option<bool>,
    pub allocated: Option<bool>,
    pub writable: bool,
    pub executable: bool,
    /// Shannon entropy of the section's file data in bits per byte.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportLibrary {
    pub name: String,
    pub symbols: Vec<String>,
    pub symbols_truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct OverlayReport {
    pub offset: u64,
    pub size: u64,
    pub includes_certificate_table: bool,
}

pub fn inspect_file(path: &Path, max_entries: usize) -> Result<FileReport> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to inspect '{}'", path.display()))?;
    if !metadata.is_file() {
        bail!("'{}' is not a regular file", path.display());
    }
    if metadata.len() > MAX_INPUT_BYTES {
        bail!("file exceeds the 256 MiB inspection limit");
    }
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open '{}'", path.display()))?;
    let bytes = read_bounded(
        file,
        MAX_INPUT_BYTES,
        "file exceeds the 256 MiB inspection limit",
    )
    .with_context(|| format!("failed to read '{}'", path.display()))?;
    inspect_bytes(&bytes, path.display().to_string(), max_entries)
}

pub fn inspect_bytes(bytes: &[u8], path: String, max_entries: usize) -> Result<FileReport> {
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        bail!("file exceeds the 256 MiB inspection limit");
    }
    if max_entries == 0 {
        bail!("max_entries must be greater than zero");
    }
    let mut report = FileReport {
        path,
        size: bytes.len(),
        format: "unknown".to_owned(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
        compression: None,
        archive: None,
        executable: None,
        document: None,
        findings: Vec::new(),
    };

    if is_zip(bytes) {
        report.format = "ZIP archive".to_owned();
        report.archive = Some(inspect_zip(bytes, max_entries, &mut report.findings)?);
        if let Some(document) = document::inspect_ooxml(bytes) {
            report.format = document.kind.clone();
            attach_document(&mut report, document);
        }
    } else if document::is_ole(bytes) {
        let document = document::inspect_ole(bytes);
        report.format = document.kind.clone();
        attach_document(&mut report, document);
    } else if document::is_lnk(bytes) {
        report.format = "Windows shortcut (LNK)".to_owned();
        let document = document::inspect_lnk(bytes)?;
        attach_document(&mut report, document);
    } else if is_tar(bytes) {
        report.format = "TAR archive".to_owned();
        report.archive = Some(inspect_tar(bytes, max_entries, &mut report.findings)?);
    } else if bytes.starts_with(&[0x1F, 0x8B]) {
        inspect_compressed(
            bytes,
            "gzip",
            MultiGzDecoder::new(bytes),
            max_entries,
            &mut report,
        )?;
    } else if bytes.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        #[cfg(feature = "xz")]
        inspect_compressed(bytes, "XZ", XzDecoder::new(bytes), max_entries, &mut report)?;
        #[cfg(not(feature = "xz"))]
        {
            report.format =
                "XZ compressed data (decompression not available in this build)".to_owned();
        }
    } else if bytes.starts_with(b"BZh") {
        inspect_compressed(
            bytes,
            "BZip2",
            MultiBzDecoder::new(bytes),
            max_entries,
            &mut report,
        )?;
    } else if let Some(executable) = inspect_elf(bytes)? {
        report.format = "ELF executable".to_owned();
        attach_executable(&mut report, executable);
    } else if let Some(executable) = inspect_pe(bytes)? {
        report.format = if executable.dotnet.is_some() {
            "PE executable (.NET)".to_owned()
        } else {
            "PE executable".to_owned()
        };
        attach_executable(&mut report, executable);
    } else if let Some(executable) = inspect_macho(bytes)? {
        report.format = if executable.universal_architectures.is_empty() {
            "Mach-O executable".to_owned()
        } else {
            format!(
                "Mach-O universal binary ({})",
                executable.universal_architectures.join(", ")
            )
        };
        attach_executable(&mut report, executable);
    } else if document::is_pdf(bytes) {
        report.format = "PDF document".to_owned();
        attach_document(&mut report, document::inspect_pdf(bytes));
    } else if rtf::is_rtf(bytes) {
        report.format = "RTF document".to_owned();
        attach_document(&mut report, rtf::inspect_rtf(bytes));
    } else if let Some(language) = script::language(&report.path)
        && let Some(document) = script::inspect(bytes, language)
    {
        report.format = document.kind.clone();
        attach_document(&mut report, document);
    }

    Ok(report)
}

fn inspect_compressed<R: Read>(
    original: &[u8],
    algorithm: &str,
    decoder: R,
    max_entries: usize,
    report: &mut FileReport,
) -> Result<()> {
    let payload = read_limited(decoder)
        .with_context(|| format!("invalid or unreadable {algorithm} stream"))?;
    let payload_format = detect_payload_format(&payload);
    report.format = if is_tar(&payload) {
        format!("{algorithm}-compressed TAR archive")
    } else {
        format!("{algorithm} stream")
    };
    report.compression = Some(CompressionReport {
        algorithm: algorithm.to_owned(),
        compressed_bytes: original.len(),
        decompressed_bytes: payload.len(),
        payload_format: payload_format.clone(),
    });
    if is_tar(&payload) {
        report.archive = Some(inspect_tar(&payload, max_entries, &mut report.findings)?);
    } else if let Some(executable) = inspect_elf(&payload)? {
        attach_executable(report, executable);
    } else if let Some(executable) = inspect_pe(&payload)? {
        attach_executable(report, executable);
    } else if let Some(executable) = inspect_macho(&payload)? {
        attach_executable(report, executable);
    }
    Ok(())
}

fn attach_document(report: &mut FileReport, document: DocumentReport) {
    report
        .findings
        .extend(document.suspicious_properties.iter().cloned());
    report.document = Some(document);
}

fn attach_executable(report: &mut FileReport, executable: ExecutableReport) {
    report
        .findings
        .extend(executable.suspicious_properties.iter().cloned());
    report.executable = Some(executable);
}

fn read_limited<R: Read>(reader: R) -> Result<Vec<u8>> {
    read_bounded(
        reader,
        MAX_DECOMPRESSED_BYTES,
        "decompressed payload exceeds the 64 MiB safety limit",
    )
}

fn read_bounded<R: Read>(reader: R, limit: u64, limit_message: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    reader.take(limit + 1).read_to_end(&mut output)?;
    if output.len() as u64 > limit {
        bail!("{limit_message}");
    }
    Ok(output)
}

fn detect_payload_format(bytes: &[u8]) -> String {
    if is_tar(bytes) {
        "TAR archive"
    } else if bytes.starts_with(b"\x7FELF") {
        "ELF executable"
    } else if bytes.starts_with(b"MZ") {
        "PE/DOS executable"
    } else if std::str::from_utf8(bytes).is_ok() {
        "UTF-8 text"
    } else {
        "binary data"
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use bzip2::Compression as BzipCompression;
    use bzip2::write::BzEncoder;
    #[cfg(feature = "xz")]
    use xz2::write::XzEncoder;
    use zip::write::SimpleFileOptions;

    use super::archive::archive_path_is_safe;
    use super::inspect_bytes;

    #[test]
    fn bounded_read_accepts_exact_limit_and_stops_after_first_excess_byte() {
        let mut input = Cursor::new(b"1234567890123456".as_slice());
        let error = super::read_bounded(&mut input, 8, "fixture exceeds limit")
            .expect_err("reject oversized stream");
        assert_eq!(input.position(), 9);
        assert!(error.to_string().contains("fixture exceeds limit"));
        assert_eq!(
            super::read_bounded(Cursor::new(b"12345678"), 8, "too large").unwrap(),
            b"12345678"
        );
    }

    #[test]
    fn memory_inspection_rejects_oversized_input_before_hashing() {
        let bytes = vec![0_u8; super::MAX_INPUT_BYTES as usize + 1];
        let error = inspect_bytes(&bytes, "synthetic".into(), 1).unwrap_err();
        assert!(error.to_string().contains("256 MiB"));
    }

    #[test]
    fn compressed_payload_limit_is_enforced_for_high_expansion_gzip() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let chunk = [0_u8; 64 * 1024];
        for _ in 0..super::MAX_DECOMPRESSED_BYTES / chunk.len() as u64 {
            encoder.write_all(&chunk).unwrap();
        }
        encoder.write_all(b"x").unwrap();
        let compressed = encoder.finish().unwrap();
        let error = inspect_bytes(&compressed, "synthetic.gz".into(), 1).unwrap_err();
        assert!(format!("{error:#}").contains("64 MiB safety limit"));
    }

    #[cfg(feature = "xz")]
    #[test]
    fn synthetic_parser_mutations_and_truncations_do_not_panic() {
        let tar = tar_fixture();
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        zip.start_file("synthetic.txt", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"safe fixture").unwrap();
        let zip = zip.finish().unwrap().into_inner();
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzip.write_all(&tar).unwrap();
        let gzip = gzip.finish().unwrap();
        let mut bzip = BzEncoder::new(Vec::new(), BzipCompression::fast());
        bzip.write_all(&tar).unwrap();
        let bzip = bzip.finish().unwrap();
        let mut xz = XzEncoder::new(Vec::new(), 1);
        xz.write_all(&tar).unwrap();
        let xz = xz.finish().unwrap();
        for (name, seed) in [
            ("pe", pe64_fixture()),
            ("elf", elf64_fixture()),
            ("tar", tar),
            ("zip", zip),
            ("gzip", gzip),
            ("bzip2", bzip),
            ("xz", xz),
        ] {
            assert!(inspect_bytes(&seed, name.into(), 2).is_ok(), "seed {name}");
            for length in (0..seed.len()).step_by((seed.len() / 128).max(1)) {
                assert_parser_bounds(&seed[..length], name);
            }
            for offset in (0..seed.len()).step_by((seed.len() / 128).max(1)) {
                for replacement in [0_u8, 0x7f, 0xff] {
                    let mut mutated = seed.clone();
                    let end = (offset + 8).min(mutated.len());
                    mutated[offset..end].fill(replacement);
                    assert_parser_bounds(&mutated, name);
                }
            }
        }
    }

    #[cfg(feature = "xz")]
    fn assert_parser_bounds(bytes: &[u8], name: &str) {
        if let Ok(report) = inspect_bytes(bytes, name.into(), 2) {
            assert_eq!(report.size, bytes.len());
            if let Some(archive) = report.archive {
                assert!(archive.entries.len() <= 2);
                assert!(archive.total_entries >= archive.entries.len());
            }
            if let Some(compression) = report.compression {
                assert!(compression.decompressed_bytes as u64 <= super::MAX_DECOMPRESSED_BYTES);
            }
            if let Some(executable) = report.executable {
                assert!(executable.section_details.len() <= super::MAX_EXECUTABLE_SECTIONS);
                assert!(executable.imports.len() <= super::MAX_IMPORT_LIBRARIES);
                assert!(
                    executable
                        .imports
                        .iter()
                        .map(|library| library.symbols.len())
                        .sum::<usize>()
                        <= super::MAX_IMPORT_SYMBOLS
                );
                assert!(executable.exports.len() <= super::MAX_EXPORTS);
            }
        }
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn pe64_fixture() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x680];
        bytes[..2].copy_from_slice(b"MZ");
        put_u32(&mut bytes, 0x3c, 0x80);
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        put_u16(&mut bytes, 0x84, 0x8664);
        put_u16(&mut bytes, 0x86, 2);
        put_u16(&mut bytes, 0x94, 0xf0);

        let optional = 0x98;
        put_u16(&mut bytes, optional, 0x20b);
        put_u32(&mut bytes, optional + 16, 0x1000);
        put_u32(&mut bytes, optional + 60, 0x200);
        put_u16(&mut bytes, optional + 68, 3);
        put_u32(&mut bytes, optional + 108, 16);
        put_u32(&mut bytes, optional + 112, 0x20a0);
        put_u32(&mut bytes, optional + 116, 0x40);
        put_u32(&mut bytes, optional + 120, 0x2000);
        put_u32(&mut bytes, optional + 124, 0x28);
        put_u32(&mut bytes, optional + 144, 0x600);
        put_u32(&mut bytes, optional + 148, 0x80);

        let text = 0x188;
        bytes[text..text + 8].copy_from_slice(b".text\0\0\0");
        put_u32(&mut bytes, text + 8, 0x100);
        put_u32(&mut bytes, text + 12, 0x1000);
        put_u32(&mut bytes, text + 16, 0x200);
        put_u32(&mut bytes, text + 20, 0x200);
        put_u32(&mut bytes, text + 36, 0x6000_0020);

        let idata = text + 40;
        bytes[idata..idata + 8].copy_from_slice(b".idata\0\0");
        put_u32(&mut bytes, idata + 8, 0x200);
        put_u32(&mut bytes, idata + 12, 0x2000);
        put_u32(&mut bytes, idata + 16, 0x200);
        put_u32(&mut bytes, idata + 20, 0x400);
        put_u32(&mut bytes, idata + 36, 0xc000_0040);

        put_u32(&mut bytes, 0x400, 0x2040);
        put_u32(&mut bytes, 0x40c, 0x2060);
        put_u32(&mut bytes, 0x410, 0x2040);
        put_u64(&mut bytes, 0x440, 0x2080);
        bytes[0x460..0x46d].copy_from_slice(b"KERNEL32.dll\0");
        bytes[0x482..0x48e].copy_from_slice(b"CreateFileW\0");

        put_u32(&mut bytes, 0x4a0 + 24, 1);
        put_u32(&mut bytes, 0x4a0 + 32, 0x20d0);
        put_u32(&mut bytes, 0x4d0, 0x20e0);
        bytes[0x4e0..0x4e9].copy_from_slice(b"Exported\0");
        bytes
    }

    fn elf64_fixture() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x600];
        bytes[..6].copy_from_slice(b"\x7FELF\x02\x01");
        put_u16(&mut bytes, 16, 3);
        put_u16(&mut bytes, 18, 0x3e);
        put_u64(&mut bytes, 24, 0x400220);
        put_u64(&mut bytes, 32, 0x40);
        put_u64(&mut bytes, 40, 0x300);
        put_u16(&mut bytes, 54, 56);
        put_u16(&mut bytes, 56, 3);
        put_u16(&mut bytes, 58, 64);
        put_u16(&mut bytes, 60, 5);
        put_u16(&mut bytes, 62, 4);

        put_u32(&mut bytes, 0x40, 1);
        put_u32(&mut bytes, 0x44, 5);
        put_u64(&mut bytes, 0x50, 0x400000);
        put_u64(&mut bytes, 0x60, 0x600);

        put_u32(&mut bytes, 0x78, 3);
        put_u32(&mut bytes, 0x7c, 4);
        put_u64(&mut bytes, 0x80, 0x180);
        put_u64(&mut bytes, 0x98, 28);

        put_u32(&mut bytes, 0xb0, 2);
        put_u32(&mut bytes, 0xb4, 6);
        put_u64(&mut bytes, 0xb8, 0x1c0);
        put_u64(&mut bytes, 0xc0, 0x4001c0);
        put_u64(&mut bytes, 0xd0, 96);

        bytes[0x180..0x19c].copy_from_slice(b"/lib64/ld-linux-x86-64.so.2\0");
        for (index, (tag, value)) in [
            (5_u64, 0x400260_u64),
            (10, 28),
            (1, 1),
            (15, 11),
            (29, 20),
            (0, 0),
        ]
        .into_iter()
        .enumerate()
        {
            put_u64(&mut bytes, 0x1c0 + index * 16, tag);
            put_u64(&mut bytes, 0x1c8 + index * 16, value);
        }
        bytes[0x260..0x27c].copy_from_slice(b"\0libc.so.6\0/tmp/lib\0$ORIGIN\0");

        for (index, (name, kind, flags, address, offset, size)) in [
            (0_u32, 0_u32, 0_u64, 0_u64, 0_u64, 0_u64),
            (1, 1, 6, 0x400220, 0x220, 0x20),
            (7, 1, 3, 0x400240, 0x240, 0x20),
            (13, 1, 0, 0, 0x280, 0x10),
            (25, 3, 0, 0, 0x500, 35),
        ]
        .into_iter()
        .enumerate()
        {
            let section = 0x300 + index * 64;
            put_u32(&mut bytes, section, name);
            put_u32(&mut bytes, section + 4, kind);
            put_u64(&mut bytes, section + 8, flags);
            put_u64(&mut bytes, section + 16, address);
            put_u64(&mut bytes, section + 24, offset);
            put_u64(&mut bytes, section + 32, size);
        }
        bytes[0x500..0x523].copy_from_slice(b"\0.text\0.data\0.debug_info\0.shstrtab\0");
        bytes
    }

    #[test]
    fn recognizes_elf64_header() {
        let mut bytes = vec![0_u8; 64];
        bytes[..6].copy_from_slice(b"\x7FELF\x02\x01");
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&0x3E_u16.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x401000_u64.to_le_bytes());
        bytes[60..62].copy_from_slice(&12_u16.to_le_bytes());
        let report = inspect_bytes(&bytes, "fixture".to_owned(), 100).expect("inspect");
        let executable = report.executable.expect("executable");
        assert_eq!(report.format, "ELF executable");
        assert_eq!(executable.architecture, "x86-64");
        assert_eq!(executable.entry_point, "0x401000");
        assert_eq!(executable.sections, 12);
    }

    #[test]
    fn recognizes_pe32_plus_header() {
        let mut bytes = vec![0_u8; 512];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3C..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&5_u16.to_le_bytes());
        bytes[0x98..0x9A].copy_from_slice(&0x20B_u16.to_le_bytes());
        bytes[0xA8..0xAC].copy_from_slice(&0x1234_u32.to_le_bytes());
        bytes[0xDC..0xDE].copy_from_slice(&3_u16.to_le_bytes());
        let report = inspect_bytes(&bytes, "fixture.exe".to_owned(), 100).expect("inspect");
        let executable = report.executable.expect("executable");
        assert_eq!(executable.architecture, "x86-64");
        assert_eq!(executable.subsystem.as_deref(), Some("Windows console"));
    }

    #[test]
    fn parses_bounded_pe_metadata_without_treating_certificate_as_a_verdict() {
        let report = inspect_bytes(&pe64_fixture(), "fixture.exe".to_owned(), 100)
            .expect("inspect PE fixture");
        let executable = report.executable.expect("executable");
        assert_eq!(executable.section_details.len(), 2);
        assert_eq!(executable.imports[0].name, "KERNEL32.dll");
        assert_eq!(executable.imports[0].symbols, ["CreateFileW"]);
        assert_eq!(executable.exports, ["Exported"]);
        assert_eq!(executable.signature_present, Some(true));
        assert!(
            executable
                .overlay
                .as_ref()
                .is_some_and(|overlay| overlay.includes_certificate_table)
        );
        assert!(executable.suspicious_properties.is_empty());
        // The fixture's certificate table is filler, so only the Authenticode
        // reader may complain about it.
        assert!(
            executable
                .parse_warnings
                .iter()
                .all(|warning| warning.contains("PKCS#7")),
            "{:?}",
            executable.parse_warnings
        );
        assert!(executable.authenticode.is_none());
    }

    #[test]
    fn separates_pe_suspicious_properties_from_parser_warnings() {
        let mut suspicious = pe64_fixture();
        suspicious[0x188..0x190].copy_from_slice(b"UPX0\0\0\0\0");
        put_u32(&mut suspicious, 0x188 + 36, 0xe000_0020);
        suspicious.resize(0x700, 0);
        let report = inspect_bytes(&suspicious, "edge.exe".to_owned(), 100)
            .expect("inspect suspicious PE fixture");
        let executable = report.executable.expect("executable");
        assert!(
            executable
                .suspicious_properties
                .iter()
                .any(|finding| finding.contains("writable and executable"))
        );
        assert!(
            executable
                .suspicious_properties
                .iter()
                .any(|finding| finding.contains("packer-associated"))
        );
        assert!(
            executable
                .suspicious_properties
                .iter()
                .any(|finding| finding.contains("after mapped section data"))
        );

        let mut malformed = pe64_fixture();
        put_u32(&mut malformed, 0x98 + 120, 0x9000);
        let report = inspect_bytes(&malformed, "malformed.exe".to_owned(), 100)
            .expect("inspect malformed PE fixture");
        let executable = report.executable.expect("executable");
        assert!(executable.suspicious_properties.is_empty());
        assert!(
            executable
                .parse_warnings
                .iter()
                .any(|warning| warning.contains("import directory RVA"))
        );
        assert!(report.findings.is_empty());
    }

    #[test]
    fn marks_pe_section_output_truncation_explicitly() {
        let mut bytes = pe64_fixture();
        put_u16(&mut bytes, 0x86, 300);
        let report =
            inspect_bytes(&bytes, "many-sections.exe".to_owned(), 100).expect("inspect PE fixture");
        let executable = report.executable.expect("executable");
        assert!(executable.sections_truncated);
        assert!(
            executable
                .parse_warnings
                .iter()
                .any(|warning| warning.contains("section table is truncated"))
        );
    }

    #[test]
    fn parses_elf_interpreter_dependencies_paths_and_debug_state() {
        let report = inspect_bytes(&elf64_fixture(), "fixture.elf".to_owned(), 100)
            .expect("inspect ELF fixture");
        let executable = report.executable.expect("executable");
        assert_eq!(
            executable.interpreter.as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
        assert_eq!(executable.needed_libraries, ["libc.so.6"]);
        assert_eq!(executable.rpath.as_deref(), Some("/tmp/lib"));
        assert_eq!(executable.runpath.as_deref(), Some("$ORIGIN"));
        assert_eq!(executable.stripped, Some(true));
        assert_eq!(executable.debug_info_present, Some(true));
        assert_eq!(executable.section_details.len(), 5);
        assert!(executable.suspicious_properties.is_empty());
        assert!(executable.parse_warnings.is_empty());
    }

    #[test]
    fn reports_elf_writable_executable_sections_as_explainable_findings() {
        let mut bytes = elf64_fixture();
        put_u64(&mut bytes, 0x300 + 64 + 8, 7);
        let report =
            inspect_bytes(&bytes, "edge.elf".to_owned(), 100).expect("inspect ELF fixture");
        let executable = report.executable.expect("executable");
        assert!(
            executable
                .suspicious_properties
                .iter()
                .any(|finding| finding.contains("section '.text' is writable and executable"))
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.contains("section '.text' is writable and executable"))
        );
    }

    #[test]
    fn rejects_archive_traversal_paths() {
        assert!(archive_path_is_safe("folder/file.txt"));
        assert!(!archive_path_is_safe("../outside.txt"));
        assert!(!archive_path_is_safe("..\\outside.txt"));
        assert!(!archive_path_is_safe("/absolute/path"));
    }

    #[test]
    fn lists_zip_entries_without_extracting_them() {
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .start_file("folder/hello.txt", SimpleFileOptions::default())
            .expect("start ZIP file");
        writer.write_all(b"hello").expect("write ZIP entry");
        let bytes = writer.finish().expect("finish ZIP").into_inner();

        let report = inspect_bytes(&bytes, "fixture.zip".to_owned(), 100).expect("inspect");
        let archive = report.archive.expect("archive");
        assert_eq!(report.format, "ZIP archive");
        assert_eq!(archive.total_entries, 1);
        assert_eq!(archive.entries[0].name, "folder/hello.txt");
        assert_eq!(archive.entries[0].size, 5);
    }

    #[cfg(feature = "xz")]
    #[test]
    fn recognizes_compressed_tar_and_bounded_entry_listing() {
        let tar = tar_fixture();
        let mut encoder = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(&tar).expect("compress XZ");
        let xz = encoder.finish().expect("finish XZ");

        let report = inspect_bytes(&xz, "fixture.tar.xz".to_owned(), 1).expect("inspect");
        assert_eq!(report.format, "XZ-compressed TAR archive");
        assert_eq!(
            report.compression.expect("compression").payload_format,
            "TAR archive"
        );
        assert_eq!(report.archive.expect("archive").entries.len(), 1);
    }

    #[test]
    fn recognizes_bzip2_text_payload() {
        let mut encoder = BzEncoder::new(Vec::new(), BzipCompression::best());
        encoder.write_all(b"hello banshee").expect("compress BZip2");
        let bytes = encoder.finish().expect("finish BZip2");

        let report = inspect_bytes(&bytes, "fixture.bz2".to_owned(), 10).expect("inspect");
        let compression = report.compression.expect("compression");
        assert_eq!(report.format, "BZip2 stream");
        assert_eq!(compression.payload_format, "UTF-8 text");
        assert_eq!(compression.decompressed_bytes, 13);
    }

    #[cfg(feature = "xz")]
    fn tar_fixture() -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, value) in [
            ("first.txt", b"one".as_slice()),
            ("second.txt", b"two".as_slice()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(value.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, name, value)
                .expect("append TAR entry");
        }
        builder.into_inner().expect("finish TAR")
    }
}

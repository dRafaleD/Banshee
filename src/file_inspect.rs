use std::io::{Cursor, Read};
use std::path::{Component, Path};

use anyhow::{Context, Result, bail};
use bzip2::read::MultiBzDecoder;
use flate2::read::MultiGzDecoder;
use serde::Serialize;
use sha2::{Digest, Sha256};
use xz2::read::XzDecoder;

const MAX_INPUT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct FileReport {
    pub path: String,
    pub size: usize,
    pub format: String,
    pub sha256: String,
    pub compression: Option<CompressionReport>,
    pub archive: Option<ArchiveReport>,
    pub executable: Option<ExecutableReport>,
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
    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read '{}'", path.display()))?;
    inspect_bytes(&bytes, path.display().to_string(), max_entries)
}

pub fn inspect_bytes(bytes: &[u8], path: String, max_entries: usize) -> Result<FileReport> {
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
        findings: Vec::new(),
    };

    if is_zip(bytes) {
        report.format = "ZIP archive".to_owned();
        report.archive = Some(inspect_zip(bytes, max_entries, &mut report.findings)?);
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
        inspect_compressed(bytes, "XZ", XzDecoder::new(bytes), max_entries, &mut report)?;
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
        report.executable = Some(executable);
    } else if let Some(executable) = inspect_pe(bytes)? {
        report.format = "PE executable".to_owned();
        report.executable = Some(executable);
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
        report.executable = Some(executable);
    } else if let Some(executable) = inspect_pe(&payload)? {
        report.executable = Some(executable);
    }
    Ok(())
}

fn read_limited<R: Read>(reader: R) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    reader
        .take(MAX_DECOMPRESSED_BYTES + 1)
        .read_to_end(&mut output)?;
    if output.len() as u64 > MAX_DECOMPRESSED_BYTES {
        bail!("decompressed payload exceeds the 64 MiB safety limit");
    }
    Ok(output)
}

fn inspect_zip(
    bytes: &[u8],
    max_entries: usize,
    findings: &mut Vec<String>,
) -> Result<ArchiveReport> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).context("invalid ZIP archive")?;
    let total_entries = zip.len();
    let known_total_size = zip
        .decompressed_size()
        .and_then(|size| u64::try_from(size).ok());
    let listed = total_entries.min(max_entries);
    let mut entries = Vec::with_capacity(listed);
    let mut listed_size = 0_u64;
    for index in 0..listed {
        let entry = zip
            .by_index(index)
            .with_context(|| format!("failed to read ZIP entry {index}"))?;
        let name = entry.name().to_owned();
        let path_safe = archive_path_is_safe(&name);
        if !path_safe {
            findings.push(format!("unsafe archive path: {name}"));
        }
        if entry.encrypted() {
            findings.push(format!("encrypted ZIP entry: {name}"));
        }
        listed_size = listed_size.saturating_add(entry.size());
        entries.push(ArchiveEntry {
            name,
            kind: if entry.is_dir() { "directory" } else { "file" }.to_owned(),
            size: entry.size(),
            compressed_size: Some(entry.compressed_size()),
            encrypted: entry.encrypted(),
            path_safe,
        });
    }
    Ok(ArchiveReport {
        total_entries,
        total_size: known_total_size.unwrap_or(listed_size),
        truncated: total_entries > max_entries,
        entries,
    })
}

fn inspect_tar(
    bytes: &[u8],
    max_entries: usize,
    findings: &mut Vec<String>,
) -> Result<ArchiveReport> {
    let mut tar = tar::Archive::new(Cursor::new(bytes));
    let mut entries = Vec::new();
    let mut total_entries = 0_usize;
    let mut total_size = 0_u64;
    let mut truncated = false;
    for item in tar.entries().context("invalid TAR archive")? {
        let entry = item.context("failed to read TAR entry")?;
        total_entries += 1;
        let size = entry.header().size().context("invalid TAR entry size")?;
        total_size = total_size.saturating_add(size);
        if entries.len() >= max_entries {
            truncated = true;
            continue;
        }
        let name = entry
            .path()
            .context("invalid TAR entry path")?
            .to_string_lossy()
            .into_owned();
        let path_safe = archive_path_is_safe(&name);
        if !path_safe {
            findings.push(format!("unsafe archive path: {name}"));
        }
        let entry_type = entry.header().entry_type();
        let kind = if entry_type.is_dir() {
            "directory"
        } else if entry_type.is_symlink() {
            "symlink"
        } else if entry_type.is_hard_link() {
            "hardlink"
        } else if entry_type.is_file() {
            "file"
        } else {
            "other"
        };
        entries.push(ArchiveEntry {
            name,
            kind: kind.to_owned(),
            size,
            compressed_size: None,
            encrypted: false,
            path_safe,
        });
    }
    Ok(ArchiveReport {
        total_entries,
        total_size,
        truncated,
        entries,
    })
}

fn archive_path_is_safe(name: &str) -> bool {
    if name.is_empty() || name.contains('\0') {
        return false;
    }
    let normalized = name.replace('\\', "/");
    !normalized.starts_with('/')
        && Path::new(&normalized)
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn is_zip(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(..4),
        Some(b"PK\x03\x04" | b"PK\x05\x06" | b"PK\x07\x08")
    )
}

fn is_tar(bytes: &[u8]) -> bool {
    matches!(bytes.get(257..262), Some(b"ustar"))
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

fn inspect_elf(bytes: &[u8]) -> Result<Option<ExecutableReport>> {
    if !bytes.starts_with(b"\x7FELF") {
        return Ok(None);
    }
    if bytes.len() < 52 {
        bail!("truncated ELF header");
    }
    let bits = match bytes[4] {
        1 => 32,
        2 => 64,
        _ => bail!("invalid ELF class"),
    };
    let little = match bytes[5] {
        1 => true,
        2 => false,
        _ => bail!("invalid ELF endianness"),
    };
    let kind_value = read_u16(bytes, 16, little).context("truncated ELF type")?;
    let machine = read_u16(bytes, 18, little).context("truncated ELF machine")?;
    let (entry, sections) = if bits == 32 {
        (
            u64::from(read_u32(bytes, 24, little).context("truncated ELF entry point")?),
            read_u16(bytes, 48, little).context("truncated ELF section count")?,
        )
    } else {
        if bytes.len() < 64 {
            bail!("truncated ELF64 header");
        }
        (
            read_u64(bytes, 24, little).context("truncated ELF entry point")?,
            read_u16(bytes, 60, little).context("truncated ELF section count")?,
        )
    };
    Ok(Some(ExecutableReport {
        format: "ELF".to_owned(),
        architecture: elf_machine(machine),
        bits,
        endianness: Some(if little { "little" } else { "big" }.to_owned()),
        kind: match kind_value {
            1 => "relocatable",
            2 => "executable",
            3 => "shared object",
            4 => "core dump",
            _ => "unknown",
        }
        .to_owned(),
        entry_point: format!("0x{entry:X}"),
        sections,
        subsystem: None,
        timestamp: None,
    }))
}

fn inspect_pe(bytes: &[u8]) -> Result<Option<ExecutableReport>> {
    if !bytes.starts_with(b"MZ") {
        return Ok(None);
    }
    let pe_offset = read_u32(bytes, 0x3C, true).context("truncated DOS/PE header")? as usize;
    if bytes.get(pe_offset..pe_offset.saturating_add(4)) != Some(b"PE\0\0") {
        bail!("DOS MZ header does not point to a valid PE signature");
    }
    let machine = read_u16(bytes, pe_offset + 4, true).context("truncated PE COFF header")?;
    let sections = read_u16(bytes, pe_offset + 6, true).context("truncated PE section count")?;
    let timestamp = read_u32(bytes, pe_offset + 8, true).context("truncated PE timestamp")?;
    let optional = pe_offset.checked_add(24).context("invalid PE offset")?;
    let magic = read_u16(bytes, optional, true).context("truncated PE optional header")?;
    let bits = match magic {
        0x10B => 32,
        0x20B => 64,
        _ => bail!("unsupported PE optional-header magic 0x{magic:04X}"),
    };
    let entry = read_u32(bytes, optional + 16, true).context("truncated PE entry point")?;
    let subsystem = read_u16(bytes, optional + 68, true).context("truncated PE subsystem")?;
    Ok(Some(ExecutableReport {
        format: "PE".to_owned(),
        architecture: pe_machine(machine),
        bits,
        endianness: Some("little".to_owned()),
        kind: "executable image".to_owned(),
        entry_point: format!("RVA 0x{entry:X}"),
        sections,
        subsystem: Some(pe_subsystem(subsystem)),
        timestamp: Some(timestamp),
    }))
}

fn read_u16(bytes: &[u8], offset: usize, little: bool) -> Option<u16> {
    let value: [u8; 2] = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(if little {
        u16::from_le_bytes(value)
    } else {
        u16::from_be_bytes(value)
    })
}

fn read_u32(bytes: &[u8], offset: usize, little: bool) -> Option<u32> {
    let value: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(if little {
        u32::from_le_bytes(value)
    } else {
        u32::from_be_bytes(value)
    })
}

fn read_u64(bytes: &[u8], offset: usize, little: bool) -> Option<u64> {
    let value: [u8; 8] = bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(if little {
        u64::from_le_bytes(value)
    } else {
        u64::from_be_bytes(value)
    })
}

fn elf_machine(machine: u16) -> String {
    match machine {
        0x03 => "x86",
        0x08 => "MIPS",
        0x14 => "PowerPC",
        0x28 => "ARM",
        0x3E => "x86-64",
        0xB7 => "AArch64",
        0xF3 => "RISC-V",
        _ => return format!("unknown (0x{machine:04X})"),
    }
    .to_owned()
}

fn pe_machine(machine: u16) -> String {
    match machine {
        0x014C => "x86",
        0x01C0 | 0x01C4 => "ARM",
        0x8664 => "x86-64",
        0xAA64 => "AArch64",
        0x5064 => "RISC-V 64",
        _ => return format!("unknown (0x{machine:04X})"),
    }
    .to_owned()
}

fn pe_subsystem(subsystem: u16) -> String {
    match subsystem {
        1 => "native",
        2 => "Windows GUI",
        3 => "Windows console",
        7 => "POSIX console",
        9 => "Windows CE GUI",
        10 => "EFI application",
        11 => "EFI boot service driver",
        12 => "EFI runtime driver",
        14 => "Xbox",
        16 => "Windows boot application",
        _ => return format!("unknown ({subsystem})"),
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use bzip2::Compression as BzipCompression;
    use bzip2::write::BzEncoder;
    use xz2::write::XzEncoder;
    use zip::write::SimpleFileOptions;

    use super::{archive_path_is_safe, inspect_bytes};

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

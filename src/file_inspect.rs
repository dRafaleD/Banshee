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
        attach_executable(&mut report, executable);
    } else if let Some(executable) = inspect_pe(bytes)? {
        report.format = "PE executable".to_owned();
        attach_executable(&mut report, executable);
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
    }
    Ok(())
}

fn attach_executable(report: &mut FileReport, executable: ExecutableReport) {
    report
        .findings
        .extend(executable.suspicious_properties.iter().cloned());
    report.executable = Some(executable);
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
    let mut report = ExecutableReport {
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
        section_details: Vec::new(),
        sections_truncated: false,
        imports: Vec::new(),
        imports_truncated: false,
        exports: Vec::new(),
        exports_truncated: false,
        overlay: None,
        signature_present: None,
        interpreter: None,
        needed_libraries: Vec::new(),
        needed_libraries_truncated: false,
        rpath: None,
        runpath: None,
        stripped: None,
        debug_info_present: None,
        parse_warnings: Vec::new(),
        suspicious_properties: Vec::new(),
    };
    enrich_elf(bytes, bits, little, &mut report);
    Ok(Some(report))
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
    let mut report = ExecutableReport {
        format: "PE".to_owned(),
        architecture: pe_machine(machine),
        bits,
        endianness: Some("little".to_owned()),
        kind: "executable image".to_owned(),
        entry_point: format!("RVA 0x{entry:X}"),
        sections,
        subsystem: Some(pe_subsystem(subsystem)),
        timestamp: Some(timestamp),
        section_details: Vec::new(),
        sections_truncated: false,
        imports: Vec::new(),
        imports_truncated: false,
        exports: Vec::new(),
        exports_truncated: false,
        overlay: None,
        signature_present: None,
        interpreter: None,
        needed_libraries: Vec::new(),
        needed_libraries_truncated: false,
        rpath: None,
        runpath: None,
        stripped: None,
        debug_info_present: None,
        parse_warnings: Vec::new(),
        suspicious_properties: Vec::new(),
    };
    enrich_pe(bytes, pe_offset, optional, bits, sections, &mut report);
    Ok(Some(report))
}

#[derive(Debug, Clone)]
struct PeSectionMap {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

fn enrich_pe(
    bytes: &[u8],
    pe_offset: usize,
    optional: usize,
    bits: u8,
    declared_sections: u16,
    report: &mut ExecutableReport,
) {
    let Some(optional_size) = read_u16(bytes, pe_offset.saturating_add(20), true) else {
        report
            .parse_warnings
            .push("PE optional-header size is unavailable".to_owned());
        return;
    };
    let minimum_optional_size = if bits == 64 { 112 } else { 96 };
    if usize::from(optional_size) < minimum_optional_size {
        report.parse_warnings.push(format!(
            "PE optional header is too small for extended inspection: {optional_size} bytes"
        ));
        return;
    }
    let Some(section_table) = optional.checked_add(usize::from(optional_size)) else {
        report
            .parse_warnings
            .push("PE section-table offset overflowed".to_owned());
        return;
    };
    let section_count = usize::from(declared_sections).min(MAX_EXECUTABLE_SECTIONS);
    report.sections_truncated = usize::from(declared_sections) > section_count;
    let mut section_maps = Vec::new();
    let mut section_raw_end = read_u32(bytes, optional.saturating_add(60), true)
        .map(u64::from)
        .unwrap_or(0);
    for index in 0..section_count {
        let Some(offset) = section_table.checked_add(index.saturating_mul(40)) else {
            report
                .parse_warnings
                .push("PE section-header offset overflowed".to_owned());
            break;
        };
        let Some(header) = bytes.get(offset..offset.saturating_add(40)) else {
            report
                .parse_warnings
                .push(format!("PE section table is truncated at entry {index}"));
            break;
        };
        let name = bounded_name(&header[..8]);
        let virtual_size = read_u32(header, 8, true).unwrap_or(0);
        let virtual_address = read_u32(header, 12, true).unwrap_or(0);
        let raw_size = read_u32(header, 16, true).unwrap_or(0);
        let raw_offset = read_u32(header, 20, true).unwrap_or(0);
        let characteristics = read_u32(header, 36, true).unwrap_or(0);
        let readable = characteristics & 0x4000_0000 != 0;
        let writable = characteristics & 0x8000_0000 != 0;
        let executable = characteristics & 0x2000_0000 != 0;
        let raw_end = u64::from(raw_offset).saturating_add(u64::from(raw_size));
        if raw_size > 0 && raw_end > bytes.len() as u64 {
            report.parse_warnings.push(format!(
                "PE section '{}' raw range extends beyond the file",
                display_section_name(&name, index)
            ));
        } else {
            section_raw_end = section_raw_end.max(raw_end);
        }
        if writable && executable {
            report.suspicious_properties.push(format!(
                "PE section '{}' is writable and executable",
                display_section_name(&name, index)
            ));
        }
        if is_packer_section_name(&name) {
            report.suspicious_properties.push(format!(
                "PE section '{}' uses a packer-associated name",
                display_section_name(&name, index)
            ));
        }
        report.section_details.push(ExecutableSection {
            name: display_section_name(&name, index),
            virtual_address: format!("RVA 0x{virtual_address:X}"),
            file_offset: u64::from(raw_offset),
            file_size: u64::from(raw_size),
            memory_size: u64::from(virtual_size),
            readable: Some(readable),
            allocated: None,
            writable,
            executable,
        });
        section_maps.push(PeSectionMap {
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
        });
    }

    let directory_count_offset = optional + if bits == 64 { 108 } else { 92 };
    let directory_start = optional + if bits == 64 { 112 } else { 96 };
    let directory_count = read_u32(bytes, directory_count_offset, true).unwrap_or(0) as usize;
    let optional_end = optional.saturating_add(usize::from(optional_size));
    let directory = |index: usize| -> Option<(u32, u32)> {
        if index >= directory_count {
            return None;
        }
        let offset = directory_start.checked_add(index.checked_mul(8)?)?;
        if offset.checked_add(8)? > optional_end {
            return None;
        }
        Some((
            read_u32(bytes, offset, true)?,
            read_u32(bytes, offset + 4, true)?,
        ))
    };
    let size_of_headers = read_u32(bytes, optional + 60, true).unwrap_or(0);
    if let Some((export_rva, export_size)) = directory(0)
        && export_rva != 0
        && export_size != 0
    {
        parse_pe_exports(bytes, export_rva, &section_maps, size_of_headers, report);
    }
    if let Some((import_rva, import_size)) = directory(1)
        && import_rva != 0
        && import_size != 0
    {
        parse_pe_imports(
            bytes,
            import_rva,
            import_size,
            bits,
            &section_maps,
            size_of_headers,
            report,
        );
    }

    let mut certificate_range = None;
    if let Some((certificate_offset, certificate_size)) = directory(4) {
        report.signature_present = Some(false);
        if certificate_offset != 0 && certificate_size != 0 {
            let start = u64::from(certificate_offset);
            let end = start.saturating_add(u64::from(certificate_size));
            if end <= bytes.len() as u64 {
                report.signature_present = Some(true);
                certificate_range = Some((start, end));
            } else {
                report.parse_warnings.push(
                    "PE certificate table points outside the file; signature presence is invalid"
                        .to_owned(),
                );
            }
        }
    }
    let file_len = bytes.len() as u64;
    if section_raw_end < file_len {
        let overlay_size = file_len - section_raw_end;
        let includes_certificate_table = certificate_range
            .is_some_and(|(start, end)| start >= section_raw_end && end <= file_len);
        report.overlay = Some(OverlayReport {
            offset: section_raw_end,
            size: overlay_size,
            includes_certificate_table,
        });
        let certificate_only = certificate_range
            .is_some_and(|(start, end)| start == section_raw_end && end == file_len);
        if !certificate_only {
            report.suspicious_properties.push(format!(
                "PE file contains {overlay_size} bytes after mapped section data"
            ));
        }
    }
}

fn parse_pe_imports(
    bytes: &[u8],
    directory_rva: u32,
    directory_size: u32,
    bits: u8,
    sections: &[PeSectionMap],
    size_of_headers: u32,
    report: &mut ExecutableReport,
) {
    let Some(start) = pe_rva_to_offset(directory_rva, sections, size_of_headers) else {
        report
            .parse_warnings
            .push("PE import directory RVA cannot be mapped to file data".to_owned());
        return;
    };
    let descriptor_limit = (usize::try_from(directory_size).unwrap_or(usize::MAX) / 20)
        .saturating_add(1)
        .min(MAX_IMPORT_LIBRARIES + 1);
    let mut symbols_seen = 0_usize;
    for index in 0..descriptor_limit {
        let offset = start.saturating_add(index.saturating_mul(20));
        let Some(descriptor) = bytes.get(offset..offset.saturating_add(20)) else {
            report
                .parse_warnings
                .push("PE import descriptor table is truncated".to_owned());
            break;
        };
        if descriptor.iter().all(|byte| *byte == 0) {
            break;
        }
        if report.imports.len() >= MAX_IMPORT_LIBRARIES {
            report.imports_truncated = true;
            break;
        }
        let original_thunk = read_u32(descriptor, 0, true).unwrap_or(0);
        let name_rva = read_u32(descriptor, 12, true).unwrap_or(0);
        let first_thunk = read_u32(descriptor, 16, true).unwrap_or(0);
        let name = pe_rva_to_offset(name_rva, sections, size_of_headers)
            .and_then(|offset| read_c_string(bytes, offset, MAX_EXECUTABLE_STRING_BYTES))
            .unwrap_or_else(|| {
                report
                    .parse_warnings
                    .push(format!("PE import library name {index} is unavailable"));
                format!("<library-{index}>")
            });
        let thunk_rva = if original_thunk != 0 {
            original_thunk
        } else {
            first_thunk
        };
        let mut library = ImportLibrary {
            name,
            symbols: Vec::new(),
            symbols_truncated: false,
        };
        let Some(thunk_start) = pe_rva_to_offset(thunk_rva, sections, size_of_headers) else {
            report.parse_warnings.push(format!(
                "PE import thunk table for '{}' is unavailable",
                library.name
            ));
            report.imports.push(library);
            continue;
        };
        let thunk_size = if bits == 64 { 8 } else { 4 };
        loop {
            if symbols_seen >= MAX_IMPORT_SYMBOLS {
                library.symbols_truncated = true;
                report.imports_truncated = true;
                break;
            }
            let offset = thunk_start.saturating_add(library.symbols.len() * thunk_size);
            let value = if bits == 64 {
                read_u64(bytes, offset, true)
            } else {
                read_u32(bytes, offset, true).map(u64::from)
            };
            let Some(value) = value else {
                report.parse_warnings.push(format!(
                    "PE import thunk table for '{}' is truncated",
                    library.name
                ));
                break;
            };
            if value == 0 {
                break;
            }
            let ordinal_mask = if bits == 64 {
                0x8000_0000_0000_0000
            } else {
                0x8000_0000
            };
            let symbol = if value & ordinal_mask != 0 {
                format!("#{}", value & 0xffff)
            } else if value <= u64::from(u32::MAX) {
                pe_rva_to_offset(value as u32, sections, size_of_headers)
                    .and_then(|offset| offset.checked_add(2))
                    .and_then(|offset| read_c_string(bytes, offset, MAX_EXECUTABLE_STRING_BYTES))
                    .unwrap_or_else(|| "<unresolved-name>".to_owned())
            } else {
                "<invalid-name-rva>".to_owned()
            };
            library.symbols.push(symbol);
            symbols_seen += 1;
        }
        report.imports.push(library);
    }
}

fn parse_pe_exports(
    bytes: &[u8],
    directory_rva: u32,
    sections: &[PeSectionMap],
    size_of_headers: u32,
    report: &mut ExecutableReport,
) {
    let Some(offset) = pe_rva_to_offset(directory_rva, sections, size_of_headers) else {
        report
            .parse_warnings
            .push("PE export directory RVA cannot be mapped to file data".to_owned());
        return;
    };
    let Some(directory) = bytes.get(offset..offset.saturating_add(40)) else {
        report
            .parse_warnings
            .push("PE export directory is truncated".to_owned());
        return;
    };
    let names = read_u32(directory, 24, true).unwrap_or(0) as usize;
    let names_rva = read_u32(directory, 32, true).unwrap_or(0);
    let Some(names_offset) = pe_rva_to_offset(names_rva, sections, size_of_headers) else {
        report
            .parse_warnings
            .push("PE export name table is unavailable".to_owned());
        return;
    };
    let count = names.min(MAX_EXPORTS);
    report.exports_truncated = names > count;
    for index in 0..count {
        let Some(name_rva) = read_u32(bytes, names_offset.saturating_add(index * 4), true) else {
            report
                .parse_warnings
                .push("PE export name table is truncated".to_owned());
            break;
        };
        let Some(name) = pe_rva_to_offset(name_rva, sections, size_of_headers)
            .and_then(|offset| read_c_string(bytes, offset, MAX_EXECUTABLE_STRING_BYTES))
        else {
            report
                .parse_warnings
                .push(format!("PE export name {index} is unavailable"));
            continue;
        };
        report.exports.push(name);
    }
}

fn pe_rva_to_offset(rva: u32, sections: &[PeSectionMap], size_of_headers: u32) -> Option<usize> {
    if rva < size_of_headers {
        return usize::try_from(rva).ok();
    }
    sections.iter().find_map(|section| {
        let span = section.virtual_size.max(section.raw_size);
        let delta = rva.checked_sub(section.virtual_address)?;
        if delta >= span || delta >= section.raw_size {
            return None;
        }
        usize::try_from(section.raw_offset.checked_add(delta)?).ok()
    })
}

#[derive(Debug, Clone)]
struct ElfSegment {
    kind: u32,
    flags: u32,
    offset: u64,
    virtual_address: u64,
    file_size: u64,
}

#[derive(Debug, Clone)]
struct ElfSectionRaw {
    name_offset: u32,
    kind: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
}

fn enrich_elf(bytes: &[u8], bits: u8, little: bool, report: &mut ExecutableReport) {
    let (
        program_offset,
        program_entry_size,
        program_count,
        section_offset,
        section_entry_size,
        section_count,
        string_index,
    ) = if bits == 32 {
        (
            read_u32(bytes, 28, little).map(u64::from),
            read_u16(bytes, 42, little),
            read_u16(bytes, 44, little),
            read_u32(bytes, 32, little).map(u64::from),
            read_u16(bytes, 46, little),
            read_u16(bytes, 48, little),
            read_u16(bytes, 50, little),
        )
    } else {
        (
            read_u64(bytes, 32, little),
            read_u16(bytes, 54, little),
            read_u16(bytes, 56, little),
            read_u64(bytes, 40, little),
            read_u16(bytes, 58, little),
            read_u16(bytes, 60, little),
            read_u16(bytes, 62, little),
        )
    };

    let segments = parse_elf_segments(
        bytes,
        bits,
        little,
        program_offset.unwrap_or(0),
        program_entry_size.unwrap_or(0),
        program_count.unwrap_or(0),
        report,
    );
    if let Some(interpreter_segment) = segments.iter().find(|segment| segment.kind == 3) {
        report.interpreter = read_file_string(
            bytes,
            interpreter_segment.offset,
            interpreter_segment.file_size,
        );
        if report.interpreter.is_none() {
            report
                .parse_warnings
                .push("ELF interpreter path is unavailable or invalid".to_owned());
        }
    }
    parse_elf_dynamic(bytes, bits, little, &segments, report);
    parse_elf_sections(
        bytes,
        bits,
        little,
        (
            section_offset.unwrap_or(0),
            section_entry_size.unwrap_or(0),
            section_count.unwrap_or(0),
            string_index.unwrap_or(0),
        ),
        report,
    );
}

fn parse_elf_segments(
    bytes: &[u8],
    bits: u8,
    little: bool,
    table_offset: u64,
    entry_size: u16,
    declared_count: u16,
    report: &mut ExecutableReport,
) -> Vec<ElfSegment> {
    if table_offset == 0 || declared_count == 0 {
        return Vec::new();
    }
    let minimum_size = if bits == 64 { 56 } else { 32 };
    if usize::from(entry_size) < minimum_size {
        report
            .parse_warnings
            .push("ELF program-header entry size is invalid".to_owned());
        return Vec::new();
    }
    let count = usize::from(declared_count).min(MAX_EXECUTABLE_SECTIONS);
    if usize::from(declared_count) > count {
        report
            .parse_warnings
            .push("ELF program-header list was truncated at safety limit".to_owned());
    }
    let mut segments = Vec::new();
    for index in 0..count {
        let Some(offset) = table_entry_offset(table_offset, entry_size, index) else {
            report
                .parse_warnings
                .push("ELF program-header offset overflowed".to_owned());
            break;
        };
        let Some(header) = bytes.get(offset..offset.saturating_add(minimum_size)) else {
            report.parse_warnings.push(format!(
                "ELF program-header table is truncated at entry {index}"
            ));
            break;
        };
        let segment = if bits == 64 {
            ElfSegment {
                kind: read_u32(header, 0, little).unwrap_or(0),
                flags: read_u32(header, 4, little).unwrap_or(0),
                offset: read_u64(header, 8, little).unwrap_or(0),
                virtual_address: read_u64(header, 16, little).unwrap_or(0),
                file_size: read_u64(header, 32, little).unwrap_or(0),
            }
        } else {
            ElfSegment {
                kind: read_u32(header, 0, little).unwrap_or(0),
                flags: read_u32(header, 24, little).unwrap_or(0),
                offset: u64::from(read_u32(header, 4, little).unwrap_or(0)),
                virtual_address: u64::from(read_u32(header, 8, little).unwrap_or(0)),
                file_size: u64::from(read_u32(header, 16, little).unwrap_or(0)),
            }
        };
        if segment.offset.saturating_add(segment.file_size) > bytes.len() as u64 {
            report.parse_warnings.push(format!(
                "ELF program segment {index} extends beyond the file"
            ));
        }
        if segment.flags & 0x3 == 0x3 {
            report.suspicious_properties.push(format!(
                "ELF program segment {index} is writable and executable"
            ));
        }
        segments.push(segment);
    }
    segments
}

fn parse_elf_dynamic(
    bytes: &[u8],
    bits: u8,
    little: bool,
    segments: &[ElfSegment],
    report: &mut ExecutableReport,
) {
    let Some(dynamic) = segments.iter().find(|segment| segment.kind == 2) else {
        return;
    };
    let entry_size = if bits == 64 { 16 } else { 8 };
    let declared_entries = usize::try_from(dynamic.file_size)
        .unwrap_or(usize::MAX)
        .checked_div(entry_size)
        .unwrap_or(0);
    let available_entries = declared_entries.min(MAX_IMPORT_SYMBOLS);
    if declared_entries > available_entries {
        report.needed_libraries_truncated = true;
    }
    let mut string_table_address = None;
    let mut string_table_size = None;
    let mut needed = Vec::new();
    let mut rpath = None;
    let mut runpath = None;
    for index in 0..available_entries {
        let Some(offset) = usize::try_from(dynamic.offset)
            .ok()
            .and_then(|offset| offset.checked_add(index * entry_size))
        else {
            report
                .parse_warnings
                .push("ELF dynamic-table offset overflowed".to_owned());
            break;
        };
        let (tag, value) = if bits == 64 {
            (
                read_u64(bytes, offset, little),
                read_u64(bytes, offset + 8, little),
            )
        } else {
            (
                read_u32(bytes, offset, little).map(u64::from),
                read_u32(bytes, offset + 4, little).map(u64::from),
            )
        };
        let (Some(tag), Some(value)) = (tag, value) else {
            report
                .parse_warnings
                .push("ELF dynamic table is truncated".to_owned());
            break;
        };
        match tag {
            0 => break,
            1 => needed.push(value),
            5 => string_table_address = Some(value),
            10 => string_table_size = Some(value),
            15 => rpath = Some(value),
            29 => runpath = Some(value),
            _ => {}
        }
    }
    let Some(string_address) = string_table_address else {
        if !needed.is_empty() || rpath.is_some() || runpath.is_some() {
            report
                .parse_warnings
                .push("ELF dynamic string table address is missing".to_owned());
        }
        return;
    };
    let Some(string_offset) = elf_vaddr_to_offset(string_address, segments) else {
        report
            .parse_warnings
            .push("ELF dynamic string table cannot be mapped to file data".to_owned());
        return;
    };
    let string_limit = string_table_size.unwrap_or(MAX_EXECUTABLE_STRING_BYTES as u64);
    if needed.len() > MAX_IMPORT_SYMBOLS {
        report.needed_libraries_truncated = true;
    }
    for offset in needed.into_iter().take(MAX_IMPORT_SYMBOLS) {
        if offset >= string_limit {
            report
                .parse_warnings
                .push("ELF DT_NEEDED offset exceeds the dynamic string table".to_owned());
            continue;
        }
        if let Some(value) = read_c_string_u64(bytes, string_offset.saturating_add(offset)) {
            report.needed_libraries.push(value);
        }
    }
    report.rpath = rpath.and_then(|offset| {
        (offset < string_limit)
            .then(|| read_c_string_u64(bytes, string_offset.saturating_add(offset)))
            .flatten()
    });
    report.runpath = runpath.and_then(|offset| {
        (offset < string_limit)
            .then(|| read_c_string_u64(bytes, string_offset.saturating_add(offset)))
            .flatten()
    });
}

fn parse_elf_sections(
    bytes: &[u8],
    bits: u8,
    little: bool,
    table: (u64, u16, u16, u16),
    report: &mut ExecutableReport,
) {
    let (table_offset, entry_size, declared_count, string_index) = table;
    if table_offset == 0 || declared_count == 0 {
        return;
    }
    let minimum_size = if bits == 64 { 64 } else { 40 };
    if usize::from(entry_size) < minimum_size {
        report
            .parse_warnings
            .push("ELF section-header entry size is invalid".to_owned());
        return;
    }
    let count = usize::from(declared_count).min(MAX_EXECUTABLE_SECTIONS);
    report.sections_truncated = usize::from(declared_count) > count;
    let mut sections = Vec::new();
    for index in 0..count {
        let Some(offset) = table_entry_offset(table_offset, entry_size, index) else {
            report
                .parse_warnings
                .push("ELF section-header offset overflowed".to_owned());
            break;
        };
        let Some(header) = bytes.get(offset..offset.saturating_add(minimum_size)) else {
            report.parse_warnings.push(format!(
                "ELF section-header table is truncated at entry {index}"
            ));
            break;
        };
        sections.push(if bits == 64 {
            ElfSectionRaw {
                name_offset: read_u32(header, 0, little).unwrap_or(0),
                kind: read_u32(header, 4, little).unwrap_or(0),
                flags: read_u64(header, 8, little).unwrap_or(0),
                address: read_u64(header, 16, little).unwrap_or(0),
                offset: read_u64(header, 24, little).unwrap_or(0),
                size: read_u64(header, 32, little).unwrap_or(0),
            }
        } else {
            ElfSectionRaw {
                name_offset: read_u32(header, 0, little).unwrap_or(0),
                kind: read_u32(header, 4, little).unwrap_or(0),
                flags: u64::from(read_u32(header, 8, little).unwrap_or(0)),
                address: u64::from(read_u32(header, 12, little).unwrap_or(0)),
                offset: u64::from(read_u32(header, 16, little).unwrap_or(0)),
                size: u64::from(read_u32(header, 20, little).unwrap_or(0)),
            }
        });
    }
    let Some(string_section) = sections.get(usize::from(string_index)) else {
        report
            .parse_warnings
            .push("ELF section-name string table index is invalid".to_owned());
        return;
    };
    let Some(string_data) = file_slice(bytes, string_section.offset, string_section.size) else {
        report
            .parse_warnings
            .push("ELF section-name string table is outside the file".to_owned());
        return;
    };
    let mut names = Vec::new();
    for (index, section) in sections.iter().enumerate() {
        let name = read_c_string(
            string_data,
            usize::try_from(section.name_offset).unwrap_or(usize::MAX),
            MAX_EXECUTABLE_STRING_BYTES,
        )
        .unwrap_or_else(|| format!("<section-{index}>"));
        let writable = section.flags & 0x1 != 0;
        let executable = section.flags & 0x4 != 0;
        let allocated = section.flags & 0x2 != 0;
        if writable && executable {
            report.suspicious_properties.push(format!(
                "ELF section '{}' is writable and executable",
                display_section_name(&name, index)
            ));
        }
        if section.kind != 8 && section.offset.saturating_add(section.size) > bytes.len() as u64 {
            report.parse_warnings.push(format!(
                "ELF section '{}' extends beyond the file",
                display_section_name(&name, index)
            ));
        }
        names.push(name.clone());
        report.section_details.push(ExecutableSection {
            name: display_section_name(&name, index),
            virtual_address: format!("0x{:X}", section.address),
            file_offset: section.offset,
            file_size: if section.kind == 8 { 0 } else { section.size },
            memory_size: section.size,
            readable: None,
            allocated: Some(allocated),
            writable,
            executable,
        });
    }
    report.stripped = Some(!names.iter().any(|name| name == ".symtab"));
    report.debug_info_present = Some(
        names
            .iter()
            .any(|name| name.starts_with(".debug_") || name.starts_with(".zdebug_")),
    );
}

fn table_entry_offset(table_offset: u64, entry_size: u16, index: usize) -> Option<usize> {
    let offset = table_offset.checked_add((index as u64).checked_mul(u64::from(entry_size))?)?;
    usize::try_from(offset).ok()
}

fn elf_vaddr_to_offset(address: u64, segments: &[ElfSegment]) -> Option<u64> {
    segments
        .iter()
        .filter(|segment| segment.kind == 1)
        .find_map(|segment| {
            let delta = address.checked_sub(segment.virtual_address)?;
            (delta < segment.file_size).then(|| segment.offset.saturating_add(delta))
        })
}

fn file_slice(bytes: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = usize::try_from(offset.checked_add(size)?).ok()?;
    bytes.get(start..end)
}

fn read_file_string(bytes: &[u8], offset: u64, size: u64) -> Option<String> {
    let slice = file_slice(bytes, offset, size.min(MAX_EXECUTABLE_STRING_BYTES as u64))?;
    let end = slice
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(slice.len());
    std::str::from_utf8(&slice[..end])
        .ok()
        .map(ToOwned::to_owned)
}

fn read_c_string_u64(bytes: &[u8], offset: u64) -> Option<String> {
    read_c_string(
        bytes,
        usize::try_from(offset).ok()?,
        MAX_EXECUTABLE_STRING_BYTES,
    )
}

fn read_c_string(bytes: &[u8], offset: usize, maximum: usize) -> Option<String> {
    let remaining = bytes.get(offset..)?;
    let end = remaining.iter().take(maximum).position(|byte| *byte == 0)?;
    std::str::from_utf8(&remaining[..end])
        .ok()
        .map(ToOwned::to_owned)
}

fn bounded_name(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn display_section_name(name: &str, index: usize) -> String {
    if name.is_empty() {
        format!("<section-{index}>")
    } else {
        name.to_owned()
    }
}

fn is_packer_section_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "upx0" | "upx1" | "upx2" | ".aspack" | ".packed" | "mpress1" | "mpress2"
    )
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
        assert!(executable.parse_warnings.is_empty());
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

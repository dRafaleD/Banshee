use anyhow::{Context, Result, bail};

use super::binary::{
    bounded_name, display_section_name, is_packer_section_name, range_entropy, read_c_string,
    read_u16, read_u32, read_u64,
};
use super::{
    ExecutableReport, ExecutableSection, ImportLibrary, MAX_EXECUTABLE_SECTIONS,
    MAX_EXECUTABLE_STRING_BYTES, MAX_EXPORTS, MAX_IMPORT_LIBRARIES, MAX_IMPORT_SYMBOLS,
    OverlayReport,
};

pub(super) fn inspect_pe(bytes: &[u8]) -> Result<Option<ExecutableReport>> {
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
        imphash: None,
        rich_header: None,
        tls_callbacks: None,
    };
    report.rich_header = super::pe_extra::rich_header(bytes, pe_offset);
    enrich_pe(bytes, pe_offset, optional, bits, sections, &mut report);
    super::pe_extra::annotate(&mut report, entry);
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
            entropy: range_entropy(bytes, u64::from(raw_offset), u64::from(raw_size)),
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

    if let Some((tls_rva, tls_size)) = directory(9)
        && tls_rva != 0
        && tls_size != 0
    {
        let image_base = if bits == 64 {
            read_u64(bytes, optional + 24, true)
        } else {
            read_u32(bytes, optional + 28, true).map(u64::from)
        };
        let count = pe_rva_to_offset(tls_rva, &section_maps, size_of_headers).and_then(|offset| {
            super::pe_extra::tls_callback_count(bytes, offset, bits, image_base?, |rva| {
                pe_rva_to_offset(rva, &section_maps, size_of_headers)
            })
        });
        match count {
            Some(count) => {
                report.tls_callbacks = Some(count);
                if count > 0 {
                    report.suspicious_properties.push(format!(
                        "PE declares {count} TLS callback(s), which run before the entry point"
                    ));
                }
            }
            None => report
                .parse_warnings
                .push("PE TLS directory cannot be mapped to file data".to_owned()),
        }
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

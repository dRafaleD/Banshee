use anyhow::{Context, Result, bail};

use super::binary::{
    display_section_name, file_slice, range_entropy, read_c_string, read_c_string_u64,
    read_file_string, read_u16, read_u32, read_u64,
};
use super::{
    ExecutableReport, ExecutableSection, MAX_EXECUTABLE_SECTIONS, MAX_EXECUTABLE_STRING_BYTES,
    MAX_IMPORT_SYMBOLS,
};

pub(super) fn inspect_elf(bytes: &[u8]) -> Result<Option<ExecutableReport>> {
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
        imphash: None,
        rich_header: None,
        tls_callbacks: None,
        universal_architectures: Vec::new(),
    };
    enrich_elf(bytes, bits, little, &mut report);
    Ok(Some(report))
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
            entropy: if section.kind == 8 {
                None
            } else {
                range_entropy(bytes, section.offset, section.size)
            },
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

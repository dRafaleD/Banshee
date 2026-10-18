//! Windows minidump (`.dmp`, `MDMP`) inspection. The stream directory is
//! read for the dump time and type, system and process information, threads,
//! loaded modules, captured memory and the exception record. A dump whose
//! main module is `lsass.exe` holds Windows credentials and is a common
//! credential-theft artifact. Memory contents are left to the printable-string
//! analysis that every report already runs.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::document::DocumentReport;

const MAX_STREAMS: usize = 4_096;
/// Module names kept per dump; module lists can repeat or point every
/// entry at one long name, so both count and total size are bounded.
const MAX_MODULES: usize = 4_096;
const MAX_MODULE_NAME_BYTES: usize = 1024 * 1024;
/// Windows paths are at most 32,767 UTF-16 units.
const MAX_STRING_BYTES: usize = 65_534;
const MODULE_BYTES: usize = 108;
const MAX_LISTED_MODULES: usize = 32;

pub(super) fn is_minidump(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MDMP")
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

/// MINIDUMP_STRING: a byte length followed by UTF-16LE text.
fn string_at(bytes: &[u8], rva: usize) -> Option<String> {
    let length = u32_at(bytes, rva)? as usize;
    if length > MAX_STRING_BYTES {
        return None;
    }
    let raw = bytes.get(rva + 4..rva + 4 + length)?;
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

fn dump_type(flags: u64) -> String {
    const NAMES: &[(u64, &str)] = &[
        (0x0000_0001, "data segments"),
        (0x0000_0002, "full memory"),
        (0x0000_0004, "handle data"),
        (0x0000_0020, "indirectly referenced memory"),
        (0x0000_0040, "data segments only"),
        (0x0000_0100, "process thread data"),
        (0x0000_0200, "private read-write memory"),
        (0x0000_0800, "full memory info"),
        (0x0000_1000, "thread info"),
        (0x0000_2000, "code segments"),
        (0x0004_0000, "token information"),
    ];
    let names: Vec<&str> = NAMES
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if names.is_empty() {
        "normal".to_owned()
    } else {
        names.join(", ")
    }
}

fn architecture(code: u16) -> String {
    match code {
        0 => "x86".to_owned(),
        5 => "ARM".to_owned(),
        6 => "IA-64".to_owned(),
        9 => "x64".to_owned(),
        12 => "ARM64".to_owned(),
        other => format!("architecture {other}"),
    }
}

/// File name part of a Windows path.
fn base_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

pub(super) fn inspect(bytes: &[u8]) -> DocumentReport {
    let mut report = DocumentReport::new("Windows minidump");
    let (Some(streams), Some(directory), Some(timestamp), Some(flags)) = (
        u32_at(bytes, 8),
        u32_at(bytes, 12),
        u32_at(bytes, 20),
        u64_at(bytes, 24),
    ) else {
        report
            .suspicious_properties
            .push("minidump header is truncated".to_owned());
        return report;
    };
    let streams = streams as usize;
    report.property("Streams", streams.to_string());
    if let Some(time) = OffsetDateTime::from_unix_timestamp(i64::from(timestamp))
        .ok()
        .and_then(|time| time.format(&Rfc3339).ok())
    {
        report.property("Dump time (UTC)", time);
    }
    report.property("Dump type", dump_type(flags));
    if streams > MAX_STREAMS {
        report.notes.push(format!(
            "the directory declares {streams} streams; only the first {MAX_STREAMS} are read"
        ));
    }

    let mut modules: Vec<String> = Vec::new();
    let mut module_count = 0_usize;
    let mut name_bytes = 0_usize;
    let mut names_truncated = false;
    for index in 0..streams.min(MAX_STREAMS) {
        let entry = directory as usize + index * 12;
        let (Some(kind), Some(size), Some(rva)) = (
            u32_at(bytes, entry),
            u32_at(bytes, entry + 4),
            u32_at(bytes, entry + 8),
        ) else {
            report.notes.push(format!(
                "stream directory is truncated after {index} entries"
            ));
            break;
        };
        let rva = rva as usize;
        let Some(stream) = bytes.get(rva..rva.saturating_add(size as usize)) else {
            report.notes.push(format!(
                "stream {index} (type {kind}) points beyond the end of the file"
            ));
            continue;
        };
        match kind {
            3 => {
                if let Some(threads) = u32_at(stream, 0) {
                    report.property("Threads", threads.to_string());
                }
            }
            4 => {
                let count = u32_at(stream, 0).unwrap_or_default() as usize;
                module_count = count;
                // Entries beyond the stream cannot exist, whatever the count says.
                let present = count.min(stream.len().saturating_sub(4) / MODULE_BYTES);
                for module in 0..present {
                    if modules.len() >= MAX_MODULES || name_bytes >= MAX_MODULE_NAME_BYTES {
                        names_truncated = true;
                        break;
                    }
                    let Some(name_rva) = u32_at(stream, 4 + module * MODULE_BYTES + 20) else {
                        break;
                    };
                    if let Some(name) = string_at(bytes, name_rva as usize) {
                        name_bytes += name.len();
                        modules.push(name);
                    }
                }
            }
            5 => {
                if let Some(ranges) = u32_at(stream, 0) {
                    let present = (ranges as usize).min(stream.len().saturating_sub(4) / 16);
                    let total: u64 = (0..present)
                        .filter_map(|range| u32_at(stream, 4 + range * 16 + 8))
                        .map(u64::from)
                        .sum();
                    report.property("Memory ranges", format!("{ranges} ({total} bytes)"));
                }
            }
            9 => {
                if let Some(ranges) = u64_at(stream, 0) {
                    let present = usize::try_from(ranges)
                        .unwrap_or(usize::MAX)
                        .min(stream.len().saturating_sub(16) / 16);
                    let total: u64 = (0..present)
                        .filter_map(|range| u64_at(stream, 16 + range * 16 + 8))
                        .fold(0_u64, u64::saturating_add);
                    report.property("Memory ranges", format!("{ranges} ({total} bytes)"));
                }
            }
            6 => {
                if let (Some(thread), Some(code), Some(address)) =
                    (u32_at(stream, 0), u32_at(stream, 8), u64_at(stream, 24))
                {
                    report.property(
                        "Exception",
                        format!("code 0x{code:08X} at 0x{address:X} in thread {thread}"),
                    );
                }
            }
            7 => {
                if let (Some(arch), Some(major), Some(minor), Some(build)) = (
                    u16_at(stream, 0),
                    u32_at(stream, 8),
                    u32_at(stream, 12),
                    u32_at(stream, 16),
                ) {
                    report.property("Processor", architecture(arch));
                    report.property("Windows version", format!("{major}.{minor}.{build}"));
                }
            }
            15 => {
                if let (Some(flags), Some(process)) = (u32_at(stream, 4), u32_at(stream, 8))
                    && flags & 1 != 0
                {
                    report.property("Process ID", process.to_string());
                }
            }
            _ => {}
        }
    }

    if module_count > 0 {
        report.property("Modules", module_count.to_string());
    }
    if let Some(main) = modules.first() {
        report.property("Main module", main.clone());
        if base_name(main).eq_ignore_ascii_case("lsass.exe") {
            report.suspicious_properties.push(
                "minidump of lsass.exe, which holds Windows logon credentials; such dumps are made to steal them"
                    .to_owned(),
            );
        }
    }
    for (index, module) in modules.iter().enumerate().skip(1).take(MAX_LISTED_MODULES) {
        report.property(&format!("Module {}", index + 1), module.clone());
    }
    if modules.len() > MAX_LISTED_MODULES + 1 {
        report.notes.push(format!(
            "only the main module and the next {MAX_LISTED_MODULES} modules are listed"
        ));
    }
    if names_truncated {
        report.notes.push(format!(
            "module names were read up to {MAX_MODULES} names or {} KiB",
            MAX_MODULE_NAME_BYTES / 1024
        ));
    }
    report.extra_text = modules;
    report
}

#[cfg(test)]
mod tests {
    use super::{inspect, is_minidump};

    fn utf16(text: &str) -> Vec<u8> {
        let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut bytes = (units.len() as u32).to_le_bytes().to_vec();
        bytes.extend(units);
        bytes.extend([0, 0]);
        bytes
    }

    /// Header, a three-entry directory, then system info, a module list
    /// with two modules and their names.
    fn dump(main: &str) -> Vec<u8> {
        let mut bytes = b"MDMP".to_vec();
        bytes.extend(0xA793u32.to_le_bytes());
        bytes.extend(3u32.to_le_bytes());
        bytes.extend(32u32.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(1_700_000_000u32.to_le_bytes());
        bytes.extend(2u64.to_le_bytes());
        let directory_end = 32 + 3 * 12;
        let system_at = directory_end;
        let system_size = 56;
        let modules_at = system_at + system_size;
        let modules_size = 4 + 2 * 108;
        let names_at = modules_at + modules_size;
        let main_name = utf16(main);
        let second_name = utf16("C:\\Windows\\System32\\ntdll.dll");
        for (kind, size, rva) in [
            (7u32, system_size, system_at),
            (4, modules_size, modules_at),
            (3, 4, names_at + main_name.len() + second_name.len()),
        ] {
            bytes.extend(kind.to_le_bytes());
            bytes.extend((size as u32).to_le_bytes());
            bytes.extend((rva as u32).to_le_bytes());
        }
        let mut system = vec![9, 0, 6, 0, 0, 0, 8, 1];
        system.extend(10u32.to_le_bytes());
        system.extend(0u32.to_le_bytes());
        system.extend(26200u32.to_le_bytes());
        system.resize(system_size, 0);
        bytes.extend(system);
        bytes.extend(2u32.to_le_bytes());
        for name_rva in [names_at, names_at + main_name.len()] {
            let mut module = vec![0; 108];
            module[20..24].copy_from_slice(&(name_rva as u32).to_le_bytes());
            bytes.extend(module);
        }
        bytes.extend(main_name);
        bytes.extend(second_name);
        bytes.extend(7u32.to_le_bytes());
        bytes
    }

    fn property<'a>(report: &'a crate::file_inspect::DocumentReport, name: &str) -> &'a str {
        report
            .properties
            .iter()
            .find(|property| property.name == name)
            .map(|property| property.value.as_str())
            .unwrap_or_else(|| panic!("missing {name}: {:?}", report.properties))
    }

    #[test]
    fn reads_system_modules_and_threads() {
        let bytes = dump("C:\\Program Files\\Tool\\tool.exe");
        assert!(is_minidump(&bytes));
        let report = inspect(&bytes);
        assert_eq!(property(&report, "Streams"), "3");
        assert_eq!(property(&report, "Dump type"), "full memory");
        assert_eq!(property(&report, "Dump time (UTC)"), "2023-11-14T22:13:20Z");
        assert_eq!(property(&report, "Processor"), "x64");
        assert_eq!(property(&report, "Windows version"), "10.0.26200");
        assert_eq!(property(&report, "Modules"), "2");
        assert_eq!(
            property(&report, "Main module"),
            "C:\\Program Files\\Tool\\tool.exe"
        );
        assert_eq!(
            property(&report, "Module 2"),
            "C:\\Windows\\System32\\ntdll.dll"
        );
        assert_eq!(property(&report, "Threads"), "7");
        assert!(report.suspicious_properties.is_empty());
    }

    #[test]
    fn flags_lsass_dumps_and_survives_truncation() {
        let report = inspect(&dump("C:\\Windows\\System32\\lsass.exe"));
        assert!(report.suspicious_properties[0].contains("lsass.exe"));

        let mut truncated = dump("x.exe");
        truncated.truncate(80);
        let report = inspect(&truncated);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("beyond the end"))
        );
        assert!(inspect(b"MDMP").suspicious_properties[0].contains("truncated"));
    }

    #[test]
    fn crafted_counts_and_shared_names_stay_bounded() {
        // 4,096 directory entries all pointing at one module list whose
        // 2,000 entries share one 64 KiB name, plus a memory list claiming
        // u32::MAX ranges in four bytes.
        let streams = 4_096_usize;
        let directory = 32;
        let modules_at = directory + streams * 12;
        let module_entries = 2_000;
        let memory_at = modules_at + 4 + module_entries * 108;
        let name_at = memory_at + 4;
        let mut bytes = b"MDMP".to_vec();
        bytes.extend(0xA793u32.to_le_bytes());
        bytes.extend((streams as u32).to_le_bytes());
        bytes.extend((directory as u32).to_le_bytes());
        bytes.extend([0; 16]);
        for index in 0..streams {
            let (kind, size, rva) = if index == 0 {
                (5u32, 4u32, memory_at)
            } else {
                (4, (4 + module_entries * 108) as u32, modules_at)
            };
            bytes.extend(kind.to_le_bytes());
            bytes.extend(size.to_le_bytes());
            bytes.extend((rva as u32).to_le_bytes());
        }
        bytes.extend(u32::MAX.to_le_bytes());
        for _ in 0..module_entries {
            let mut module = vec![0; 108];
            module[20..24].copy_from_slice(&(name_at as u32).to_le_bytes());
            bytes.extend(module);
        }
        bytes.extend(u32::MAX.to_le_bytes());
        bytes.extend(65_534u32.to_le_bytes());
        bytes.extend(std::iter::repeat_n([b'A', 0], 32_767).flatten());

        let started = std::time::Instant::now();
        let report = inspect(&bytes);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        let kept: usize = report.extra_text.iter().map(String::len).sum();
        assert!(kept <= 1024 * 1024 + 65_534, "{kept} bytes of module names");
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("module names were read up to"))
        );
        assert_eq!(property(&report, "Memory ranges"), "4294967295 (0 bytes)");
    }
}

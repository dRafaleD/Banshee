//! Mach-O (macOS, iOS) executable inspection: thin 32/64-bit images in either
//! byte order and universal ("fat") binaries, whose first slice is described.
//! Only headers and load commands are read; nothing is mapped or executed.

use anyhow::{Result, bail};

use super::binary::{range_entropy, read_c_string, read_u32, read_u64};
use super::{ExecutableReport, ExecutableSection, MAX_EXECUTABLE_SECTIONS};

const MAX_LOAD_COMMANDS: u32 = 4_096;
const MAX_DYLIBS: usize = 512;
const MAX_FAT_ARCHES: u32 = 32;
const MAX_PATH_BYTES: usize = 1_024;

const LC_SEGMENT: u32 = 0x1;
const LC_SYMTAB: u32 = 0x2;
const LC_LOAD_DYLIB: u32 = 0xC;
const LC_LOAD_DYLINKER: u32 = 0xE;
const LC_SEGMENT_64: u32 = 0x19;
const LC_CODE_SIGNATURE: u32 = 0x1D;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_ENCRYPTION_INFO_64: u32 = 0x2C;
const LC_REQ_DYLD: u32 = 0x8000_0000;
const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
const LC_RPATH: u32 = 0x1C | LC_REQ_DYLD;
const LC_REEXPORT_DYLIB: u32 = 0x1F | LC_REQ_DYLD;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;
const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;

const MH_PIE: u32 = 0x0020_0000;
const MH_ALLOW_STACK_EXECUTION: u32 = 0x0002_0000;
const VM_PROT_READ: u32 = 0x1;
const VM_PROT_WRITE: u32 = 0x2;
const VM_PROT_EXECUTE: u32 = 0x4;

fn cpu_name(cpu: u32) -> String {
    match cpu {
        7 => "x86",
        0x0100_0007 => "x86_64",
        12 => "ARM",
        0x0100_000C => "ARM64",
        0x0200_000C => "ARM64_32",
        18 => "PowerPC",
        0x0100_0012 => "PowerPC64",
        _ => return format!("unknown (0x{cpu:X})"),
    }
    .to_owned()
}

fn file_type(kind: u32) -> &'static str {
    match kind {
        1 => "object",
        2 => "executable",
        3 => "fixed VM library",
        4 => "core dump",
        5 => "preloaded executable",
        6 => "dynamic library",
        7 => "dynamic linker",
        8 => "bundle",
        9 => "dynamic library stub",
        10 => "debug symbols",
        11 => "kernel extension",
        12 => "file set",
        _ => "unknown",
    }
}

/// Byte order and word size of a thin image, from its magic number.
fn thin_layout(bytes: &[u8]) -> Option<(bool, u8)> {
    match read_u32(bytes, 0, true)? {
        0xFEED_FACE => Some((true, 32)),
        0xFEED_FACF => Some((true, 64)),
        0xCEFA_EDFE => Some((false, 32)),
        0xCFFA_EDFE => Some((false, 64)),
        _ => None,
    }
}

/// Universal binary slices as (cpu type, offset, size). `None` when the data
/// is not a universal binary; Java class files share the 0xCAFEBABE magic, so
/// an implausible architecture count is treated as "not Mach-O".
fn fat_slices(bytes: &[u8]) -> Option<Result<Vec<(u32, u64, u64)>>> {
    let wide = match read_u32(bytes, 0, false)? {
        0xCAFE_BABE => false,
        0xCAFE_BABF => true,
        _ => return None,
    };
    let count = read_u32(bytes, 4, false)?;
    if count == 0 || count > MAX_FAT_ARCHES {
        return None;
    }
    let entry_size = if wide { 32 } else { 20 };
    let mut slices = Vec::new();
    for index in 0..count as usize {
        let base = 8 + index * entry_size;
        let parsed = if wide {
            read_u32(bytes, base, false).zip(read_u64(bytes, base + 8, false).zip(read_u64(
                bytes,
                base + 16,
                false,
            )))
        } else {
            read_u32(bytes, base, false).zip(
                read_u32(bytes, base + 8, false)
                    .map(u64::from)
                    .zip(read_u32(bytes, base + 12, false).map(u64::from)),
            )
        };
        let Some((cpu, (offset, size))) = parsed else {
            return Some(Err(anyhow::anyhow!("truncated universal binary header")));
        };
        slices.push((cpu, offset, size));
    }
    Some(Ok(slices))
}

pub(super) fn inspect_macho(bytes: &[u8]) -> Result<Option<ExecutableReport>> {
    if let Some(slices) = fat_slices(bytes) {
        let slices = slices?;
        let architectures: Vec<String> = slices.iter().map(|(cpu, ..)| cpu_name(*cpu)).collect();
        let (_, offset, size) = slices[0];
        let end = offset
            .checked_add(size)
            .filter(|end| *end <= bytes.len() as u64);
        let Some(end) = end else {
            bail!("universal binary slice lies outside the file");
        };
        let slice = &bytes[offset as usize..end as usize];
        let Some(mut report) = inspect_thin(slice, offset)? else {
            bail!("first universal binary slice is not a Mach-O image");
        };
        report.universal_architectures = architectures;
        return Ok(Some(report));
    }
    inspect_thin(bytes, 0)
}

/// Inspects one thin image. `base` is its offset in the whole file, so that
/// reported file offsets refer to the original input.
fn inspect_thin(bytes: &[u8], base: u64) -> Result<Option<ExecutableReport>> {
    let Some((little, bits)) = thin_layout(bytes) else {
        return Ok(None);
    };
    let header_size = if bits == 64 { 32 } else { 28 };
    if bytes.len() < header_size {
        bail!("truncated Mach-O header");
    }
    let field = |offset| read_u32(bytes, offset, little).unwrap_or(0);
    let (cpu, kind, command_count, commands_size, flags) =
        (field(4), field(12), field(16), field(20), field(24));

    let mut report = ExecutableReport {
        format: "Mach-O".to_owned(),
        architecture: cpu_name(cpu),
        bits,
        endianness: Some(if little { "little" } else { "big" }.to_owned()),
        kind: file_type(kind).to_owned(),
        entry_point: "none".to_owned(),
        sections: 0,
        subsystem: None,
        timestamp: None,
        section_details: Vec::new(),
        sections_truncated: false,
        imports: Vec::new(),
        imports_truncated: false,
        exports: Vec::new(),
        exports_truncated: false,
        overlay: None,
        signature_present: Some(false),
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
        dotnet: None,
        authenticode: None,
    };

    if command_count > MAX_LOAD_COMMANDS {
        report.parse_warnings.push(format!(
            "{command_count} load commands declared; only the first {MAX_LOAD_COMMANDS} are read"
        ));
    }
    let commands_end = header_size
        .saturating_add(commands_size as usize)
        .min(bytes.len());
    if header_size + commands_size as usize > bytes.len() {
        report
            .parse_warnings
            .push("load commands extend past the end of the file".to_owned());
    }

    let mut rpaths = Vec::new();
    let mut offset = header_size;
    for _ in 0..command_count.min(MAX_LOAD_COMMANDS) {
        let (Some(command), Some(size)) = (
            read_u32(bytes, offset, little),
            read_u32(bytes, offset + 4, little),
        ) else {
            report
                .parse_warnings
                .push("truncated load command".to_owned());
            break;
        };
        let size = size as usize;
        if size < 8 || offset + size > commands_end {
            report.parse_warnings.push(format!(
                "invalid load command size {size} at offset {offset}"
            ));
            break;
        }
        let body = &bytes[offset..offset + size];
        // `lc_str` fields hold an offset from the start of the command.
        let command_string = |field: usize| {
            read_u32(body, field, little)
                .and_then(|start| read_c_string(body, start as usize, MAX_PATH_BYTES))
        };
        match command {
            LC_SEGMENT | LC_SEGMENT_64 => {
                if let Some(section) = segment(body, command == LC_SEGMENT_64, little, bytes, base)
                {
                    report.sections = report.sections.saturating_add(1);
                    if report.section_details.len() < MAX_EXECUTABLE_SECTIONS {
                        report.section_details.push(section);
                    } else {
                        report.sections_truncated = true;
                    }
                }
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
            | LC_LOAD_UPWARD_DYLIB => {
                if let Some(name) = command_string(8) {
                    if report.needed_libraries.len() < MAX_DYLIBS {
                        report.needed_libraries.push(name);
                    } else {
                        report.needed_libraries_truncated = true;
                    }
                }
            }
            LC_RPATH => rpaths.extend(command_string(8)),
            LC_LOAD_DYLINKER => report.interpreter = command_string(8),
            LC_CODE_SIGNATURE => report.signature_present = Some(true),
            LC_MAIN => {
                if let Some(entry) = read_u64(body, 8, little) {
                    report.entry_point = format!("0x{entry:X} (file offset)");
                }
            }
            LC_SYMTAB => {
                report.stripped = read_u32(body, 12, little).map(|symbols| symbols == 0);
            }
            LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64
                if read_u32(body, 16, little).is_some_and(|id| id != 0) =>
            {
                report.suspicious_properties.push(
                    "Mach-O image is encrypted (LC_ENCRYPTION_INFO cryptid set); its code cannot be analyzed statically"
                        .to_owned(),
                );
            }
            _ => {}
        }
        offset += size;
    }
    if !rpaths.is_empty() {
        report.rpath = Some(rpaths.join(":"));
    }
    flag_properties(&mut report, kind, flags);
    Ok(Some(report))
}

fn segment(
    body: &[u8],
    wide: bool,
    little: bool,
    image: &[u8],
    base: u64,
) -> Option<ExecutableSection> {
    let name = read_c_string(body, 8, 16).unwrap_or_default();
    let (address, memory_size, file_offset, file_size, initial) = if wide {
        (
            read_u64(body, 24, little)?,
            read_u64(body, 32, little)?,
            read_u64(body, 40, little)?,
            read_u64(body, 48, little)?,
            read_u32(body, 60, little)?,
        )
    } else {
        (
            u64::from(read_u32(body, 24, little)?),
            u64::from(read_u32(body, 28, little)?),
            u64::from(read_u32(body, 32, little)?),
            u64::from(read_u32(body, 36, little)?),
            read_u32(body, 44, little)?,
        )
    };
    Some(ExecutableSection {
        name: if name.is_empty() {
            "(unnamed)".to_owned()
        } else {
            name
        },
        virtual_address: format!("0x{address:X}"),
        file_offset: base.saturating_add(file_offset),
        file_size,
        memory_size,
        readable: Some(initial & VM_PROT_READ != 0),
        allocated: None,
        writable: initial & VM_PROT_WRITE != 0,
        executable: initial & VM_PROT_EXECUTE != 0,
        entropy: range_entropy(image, file_offset, file_size),
    })
}

fn flag_properties(report: &mut ExecutableReport, kind: u32, flags: u32) {
    for section in &report.section_details {
        if section.writable && section.executable {
            report.suspicious_properties.push(format!(
                "Mach-O segment {} is both writable and executable",
                section.name
            ));
        }
    }
    if flags & MH_ALLOW_STACK_EXECUTION != 0 {
        report
            .suspicious_properties
            .push("Mach-O header allows stack execution (MH_ALLOW_STACK_EXECUTION)".to_owned());
    }
    if kind == 2 && flags & MH_PIE == 0 {
        report.suspicious_properties.push(
            "Mach-O executable is not position independent (no MH_PIE); ASLR is weakened"
                .to_owned(),
        );
    }
    if let Some(dyld) = &report.interpreter
        && dyld != "/usr/lib/dyld"
    {
        report
            .suspicious_properties
            .push(format!("Mach-O uses an unusual dynamic linker: {dyld}"));
    }
    for library in &report.needed_libraries {
        let lowered = library.to_ascii_lowercase();
        if lowered.starts_with("/tmp/")
            || lowered.starts_with("/private/tmp/")
            || lowered.starts_with("/users/shared/")
            || !(library.starts_with('/') || library.starts_with('@'))
        {
            report.suspicious_properties.push(format!(
                "Mach-O loads a library from a writable or relative path: {library}"
            ));
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::inspect_macho;

    /// Builds a small 64-bit little-endian Mach-O image with the given header
    /// flags, file type and load commands.
    pub(crate) fn image(kind: u32, flags: u32, commands: &[Vec<u8>]) -> Vec<u8> {
        let size: usize = commands.iter().map(Vec::len).sum();
        let mut bytes = Vec::new();
        for value in [
            0xFEED_FACF_u32,
            0x0100_000C,
            0,
            kind,
            commands.len() as u32,
            size as u32,
            flags,
            0,
        ] {
            bytes.extend(value.to_le_bytes());
        }
        for command in commands {
            bytes.extend(command);
        }
        bytes
    }

    fn string_command(kind: u32, text: &str) -> Vec<u8> {
        let mut body = text.as_bytes().to_vec();
        body.push(0);
        while !(12 + body.len()).is_multiple_of(8) {
            body.push(0);
        }
        let mut command = Vec::new();
        command.extend(kind.to_le_bytes());
        command.extend(((12 + body.len()) as u32).to_le_bytes());
        command.extend(12u32.to_le_bytes());
        command.extend(body);
        command
    }

    fn segment64(name: &str, protection: u32) -> Vec<u8> {
        let mut command = Vec::new();
        command.extend(0x19u32.to_le_bytes());
        command.extend(72u32.to_le_bytes());
        let mut segment_name = [0u8; 16];
        segment_name[..name.len()].copy_from_slice(name.as_bytes());
        command.extend(segment_name);
        for value in [0x1_0000_0000_u64, 0x4000, 0, 0] {
            command.extend(value.to_le_bytes());
        }
        for value in [7u32, protection, 0, 0] {
            command.extend(value.to_le_bytes());
        }
        command
    }

    fn main_command(entry: u64) -> Vec<u8> {
        let mut command = Vec::new();
        command.extend(0x8000_0028_u32.to_le_bytes());
        command.extend(24u32.to_le_bytes());
        command.extend(entry.to_le_bytes());
        command.extend(0u64.to_le_bytes());
        command
    }

    #[test]
    fn reads_a_signed_pie_executable() {
        let mut signature = Vec::new();
        signature.extend(0x1Du32.to_le_bytes());
        signature.extend(16u32.to_le_bytes());
        signature.extend([0; 8]);
        let bytes = image(
            2,
            0x0020_0000,
            &[
                segment64("__TEXT", 5),
                string_command(0xE, "/usr/lib/dyld"),
                string_command(0xC, "/usr/lib/libSystem.B.dylib"),
                string_command(0x8000_001C, "@executable_path/../Frameworks"),
                main_command(0x3F80),
                signature,
            ],
        );
        let report = inspect_macho(&bytes).unwrap().expect("Mach-O");
        assert_eq!(report.format, "Mach-O");
        assert_eq!(report.architecture, "ARM64");
        assert_eq!(report.kind, "executable");
        assert_eq!(report.entry_point, "0x3F80 (file offset)");
        assert_eq!(report.interpreter.as_deref(), Some("/usr/lib/dyld"));
        assert_eq!(report.needed_libraries, ["/usr/lib/libSystem.B.dylib"]);
        assert_eq!(
            report.rpath.as_deref(),
            Some("@executable_path/../Frameworks")
        );
        assert_eq!(report.signature_present, Some(true));
        assert_eq!(report.section_details[0].name, "__TEXT");
        assert!(report.section_details[0].executable && !report.section_details[0].writable);
        assert!(
            report.suspicious_properties.is_empty(),
            "{:?}",
            report.suspicious_properties
        );
    }

    #[test]
    fn flags_risky_properties() {
        let bytes = image(
            2,
            0x0002_0000,
            &[
                segment64("__DATA", 7),
                string_command(0xC, "/tmp/libhook.dylib"),
                string_command(0xC, "libplain.dylib"),
            ],
        );
        let report = inspect_macho(&bytes).unwrap().expect("Mach-O");
        let text = report.suspicious_properties.join("\n");
        assert!(
            text.contains("__DATA is both writable and executable"),
            "{text}"
        );
        assert!(text.contains("allows stack execution"), "{text}");
        assert!(text.contains("not position independent"), "{text}");
        assert!(text.contains("/tmp/libhook.dylib"), "{text}");
        assert!(text.contains("libplain.dylib"), "{text}");
        assert_eq!(report.signature_present, Some(false));
    }

    #[test]
    fn describes_the_first_slice_of_a_universal_binary() {
        let thin = image(6, 0, &[string_command(0xC, "/usr/lib/libc++.1.dylib")]);
        let mut fat = Vec::new();
        for value in [0xCAFE_BABE_u32, 2] {
            fat.extend(value.to_be_bytes());
        }
        let offset = 64u32;
        for cpu in [0x0100_000C_u32, 0x0100_0007] {
            for value in [cpu, 0, offset, thin.len() as u32, 0] {
                fat.extend(value.to_be_bytes());
            }
        }
        fat.resize(offset as usize, 0);
        fat.extend(&thin);
        let report = inspect_macho(&fat).unwrap().expect("Mach-O");
        assert_eq!(report.universal_architectures, ["ARM64", "x86_64"]);
        assert_eq!(report.kind, "dynamic library");
        assert_eq!(report.needed_libraries, ["/usr/lib/libc++.1.dylib"]);
    }

    #[test]
    fn java_class_files_are_not_mistaken_for_universal_binaries() {
        // CAFEBABE followed by minor 0 / major 52 (Java 8).
        let class = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34, 0, 0];
        assert!(inspect_macho(&class).unwrap().is_none());
    }

    #[test]
    fn truncated_or_inconsistent_input_does_not_panic() {
        let bytes = image(2, 0x0020_0000, &[main_command(1)]);
        for length in 0..bytes.len() {
            let _ = inspect_macho(&bytes[..length]);
        }
        // A load command whose size runs past the declared table is reported.
        let mut broken = image(2, 0, &[main_command(1)]);
        broken[32 + 4..32 + 8].copy_from_slice(&4096u32.to_le_bytes());
        let report = inspect_macho(&broken).unwrap().expect("Mach-O");
        assert!(!report.parse_warnings.is_empty());
    }
}

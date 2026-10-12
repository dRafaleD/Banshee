//! Additional PE triage metadata: import hash, Rich header, TLS callbacks.

use md5::{Digest, Md5};
use serde::Serialize;

use super::binary::{read_u32, read_u64};
use super::{ExecutableReport, ImportLibrary};

const MAX_RICH_ENTRIES: usize = 64;
const MAX_TLS_CALLBACKS: usize = 64;

#[derive(Debug, Clone, Serialize)]
pub struct RichHeader {
    /// XOR key stored after the `Rich` marker; it doubles as the checksum.
    pub key: String,
    pub checksum_valid: bool,
    pub entries: Vec<RichEntry>,
    pub entries_truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RichEntry {
    pub product_id: u16,
    pub build: u16,
    pub count: u32,
}

/// Import hash compatible with pefile's `get_imphash`: lowercase
/// `library.function` pairs joined by commas, hashed with MD5. Returns `None`
/// when the import list is incomplete, because a partial hash would mislead.
pub(super) fn imphash(imports: &[ImportLibrary], truncated: bool) -> Option<String> {
    if truncated || imports.is_empty() {
        return None;
    }
    let mut entries = Vec::new();
    for library in imports {
        if library.symbols_truncated || library.name.starts_with('<') {
            return None;
        }
        let lower = library.name.to_ascii_lowercase();
        let base = match lower.rsplit_once('.') {
            Some((base, "dll" | "ocx" | "sys")) => base,
            _ => lower.as_str(),
        };
        for symbol in &library.symbols {
            if symbol.starts_with('<') {
                return None;
            }
            let function = match symbol.strip_prefix('#') {
                Some(ordinal) => {
                    let ordinal = ordinal.parse::<u16>().ok()?;
                    // pefile looks ordinals up by the full lowercase DLL name.
                    super::ordinals::lookup(&lower, ordinal)
                        .map_or_else(|| format!("ord{ordinal}"), str::to_owned)
                }
                None => symbol.clone(),
            };
            entries.push(format!("{base}.{}", function.to_ascii_lowercase()));
        }
    }
    if entries.is_empty() {
        return None;
    }
    Some(format!("{:x}", Md5::digest(entries.join(",").as_bytes())))
}

/// Decodes the undocumented Rich header between the DOS stub and PE header.
pub(super) fn rich_header(bytes: &[u8], pe_offset: usize) -> Option<RichHeader> {
    let region = bytes.get(..pe_offset.min(bytes.len()))?;
    let rich = (0x80..region.len().saturating_sub(7))
        .step_by(4)
        .find(|offset| &region[*offset..*offset + 4] == b"Rich")?;
    let key = read_u32(region, rich + 4, true)?;
    let start = (0x80..rich)
        .step_by(4)
        .find(|offset| read_u32(region, *offset, true) == Some(key ^ 0x536E_6144))?; // "DanS"

    let mut entries = Vec::new();
    let mut truncated = false;
    let mut checksum = start as u32;
    for (index, byte) in region[..start].iter().enumerate() {
        if (0x3C..0x40).contains(&index) {
            continue; // e_lfanew is excluded from the checksum
        }
        checksum = checksum.wrapping_add(u32::from(*byte).rotate_left(index as u32));
    }
    // DanS is followed by three zero padding dwords before the entries.
    let mut offset = start + 16;
    while offset + 8 <= rich {
        let comp_id = read_u32(region, offset, true)? ^ key;
        let count = read_u32(region, offset + 4, true)? ^ key;
        checksum = checksum.wrapping_add(comp_id.rotate_left(count));
        if entries.len() < MAX_RICH_ENTRIES {
            entries.push(RichEntry {
                product_id: (comp_id >> 16) as u16,
                build: comp_id as u16,
                count,
            });
        } else {
            truncated = true;
        }
        offset += 8;
    }
    Some(RichHeader {
        key: format!("0x{key:08x}"),
        checksum_valid: checksum == key,
        entries,
        entries_truncated: truncated,
    })
}

/// Counts TLS callbacks, which run before the entry point.
pub(super) fn tls_callback_count(
    bytes: &[u8],
    tls_offset: usize,
    bits: u8,
    image_base: u64,
    rva_to_offset: impl Fn(u32) -> Option<usize>,
) -> Option<usize> {
    let pointer = if bits == 64 { 8 } else { 4 };
    let read_pointer = |offset: usize| {
        if bits == 64 {
            read_u64(bytes, offset, true)
        } else {
            read_u32(bytes, offset, true).map(u64::from)
        }
    };
    let callbacks_va = read_pointer(tls_offset + pointer * 3)?;
    if callbacks_va == 0 {
        return Some(0);
    }
    let callbacks_rva = u32::try_from(callbacks_va.checked_sub(image_base)?).ok()?;
    let start = rva_to_offset(callbacks_rva)?;
    let mut count = 0;
    while count < MAX_TLS_CALLBACKS {
        match read_pointer(start + count * pointer) {
            Some(0) | None => break,
            Some(_) => count += 1,
        }
    }
    Some(count)
}

/// Applies the extra PE checks once sections and imports are known.
pub(super) fn annotate(report: &mut ExecutableReport, entry_rva: u32) {
    report.imphash = imphash(&report.imports, report.imports_truncated);
    if let Some(rich) = &report.rich_header
        && !rich.checksum_valid
    {
        report.suspicious_properties.push(
            "PE Rich header checksum does not match (the header may have been altered)".to_owned(),
        );
    }
    for section in &report.section_details {
        if section.executable
            && let Some(entropy) = section.entropy
            && entropy >= 7.2
        {
            report.suspicious_properties.push(format!(
                "PE executable section '{}' has high entropy ({entropy:.2} bits/byte), consistent with packed or encrypted code",
                section.name
            ));
        }
    }
    let entry_in_executable_section = report.section_details.iter().any(|section| {
        section.executable
            && section
                .virtual_address
                .strip_prefix("RVA 0x")
                .and_then(|address| u32::from_str_radix(address, 16).ok())
                .is_some_and(|start| {
                    let size = section.memory_size.max(section.file_size);
                    u64::from(entry_rva) >= u64::from(start)
                        && u64::from(entry_rva) < u64::from(start) + size
                })
    });
    if entry_rva != 0 && !report.section_details.is_empty() && !entry_in_executable_section {
        report.suspicious_properties.push(format!(
            "PE entry point RVA 0x{entry_rva:X} is outside every executable section"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::{ImportLibrary, imphash, rich_header};

    fn library(name: &str, symbols: &[&str]) -> ImportLibrary {
        ImportLibrary {
            name: name.to_owned(),
            symbols: symbols.iter().map(|symbol| (*symbol).to_owned()).collect(),
            symbols_truncated: false,
        }
    }

    #[test]
    fn imphash_follows_pefile_normalization() {
        let imports = [
            library("KERNEL32.dll", &["GetProcAddress", "LoadLibraryA"]),
            library("WS2_32.dll", &["#23", "#9999"]),
            library("custom.drv", &["Init"]),
        ];
        let expected = format!(
            "{:x}",
            <md5::Md5 as md5::Digest>::digest(
                b"kernel32.getprocaddress,kernel32.loadlibrarya,ws2_32.socket,ws2_32.ord9999,custom.drv.init"
            )
        );
        assert_eq!(imphash(&imports, false).as_deref(), Some(expected.as_str()));
        assert_eq!(
            imphash(&imports, true),
            None,
            "truncated lists have no hash"
        );
        assert_eq!(
            imphash(&[library("a.dll", &["<unresolved-name>"])], false),
            None
        );
    }

    fn rich_fixture(entries: &[(u32, u32)]) -> Vec<u8> {
        let pe_offset = 0x80 + 16 + entries.len() * 8 + 8;
        let mut bytes = vec![0_u8; pe_offset + 4];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3C..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        bytes[0x40..0x48].copy_from_slice(b"stub!!!!");
        let mut key = 0x80_u32;
        for (index, byte) in bytes[..0x80].iter().enumerate() {
            if !(0x3C..0x40).contains(&index) {
                key = key.wrapping_add(u32::from(*byte).rotate_left(index as u32));
            }
        }
        for (comp_id, count) in entries {
            key = key.wrapping_add(comp_id.rotate_left(*count));
        }
        let mut offset = 0x80;
        for value in [0x536E_6144_u32, 0, 0, 0] {
            bytes[offset..offset + 4].copy_from_slice(&(value ^ key).to_le_bytes());
            offset += 4;
        }
        for (comp_id, count) in entries {
            bytes[offset..offset + 4].copy_from_slice(&(comp_id ^ key).to_le_bytes());
            bytes[offset + 4..offset + 8].copy_from_slice(&(count ^ key).to_le_bytes());
            offset += 8;
        }
        bytes[offset..offset + 4].copy_from_slice(b"Rich");
        bytes[offset + 4..offset + 8].copy_from_slice(&key.to_le_bytes());
        bytes
    }

    #[test]
    fn rich_header_decodes_entries_and_detects_tampering() {
        let entries = [(0x0104_7809, 12), (0x0105_7809, 3)];
        let mut bytes = rich_fixture(&entries);
        let pe_offset = bytes.len() - 4;
        let rich = rich_header(&bytes, pe_offset).expect("rich header");
        assert!(rich.checksum_valid);
        assert_eq!(rich.entries.len(), 2);
        assert_eq!(
            (
                rich.entries[0].product_id,
                rich.entries[0].build,
                rich.entries[0].count
            ),
            (0x0104, 0x7809, 12)
        );

        bytes[0x44] ^= 0x20; // alter the DOS stub without touching the header
        assert!(
            !rich_header(&bytes, pe_offset)
                .expect("rich header")
                .checksum_valid
        );
        assert!(rich_header(&bytes[..0x90], 0x90).is_none());
    }
}

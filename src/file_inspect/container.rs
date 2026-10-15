//! Disk images and other containers used to deliver payloads: ISO 9660 images
//! (with Joliet names) and Microsoft cabinets are listed without extraction;
//! 7-Zip, RAR, VHD, VHDX and WIM files are identified only, since listing them
//! needs decompression or a filesystem driver.

use std::collections::HashSet;

use super::archive::archive_path_is_safe;
use super::{ArchiveEntry, ArchiveReport};

const SECTOR: usize = 2048;
const MAX_DEPTH: usize = 16;
const MAX_DIRECTORIES: usize = 4_096;

/// File types that run code when opened from a mounted image or cabinet.
const RISKY_EXTENSIONS: &[&str] = &[
    "exe", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta",
    "lnk", "msi", "dll", "cpl", "jar", "chm", "url", "iso", "img", "vhd",
];

fn risky(name: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(_, extension)| {
        RISKY_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str())
    })
}

/// Formats recognized but not listed, by signature.
pub(super) fn identify_only(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        Some("7-Zip archive (contents not listed)")
    } else if bytes.starts_with(b"Rar!\x1A\x07") {
        Some("RAR archive (contents not listed)")
    } else if bytes.starts_with(b"vhdxfile") {
        Some("VHDX virtual disk (contents not listed)")
    } else if bytes.starts_with(b"conectix")
        || (bytes.len() >= 512 && bytes[bytes.len() - 512..].starts_with(b"conectix"))
    {
        Some("VHD virtual disk (contents not listed)")
    } else if bytes.starts_with(b"MSWIM\0\0\0") {
        Some("Windows imaging (WIM) archive (contents not listed)")
    } else {
        None
    }
}

pub(super) fn is_iso(bytes: &[u8]) -> bool {
    bytes.get(16 * SECTOR + 1..16 * SECTOR + 6) == Some(b"CD001")
}

pub(super) fn is_cab(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MSCF\0\0\0\0")
}

fn u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn add_entry(
    entries: &mut Vec<ArchiveEntry>,
    totals: &mut (usize, u64),
    max_entries: usize,
    findings: &mut Vec<String>,
    entry: ArchiveEntry,
    hidden: bool,
    container: &str,
) {
    totals.0 += 1;
    totals.1 = totals.1.saturating_add(entry.size);
    if !entry.path_safe {
        findings.push(format!("unsafe archive path: {}", entry.name));
    }
    if entry.kind == "file" && risky(&entry.name) {
        findings.push(format!(
            "{container} contains a file that runs code when opened: {}",
            entry.name
        ));
    }
    if hidden && entry.kind == "file" {
        findings.push(format!(
            "{container} contains a hidden file: {}",
            entry.name
        ));
    }
    if entries.len() < max_entries {
        entries.push(entry);
    }
}

/// Lists an ISO 9660 image, preferring Joliet (UTF-16) names when present.
pub(super) fn inspect_iso(
    bytes: &[u8],
    max_entries: usize,
    findings: &mut Vec<String>,
) -> ArchiveReport {
    // Volume descriptors start at sector 16 and end with type 255.
    let mut root = None;
    let mut joliet = false;
    for index in 16..64 {
        let Some(descriptor) = bytes.get(index * SECTOR..(index + 1) * SECTOR) else {
            break;
        };
        if &descriptor[1..6] != b"CD001" || descriptor[0] == 255 {
            break;
        }
        let record = descriptor.get(156..190);
        match descriptor[0] {
            1 if root.is_none() => root = record,
            // Joliet: supplementary descriptor with a UCS-2 escape sequence.
            2 if descriptor.get(88..90) == Some(b"%/") => {
                root = record;
                joliet = true;
            }
            _ => {}
        }
    }

    let mut entries = Vec::new();
    let mut totals = (0usize, 0u64);
    let mut queue: Vec<(u32, u32, String, usize)> = Vec::new();
    if let Some(record) = root
        && let (Some(extent), Some(size)) = (u32_le(record, 2), u32_le(record, 10))
    {
        queue.push((extent, size, String::new(), 0));
    } else {
        findings.push("ISO image has no readable root directory".to_owned());
    }
    let mut visited = HashSet::new();
    while let Some((extent, size, prefix, depth)) = queue.pop() {
        if depth > MAX_DEPTH || !visited.insert(extent) || visited.len() > MAX_DIRECTORIES {
            continue;
        }
        let start = extent as usize * SECTOR;
        let Some(directory) =
            bytes.get(start..start.saturating_add(size as usize).min(bytes.len()))
        else {
            continue;
        };
        let mut offset = 0;
        while offset < directory.len() {
            let length = usize::from(directory[offset]);
            if length == 0 {
                // Records never cross sectors; skip the padding.
                offset = (offset / SECTOR + 1) * SECTOR;
                continue;
            }
            let Some(record) = directory.get(offset..offset + length) else {
                break;
            };
            offset += length;
            let (Some(child_extent), Some(child_size), Some(&flags), Some(&name_length)) = (
                u32_le(record, 2),
                u32_le(record, 10),
                record.get(25),
                record.get(32),
            ) else {
                continue;
            };
            let Some(raw) = record.get(33..33 + usize::from(name_length)) else {
                continue;
            };
            if raw == [0] || raw == [1] {
                continue; // "." and ".."
            }
            let mut name = if joliet {
                let units: Vec<u16> = raw
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_be_bytes(*pair))
                    .collect();
                String::from_utf16_lossy(&units)
            } else {
                String::from_utf8_lossy(raw).into_owned()
            };
            if let Some((stem, _)) = name.rsplit_once(';') {
                name = stem.trim_end_matches('.').to_owned();
            }
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let is_directory = flags & 0x02 != 0;
            add_entry(
                &mut entries,
                &mut totals,
                max_entries,
                findings,
                ArchiveEntry {
                    path_safe: archive_path_is_safe(&path),
                    name: path.clone(),
                    kind: if is_directory { "directory" } else { "file" }.to_owned(),
                    size: if is_directory {
                        0
                    } else {
                        u64::from(child_size)
                    },
                    compressed_size: None,
                    encrypted: false,
                },
                flags & 0x01 != 0,
                "Disk image",
            );
            if is_directory {
                queue.push((child_extent, child_size, path, depth + 1));
            }
        }
    }
    ArchiveReport {
        total_entries: totals.0,
        total_size: totals.1,
        truncated: totals.0 > max_entries,
        entries,
    }
}

/// Lists the files of a Microsoft cabinet from its CFFILE table.
pub(super) fn inspect_cab(
    bytes: &[u8],
    max_entries: usize,
    findings: &mut Vec<String>,
) -> ArchiveReport {
    let mut entries = Vec::new();
    let mut totals = (0usize, 0u64);
    let (Some(first_file), Some(count)) = (u32_le(bytes, 16), u16_le(bytes, 28)) else {
        findings.push("cabinet header is truncated".to_owned());
        return ArchiveReport {
            total_entries: 0,
            total_size: 0,
            truncated: false,
            entries,
        };
    };
    let mut offset = first_file as usize;
    for _ in 0..count {
        let (Some(size), Some(attributes)) = (u32_le(bytes, offset), u16_le(bytes, offset + 14))
        else {
            findings.push("cabinet file table is truncated".to_owned());
            break;
        };
        let Some(raw) = bytes.get(offset + 16..) else {
            break;
        };
        let Some(end) = raw.iter().take(1024).position(|byte| *byte == 0) else {
            findings.push("cabinet file name is not terminated".to_owned());
            break;
        };
        let name = String::from_utf8_lossy(&raw[..end]).replace('\\', "/");
        offset += 16 + end + 1;
        add_entry(
            &mut entries,
            &mut totals,
            max_entries,
            findings,
            ArchiveEntry {
                path_safe: archive_path_is_safe(&name),
                name,
                kind: "file".to_owned(),
                size: u64::from(size),
                compressed_size: None,
                encrypted: false,
            },
            attributes & 0x02 != 0,
            "Cabinet",
        );
    }
    ArchiveReport {
        total_entries: totals.0,
        total_size: totals.1,
        truncated: totals.0 > max_entries,
        entries,
    }
}

#[cfg(test)]
mod tests {
    use super::{identify_only, inspect_cab, inspect_iso, is_cab, is_iso};

    /// Directory record with the given extent, size, flags and name bytes.
    fn record(extent: u32, size: u32, flags: u8, name: &[u8]) -> Vec<u8> {
        let mut length = 33 + name.len();
        length += length % 2;
        let mut record = vec![0u8; length];
        record[0] = length as u8;
        record[2..6].copy_from_slice(&extent.to_le_bytes());
        record[10..14].copy_from_slice(&size.to_le_bytes());
        record[25] = flags;
        record[32] = name.len() as u8;
        record[33..33 + name.len()].copy_from_slice(name);
        record
    }

    fn joliet(name: &str) -> Vec<u8> {
        name.encode_utf16().flat_map(u16::to_be_bytes).collect()
    }

    /// A small Joliet ISO: root holds invoice.lnk (hidden), payload/run.dll.
    fn iso() -> Vec<u8> {
        let mut image = vec![0u8; 24 * 2048];
        let mut descriptor = |sector: usize, kind: u8, root_extent: u32| {
            let start = sector * 2048;
            image[start] = kind;
            image[start + 1..start + 6].copy_from_slice(b"CD001");
            if kind == 2 {
                image[start + 88..start + 91].copy_from_slice(b"%/E");
            }
            if kind != 255 {
                let root = record(root_extent, 2048, 0x02, &[0]);
                image[start + 156..start + 156 + root.len()].copy_from_slice(&root);
            }
        };
        descriptor(16, 1, 20);
        descriptor(17, 2, 21);
        descriptor(18, 255, 0);
        let mut root = record(21, 2048, 0x02, &[0]);
        root.extend(record(21, 2048, 0x02, &[1]));
        root.extend(record(23, 120, 0x01, &joliet("invoice.lnk;1")));
        root.extend(record(22, 2048, 0x02, &joliet("payload")));
        image[21 * 2048..21 * 2048 + root.len()].copy_from_slice(&root);
        let child = record(23, 4096, 0x00, &joliet("run.dll"));
        image[22 * 2048..22 * 2048 + child.len()].copy_from_slice(&child);
        image
    }

    #[test]
    fn lists_a_joliet_iso_and_flags_risky_and_hidden_files() {
        let image = iso();
        assert!(is_iso(&image));
        let mut findings = Vec::new();
        let report = inspect_iso(&image, 100, &mut findings);
        let names: Vec<&str> = report
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, ["invoice.lnk", "payload", "payload/run.dll"]);
        assert_eq!(report.total_size, 120 + 4096);
        let text = findings.join("\n");
        assert!(
            text.contains("runs code when opened: invoice.lnk"),
            "{text}"
        );
        assert!(
            text.contains("runs code when opened: payload/run.dll"),
            "{text}"
        );
        assert!(text.contains("hidden file: invoice.lnk"), "{text}");
    }

    #[test]
    fn directory_loops_and_truncation_are_bounded() {
        let mut image = iso();
        // Point the child directory back at the root.
        let looped = record(21, 2048, 0x02, &joliet("loop"));
        image[22 * 2048..22 * 2048 + looped.len()].copy_from_slice(&looped);
        let mut findings = Vec::new();
        let report = inspect_iso(&image, 100, &mut findings);
        assert!(report.total_entries < 10);
        for length in [0, 16 * 2048, 17 * 2048 + 10, 21 * 2048 + 40] {
            let _ = inspect_iso(&image[..length], 100, &mut Vec::new());
        }
    }

    #[test]
    fn lists_cabinet_files() {
        let mut cab = b"MSCF\0\0\0\0".to_vec();
        cab.resize(36, 0);
        cab[16..20].copy_from_slice(&36u32.to_le_bytes());
        cab[28..30].copy_from_slice(&2u16.to_le_bytes());
        for (name, size, attributes) in [("readme.txt", 10u32, 0u16), ("bin\\setup.exe", 2048, 2)] {
            let mut entry = vec![0u8; 16];
            entry[0..4].copy_from_slice(&size.to_le_bytes());
            entry[14..16].copy_from_slice(&attributes.to_le_bytes());
            entry.extend(name.as_bytes());
            entry.push(0);
            cab.extend(entry);
        }
        assert!(is_cab(&cab));
        let mut findings = Vec::new();
        let report = inspect_cab(&cab, 100, &mut findings);
        let names: Vec<&str> = report
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, ["readme.txt", "bin/setup.exe"]);
        let text = findings.join("\n");
        assert!(
            text.contains("runs code when opened: bin/setup.exe"),
            "{text}"
        );
        assert!(text.contains("hidden file: bin/setup.exe"), "{text}");
        // A truncated table is reported, not a panic.
        let mut findings = Vec::new();
        let _ = inspect_cab(&cab[..50], 100, &mut findings);
        assert!(!findings.is_empty());
    }

    #[test]
    fn identifies_unlisted_containers() {
        assert!(
            identify_only(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 4])
                .unwrap()
                .starts_with("7-Zip")
        );
        assert!(
            identify_only(b"Rar!\x1A\x07\x01\x00")
                .unwrap()
                .starts_with("RAR")
        );
        assert!(identify_only(b"vhdxfile....").unwrap().starts_with("VHDX"));
        assert!(identify_only(b"plain text").is_none());
    }
}

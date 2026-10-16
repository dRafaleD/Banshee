use std::io::Cursor;
use std::path::{Component, Path};

use anyhow::{Context, Result};

use super::{ArchiveEntry, ArchiveReport};

pub(super) fn inspect_zip(
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
        // A name that is not valid text is shown lossily instead of failing the listing.
        let name = entry.name().map_or_else(
            |_| String::from_utf8_lossy(entry.name_raw()).into_owned(),
            std::borrow::Cow::into_owned,
        );
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

pub(super) fn inspect_tar(
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

pub(super) fn archive_path_is_safe(name: &str) -> bool {
    if name.is_empty() || name.contains('\0') {
        return false;
    }
    let normalized = name.replace('\\', "/");
    !normalized.starts_with('/')
        && Path::new(&normalized)
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

pub(super) fn is_zip(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(..4),
        Some(b"PK\x03\x04" | b"PK\x05\x06" | b"PK\x07\x08")
    )
}

pub(super) fn is_tar(bytes: &[u8]) -> bool {
    matches!(bytes.get(257..262), Some(b"ustar"))
}

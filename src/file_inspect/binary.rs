//! Bounds-checked byte readers shared by the executable parsers.

use super::MAX_EXECUTABLE_STRING_BYTES;

pub(super) fn file_slice(bytes: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = usize::try_from(offset.checked_add(size)?).ok()?;
    bytes.get(start..end)
}

pub(super) fn read_file_string(bytes: &[u8], offset: u64, size: u64) -> Option<String> {
    let slice = file_slice(bytes, offset, size.min(MAX_EXECUTABLE_STRING_BYTES as u64))?;
    let end = slice
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(slice.len());
    std::str::from_utf8(&slice[..end])
        .ok()
        .map(ToOwned::to_owned)
}

pub(super) fn read_c_string_u64(bytes: &[u8], offset: u64) -> Option<String> {
    read_c_string(
        bytes,
        usize::try_from(offset).ok()?,
        MAX_EXECUTABLE_STRING_BYTES,
    )
}

pub(super) fn read_c_string(bytes: &[u8], offset: usize, maximum: usize) -> Option<String> {
    let remaining = bytes.get(offset..)?;
    let end = remaining.iter().take(maximum).position(|byte| *byte == 0)?;
    std::str::from_utf8(&remaining[..end])
        .ok()
        .map(ToOwned::to_owned)
}

pub(super) fn bounded_name(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

pub(super) fn display_section_name(name: &str, index: usize) -> String {
    if name.is_empty() {
        format!("<section-{index}>")
    } else {
        name.to_owned()
    }
}

pub(super) fn is_packer_section_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "upx0" | "upx1" | "upx2" | ".aspack" | ".packed" | "mpress1" | "mpress2"
    )
}

pub(super) fn read_u16(bytes: &[u8], offset: usize, little: bool) -> Option<u16> {
    let value: [u8; 2] = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(if little {
        u16::from_le_bytes(value)
    } else {
        u16::from_be_bytes(value)
    })
}

pub(super) fn read_u32(bytes: &[u8], offset: usize, little: bool) -> Option<u32> {
    let value: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(if little {
        u32::from_le_bytes(value)
    } else {
        u32::from_be_bytes(value)
    })
}

pub(super) fn read_u64(bytes: &[u8], offset: usize, little: bool) -> Option<u64> {
    let value: [u8; 8] = bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(if little {
        u64::from_le_bytes(value)
    } else {
        u64::from_be_bytes(value)
    })
}

/// Shannon entropy in bits per byte of a section's file data, or `None` when
/// the declared range is empty or outside the file.
pub(super) fn range_entropy(bytes: &[u8], offset: u64, size: u64) -> Option<f64> {
    let data = file_slice(bytes, offset, size).filter(|data| !data.is_empty())?;
    let mut counts = [0_u64; 256];
    for byte in data {
        counts[usize::from(*byte)] += 1;
    }
    let length = data.len() as f64;
    let entropy = counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum::<f64>();
    Some((entropy * 100.0).round() / 100.0)
}

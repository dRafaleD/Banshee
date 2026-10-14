use std::fs::File;
use std::io::{self, IsTerminal, Read};
use std::path::Path;

use anyhow::{Context, Result, bail};

const MAX_RAW_INPUT_BYTES: u64 = 64 * 1024 * 1024;

pub fn read(argument: &Option<String>, file: Option<&Path>) -> Result<String> {
    if let Some(value) = argument {
        ensure_size(value.len())?;
        return Ok(value.clone());
    }

    if let Some(path) = file {
        let value = String::from_utf8(read_file(path)?)
            .with_context(|| format!("input file '{}' is not valid UTF-8", path.display()))?;
        return Ok(trim_line_ending(value));
    }

    if io::stdin().is_terminal() {
        bail!("no input provided; pass a value, use --file, or pipe data through stdin");
    }

    let value = String::from_utf8(read_limited(io::stdin())?)
        .context("stdin is not valid UTF-8; use a binary-capable command")?;
    Ok(trim_line_ending(value))
}

/// Reads exact bytes. Unlike `read`, file and stdin line endings are preserved.
pub fn read_bytes(argument: &Option<String>, file: Option<&Path>) -> Result<Vec<u8>> {
    if let Some(value) = argument {
        ensure_size(value.len())?;
        return Ok(value.as_bytes().to_vec());
    }
    if let Some(path) = file {
        return read_file(path);
    }
    if io::stdin().is_terminal() {
        bail!("no input provided; pass a value, use --file, or pipe data through stdin");
    }
    read_limited(io::stdin())
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to inspect input file '{}'", path.display()))?;
    if !metadata.is_file() {
        bail!("input path '{}' is not a regular file", path.display());
    }
    let file = File::open(path)
        .with_context(|| format!("failed to read input file '{}'", path.display()))?;
    read_limited(file)
}

fn read_limited<R: Read>(reader: R) -> Result<Vec<u8>> {
    read_limited_with_limit(reader, MAX_RAW_INPUT_BYTES)
}

/// Reads a regular file without trusting its earlier metadata size; a file
/// that grows while it is read still stops one byte past `limit`.
pub(crate) fn read_regular_file_limited(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to inspect {label} '{}'", path.display()))?;
    if !metadata.is_file() {
        bail!("{label} '{}' is not a regular file", path.display());
    }
    if metadata.len() > limit {
        bail!("{label} exceeds the {} safety limit", format_limit(limit));
    }
    let file =
        File::open(path).with_context(|| format!("failed to read {label} '{}'", path.display()))?;
    read_limited_with_limit(file, limit)
        .with_context(|| format!("failed to read {label} '{}'", path.display()))
}

/// UTF-8 variant of [`read_regular_file_limited`].
pub(crate) fn read_regular_text_file_limited(
    path: &Path,
    limit: u64,
    label: &str,
) -> Result<String> {
    String::from_utf8(read_regular_file_limited(path, limit, label)?)
        .with_context(|| format!("{label} '{}' is not valid UTF-8", path.display()))
}

fn read_limited_with_limit<R: Read>(reader: R, limit: u64) -> Result<Vec<u8>> {
    let mut value = Vec::new();
    reader
        .take(limit + 1)
        .read_to_end(&mut value)
        .context("failed to read input")?;
    if value.len() as u64 > limit {
        bail!("input exceeds the {} safety limit", format_limit(limit));
    }
    Ok(value)
}

fn format_limit(limit: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    const KIB: u64 = 1024;
    if limit >= MIB && limit.is_multiple_of(MIB) {
        format!("{} MiB", limit / MIB)
    } else if limit >= KIB && limit.is_multiple_of(KIB) {
        format!("{} KiB", limit / KIB)
    } else {
        format!("{limit}-byte")
    }
}

fn ensure_size(size: usize) -> Result<()> {
    if size as u64 > MAX_RAW_INPUT_BYTES {
        bail!("input exceeds the 64 MiB safety limit");
    }
    Ok(())
}

fn trim_line_ending(mut value: String) -> String {
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use super::{read_limited_with_limit, trim_line_ending};

    #[test]
    fn removes_one_trailing_line_ending() {
        assert_eq!(trim_line_ending("value\r\n".into()), "value");
        assert_eq!(trim_line_ending("value\n\n".into()), "value\n");
    }

    #[test]
    fn bounded_reader_rejects_data_past_its_limit() {
        let mut cursor = Cursor::new(b"12345".to_vec());
        let mut output = Vec::new();
        cursor
            .by_ref()
            .take(5)
            .read_to_end(&mut output)
            .expect("read fixture");
        assert_eq!(output, b"12345");

        let too_large = Cursor::new(b"12345".to_vec());
        assert!(read_limited_with_limit(too_large, 4).is_err());
    }

    #[test]
    fn regular_file_reader_enforces_limits_and_file_type() {
        let directory = std::env::temp_dir().join(format!(
            "banshee-input-limit-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&directory).expect("create directory");
        let path = directory.join("value.txt");
        std::fs::write(&path, b"12345").expect("write fixture");

        assert_eq!(
            super::read_regular_file_limited(&path, 5, "fixture").expect("within limit"),
            b"12345"
        );
        let error = super::read_regular_file_limited(&path, 4, "fixture")
            .expect_err("over limit")
            .to_string();
        assert!(error.contains("4-byte safety limit"), "{error}");
        assert!(super::read_regular_file_limited(&directory, 5, "fixture").is_err());

        std::fs::write(&path, [0xff, 0xfe]).expect("write invalid UTF-8");
        assert!(super::read_regular_text_file_limited(&path, 5, "fixture").is_err());
        std::fs::remove_dir_all(&directory).expect("remove directory");
    }
}

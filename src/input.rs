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

fn read_limited_with_limit<R: Read>(reader: R, limit: u64) -> Result<Vec<u8>> {
    let mut value = Vec::new();
    reader
        .take(limit + 1)
        .read_to_end(&mut value)
        .context("failed to read input")?;
    if value.len() as u64 > limit {
        bail!("input exceeds the 64 MiB safety limit");
    }
    Ok(value)
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
}

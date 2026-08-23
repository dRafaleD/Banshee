use std::io::{self, IsTerminal, Read};
use std::path::Path;

use anyhow::{Context, Result, bail};

const MAX_RAW_INPUT_BYTES: u64 = 64 * 1024 * 1024;

pub fn read(argument: &Option<String>, file: Option<&Path>) -> Result<String> {
    if let Some(value) = argument {
        return Ok(value.clone());
    }

    if let Some(path) = file {
        return std::fs::read_to_string(path)
            .with_context(|| format!("failed to read input file '{}'", path.display()))
            .map(trim_line_ending);
    }

    if io::stdin().is_terminal() {
        bail!("no input provided; pass a value, use --file, or pipe data through stdin");
    }

    let mut value = String::new();
    io::stdin()
        .read_to_string(&mut value)
        .context("failed to read stdin")?;

    Ok(trim_line_ending(value))
}

/// Reads exact bytes. Unlike `read`, file and stdin line endings are preserved.
pub fn read_bytes(argument: &Option<String>, file: Option<&Path>) -> Result<Vec<u8>> {
    if let Some(value) = argument {
        return Ok(value.as_bytes().to_vec());
    }
    if let Some(path) = file {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("failed to inspect input file '{}'", path.display()))?;
        if metadata.len() > MAX_RAW_INPUT_BYTES {
            bail!("input exceeds the 64 MiB binary analysis limit");
        }
        return std::fs::read(path)
            .with_context(|| format!("failed to read input file '{}'", path.display()));
    }
    if io::stdin().is_terminal() {
        bail!("no input provided; pass a value, use --file, or pipe data through stdin");
    }
    let mut value = Vec::new();
    io::stdin()
        .take(MAX_RAW_INPUT_BYTES + 1)
        .read_to_end(&mut value)
        .context("failed to read stdin")?;
    if value.len() as u64 > MAX_RAW_INPUT_BYTES {
        bail!("input exceeds the 64 MiB binary analysis limit");
    }
    Ok(value)
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
    use super::trim_line_ending;

    #[test]
    fn removes_one_trailing_line_ending() {
        assert_eq!(trim_line_ending("value\r\n".into()), "value");
        assert_eq!(trim_line_ending("value\n\n".into()), "value\n");
    }
}

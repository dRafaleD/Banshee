use std::fmt;
use std::io::{Read, Write};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use flate2::Compression;
use flate2::read::{GzDecoder, ZlibDecoder};
use flate2::write::{GzEncoder, ZlibEncoder};
use serde::Serialize;

use crate::codec::{self, Codec};

const MAX_RECIPE_BYTES: usize = 64 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECIPE_STEPS: usize = 32;

#[derive(Debug, Clone, Serialize)]
pub struct RecipeStepReport {
    pub index: usize,
    pub operation: String,
    pub input_bytes: usize,
    pub output_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecipeReport {
    pub recipe: String,
    pub steps: Vec<RecipeStepReport>,
    pub final_bytes: usize,
    pub final_text: Option<String>,
    pub final_base64: String,
}

#[derive(Debug, Clone)]
pub struct RecipeResult {
    pub report: RecipeReport,
    pub output: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
enum CompressionCodec {
    Gzip,
    Zlib,
}

#[derive(Debug, Clone, Copy)]
enum RecipeOperation {
    Decode(Codec),
    Encode(Codec),
    Decompress(CompressionCodec),
    Compress(CompressionCodec),
}

impl fmt::Display for RecipeOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(codec) => write!(formatter, "decode:{}", codec_name(*codec)),
            Self::Encode(codec) => write!(formatter, "encode:{}", codec_name(*codec)),
            Self::Decompress(codec) => write!(formatter, "decode:{}", compression_name(*codec)),
            Self::Compress(codec) => write!(formatter, "encode:{}", compression_name(*codec)),
        }
    }
}

pub fn run(recipe: &str, mut value: Vec<u8>) -> Result<RecipeResult> {
    ensure_size(&value)?;
    let operations = parse_recipe(recipe)?;
    let mut steps = Vec::with_capacity(operations.len());

    for (offset, operation) in operations.iter().enumerate() {
        let input_bytes = value.len();
        value = apply(*operation, value)
            .with_context(|| format!("recipe step {} ({operation}) failed", offset + 1))?;
        ensure_size(&value)?;
        steps.push(RecipeStepReport {
            index: offset + 1,
            operation: operation.to_string(),
            input_bytes,
            output_bytes: value.len(),
        });
    }

    let report = RecipeReport {
        recipe: recipe.trim().to_owned(),
        steps,
        final_bytes: value.len(),
        final_text: String::from_utf8(value.clone()).ok(),
        final_base64: STANDARD.encode(&value),
    };
    Ok(RecipeResult {
        report,
        output: value,
    })
}

fn parse_recipe(recipe: &str) -> Result<Vec<RecipeOperation>> {
    let source = recipe.trim();
    if source.is_empty() {
        bail!("recipe cannot be empty");
    }

    let mut operations = Vec::new();
    for (offset, raw) in source.split('|').enumerate() {
        let name = raw.trim().to_ascii_lowercase();
        if name.is_empty() {
            bail!("recipe step {} is empty", offset + 1);
        }
        operations.push(
            parse_operation(&name).with_context(|| {
                format!("invalid recipe step {} ('{}')", offset + 1, raw.trim())
            })?,
        );
    }
    if operations.len() > MAX_RECIPE_STEPS {
        bail!("recipe exceeds the {MAX_RECIPE_STEPS}-step limit");
    }
    Ok(operations)
}

fn parse_operation(name: &str) -> Result<RecipeOperation> {
    let (direction, format) = match name.split_once(':') {
        Some((direction, format)) => (direction, format),
        None => ("decode", name),
    };
    let operation = match (direction, format) {
        ("decode", format) => decode_operation(format),
        ("encode", format) => encode_operation(format),
        _ => None,
    };
    operation.ok_or_else(|| {
        anyhow!(
            "unsupported operation; use base64, base64url, base32, base85, hex, binary, octal, rot13, punycode, url, html, unicode, gzip, zlib, or encode:<format>"
        )
    })
}

fn decode_operation(format: &str) -> Option<RecipeOperation> {
    Some(match format {
        "base64" => RecipeOperation::Decode(Codec::Base64),
        "base64url" => RecipeOperation::Decode(Codec::Base64url),
        "base32" => RecipeOperation::Decode(Codec::Base32),
        "base85" | "ascii85" => RecipeOperation::Decode(Codec::Base85),
        "hex" => RecipeOperation::Decode(Codec::Hex),
        "binary" | "bin" => RecipeOperation::Decode(Codec::Binary),
        "octal" | "oct" => RecipeOperation::Decode(Codec::Octal),
        "rot13" => RecipeOperation::Decode(Codec::Rot13),
        "punycode" | "idna" => RecipeOperation::Decode(Codec::Punycode),
        "url" => RecipeOperation::Decode(Codec::Url),
        "html" => RecipeOperation::Decode(Codec::Html),
        "unicode" => RecipeOperation::Decode(Codec::Unicode),
        "gzip" => RecipeOperation::Decompress(CompressionCodec::Gzip),
        "zlib" => RecipeOperation::Decompress(CompressionCodec::Zlib),
        _ => return None,
    })
}

fn encode_operation(format: &str) -> Option<RecipeOperation> {
    Some(match format {
        "base64" => RecipeOperation::Encode(Codec::Base64),
        "base64url" => RecipeOperation::Encode(Codec::Base64url),
        "base32" => RecipeOperation::Encode(Codec::Base32),
        "base85" | "ascii85" => RecipeOperation::Encode(Codec::Base85),
        "hex" => RecipeOperation::Encode(Codec::Hex),
        "binary" | "bin" => RecipeOperation::Encode(Codec::Binary),
        "octal" | "oct" => RecipeOperation::Encode(Codec::Octal),
        "rot13" => RecipeOperation::Encode(Codec::Rot13),
        "punycode" | "idna" => RecipeOperation::Encode(Codec::Punycode),
        "url" => RecipeOperation::Encode(Codec::Url),
        "html" => RecipeOperation::Encode(Codec::Html),
        "unicode" => RecipeOperation::Encode(Codec::Unicode),
        "gzip" => RecipeOperation::Compress(CompressionCodec::Gzip),
        "zlib" => RecipeOperation::Compress(CompressionCodec::Zlib),
        _ => return None,
    })
}

fn apply(operation: RecipeOperation, value: Vec<u8>) -> Result<Vec<u8>> {
    match operation {
        RecipeOperation::Decode(codec) => {
            let input = std::str::from_utf8(&value)
                .context("this decoding operation requires UTF-8 text input")?;
            codec::decode(input, codec)
        }
        RecipeOperation::Encode(codec) => Ok(codec::encode_bytes(&value, codec)?.into_bytes()),
        RecipeOperation::Decompress(codec) => decompress(&value, codec),
        RecipeOperation::Compress(codec) => compress(&value, codec),
    }
}

fn decompress(input: &[u8], codec: CompressionCodec) -> Result<Vec<u8>> {
    let reader: Box<dyn Read> = match codec {
        CompressionCodec::Gzip => Box::new(GzDecoder::new(input)),
        CompressionCodec::Zlib => Box::new(ZlibDecoder::new(input)),
    };
    let mut output = Vec::new();
    reader
        .take(MAX_DECOMPRESSED_BYTES + 1)
        .read_to_end(&mut output)
        .context("invalid or unreadable compressed data")?;
    if output.len() as u64 > MAX_DECOMPRESSED_BYTES {
        bail!("decompressed output exceeds the 16 MiB safety limit");
    }
    Ok(output)
}

fn compress(input: &[u8], codec: CompressionCodec) -> Result<Vec<u8>> {
    let mut output = match codec {
        CompressionCodec::Gzip => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(input).context("failed to gzip input")?;
            encoder.finish().context("failed to finalize gzip data")?
        }
        CompressionCodec::Zlib => {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(input)
                .context("failed to zlib-compress input")?;
            encoder.finish().context("failed to finalize zlib data")?
        }
    };
    output.shrink_to_fit();
    Ok(output)
}

fn ensure_size(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_RECIPE_BYTES {
        bail!("recipe output exceeds the 64 MiB safety limit");
    }
    Ok(())
}

fn codec_name(codec: Codec) -> &'static str {
    match codec {
        Codec::Base64 => "base64",
        Codec::Base64url => "base64url",
        Codec::Base32 => "base32",
        Codec::Base85 => "base85",
        Codec::Hex => "hex",
        Codec::Binary => "binary",
        Codec::Octal => "octal",
        Codec::Rot13 => "rot13",
        Codec::Punycode => "punycode",
        Codec::Url => "url",
        Codec::Html => "html",
        Codec::Unicode => "unicode",
    }
}

fn compression_name(codec: CompressionCodec) -> &'static str {
    match codec {
        CompressionCodec::Gzip => "gzip",
        CompressionCodec::Zlib => "zlib",
    }
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn applies_nested_decoding_recipe() {
        let result = run("base64 | url", b"aGVsbG8lMjB3b3JsZA==".to_vec()).expect("recipe");
        assert_eq!(result.output, b"hello world");
        assert_eq!(result.report.steps.len(), 2);
    }

    #[test]
    fn applies_explicit_encoding_recipe() {
        let result = run("url|encode:base64", b"hello%20world".to_vec()).expect("recipe");
        assert_eq!(result.output, b"aGVsbG8gd29ybGQ=");
    }

    #[test]
    fn identifies_invalid_step() {
        let error = run("base64|unknown", b"aGVsbG8=".to_vec()).expect_err("invalid recipe");
        assert!(error.to_string().contains("invalid recipe step 2"));
    }

    #[test]
    fn supports_new_text_codecs_in_recipes() {
        let result = run("rot13|encode:base32", b"Uryyb".to_vec()).expect("recipe");
        assert_eq!(result.output, b"JBSWY3DP");
    }
}

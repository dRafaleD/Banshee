//! `banshee doctor`: offline checks of the local installation.
//!
//! Every check runs in-process on synthetic data. Nothing is downloaded, no
//! network request is made, and the only file written is a uniquely named
//! temporary file that is removed immediately.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub version: &'static str,
    pub platform: String,
    pub checks: Vec<Check>,
    pub healthy: bool,
}

pub fn run() -> DoctorReport {
    let mut checks = vec![
        Check {
            name: "build",
            status: CheckStatus::Ok,
            detail: format!(
                "{} build for {}-{}",
                if cfg!(debug_assertions) {
                    "debug"
                } else {
                    "release"
                },
                std::env::consts::ARCH,
                std::env::consts::OS
            ),
        },
        check("gzip and zlib", check_deflate),
        check("bzip2", check_bzip2),
        if cfg!(feature = "xz") {
            check("xz (liblzma)", check_xz)
        } else {
            Check {
                name: "xz (liblzma)",
                status: CheckStatus::Warn,
                detail: "not built in; XZ payloads are identified but not decompressed".to_owned(),
            }
        },
        Check {
            name: "signature verification",
            status: if cfg!(feature = "crypto-verify") {
                CheckStatus::Ok
            } else {
                CheckStatus::Warn
            },
            detail: if cfg!(feature = "crypto-verify") {
                "JWT and X.509 signature verification available".to_owned()
            } else {
                "not built in; jwt verify fails and chain signatures report unsupported".to_owned()
            },
        },
        check("decoder self-test", check_decoder),
        check("rule engine", check_rules),
        check("TLD snapshot", check_tlds),
        check("temporary directory", check_temporary_directory),
    ];
    checks.push(check_path());
    checks.push(Check {
        name: "color output",
        status: CheckStatus::Ok,
        detail: if std::env::var_os("NO_COLOR").is_some() {
            "disabled by NO_COLOR".to_owned()
        } else {
            "enabled only for interactive terminals; use --no-color or NO_COLOR to disable"
                .to_owned()
        },
    });
    let healthy = checks.iter().all(|check| check.status != CheckStatus::Fail);
    DoctorReport {
        version: env!("CARGO_PKG_VERSION"),
        platform: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
        checks,
        healthy,
    }
}

fn check(name: &'static str, test: fn() -> Result<String>) -> Check {
    match test() {
        Ok(detail) => Check {
            name,
            status: CheckStatus::Ok,
            detail,
        },
        Err(error) => Check {
            name,
            status: CheckStatus::Fail,
            detail: format!("{error:#}"),
        },
    }
}

const SAMPLE: &[u8] = b"Banshee doctor round-trip sample: http://doctor.example.test/";

fn round_trip(
    name: &str,
    compress: impl FnOnce(&[u8]) -> std::io::Result<Vec<u8>>,
    decompress: impl FnOnce(&[u8]) -> std::io::Result<Vec<u8>>,
) -> Result<String> {
    let compressed = compress(SAMPLE).with_context(|| format!("{name} compression failed"))?;
    let restored =
        decompress(&compressed).with_context(|| format!("{name} decompression failed"))?;
    if restored != SAMPLE {
        bail!("{name} round trip produced different bytes");
    }
    Ok(format!("{} byte round trip succeeded", SAMPLE.len()))
}

fn read_all(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader.read_to_end(&mut output)?;
    Ok(output)
}

fn check_deflate() -> Result<String> {
    round_trip(
        "gzip",
        |data| {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(data)?;
            encoder.finish()
        },
        |data| read_all(flate2::read::GzDecoder::new(data)),
    )?;
    round_trip(
        "zlib",
        |data| {
            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(data)?;
            encoder.finish()
        },
        |data| read_all(flate2::read::ZlibDecoder::new(data)),
    )
}

fn check_bzip2() -> Result<String> {
    round_trip(
        "bzip2",
        |data| {
            let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
            encoder.write_all(data)?;
            encoder.finish()
        },
        |data| read_all(bzip2::read::BzDecoder::new(data)),
    )
}

#[cfg(not(feature = "xz"))]
fn check_xz() -> Result<String> {
    bail!("xz support is not built in")
}

#[cfg(feature = "xz")]
fn check_xz() -> Result<String> {
    round_trip(
        "xz",
        |data| {
            let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 1);
            encoder.write_all(data)?;
            encoder.finish()
        },
        |data| read_all(xz2::read::XzDecoder::new(data)),
    )
    .context("liblzma is unavailable or broken; on Linux install liblzma (for example liblzma5)")
}

fn check_decoder() -> Result<String> {
    let report = crate::analysis::Analyzer::new(8).analyze("aGVsbG8lMjB3b3JsZA==");
    if report.final_value != "hello world" || report.layers.len() != 2 {
        bail!(
            "expected two layers decoding to 'hello world', got {} layer(s) and '{}'",
            report.layers.len(),
            report.final_value
        );
    }
    Ok("Base64 and URL layers decoded".to_owned())
}

fn check_rules() -> Result<String> {
    let source = "version = 1\n[[rules]]\nid = 'doctor'\nkind = 'hex'\npattern = '4D 5A ?? 00'\n";
    let report = crate::rules::scan_source(source, b"--MZ\x90\x00--")?;
    if report.matched_rules != 1 {
        bail!("synthetic hex rule did not match");
    }
    Ok("synthetic hex rule compiled and matched".to_owned())
}

fn check_tlds() -> Result<String> {
    let version = crate::tld::snapshot_version().context("TLD snapshot has no version line")?;
    if !crate::tld::has_known_tld("doctor.example.com") || crate::tld::has_known_tld("gate.php") {
        bail!("TLD validation returned unexpected results");
    }
    Ok(version.to_owned())
}

fn check_temporary_directory() -> Result<String> {
    let directory = std::env::temp_dir();
    let path = directory.join(format!(
        "banshee-doctor-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("cannot create a file in '{}'", directory.display()))?;
    file.write_all(b"doctor")?;
    drop(file);
    std::fs::remove_file(&path).with_context(|| format!("cannot remove '{}'", path.display()))?;
    Ok(format!("'{}' is writable", directory.display()))
}

fn check_path() -> Check {
    let current = std::env::current_exe().ok();
    let found = find_on_path(executable_name());
    let (status, detail) = match (&found, &current) {
        (None, _) => (
            CheckStatus::Warn,
            "banshee is not on PATH; call it by full path or see docs/INSTALLATION.md".to_owned(),
        ),
        (Some(found), Some(current)) if same_file(found, current) => (
            CheckStatus::Ok,
            format!("this binary is first on PATH: {}", found.display()),
        ),
        (Some(found), _) => (
            CheckStatus::Warn,
            format!(
                "PATH resolves to a different binary: {} (running {})",
                found.display(),
                current.as_deref().map_or_else(
                    || "an unknown path".to_owned(),
                    |path| path.display().to_string()
                )
            ),
        ),
    };
    Check {
        name: "PATH",
        status,
        detail,
    }
}

const fn executable_name() -> &'static str {
    if cfg!(windows) {
        "banshee.exe"
    } else {
        "banshee"
    }
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
}

fn same_file(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

pub fn print(report: &DoctorReport, json: bool) -> Result<()> {
    crate::output::print_json_or(report, json, |output| {
        writeln!(output, "Banshee {} ({})", report.version, report.platform)?;
        for check in &report.checks {
            let label = match check.status {
                CheckStatus::Ok => "ok  ",
                CheckStatus::Warn => "warn",
                CheckStatus::Fail => "FAIL",
            };
            writeln!(
                output,
                "[{label}] {}: {}",
                check.name,
                crate::output::terminal_safe(&check.detail)
            )?;
        }
        writeln!(
            output,
            "{}",
            if report.healthy {
                "No problems found."
            } else {
                "Some checks failed; see docs/INSTALLATION.md#troubleshooting."
            }
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{CheckStatus, run};

    #[test]
    fn doctor_checks_pass_in_the_test_environment() {
        let report = run();
        let failures = report
            .checks
            .iter()
            .filter(|check| check.status == CheckStatus::Fail)
            .map(|check| format!("{}: {}", check.name, check.detail))
            .collect::<Vec<_>>();
        assert!(failures.is_empty(), "{failures:?}");
        assert!(report.healthy);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "xz (liblzma)")
        );
    }
}

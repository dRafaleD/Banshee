use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const BUNDLE_SCHEMA_VERSION: u8 = 1;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_MANIFEST_ENTRIES: usize = 32;
const MAX_VERIFIED_BYTES: u64 = 512 * 1024 * 1024;
const REQUIRED_BUNDLE_ENTRIES: [&str; 6] = [
    "hashes.txt",
    "iocs.json",
    "metadata.json",
    "report.json",
    "report.md",
    "rule-matches.json",
];

#[derive(Debug, Clone, Copy)]
pub struct CreateOptions<'a> {
    pub rules: Option<crate::report::RuleSource<'a>>,
    pub include_sample: bool,
    pub max_entries: usize,
    pub max_depth: u8,
    pub max_tokens: usize,
    pub force: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateReport {
    pub bundle: String,
    pub files_written: usize,
    pub source_sample_included: bool,
    pub total_findings: usize,
    pub replaced_existing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup_warning: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct BundleMetadata {
    schema_version: u8,
    banshee_version: String,
    analyzed_at_utc: String,
    source_path: String,
    source_sample_included: bool,
    options: BundleCommandOptions,
}

#[derive(Debug, Clone, Serialize)]
struct BundleCommandOptions {
    rule_file: Option<String>,
    max_entries: usize,
    max_depth: u8,
    max_tokens: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub schema_version: u8,
    pub generated_by: String,
    pub entries: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationReport {
    pub bundle: String,
    pub valid: bool,
    pub entries_checked: usize,
    pub total_bytes_checked: u64,
    pub errors: Vec<String>,
}

struct StagingGuard {
    path: PathBuf,
    armed: bool,
}

impl StagingGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

pub fn create(source: &Path, target: &Path, options: CreateOptions<'_>) -> Result<CreateReport> {
    validate_target(source, target, options.force)?;
    let parent = target_parent(target);
    let staging = unique_sibling(target, "staging")?;
    fs::create_dir(&staging)
        .with_context(|| format!("failed to create staging directory '{}'", staging.display()))?;
    let mut guard = StagingGuard {
        path: staging.clone(),
        armed: true,
    };

    let report = crate::report::generate(
        source,
        options.rules,
        options.max_entries,
        options.max_depth,
        options.max_tokens,
    )?;
    let mut entries = Vec::new();

    let mut json = Vec::new();
    crate::report::write_to(&mut json, &report, crate::report::ReportFormat::Json)?;
    write_entry(&staging, "report.json", &json, &mut entries)?;

    let mut markdown = Vec::new();
    crate::report::write_to(
        &mut markdown,
        &report,
        crate::report::ReportFormat::Markdown,
    )?;
    write_entry(&staging, "report.md", &markdown, &mut entries)?;

    let hashes = format!(
        "MD5     {}\nSHA-1   {}\nSHA-256 {}\n",
        report.hashes.md5, report.hashes.sha1, report.hashes.sha256
    );
    write_entry(&staging, "hashes.txt", hashes.as_bytes(), &mut entries)?;

    let mut iocs = serde_json::to_vec_pretty(&report.content_analysis.report.iocs)
        .context("failed to serialize IOC evidence")?;
    iocs.push(b'\n');
    write_entry(&staging, "iocs.json", &iocs, &mut entries)?;

    let mut rules = serde_json::to_vec_pretty(&report.rule_analysis)
        .context("failed to serialize rule evidence")?;
    rules.push(b'\n');
    write_entry(&staging, "rule-matches.json", &rules, &mut entries)?;

    let metadata = BundleMetadata {
        schema_version: BUNDLE_SCHEMA_VERSION,
        banshee_version: env!("CARGO_PKG_VERSION").to_owned(),
        analyzed_at_utc: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .context("failed to format UTC analysis timestamp")?,
        source_path: source.display().to_string(),
        source_sample_included: options.include_sample,
        options: BundleCommandOptions {
            rule_file: options.rules.map(|rules| rules.label()),
            max_entries: options.max_entries,
            max_depth: options.max_depth,
            max_tokens: options.max_tokens,
        },
    };
    let mut metadata_bytes =
        serde_json::to_vec_pretty(&metadata).context("failed to serialize bundle metadata")?;
    metadata_bytes.push(b'\n');
    write_entry(&staging, "metadata.json", &metadata_bytes, &mut entries)?;

    if options.include_sample {
        let sample_target = staging.join("source-sample.bin");
        fs::copy(source, &sample_target).with_context(|| {
            format!(
                "failed to copy source sample into '{}'",
                sample_target.display()
            )
        })?;
        entries.push(manifest_entry(&sample_target, "source-sample.bin")?);
    }

    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let manifest = BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION,
        generated_by: format!("banshee {}", env!("CARGO_PKG_VERSION")),
        entries,
    };
    let mut manifest_bytes =
        serde_json::to_vec_pretty(&manifest).context("failed to serialize bundle manifest")?;
    manifest_bytes.push(b'\n');
    fs::write(staging.join("manifest.json"), manifest_bytes)
        .context("failed to write bundle manifest")?;

    let existed = fs::symlink_metadata(target).is_ok();
    if existed && !options.force {
        bail!(
            "evidence output '{}' was created while the bundle was being prepared; refusing to overwrite it",
            target.display()
        );
    }
    if existed {
        ensure_valid_replace_target(target)?;
    }
    let backup = if existed {
        let backup = unique_sibling(target, "backup")?;
        fs::rename(target, &backup).with_context(|| {
            format!(
                "failed to move existing target '{}' aside",
                target.display()
            )
        })?;
        let verification = match verify(&backup) {
            Ok(verification) => verification,
            Err(error) => {
                let _ = fs::rename(&backup, target);
                return Err(error).with_context(|| {
                    format!(
                        "existing evidence target '{}' changed before replacement",
                        target.display()
                    )
                });
            }
        };
        if !verification.valid {
            let _ = fs::rename(&backup, target);
            bail!(
                "--force refused to replace '{}': existing bundle failed verification: {}",
                target.display(),
                verification.errors.join("; ")
            );
        }
        Some(backup)
    } else {
        None
    };

    if let Err(error) = fs::rename(&staging, target) {
        if let Some(backup) = &backup {
            let _ = fs::rename(backup, target);
        }
        return Err(error).with_context(|| {
            format!(
                "failed to finalize evidence bundle '{}' from staging directory in '{}'",
                target.display(),
                parent.display()
            )
        });
    }
    guard.disarm();

    let cleanup_warning = backup.and_then(|path| {
        remove_path(&path)
            .err()
            .map(|error| format!("old target remains at '{}': {error}", path.display()))
    });
    Ok(CreateReport {
        bundle: target.display().to_string(),
        files_written: manifest.entries.len() + 1,
        source_sample_included: options.include_sample,
        total_findings: report.summary.total_findings,
        replaced_existing: existed,
        cleanup_warning,
    })
}

pub fn verify(bundle: &Path) -> Result<VerificationReport> {
    let metadata = fs::symlink_metadata(bundle)
        .with_context(|| format!("failed to inspect bundle '{}'", bundle.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("'{}' is not an evidence bundle directory", bundle.display());
    }
    let manifest_path = bundle.join("manifest.json");
    let manifest_metadata = fs::symlink_metadata(&manifest_path)
        .with_context(|| format!("missing manifest '{}'", manifest_path.display()))?;
    if !manifest_metadata.is_file() || manifest_metadata.file_type().is_symlink() {
        bail!("bundle manifest must be a regular file, not a symbolic link");
    }
    if manifest_metadata.len() > MAX_MANIFEST_BYTES {
        bail!("bundle manifest exceeds the 1 MiB safety limit");
    }
    let manifest_source = crate::input::read_regular_text_file_limited(
        &manifest_path,
        MAX_MANIFEST_BYTES,
        "bundle manifest",
    )?;
    let manifest: BundleManifest =
        serde_json::from_str(&manifest_source).context("invalid evidence manifest JSON")?;
    if manifest.schema_version != BUNDLE_SCHEMA_VERSION {
        bail!(
            "unsupported evidence manifest schema version {}; expected {}",
            manifest.schema_version,
            BUNDLE_SCHEMA_VERSION
        );
    }
    if manifest.entries.len() > MAX_MANIFEST_ENTRIES {
        bail!("evidence manifest exceeds the {MAX_MANIFEST_ENTRIES}-entry safety limit");
    }

    let mut errors = Vec::new();
    let mut expected = HashSet::from(["manifest.json".to_owned()]);
    let mut entries_checked = 0_usize;
    let mut total_bytes_checked = 0_u64;
    let mut previous = None;
    for entry in &manifest.entries {
        if !safe_entry_name(&entry.path) {
            errors.push(format!("unsafe manifest path: {}", entry.path));
            continue;
        }
        if previous.as_ref().is_some_and(|value| value >= &entry.path) {
            errors.push("manifest entries are not strictly sorted and unique".to_owned());
        }
        previous = Some(entry.path.clone());
        if !expected.insert(entry.path.clone()) {
            errors.push(format!("duplicate manifest path: {}", entry.path));
            continue;
        }
        if entry.sha256.len() != 64 || !entry.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            errors.push(format!("invalid SHA-256 digest for {}", entry.path));
            continue;
        }
        let path = bundle.join(&entry.path);
        let file_metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
            Ok(_) => {
                errors.push(format!("entry is not a regular file: {}", entry.path));
                continue;
            }
            Err(_) => {
                errors.push(format!("missing entry: {}", entry.path));
                continue;
            }
        };
        if file_metadata.len() != entry.size {
            errors.push(format!(
                "size mismatch for {}: expected {}, found {}",
                entry.path,
                entry.size,
                file_metadata.len()
            ));
        }
        total_bytes_checked = total_bytes_checked.saturating_add(file_metadata.len());
        if total_bytes_checked > MAX_VERIFIED_BYTES {
            bail!("bundle verification exceeds the 512 MiB safety limit");
        }
        let digest = hash_file(&path)?;
        if digest != entry.sha256 {
            errors.push(format!("SHA-256 mismatch for {}", entry.path));
        }
        entries_checked += 1;
    }

    for required in REQUIRED_BUNDLE_ENTRIES {
        if !expected.contains(required) {
            errors.push(format!("missing required manifest entry: {required}"));
        }
    }

    for directory_entry in fs::read_dir(bundle)
        .with_context(|| format!("failed to list bundle '{}'", bundle.display()))?
    {
        let directory_entry = directory_entry.context("failed to read bundle directory entry")?;
        let name = directory_entry.file_name().to_string_lossy().into_owned();
        if !expected.contains(&name) {
            errors.push(format!("unlisted bundle entry: {name}"));
        }
    }

    Ok(VerificationReport {
        bundle: bundle.display().to_string(),
        valid: errors.is_empty(),
        entries_checked,
        total_bytes_checked,
        errors,
    })
}

fn validate_target(source: &Path, target: &Path, force: bool) -> Result<()> {
    let parent = target_parent(target);
    if target.file_name().is_none() {
        bail!("evidence output must name a bundle directory");
    }
    let parent_metadata = fs::metadata(parent).with_context(|| {
        format!(
            "evidence output parent directory '{}' does not exist",
            parent.display()
        )
    })?;
    if !parent_metadata.is_dir() {
        bail!(
            "evidence output parent '{}' is not a directory",
            parent.display()
        );
    }
    let canonical_source = fs::canonicalize(source)
        .with_context(|| format!("failed to resolve source file '{}'", source.display()))?;
    let target_metadata = fs::symlink_metadata(target).ok();
    let resolved_target = match &target_metadata {
        Some(_) => fs::canonicalize(target)
            .with_context(|| format!("failed to resolve evidence output '{}'", target.display()))?,
        None => fs::canonicalize(parent)
            .with_context(|| format!("failed to resolve output parent '{}'", parent.display()))?
            .join(target.file_name().expect("target filename checked")),
    };
    if paths_equal(&canonical_source, &resolved_target) {
        bail!("source file and evidence output path must be different");
    }
    if target_metadata
        .as_ref()
        .is_some_and(|metadata| metadata.is_dir())
        && canonical_source.starts_with(&resolved_target)
    {
        bail!("evidence output cannot contain the source file");
    }
    if target_metadata.is_some() && !force {
        bail!(
            "evidence output '{}' already exists; use --force to replace it",
            target.display()
        );
    }
    if target_metadata.is_some() && force {
        ensure_valid_replace_target(target)?;
    }
    Ok(())
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    if cfg!(windows) {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    } else {
        left == right
    }
}

fn unique_sibling(target: &Path, role: &str) -> Result<PathBuf> {
    let parent = target_parent(target);
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .context("evidence output name must be valid UTF-8")?;
    for index in 0..100_u8 {
        let candidate = parent.join(format!(
            ".{name}.banshee-{role}-{}-{index}",
            std::process::id()
        ));
        if fs::symlink_metadata(&candidate).is_err() {
            return Ok(candidate);
        }
    }
    bail!("could not allocate a unique evidence {role} path")
}

fn target_parent(target: &Path) -> &Path {
    target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn ensure_valid_replace_target(target: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(target)
        .with_context(|| format!("failed to inspect evidence output '{}'", target.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("--force can replace only an existing evidence bundle directory");
    }
    let marker = target.join("manifest.json");
    let marker_metadata = fs::symlink_metadata(&marker).ok();
    if !marker_metadata
        .is_some_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
    {
        bail!(
            "--force refused to replace '{}': manifest.json bundle marker is missing",
            target.display()
        );
    }
    let verification = verify(target).with_context(|| {
        format!(
            "--force refused to replace '{}': existing bundle is invalid",
            target.display()
        )
    })?;
    if !verification.valid {
        bail!(
            "--force refused to replace '{}': existing bundle failed verification: {}",
            target.display(),
            verification.errors.join("; ")
        );
    }
    Ok(())
}

fn write_entry(
    directory: &Path,
    name: &str,
    content: &[u8],
    entries: &mut Vec<ManifestEntry>,
) -> Result<()> {
    let path = directory.join(name);
    fs::write(&path, content)
        .with_context(|| format!("failed to write evidence file '{}'", path.display()))?;
    entries.push(manifest_entry(&path, name)?);
    Ok(())
}

fn manifest_entry(path: &Path, name: &str) -> Result<ManifestEntry> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to inspect evidence file '{}'", path.display()))?;
    Ok(ManifestEntry {
        path: name.to_owned(),
        size: metadata.len(),
        sha256: hash_file(path)?,
    })
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open evidence file '{}'", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read evidence file '{}'", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn safe_entry_name(value: &str) -> bool {
    let mut components = Path::new(value).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn remove_path(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect old target '{}'", path.display()))?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
    .with_context(|| format!("failed to remove old target '{}'", path.display()))
}

#[cfg(test)]
mod tests {
    use super::{CreateOptions, create, verify};

    #[test]
    fn creates_verifies_and_detects_tampering_without_copying_source_by_default() {
        let root =
            std::env::temp_dir().join(format!("banshee-evidence-unit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).expect("create fixture root");
        let source = root.join("sample.txt");
        let bundle = root.join("bundle");
        std::fs::write(&source, b"host=example.com token=secret-value").expect("write sample");

        let created = create(
            &source,
            &bundle,
            CreateOptions {
                rules: None,
                include_sample: false,
                max_entries: 100,
                max_depth: 4,
                max_tokens: 100,
                force: false,
            },
        )
        .expect("create bundle");
        assert_eq!(created.files_written, 7);
        assert!(!bundle.join("source-sample.bin").exists());
        assert!(verify(&bundle).expect("verify bundle").valid);

        std::fs::write(bundle.join("hashes.txt"), b"tampered").expect("tamper evidence");
        let verification = verify(&bundle).expect("verify tampered bundle");
        assert!(!verification.valid);
        assert!(
            verification
                .errors
                .iter()
                .any(|error| error.contains("hashes.txt"))
        );
        std::fs::remove_dir_all(root).expect("remove fixture root");
    }
}

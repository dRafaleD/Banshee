//! Known-good hash lists for directory scans. A list is any text file with
//! MD5, SHA-1 or SHA-256 digests: one per line, `sha256sum` output, or CSV
//! exports such as NSRL's. Files whose digest is listed are reported as
//! known-good and not analyzed, which keeps clean system files out of the
//! findings. The list is trusted as given; a wrong list hides real files.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Result, bail};

use crate::hash::HashAlgorithm;

const MAX_LIST_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Default)]
pub struct KnownHashes {
    digests: HashSet<String>,
    md5: bool,
    sha1: bool,
    sha256: bool,
}

impl KnownHashes {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes =
            crate::input::read_regular_file_limited(path, MAX_LIST_BYTES, "known-good hash list")?;
        let list = Self::parse(&String::from_utf8_lossy(&bytes));
        if list.digests.is_empty() {
            bail!(
                "known-good hash list '{}' contains no MD5, SHA-1 or SHA-256 digests",
                path.display()
            );
        }
        Ok(list)
    }

    /// Collects every 32, 40 or 64 hex-digit token outside `#` comments.
    pub fn parse(text: &str) -> Self {
        let mut list = Self::default();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or_default();
            for token in line.split(|character: char| !character.is_ascii_hexdigit()) {
                match token.len() {
                    32 => list.md5 = true,
                    40 => list.sha1 = true,
                    64 => list.sha256 = true,
                    _ => continue,
                }
                list.digests.insert(token.to_ascii_lowercase());
            }
        }
        list
    }

    pub fn len(&self) -> usize {
        self.digests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }

    /// The algorithm whose digest of `bytes` is listed, computing only the
    /// algorithms the list contains.
    pub fn matches(&self, bytes: &[u8]) -> Option<HashAlgorithm> {
        [
            (self.sha256, HashAlgorithm::Sha256),
            (self.sha1, HashAlgorithm::Sha1),
            (self.md5, HashAlgorithm::Md5),
        ]
        .into_iter()
        .filter(|(present, _)| *present)
        .find(|(_, algorithm)| {
            crate::hash::calculate_bytes(bytes, *algorithm)
                .is_ok_and(|report| self.digests.contains(&report.digest.to_ascii_lowercase()))
        })
        .map(|(_, algorithm)| algorithm)
    }
}

#[cfg(test)]
mod tests {
    use super::KnownHashes;
    use crate::hash::HashAlgorithm;

    #[test]
    fn reads_plain_sha256sum_and_nsrl_style_lists() {
        let list = KnownHashes::parse(
            "# comment with deadbeefdeadbeefdeadbeefdeadbeef\n\
             2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824  hello.txt\n\
             \"AAF4C61DDCC5E8A2DABEDE0F3B482CD9AEA9434D\",\"5D41402ABC4B2A76B9719D911017C592\",\"x\"\n\
             short ab12 and 12345678901234567890123456789012345 are ignored\n",
        );
        assert_eq!(list.len(), 3);
        assert_eq!(list.matches(b"hello"), Some(HashAlgorithm::Sha256));
        assert_eq!(list.matches(b"other"), None);

        let sha1_only = KnownHashes::parse("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d\n");
        assert_eq!(sha1_only.matches(b"hello"), Some(HashAlgorithm::Sha1));
        assert!(KnownHashes::parse("nothing here").is_empty());
    }
}

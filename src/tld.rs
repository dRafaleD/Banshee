//! Offline top-level-domain validation for extracted host names.
//!
//! The IANA snapshot is compiled into the binary, so `System.Net.WebClient`
//! or `gate.php` are not reported as domains while real hosts are. Reserved
//! special-use names stay accepted because they are common in tests, Tor
//! traffic and internal networks.

use std::collections::HashSet;
use std::sync::OnceLock;

const IANA_TLDS: &str = include_str!("data/tlds.txt");

/// RFC 6761 (`test`, `example`, `invalid`, `localhost`), RFC 7686 (`onion`),
/// RFC 9476 (`alt`), ICANN-reserved `internal`, and common private suffixes.
const SPECIAL_USE_TLDS: &[&str] = &[
    "alt",
    "corp",
    "example",
    "internal",
    "invalid",
    "lan",
    "local",
    "localhost",
    "onion",
    "test",
];

fn known_tlds() -> &'static HashSet<&'static str> {
    static TLDS: OnceLock<HashSet<&'static str>> = OnceLock::new();
    TLDS.get_or_init(|| {
        IANA_TLDS
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .chain(SPECIAL_USE_TLDS.iter().copied())
            .collect()
    })
}

/// The `# Version ...` line of the embedded IANA snapshot.
pub(crate) fn snapshot_version() -> Option<&'static str> {
    IANA_TLDS
        .lines()
        .find_map(|line| line.strip_prefix("# Version "))
        .map(str::trim)
}

/// Returns whether the final label of `domain` is a delegated or special-use TLD.
pub(crate) fn has_known_tld(domain: &str) -> bool {
    domain
        .trim_end_matches('.')
        .rsplit('.')
        .next()
        .is_some_and(|label| known_tlds().contains(label.to_ascii_lowercase().as_str()))
}

#[cfg(test)]
mod tests {
    use super::{IANA_TLDS, has_known_tld, known_tlds, snapshot_version};

    #[test]
    fn snapshot_is_versioned_and_complete() {
        assert!(
            IANA_TLDS
                .lines()
                .nth(1)
                .is_some_and(|line| line.starts_with("# Version "))
        );
        // The version is the IANA serial (YYYYMMDDNN) followed by a timestamp.
        let version = snapshot_version().expect("version line");
        assert!(
            version.len() > 10 && version[..10].bytes().all(|byte| byte.is_ascii_digit()),
            "{version}"
        );
        assert!(known_tlds().len() > 1_000);
        // Header comments and blank lines must never become TLD entries.
        assert!(
            known_tlds()
                .iter()
                .all(|tld| !tld.is_empty() && !tld.starts_with('#') && !tld.contains(' ')),
        );
        assert!(
            IANA_TLDS
                .lines()
                .filter(|line| !line.starts_with('#'))
                .all(
                    |line| line == line.to_ascii_lowercase() && !line.contains(char::is_whitespace)
                )
        );
    }

    #[test]
    fn accepts_real_and_special_use_tlds() {
        for domain in [
            "example.com",
            "Example.ORG",
            "tool.py",
            "archive.zip",
            "c2.example.test",
            "host.corp.local",
            "abcdefghijklmnop.onion",
            "fqdn.example.com.",
        ] {
            assert!(has_known_tld(domain), "{domain}");
        }
    }

    #[test]
    fn rejects_code_identifiers_and_file_names() {
        for value in [
            "System.Net.WebClient",
            "os.path",
            "gate.php",
            "payload.exe",
            "config.json",
            "user.home",
        ] {
            assert!(!has_known_tld(value), "{value}");
        }
    }
}

//! MITRE ATT&CK techniques for Banshee's own heuristic findings. Local rules
//! declare their techniques themselves; this table covers the findings that
//! file inspection and IOC extraction produce, matched on the wording those
//! findings use. Only findings with a clear technique are listed, and a
//! mapping describes what the finding suggests, not confirmed behavior.

/// Lowercase phrase found in a finding, and the techniques it suggests.
const HEURISTICS: &[(&str, &[&str])] = &[
    // Script content (file_inspect::script).
    (
        "runs an encoded powershell command",
        &["T1059.001", "T1027"],
    ),
    (
        "downloads content and executes it in memory",
        &["T1059.001", "T1105"],
    ),
    ("tampers with amsi", &["T1562.001"]),
    ("weakens microsoft defender", &["T1562.001"]),
    ("loads a .net assembly from memory", &["T1620"]),
    ("calls native memory apis", &["T1055"]),
    (
        "downloads a file over http and writes it to disk",
        &["T1105"],
    ),
    ("runs commands through wscript.shell", &["T1059.005"]),
    ("(lolbin)", &["T1218"]),
    ("deletes shadow copies or disables recovery", &["T1490"]),
    ("adds a run key for persistence", &["T1547.001"]),
    ("creates a scheduled task", &["T1053.005"]),
    ("starts powershell hidden", &["T1059.001", "T1564.003"]),
    // Documents, email and containers.
    ("equation editor object", &["T1203"]),
    ("remote template", &["T1221"]),
    ("double extension", &["T1036.007"]),
    ("reply-to domain", &["T1566"]),
    ("contains a hidden file", &["T1564.001"]),
    // Executables.
    ("upx packer markers", &["T1027.002"]),
    ("packer-associated", &["T1027.002"]),
    // Event logs (file_inspect::evtx).
    ("(audit log cleared)", &["T1070.001"]),
    ("(event log cleared)", &["T1070.001"]),
    // Lookalike domains (homoglyph).
    ("possible homoglyph", &["T1583.001"]),
];

/// Techniques suggested by a heuristic finding's text, in table order and
/// without duplicates.
pub fn for_finding(text: &str) -> Vec<String> {
    let lowered = text.to_lowercase();
    let mut techniques: Vec<String> = Vec::new();
    for (phrase, ids) in HEURISTICS {
        if lowered.contains(phrase) {
            for id in *ids {
                if !techniques.iter().any(|known| known == id) {
                    techniques.push((*id).to_owned());
                }
            }
        }
    }
    techniques
}

#[cfg(test)]
mod tests {
    use super::{HEURISTICS, for_finding};

    #[test]
    fn maps_known_wording_and_ignores_the_rest() {
        assert_eq!(
            for_finding("PowerShell script runs an encoded PowerShell command"),
            ["T1059.001", "T1027"]
        );
        assert_eq!(
            for_finding(
                "log contains 1 record(s) of event 1102 (audit log cleared); earlier events may have been removed"
            ),
            ["T1070.001"]
        );
        assert_eq!(
            for_finding(
                "Email attachment hides its real type behind a double extension: a.pdf.exe"
            ),
            ["T1036.007"]
        );
        assert!(
            for_finding("ELF has no section headers, which packers and stripping tools produce")
                .is_empty()
        );
        assert!(for_finding("cabinet header is truncated").is_empty());
    }

    #[test]
    fn table_uses_lowercase_phrases_and_valid_technique_ids() {
        for (phrase, ids) in HEURISTICS {
            assert_eq!(*phrase, phrase.to_lowercase(), "{phrase}");
            assert!(!ids.is_empty(), "{phrase}");
            for id in *ids {
                let (technique, sub) = id.split_once('.').unwrap_or((id, "000"));
                assert!(
                    technique.len() == 5
                        && technique.starts_with('T')
                        && technique[1..].bytes().all(|byte| byte.is_ascii_digit())
                        && sub.len() == 3
                        && sub.bytes().all(|byte| byte.is_ascii_digit()),
                    "{id}"
                );
            }
        }
    }
}

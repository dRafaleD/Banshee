//! SARIF 2.1.0 output for report and scan findings, so code-scanning tools can
//! ingest them. Findings keep their source and severity; nothing is a verdict.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::report::{ReportFinding, UnifiedReport};
use crate::rules::Severity;

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Info | Severity::Low => "note",
        Severity::Medium => "warning",
        Severity::High | Severity::Critical => "error",
    }
}

fn rule_id(finding: &ReportFinding) -> String {
    let source = finding.source.to_string().replace(' ', "-");
    format!("banshee/{source}/{}", finding.kind)
}

/// Relative paths stay relative; absolute ones become `file://` URIs.
fn artifact_uri(path: &str) -> String {
    let path = path.replace('\\', "/");
    if path.as_bytes().get(1) == Some(&b':') {
        format!("file:///{path}")
    } else if path.starts_with('/') {
        format!("file://{path}")
    } else {
        path
    }
}

/// Builds one SARIF log from `(artifact path, report)` pairs.
pub fn build(reports: &[(&str, &UnifiedReport)]) -> Value {
    let mut rules: BTreeMap<String, String> = BTreeMap::new();
    let mut results = Vec::new();
    for (path, report) in reports {
        let uri = artifact_uri(path);
        for finding in &report.findings {
            let id = rule_id(finding);
            rules
                .entry(id.clone())
                .or_insert_with(|| format!("{}: {}", finding.source, finding.kind));
            let message = if finding.detail.is_empty() {
                finding.value.clone()
            } else {
                format!("{} ({})", finding.value, finding.detail)
            };
            let mut properties = json!({
                "severity": finding.severity,
                "sha256": report.hashes.sha256,
            });
            if !finding.attack.is_empty() {
                // SARIF property-bag tags; viewers can filter on them.
                properties["tags"] = json!(
                    finding
                        .attack
                        .iter()
                        .map(|id| format!("attack/{id}"))
                        .collect::<Vec<_>>()
                );
            }
            results.push(json!({
                "ruleId": id,
                "level": level(finding.severity),
                "message": { "text": message },
                "locations": [{
                    "physicalLocation": { "artifactLocation": { "uri": uri } }
                }],
                "properties": properties,
            }));
        }
    }
    let rules: Vec<Value> = rules
        .into_iter()
        .map(|(id, description)| {
            json!({ "id": id, "name": id, "shortDescription": { "text": description } })
        })
        .collect();
    json!({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "Banshee",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/dRafaleD/Banshee",
                "rules": rules,
            }},
            "results": results,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_paths_become_file_uris() {
        assert_eq!(artifact_uri("C:\\x\\a.exe"), "file:///C:/x/a.exe");
        assert_eq!(artifact_uri("/tmp/a"), "file:///tmp/a");
        assert_eq!(artifact_uri("dir\\a"), "dir/a");
    }

    #[test]
    fn maps_severity_to_sarif_levels() {
        assert_eq!(level(Severity::Info), "note");
        assert_eq!(level(Severity::Medium), "warning");
        assert_eq!(level(Severity::Critical), "error");
    }
}

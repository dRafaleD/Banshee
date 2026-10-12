pub mod analysis;
pub mod banner;
pub mod batch;
pub mod cert;
pub mod cli;
pub mod codec;
pub mod diff;
pub mod evidence;
pub mod export;
pub mod file_inspect;
pub mod hash;
pub mod input;
pub mod ioc;
pub mod jwt;
pub mod output;
pub mod recipe;
pub mod regex_tool;
pub mod report;
mod report_html;
pub mod rules;
pub mod scan;
pub mod timestamp;
mod tld;
pub mod watch;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};

use crate::analysis::Analyzer;
use crate::cli::{
    CertCommand, Cli, Command, EvidenceCommand, FileCommand, HashCommand, JwtCommand, RegexCommand,
    RulesCommand, TimestampCommand,
};

const MAX_JWT_KEY_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    Success,
    Findings,
    PartialFailure,
}

pub fn run() -> Result<RunOutcome> {
    run_with(Cli::parse())
}

pub fn run_with(cli: Cli) -> Result<RunOutcome> {
    let started = std::time::Instant::now();
    let fail_on_findings = cli.fail_on_findings;
    let verbose = cli.verbose;
    let destination = cli.output.clone();
    let evidence_create = matches!(
        &cli.command,
        Command::Evidence(args) if matches!(&args.command, EvidenceCommand::Create(_))
    );
    if verbose {
        eprintln!(
            "[banshee] offline mode; output={}",
            cli.output
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "stdout".to_owned())
        );
    }
    output::configure_destination(
        if evidence_create {
            None
        } else {
            cli.output.clone()
        },
        cli.force,
    )?;
    output::configure_quiet(cli.quiet);
    output::configure_color(cli.color, cli.no_color);
    let mut has_findings = false;
    let mut has_operational_issues = false;
    let mut explicit_findings_status = false;
    match cli.command {
        Command::Whatis(args) => {
            let value = input::read_bytes(&args.source.input, args.source.file.as_deref())?;
            let analyzer = Analyzer::new(args.max_depth);
            let report = analyzer.analyze_bytes(&value);
            has_findings |= !report.findings.is_empty();
            output::print_report(&report, args.json)?;
        }
        Command::Entropy(args) => {
            let value = input::read_bytes(&args.source.input, args.source.file.as_deref())?;
            let report = analysis::entropy::analyze_bytes(&value);
            output::print_entropy_report(&report, args.json)?;
        }
        Command::Jwt(args) => match args.command {
            JwtCommand::Inspect(args) => {
                let value = input::read(&args.source.input, args.source.file.as_deref())?;
                let report = jwt::inspect(&value)?;
                output::print_jwt_report(&report, args.json)?;
            }
            JwtCommand::Verify(args) => {
                let token = input::read(&args.source.input, args.source.file.as_deref())?;
                let key = match &args.key {
                    Some(path) => Some(input::read_regular_file_limited(
                        path,
                        MAX_JWT_KEY_BYTES,
                        "JWT key",
                    )?),
                    None => None,
                };
                let report = jwt::verify(
                    &token,
                    args.algorithm,
                    jwt::JwtVerifyOptions {
                        secret: args.secret.as_deref(),
                        pem_key: key.as_deref(),
                        validate_time: !args.ignore_time,
                        leeway: args.leeway,
                        audience: &args.audience,
                        issuer: &args.issuer,
                    },
                )?;
                output::print_json_or(&report, args.json, |output| {
                    writeln!(output, "Verified: yes")?;
                    writeln!(output, "Algorithm: {}", report.algorithm)?;
                    writeln!(
                        output,
                        "Time claims validated: {}",
                        report.time_claims_validated
                    )?;
                    writeln!(output, "Audience validated: {}", report.audience_validated)?;
                    writeln!(output, "Issuer validated: {}", report.issuer_validated)?;
                    writeln!(output, "Header: {}", report.header)?;
                    writeln!(output, "Payload: {}", report.payload)
                })?;
            }
        },
        Command::Extract(args) => {
            let source = args
                .source
                .file
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| {
                    if args.source.input.is_some() {
                        "argument".to_owned()
                    } else {
                        "stdin".to_owned()
                    }
                });
            let value = input::read(&args.source.input, args.source.file.as_deref())?;
            let report = ioc::extract(
                &value,
                ioc::ExtractOptions {
                    include_ip: args.ip,
                    include_domain: args.domain,
                    include_url: args.url,
                    include_hash: args.hash,
                    include_email: args.email,
                    include_mac: args.mac,
                    include_secret: args.secret,
                    allowlist: ioc::PatternList::from_files(&args.allowlist)?,
                    denylist: ioc::PatternList::from_files(&args.denylist)?,
                    sort: args.sort,
                    source,
                    context_lines: args.context,
                    max_context_chars: args.max_context_chars,
                    max_locations: args.max_locations,
                    max_matches: args.max_matches,
                    reveal_secrets: args.reveal_secrets,
                },
            );
            has_findings |= report.total > 0;
            output::print_ioc_report(
                &report,
                output::selected_format(args.format, args.json),
                args.defang,
                args.summary,
            )?;
        }
        Command::Hash(args) => match args.command {
            HashCommand::Calculate(args) => {
                let value = input::read_bytes(&args.source.input, args.source.file.as_deref())?;
                let report = hash::calculate_bytes(&value, args.algorithm)?;
                output::print_json_or(&report, args.json, |output| {
                    writeln!(output, "{}\t{}", report.algorithm, report.digest)
                })?;
            }
            HashCommand::Identify(args) => {
                let report = hash::identify(&args.value)?;
                output::print_json_or(&report, args.json, |output| {
                    writeln!(output, "Length: {} bits", report.bit_length)?;
                    for algorithm in &report.probable_algorithms {
                        writeln!(output, "- {algorithm}")?;
                    }
                    Ok(())
                })?;
            }
            HashCommand::Crack(args) => {
                let report = hash::crack(&args.value, &args.wordlist, args.algorithm)?;
                output::print_json_or(&report, args.json, |output| {
                    writeln!(output, "Algorithm: {}", report.algorithm)?;
                    writeln!(output, "Attempts: {}", report.attempts)?;
                    match &report.match_value {
                        Some(value) => writeln!(output, "Match: {value}"),
                        None => writeln!(output, "Match: not found"),
                    }
                })?;
            }
        },
        Command::Timestamp(args) => match args.command {
            TimestampCommand::ToHuman(args) => {
                let report = timestamp::to_human(args.value, args.unit)?;
                output::print_json_or(&report, args.json, |output| {
                    writeln!(output, "UTC: {}", report.utc)?;
                    writeln!(output, "Unix seconds: {}", report.unix_seconds)?;
                    writeln!(output, "Detected unit: {}", report.detected_unit)
                })?;
            }
            TimestampCommand::ToUnix(args) => {
                let report = timestamp::to_unix(&args.value, args.unit)?;
                output::print_json_or(&report, args.json, |output| {
                    writeln!(output, "{}\t{}", report.unit, report.value)
                })?;
            }
        },
        Command::Regex(args) => match args.command {
            RegexCommand::Test(args) => {
                let value = input::read(&args.source.input, args.source.file.as_deref())?;
                let report =
                    regex_tool::test(&args.pattern, &value, args.case_insensitive, args.multiline)?;
                output::print_json_or(&report, args.json, |output| {
                    writeln!(output, "Matches: {}", report.total)?;
                    if report.truncated {
                        writeln!(output, "Match list truncated at safety limit")?;
                    }
                    for found in &report.matches {
                        writeln!(
                            output,
                            "[{}..{}]\t{}{}",
                            found.start,
                            found.end,
                            output::terminal_safe(&found.value),
                            if found.value_truncated {
                                " [truncated]"
                            } else {
                                ""
                            }
                        )?;
                    }
                    Ok(())
                })?;
            }
            RegexCommand::Patterns(args) => {
                let report = regex_tool::patterns();
                output::print_json_or(&report, args.json, |output| {
                    for pattern in &report.patterns {
                        writeln!(output, "{}\t{}", pattern.name, pattern.pattern)?;
                    }
                    Ok(())
                })?;
            }
        },
        Command::Cert(args) => match args.command {
            CertCommand::Inspect(args) => {
                let report = cert::inspect_file(&args.path)?;
                has_findings |= !report.currently_valid;
                output::print_json_or(&report, args.json, |output| {
                    writeln!(
                        output,
                        "Format: {} / X.509 v{}",
                        report.format, report.version
                    )?;
                    writeln!(
                        output,
                        "Subject: {}",
                        output::terminal_safe(&report.subject)
                    )?;
                    writeln!(output, "Issuer: {}", output::terminal_safe(&report.issuer))?;
                    writeln!(output, "Serial: {}", output::terminal_safe(&report.serial))?;
                    writeln!(
                        output,
                        "Validity: {} -> {}",
                        report.not_before, report.not_after
                    )?;
                    writeln!(output, "Currently valid: {}", report.currently_valid)?;
                    writeln!(output, "Self-issued: {}", report.self_issued)?;
                    writeln!(
                        output,
                        "Signature algorithm: {}",
                        report.signature_algorithm
                    )?;
                    writeln!(
                        output,
                        "Public key algorithm: {}",
                        report.public_key_algorithm
                    )?;
                    if let Some(bits) = report.public_key_bits {
                        writeln!(output, "Public key size: {bits} bits")?;
                    }
                    match &report.basic_constraints {
                        Some(constraints) => writeln!(
                            output,
                            "Basic constraints: CA={}, path length={}",
                            constraints.ca,
                            constraints
                                .path_length_constraint
                                .map(|value| value.to_string())
                                .unwrap_or_else(|| "unlimited/not set".to_owned())
                        )?,
                        None => writeln!(output, "Basic constraints: not present")?,
                    }
                    if !report.key_usage.is_empty() {
                        writeln!(output, "Key usage: {}", report.key_usage.join(", "))?;
                    }
                    if !report.extended_key_usage.is_empty() {
                        writeln!(
                            output,
                            "Extended key usage: {}",
                            report.extended_key_usage.join(", ")
                        )?;
                    }
                    writeln!(output, "SHA-256: {}", report.sha256_fingerprint)?;
                    for name in &report.subject_alt_names {
                        writeln!(output, "SAN: {}", output::terminal_safe(name))?;
                    }
                    Ok(())
                })?;
            }
            CertCommand::Chain(args) => {
                let report = cert::inspect_chain_file(&args.path)?;
                has_findings |=
                    !report.ordered_leaf_to_root || !report.all_certificates_currently_valid;
                output::print_json_or(&report, args.json, |output| {
                    writeln!(output, "Certificates: {}", report.certificates.len())?;
                    for (index, certificate) in report.certificates.iter().enumerate() {
                        writeln!(
                            output,
                            "[{index}] Subject: {}",
                            output::terminal_safe(&certificate.subject)
                        )?;
                        writeln!(
                            output,
                            "    Issuer: {}",
                            output::terminal_safe(&certificate.issuer)
                        )?;
                        writeln!(
                            output,
                            "    Valid now: {}; CA: {}",
                            certificate.currently_valid,
                            certificate
                                .basic_constraints
                                .as_ref()
                                .map(|constraints| constraints.ca.to_string())
                                .unwrap_or_else(|| "unknown".to_owned())
                        )?;
                    }
                    for link in &report.links {
                        writeln!(
                            output,
                            "Link {} -> {}: issuer/subject match={}; signature={}; CA authorized={}",
                            link.child_index,
                            link.issuer_index,
                            link.issuer_subject_match,
                            link.signature_status,
                            link.issuer_authorized_to_sign
                        )?;
                    }
                    writeln!(
                        output,
                        "All supplied links valid and ordered: {}",
                        report.ordered_leaf_to_root
                    )?;
                    writeln!(
                        output,
                        "All certificates currently valid: {}",
                        report.all_certificates_currently_valid
                    )?;
                    writeln!(
                        output,
                        "Last certificate self-issued: {}",
                        report.root_self_issued
                    )?;
                    if let Some(status) = report.root_signature_status {
                        writeln!(output, "Last certificate self-signature: {status}")?;
                    }
                    writeln!(
                        output,
                        "Trust status: not evaluated (no trust store or revocation lookup)"
                    )
                })?;
            }
        },
        Command::File(args) => match args.command {
            FileCommand::Inspect(args) => {
                let report = file_inspect::inspect_file(&args.path, args.max_entries)?;
                has_findings |= !report.findings.is_empty();
                output::print_json_or(&report, args.json, |output| {
                    writeln!(output, "Path: {}", output::terminal_safe(&report.path))?;
                    writeln!(output, "Format: {}", report.format)?;
                    writeln!(output, "Size: {} bytes", report.size)?;
                    writeln!(output, "SHA-256: {}", report.sha256)?;
                    if let Some(compression) = &report.compression {
                        writeln!(
                            output,
                            "Compression: {} ({} -> {} bytes)",
                            compression.algorithm,
                            compression.compressed_bytes,
                            compression.decompressed_bytes
                        )?;
                        writeln!(output, "Payload format: {}", compression.payload_format)?;
                    }
                    if let Some(executable) = &report.executable {
                        writeln!(output, "Architecture: {}", executable.architecture)?;
                        writeln!(output, "Bitness: {}", executable.bits)?;
                        writeln!(output, "Type: {}", executable.kind)?;
                        writeln!(output, "Entry point: {}", executable.entry_point)?;
                        writeln!(output, "Sections: {}", executable.sections)?;
                        if let Some(endianness) = &executable.endianness {
                            writeln!(output, "Endianness: {endianness}")?;
                        }
                        if let Some(subsystem) = &executable.subsystem {
                            writeln!(output, "Subsystem: {subsystem}")?;
                        }
                        for section in &executable.section_details {
                            let permissions = format!(
                                "{}{}{}{}",
                                section
                                    .readable
                                    .map_or("", |value| if value { "R" } else { "-" }),
                                if section.writable { "W" } else { "-" },
                                if section.executable { "X" } else { "-" },
                                section
                                    .allocated
                                    .map_or("", |value| if value { "A" } else { "-" }),
                            );
                            writeln!(
                                output,
                                "Section: {}\t{}\tfile={}+{}\tmem={}\t{}",
                                output::terminal_safe(&section.name),
                                section.virtual_address,
                                section.file_offset,
                                section.file_size,
                                section.memory_size,
                                permissions
                            )?;
                        }
                        if executable.sections_truncated {
                            writeln!(output, "Section list truncated at safety limit")?;
                        }
                        for library in &executable.imports {
                            writeln!(
                                output,
                                "Import library: {}",
                                output::terminal_safe(&library.name)
                            )?;
                            for symbol in &library.symbols {
                                writeln!(output, "    {}", output::terminal_safe(symbol))?;
                            }
                            if library.symbols_truncated {
                                writeln!(output, "    symbol list truncated at safety limit")?;
                            }
                        }
                        if executable.imports_truncated {
                            writeln!(output, "Import list truncated at safety limit")?;
                        }
                        for export in &executable.exports {
                            writeln!(output, "Named export: {}", output::terminal_safe(export))?;
                        }
                        if executable.exports_truncated {
                            writeln!(output, "Named export list truncated at safety limit")?;
                        }
                        if let Some(overlay) = &executable.overlay {
                            writeln!(
                                output,
                                "Overlay: offset {}; {} bytes; certificate table included={}",
                                overlay.offset, overlay.size, overlay.includes_certificate_table
                            )?;
                        }
                        if let Some(present) = executable.signature_present {
                            writeln!(
                                output,
                                "PE certificate table present: {present} (signature not verified)"
                            )?;
                        }
                        if let Some(interpreter) = &executable.interpreter {
                            writeln!(
                                output,
                                "ELF interpreter: {}",
                                output::terminal_safe(interpreter)
                            )?;
                        }
                        for library in &executable.needed_libraries {
                            writeln!(output, "Needed library: {}", output::terminal_safe(library))?;
                        }
                        if executable.needed_libraries_truncated {
                            writeln!(output, "Needed library list truncated at safety limit")?;
                        }
                        if let Some(rpath) = &executable.rpath {
                            writeln!(output, "RPATH: {}", output::terminal_safe(rpath))?;
                        }
                        if let Some(runpath) = &executable.runpath {
                            writeln!(output, "RUNPATH: {}", output::terminal_safe(runpath))?;
                        }
                        if let Some(stripped) = executable.stripped {
                            writeln!(output, "Stripped: {stripped}")?;
                        }
                        if let Some(debug) = executable.debug_info_present {
                            writeln!(output, "Debug sections present: {debug}")?;
                        }
                        for warning in &executable.parse_warnings {
                            writeln!(output, "Parser warning: {}", output::terminal_safe(warning))?;
                        }
                    }
                    if let Some(archive) = &report.archive {
                        writeln!(output, "Entries: {}", archive.total_entries)?;
                        writeln!(output, "Declared content: {} bytes", archive.total_size)?;
                        if archive.truncated {
                            writeln!(output, "Entry list truncated at --max-entries")?;
                        }
                        for entry in &archive.entries {
                            writeln!(
                                output,
                                "{}\t{}\t{} bytes{}",
                                entry.kind,
                                output::terminal_safe(&entry.name),
                                entry.size,
                                if entry.path_safe {
                                    ""
                                } else {
                                    "\t[unsafe path]"
                                }
                            )?;
                        }
                    }
                    for finding in &report.findings {
                        writeln!(output, "Finding: {}", output::terminal_safe(finding))?;
                    }
                    Ok(())
                })?;
            }
        },
        Command::Rules(args) => match args.command {
            RulesCommand::Validate(args) => {
                let report = rules::validate_file(&args.path)?;
                output::print_json_or(&report, args.json, |output| {
                    writeln!(output, "Valid: yes")?;
                    writeln!(output, "Version: {}", report.version)?;
                    writeln!(output, "Rules: {}", report.rule_count)?;
                    for rule in &report.rules {
                        writeln!(
                            output,
                            "{}\t{}\t{}\t{}",
                            rule.id,
                            rule.severity,
                            rule.kind,
                            output::terminal_safe(&rule.description)
                        )?;
                        if rule.category.is_some()
                            || rule.confidence.is_some()
                            || !rule.references.is_empty()
                        {
                            writeln!(
                                output,
                                "    category={}; confidence={}; references={}",
                                rule.category
                                    .as_deref()
                                    .map_or_else(|| "-".to_owned(), output::terminal_safe),
                                rule.confidence
                                    .map_or_else(|| "-".to_owned(), |value| value.to_string()),
                                rule.references.len()
                            )?;
                        }
                        if !rule.attack.is_empty() {
                            writeln!(output, "    attack={}", rule.attack.join(","))?;
                        }
                        if !rule.file_types.is_empty()
                            || rule.min_entropy.is_some()
                            || rule.max_entropy.is_some()
                            || rule.all_conditions > 0
                            || rule.any_conditions > 0
                        {
                            let file_types = rule
                                .file_types
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(",");
                            writeln!(
                                output,
                                "    predicates: file_types={}; entropy={}..={}; conditions=all:{}/any:{}; matches={}..={}",
                                if file_types.is_empty() {
                                    "*"
                                } else {
                                    &file_types
                                },
                                rule.min_entropy.unwrap_or(0.0),
                                rule.max_entropy.unwrap_or(8.0),
                                rule.all_conditions,
                                rule.any_conditions,
                                rule.min_matches,
                                rule.max_matches
                            )?;
                        }
                    }
                    Ok(())
                })?;
            }
            RulesCommand::Scan(args) => {
                let value = input::read_bytes(&args.source.input, args.source.file.as_deref())?;
                let report = rules::scan(&args.rules, &value)?;
                has_findings |= report.matched_rules > 0;
                output::print_json_or(&report, args.json, |output| {
                    writeln!(output, "Input bytes: {}", report.input_bytes)?;
                    writeln!(output, "Rules loaded: {}", report.rules_loaded)?;
                    writeln!(output, "Matched rules: {}", report.matched_rules)?;
                    for matched in &report.matches {
                        writeln!(
                            output,
                            "[{}] {} ({}, {} match{})",
                            matched.severity,
                            matched.id,
                            matched.kind,
                            matched.total_matches,
                            if matched.total_matches == 1 { "" } else { "es" }
                        )?;
                        if !matched.description.is_empty() {
                            writeln!(
                                output,
                                "    {}",
                                output::terminal_safe(&matched.description)
                            )?;
                        }
                        writeln!(
                            output,
                            "    context: file_type={}; entropy={:.2}",
                            matched.detected_file_type, matched.entropy
                        )?;
                        if let Some(category) = &matched.category {
                            writeln!(output, "    category: {}", output::terminal_safe(category))?;
                        }
                        if let Some(confidence) = matched.confidence {
                            writeln!(output, "    confidence: {confidence}")?;
                        }
                        if matched.conditions.all_required > 0
                            || matched.conditions.any_required > 0
                        {
                            writeln!(
                                output,
                                "    conditions: all {}/{}; any {}/{}",
                                matched.conditions.all_matched,
                                matched.conditions.all_required,
                                matched.conditions.any_matched,
                                matched.conditions.any_required
                            )?;
                        }
                        for reference in &matched.references {
                            writeln!(
                                output,
                                "    reference: {}",
                                output::terminal_safe(reference)
                            )?;
                        }
                        for sample in &matched.samples {
                            writeln!(
                                output,
                                "    @{} +{}\t{}",
                                sample.offset,
                                sample.length,
                                output::terminal_safe(&sample.preview)
                            )?;
                        }
                        if matched.truncated {
                            writeln!(
                                output,
                                "    match count truncated at configured/safety limit"
                            )?;
                        }
                    }
                    Ok(())
                })?;
            }
        },
        Command::Analyze(args) => {
            let value = input::read_bytes(&args.source.input, args.source.file.as_deref())?;
            let report = batch::analyze_bytes(&value, args.max_depth, args.max_tokens);
            has_findings |= report.iocs.total > 0 || !report.analyses.is_empty();
            match output::selected_format(args.format, args.json) {
                output::OutputFormat::Text => output::print_json_or(&report, false, |output| {
                    writeln!(output, "Input bytes: {}", report.input_bytes)?;
                    writeln!(output, "Unique tokens scanned: {}", report.tokens_scanned)?;
                    writeln!(output, "Interesting tokens: {}", report.analyses.len())?;
                    writeln!(output, "IOCs: {}", report.iocs.total)?;
                    if let Some(binary) = &report.binary {
                        writeln!(output, "Binary format: {}", binary.detected_format)?;
                        writeln!(output, "Extracted strings: {}", binary.extracted_strings)?;
                    }
                    for item in &report.analyses {
                        writeln!(
                            output,
                            "{}\t{}\t{}",
                            item.line.map_or_else(
                                || "position unavailable".to_owned(),
                                |line| format!("line {line}"),
                            ),
                            item.report
                                .layers
                                .first()
                                .map(|layer| layer.kind.to_string())
                                .unwrap_or_else(|| "structured indicator".to_owned()),
                            output::terminal_safe(&item.report.final_value)
                        )?;
                    }
                    Ok(())
                })?,
                output::OutputFormat::Json => output::print_json_or(&report, true, |_| Ok(()))?,
                output::OutputFormat::Jsonl => output::print_batch_jsonl(&report)?,
                output::OutputFormat::Csv => output::print_batch_csv(&report)?,
            }
        }
        Command::Report(args) => {
            let report = report::generate(
                &args.path,
                args.rules.as_deref(),
                args.max_entries,
                args.max_depth,
                args.max_tokens,
            )?;
            has_findings |= report.summary.total_findings > 0;
            report::print(&report, args.format)?;
        }
        Command::Scan(args) => {
            let report = scan::scan(
                &args.path,
                scan::ScanOptions {
                    recursive: args.recursive,
                    rule_file: args.rules.as_deref(),
                    includes: &args.include,
                    excludes: &args.exclude,
                    max_files: args.max_files,
                    max_file_size: args.max_file_size,
                    max_total_size: args.max_total_size,
                    max_entries: args.max_entries,
                    max_depth: args.max_depth,
                    max_tokens: args.max_tokens,
                },
            )?;
            has_findings |= report.summary.total_findings > 0;
            has_operational_issues |= report.summary.unreadable > 0 || report.summary.failed > 0;
            scan::print(&report, args.format)?;
        }
        Command::Evidence(args) => match args.command {
            EvidenceCommand::Create(args) => {
                let target = destination
                    .as_deref()
                    .context("--output DIRECTORY is required for evidence create")?;
                let report = evidence::create(
                    &args.path,
                    target,
                    evidence::CreateOptions {
                        rule_file: args.rules.as_deref(),
                        include_sample: args.include_sample,
                        max_entries: args.max_entries,
                        max_depth: args.max_depth,
                        max_tokens: args.max_tokens,
                        force: cli.force,
                    },
                )?;
                has_findings |= report.total_findings > 0;
                output::with_output(|output| {
                    writeln!(
                        output,
                        "Created evidence bundle: {}",
                        output::terminal_safe(&report.bundle)
                    )?;
                    writeln!(output, "Files: {}", report.files_written)?;
                    writeln!(output, "Findings: {}", report.total_findings)?;
                    writeln!(
                        output,
                        "Source sample included: {}",
                        report.source_sample_included
                    )?;
                    if report.replaced_existing {
                        writeln!(output, "Replaced existing target: true")?;
                    }
                    if let Some(warning) = &report.cleanup_warning {
                        writeln!(
                            output,
                            "Cleanup warning: {}",
                            output::terminal_safe(warning)
                        )?;
                    }
                    Ok(())
                })?;
            }
            EvidenceCommand::Verify(args) => {
                let report = evidence::verify(&args.path)?;
                explicit_findings_status |= !report.valid;
                output::print_json_or(&report, args.json, |output| {
                    writeln!(output, "Bundle: {}", output::terminal_safe(&report.bundle))?;
                    writeln!(output, "Valid: {}", report.valid)?;
                    writeln!(output, "Entries checked: {}", report.entries_checked)?;
                    writeln!(output, "Bytes checked: {}", report.total_bytes_checked)?;
                    for error in &report.errors {
                        writeln!(output, "Error: {}", output::terminal_safe(error))?;
                    }
                    Ok(())
                })?;
            }
        },
        Command::Diff(args) => {
            let report = diff::compare(&args.left, &args.right)?;
            explicit_findings_status |= report.summary.has_changes;
            diff::print(&report, args.json)?;
        }
        Command::Export(args) => {
            output::with_output(|output| export::export(&args.input, args.format, output))?;
        }
        Command::Encode(args) => {
            let value = input::read_bytes(&args.source.input, args.source.file.as_deref())?;
            output::write_line(&codec::encode_bytes(&value, args.format)?)?;
        }
        Command::Decode(args) => {
            let value = input::read(&args.source.input, args.source.file.as_deref())?;
            let decoded = codec::decode(&value, args.format)?;
            if args.raw {
                output::write_raw(&decoded)?;
            } else {
                let decoded = String::from_utf8(decoded)
                    .context("decoded value is binary/non-UTF-8; use --raw to write its bytes")?;
                output::write_line(&decoded)?;
            }
        }
        Command::Recipe(args) => {
            let value = input::read_bytes(&args.source.input, args.source.file.as_deref())?;
            let result = recipe::run(&args.recipe, value)?;
            if args.raw {
                output::write_raw(&result.output)?;
            } else {
                output::print_json_or(&result.report, args.json, |output| {
                    writeln!(output, "Recipe: {}", result.report.recipe)?;
                    writeln!(output, "Steps:")?;
                    for step in &result.report.steps {
                        writeln!(
                            output,
                            "  [{}] {}: {} -> {} bytes",
                            step.index, step.operation, step.input_bytes, step.output_bytes
                        )?;
                    }
                    writeln!(output, "Final bytes: {}", result.report.final_bytes)?;
                    match &result.report.final_text {
                        Some(value) => {
                            writeln!(output, "Final result:\n{}", output::terminal_safe(value))
                        }
                        None => writeln!(
                            output,
                            "Final result is binary/non-UTF-8; use --raw or --json (Base64 output)."
                        ),
                    }
                })?;
            }
        }
        Command::Watch(args) => {
            let mut watcher = watch::FileWatcher::new(
                &args.path,
                watch::WatchOptions {
                    from_start: args.from_start || args.once,
                    max_depth: args.max_depth,
                    max_tokens: args.max_tokens,
                },
            )?;
            loop {
                if let Some(event) = watcher.poll(args.once)? {
                    has_findings |=
                        event.report.iocs.total > 0 || !event.report.analyses.is_empty();
                    match output::selected_format(args.format, args.json) {
                        output::OutputFormat::Text => {
                            output::print_json_or(&event, false, |output| {
                                writeln!(
                                    output,
                                    "Watch: {} bytes analyzed; {} IOC(s); {} interesting token(s){}",
                                    event.input_bytes,
                                    event.report.iocs.total,
                                    event.report.analyses.len(),
                                    if event.rotation_detected {
                                        " (file rotation/truncation detected)"
                                    } else {
                                        ""
                                    }
                                )?;
                                for ioc in &event.report.iocs.iocs {
                                    writeln!(
                                        output,
                                        "{}\t{}",
                                        ioc.kind,
                                        output::terminal_safe(&ioc.value)
                                    )?;
                                }
                                for analysis in &event.report.analyses {
                                    writeln!(
                                        output,
                                        "{}\t{}",
                                        analysis.line.map_or_else(
                                            || "position unavailable".to_owned(),
                                            |line| format!("line {line}"),
                                        ),
                                        output::terminal_safe(&analysis.report.final_value)
                                    )?;
                                }
                                Ok(())
                            })?
                        }
                        output::OutputFormat::Json => {
                            output::print_json_or(&event, true, |_| Ok(()))?
                        }
                        output::OutputFormat::Jsonl => output::print_watch_jsonl(&event)?,
                        output::OutputFormat::Csv => output::print_watch_csv(&event)?,
                    }
                }
                if args.once {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(args.interval_ms));
            }
        }
        Command::Banner(args) => banner::print(args.compact, args.mask_only)?,
        Command::Completions(args) => {
            let mut command = Cli::command();
            output::with_output(|output| {
                clap_complete::generate(args.shell, &mut command, "banshee", output);
                Ok(())
            })?;
        }
        Command::Manpage => {
            output::with_output(|output| {
                clap_mangen::Man::new(Cli::command())
                    .render(output)
                    .context("failed to render man page")
            })?;
        }
    }

    let outcome = if has_operational_issues {
        RunOutcome::PartialFailure
    } else if explicit_findings_status || fail_on_findings && has_findings {
        RunOutcome::Findings
    } else {
        RunOutcome::Success
    };
    if verbose {
        eprintln!(
            "[banshee] completed in {:.3}s; findings={has_findings}; exit={}",
            started.elapsed().as_secs_f64(),
            match outcome {
                RunOutcome::Success => 0,
                RunOutcome::Findings => 1,
                RunOutcome::PartialFailure => 2,
            }
        );
    }
    Ok(outcome)
}

pub mod analysis;
pub mod banner;
pub mod batch;
pub mod cert;
pub mod cli;
pub mod codec;
pub mod file_inspect;
pub mod hash;
pub mod input;
pub mod ioc;
pub mod jwt;
pub mod output;
pub mod recipe;
pub mod regex_tool;
pub mod rules;
pub mod timestamp;
pub mod watch;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};

use crate::analysis::Analyzer;
use crate::cli::{
    CertCommand, Cli, Command, FileCommand, HashCommand, JwtCommand, RegexCommand, RulesCommand,
    TimestampCommand,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    Success,
    Findings,
}

pub fn run() -> Result<RunOutcome> {
    run_with(Cli::parse())
}

pub fn run_with(cli: Cli) -> Result<RunOutcome> {
    let started = std::time::Instant::now();
    let fail_on_findings = cli.fail_on_findings;
    let verbose = cli.verbose;
    if verbose {
        eprintln!(
            "[banshee] offline mode; output={}",
            cli.output
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "stdout".to_owned())
        );
    }
    output::configure_destination(cli.output.clone(), cli.force)?;
    output::configure_quiet(cli.quiet);
    output::configure_color(cli.color, cli.no_color);
    let mut has_findings = false;
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
                    Some(path) => Some(
                        std::fs::read(path)
                            .with_context(|| format!("failed to read key '{}'", path.display()))?,
                    ),
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
                    allowlist: ioc::PatternList::from_files(&args.allowlist)?,
                    denylist: ioc::PatternList::from_files(&args.denylist)?,
                    sort: args.sort,
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
                            writeln!(output, "    match count truncated at safety limit")?;
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
                            "line {}\t{}\t{}",
                            item.line,
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
                                        "line {}\t{}",
                                        analysis.line,
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

    let outcome = if fail_on_findings && has_findings {
        RunOutcome::Findings
    } else {
        RunOutcome::Success
    };
    if verbose {
        eprintln!(
            "[banshee] completed in {:.3}s; findings={has_findings}; exit={}",
            started.elapsed().as_secs_f64(),
            if outcome == RunOutcome::Findings {
                1
            } else {
                0
            }
        );
    }
    Ok(outcome)
}

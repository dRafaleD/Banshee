use std::path::PathBuf;

use clap::{Args, CommandFactory as _, FromArgMatches as _, Parser, Subcommand};

/// Language of human-readable text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Language {
    // No doc comments here: clap would switch `--help` to its long layout.
    En,
    Tr,
}

/// Turkish help text for the global flags, by argument id.
const GLOBAL_HELP_TR: &[(&str, &str)] = &[
    (
        "fail_on_findings",
        "Analiz gösterge veya şüpheli içerik bulursa 1 koduyla çık",
    ),
    ("no_color", "Okunur çıktıda ANSI renklerini kapat"),
    ("color", "Okunur çıktı için renk politikası"),
    (
        "output",
        "Çıktıyı yeni bir yerel yola yaz; evidence create dizin kullanır",
    ),
    (
        "force",
        "Desteklenen yerlerde --output ile mevcut hedefin üzerine yaz",
    ),
    (
        "quiet",
        "Normal çıktıyı gizle; hatalar ve çıkış kodları korunur",
    ),
    ("verbose", "Güvenli çalışma tanılarını stderr'e yaz"),
    (
        "lang",
        "Okunur metin dili (BANSHEE_LANG=tr de olur); JSON ve rapor biçimleri İngilizce kalır",
    ),
];

/// "QUICK START" block shown below the options.
fn quick_start(turkish: bool) -> &'static str {
    if turkish {
        "HIZLI BAŞLANGIÇ:\n  banshee whatis aGVsbG8=\n  banshee extract --file application.log --defang\n  banshee report sample.bin --format json\n  banshee evidence verify case-evidence\n\nGirdi, biçim ve sınırlar için banshee <komut> --help kullanın.\nÇıkış kodları: 0 = başarılı; 1 = bulgu/fark/başarısız bütünlük; 2 = işletim hatası.\nBulgular normalde --fail-on-findings gerektirir; diff ve evidence verify doğrudan 1 döndürür."
    } else {
        "QUICK START:\n  banshee whatis aGVsbG8=\n  banshee extract --file application.log --defang\n  banshee report sample.bin --format json\n  banshee evidence verify case-evidence\n\nUse banshee <command> --help for inputs, formats, and limits.\nExit codes: 0 = success; 1 = findings/differences/failed integrity; 2 = operational error.\nFindings normally require --fail-on-findings; diff and evidence verify use status 1 directly."
    }
}

/// The command definition with the categorized command menu in its help, in
/// the current output language.
pub fn command() -> clap::Command {
    let turkish = crate::i18n::is_turkish();
    let interactive = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let color =
        interactive && std::env::var_os("NO_COLOR").is_none() && crate::terminal::enable_ansi();
    let options = crate::i18n::t("Options:", "Seçenekler:");
    let mut command = Cli::command()
        .help_template(format!(
            "{{about-with-newline}}\n{{usage-heading}} {{usage}}\n\n{{before-help}}\n{options}\n{{options}}\n{{after-help}}"
        ))
        .before_help(crate::shell_help::command_menu(color, turkish))
        .after_help(quick_start(turkish));
    if turkish {
        command = command.about("Çevrimdışı, boru dostu güvenlik analiz araç seti");
        for (id, help) in GLOBAL_HELP_TR {
            command = command.mut_arg(*id, |argument| argument.help(*help));
        }
    }
    command
}

/// Applies a `--lang` found in raw arguments, before clap renders any help.
fn apply_language_from(arguments: &[std::ffi::OsString]) {
    let words = arguments.iter().map(|argument| argument.to_string_lossy());
    if let Some(turkish) = crate::i18n::language_from_arguments(words) {
        crate::i18n::set_turkish(turkish);
    }
}

/// Parses `arguments` (starting with the program name) with that definition.
pub fn try_parse_from<I, T>(arguments: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let arguments: Vec<std::ffi::OsString> = arguments.into_iter().map(Into::into).collect();
    apply_language_from(&arguments);
    Cli::from_arg_matches(&command().try_get_matches_from(arguments)?)
}

/// Parses the process arguments, printing help or errors and exiting like clap.
pub fn parse() -> Cli {
    let arguments: Vec<std::ffi::OsString> = std::env::args_os().collect();
    apply_language_from(&arguments);
    let matches = command().get_matches_from(arguments);
    Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit())
}

#[derive(Debug, Parser)]
#[command(
    name = "banshee",
    version,
    about = "Offline, pipe-friendly security analysis toolkit",
    long_about = None,
    help_template = "{about-with-newline}
{usage-heading} {usage}

{before-help}
Options:
{options}
{after-help}",
    after_help = "QUICK START:\n  banshee whatis aGVsbG8=\n  banshee extract --file application.log --defang\n  banshee report sample.bin --format json\n  banshee evidence verify case-evidence\n\nUse banshee <command> --help for inputs, formats, and limits.\nExit codes: 0 = success; 1 = findings/differences/failed integrity; 2 = operational error.\nFindings normally require --fail-on-findings; diff and evidence verify use status 1 directly."
)]
pub struct Cli {
    /// Exit with status 1 when analysis finds indicators or suspicious content
    #[arg(long, global = true)]
    pub fail_on_findings: bool,

    /// Disable ANSI colors in human-readable output
    #[arg(long, global = true, conflicts_with = "color")]
    pub no_color: bool,

    /// Color policy for human-readable output
    #[arg(long, global = true, value_enum, default_value_t = crate::output::ColorMode::Auto)]
    pub color: crate::output::ColorMode,

    /// Write command output to a new local path; evidence create uses a directory
    #[arg(short, long, global = true, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Allow --output to replace an existing target where supported
    #[arg(long, global = true, requires = "output")]
    pub force: bool,

    /// Suppress normal command output; errors and exit statuses are preserved
    #[arg(long, global = true, conflicts_with_all = ["verbose", "output"])]
    pub quiet: bool,

    /// Emit safe execution diagnostics to stderr
    #[arg(long, global = true, conflicts_with = "quiet")]
    pub verbose: bool,

    /// Language of human-readable text (BANSHEE_LANG=tr also works); JSON and reports stay English
    #[arg(long, global = true, value_enum, value_name = "LANG")]
    pub lang: Option<Language>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Detect and recursively decode an unknown value
    Whatis(WhatisArgs),
    /// Measure entropy and classify an unknown value
    Entropy(EntropyArgs),
    /// Inspect JSON Web Tokens without sending them anywhere
    Jwt(JwtArgs),
    /// Extract and normalize IOCs from text, a file, or stdin
    Extract(ExtractArgs),
    /// Calculate, identify, or match hashes offline
    Hash(HashArgs),
    /// Convert between Unix timestamps and human-readable UTC time
    Timestamp(TimestampArgs),
    /// Test regular expressions or list common security patterns
    Regex(RegexArgs),
    /// Inspect local PEM or DER X.509 certificates
    Cert(CertArgs),
    /// Inspect archives, compressed streams, and executable headers offline
    File(FileArgs),
    /// Extract printable ASCII and UTF-16LE strings with their offsets
    Strings(StringsArgs),
    /// Show a canonical hex dump (offset, hex bytes, ASCII) of part of the input
    Hexdump(HexdumpArgs),
    /// Validate and scan with local TOML detection rules
    Rules(RulesArgs),
    /// Automatically analyze tokens and IOCs in bulk input
    Analyze(AnalyzeArgs),
    /// Build a unified offline analysis report for one local file
    Report(ReportArgs),
    /// Scan a local file or directory with bounded offline analysis
    Scan(ScanArgs),
    /// Create or verify a deterministic offline evidence bundle
    Evidence(EvidenceArgs),
    /// Compare two report JSON files or verified evidence bundles
    Diff(DiffArgs),
    /// Export saved report observables as STIX 2.1, MISP or CSV
    Export(ExportArgs),
    /// Encode text using a selected format
    Encode(EncodeArgs),
    /// Decode data using a selected format
    Decode(DecodeArgs),
    /// Apply a pipe-separated transformation recipe locally
    Recipe(RecipeArgs),
    /// Follow appended log lines and analyze them locally
    Watch(WatchArgs),
    /// Check the local installation offline (codecs, data, PATH, temp directory)
    Doctor(DoctorArgs),
    /// Open the interactive console (also the default when run on a terminal)
    Shell,
    /// Print the Banshee ASCII banner and mask emblem
    Banner(BannerArgs),
    /// Generate shell completion definitions
    Completions(CompletionsArgs),
    /// Generate a roff manual page on stdout
    Manpage,
}

#[derive(Debug, Args)]
pub struct WhatisArgs {
    #[command(flatten)]
    pub source: SourceArgs,

    /// Maximum number of nested decoding layers
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u8).range(1..=32))]
    pub max_depth: u8,

    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct EntropyArgs {
    #[command(flatten)]
    pub source: SourceArgs,

    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct JwtArgs {
    #[command(subcommand)]
    pub command: JwtCommand,
}

#[derive(Debug, Subcommand)]
pub enum JwtCommand {
    /// Decode and inspect a JWT without verifying its signature
    Inspect(JwtInspectArgs),
    /// Verify a JWT signature with an explicit algorithm and local key
    Verify(JwtVerifyArgs),
}

#[derive(Debug, Args)]
pub struct JwtInspectArgs {
    #[command(flatten)]
    pub source: SourceArgs,

    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
#[group(id = "jwt_key", required = true, multiple = false, args = ["secret", "key"])]
pub struct JwtVerifyArgs {
    #[command(flatten)]
    pub source: SourceArgs,

    /// Expected algorithm; never inferred from the untrusted token
    #[arg(short, long, value_enum)]
    pub algorithm: crate::jwt::JwtAlgorithm,

    /// HMAC secret (HS algorithms); may be visible in process listings
    #[arg(long)]
    pub secret: Option<String>,

    /// RSA, EC, or EdDSA public/private key PEM file
    #[arg(long, value_name = "PATH")]
    pub key: Option<PathBuf>,

    /// Skip exp and nbf validation; signature is still verified
    #[arg(long)]
    pub ignore_time: bool,

    /// Clock-skew allowance in seconds
    #[arg(long, default_value_t = 60)]
    pub leeway: u64,

    /// Expected audience; may be repeated or comma-separated
    #[arg(long, value_delimiter = ',')]
    pub audience: Vec<String>,

    /// Expected issuer; may be repeated or comma-separated
    #[arg(long, value_delimiter = ',')]
    pub issuer: Vec<String>,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ExtractArgs {
    #[command(flatten)]
    pub source: SourceArgs,

    /// Extract only IP addresses
    #[arg(long)]
    pub ip: bool,

    /// Extract only domains
    #[arg(long)]
    pub domain: bool,

    /// Extract only URLs
    #[arg(long)]
    pub url: bool,

    /// Extract only recognized hash values
    #[arg(long)]
    pub hash: bool,

    /// Extract only email addresses
    #[arg(long)]
    pub email: bool,

    /// Extract only MAC addresses
    #[arg(long)]
    pub mac: bool,

    /// Extract only secret and private-key candidates
    #[arg(long)]
    pub secret: bool,

    /// Suppress IOCs matching entries in a local known-safe list; supports * wildcards
    #[arg(long, value_name = "PATH")]
    pub allowlist: Vec<PathBuf>,

    /// When present, keep only IOCs matching entries in a local list; supports * wildcards
    #[arg(long, value_name = "PATH")]
    pub denylist: Vec<PathBuf>,

    /// Sort unique IOCs by kind, normalized value, or descending occurrence count
    #[arg(long, value_enum, default_value_t = crate::ioc::IocSort::Kind)]
    pub sort: crate::ioc::IocSort,

    /// Include a unique/total-occurrence summary in text output
    #[arg(long)]
    pub summary: bool,

    /// Emit machine-readable JSON with normalized values
    #[arg(long, conflicts_with_all = ["defang", "format"])]
    pub json: bool,

    /// Output format for structured results
    #[arg(long, value_enum, conflicts_with_all = ["json", "defang"])]
    pub format: Option<crate::output::OutputFormat>,

    /// Defang text output for safer sharing (for example, hxxps://host[.]tld)
    #[arg(long)]
    pub defang: bool,

    /// Include this many surrounding lines for each recorded location
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=5))]
    pub context: u8,

    /// Maximum characters retained for each context line
    #[arg(long, default_value_t = 240, value_parser = parse_context_chars)]
    pub max_context_chars: usize,

    /// Maximum recorded locations per unique IOC or secret
    #[arg(long, default_value_t = 20, value_parser = parse_locations)]
    pub max_locations: usize,

    /// Maximum total candidate matches inspected
    #[arg(long, default_value_t = 10_000, value_parser = parse_matches)]
    pub max_matches: usize,

    /// Reveal full secret candidates in output and context (unsafe for sharing)
    #[arg(long)]
    pub reveal_secrets: bool,
}

#[derive(Debug, Args)]
pub struct HashArgs {
    #[command(subcommand)]
    pub command: HashCommand,
}

#[derive(Debug, Subcommand)]
pub enum HashCommand {
    /// Calculate a cryptographic hash
    Calculate(HashCalculateArgs),
    /// Identify probable algorithms from a hash value
    Identify(HashIdentifyArgs),
    /// Match a hash against an offline wordlist
    Crack(HashCrackArgs),
    /// Calculate an ssdeep fuzzy hash of a value, file, or stdin
    Ssdeep(HashSsdeepArgs),
    /// Compare two ssdeep digests and print a 0-100 similarity score
    CompareSsdeep(HashCompareSsdeepArgs),
}

#[derive(Debug, Args)]
pub struct HashSsdeepArgs {
    #[command(flatten)]
    pub source: SourceArgs,
}

#[derive(Debug, Args)]
pub struct HashCompareSsdeepArgs {
    /// First ssdeep digest, such as 96:abc...:def...
    pub left: String,
    /// Second ssdeep digest
    pub right: String,
}

#[derive(Debug, Args)]
pub struct HashCalculateArgs {
    #[command(flatten)]
    pub source: SourceArgs,

    /// Hash algorithm
    #[arg(short, long, value_enum, default_value_t = crate::hash::HashAlgorithm::Sha256)]
    pub algorithm: crate::hash::HashAlgorithm,

    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct HashIdentifyArgs {
    /// Hash value to identify
    pub value: String,

    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct HashCrackArgs {
    /// Hash value to compare
    pub value: String,

    /// Local wordlist file, one candidate per line
    #[arg(short, long, value_name = "PATH")]
    pub wordlist: PathBuf,

    /// Algorithm; inferred from length when omitted and unambiguous
    #[arg(short, long, value_enum)]
    pub algorithm: Option<crate::hash::HashAlgorithm>,

    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct TimestampArgs {
    #[command(subcommand)]
    pub command: TimestampCommand,
}

#[derive(Debug, Subcommand)]
pub enum TimestampCommand {
    /// Convert a Unix timestamp to RFC3339 UTC
    ToHuman(TimestampToHumanArgs),
    /// Convert an RFC3339 date-time to a Unix timestamp
    ToUnix(TimestampToUnixArgs),
}

#[derive(Debug, Args)]
pub struct TimestampToHumanArgs {
    /// Numeric Unix timestamp
    pub value: i128,

    /// Input unit; inferred by magnitude when set to auto
    #[arg(short, long, value_enum, default_value_t = crate::timestamp::TimestampUnit::Auto)]
    pub unit: crate::timestamp::TimestampUnit,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct TimestampToUnixArgs {
    /// RFC3339 date-time, for example 2024-01-01T00:00:00Z
    pub value: String,

    /// Output unit
    #[arg(short, long, value_enum, default_value_t = crate::timestamp::TimestampUnit::Seconds)]
    pub unit: crate::timestamp::TimestampUnit,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RegexArgs {
    #[command(subcommand)]
    pub command: RegexCommand,
}

#[derive(Debug, Subcommand)]
pub enum RegexCommand {
    /// Test a regular expression against text, a file, or stdin
    Test(RegexTestArgs),
    /// List built-in common patterns
    Patterns(RegexPatternsArgs),
}

#[derive(Debug, Args)]
pub struct RegexTestArgs {
    /// Rust-compatible regular expression
    pub pattern: String,

    #[command(flatten)]
    pub source: SourceArgs,

    #[arg(short, long)]
    pub case_insensitive: bool,

    #[arg(short, long)]
    pub multiline: bool,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RegexPatternsArgs {
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct CertArgs {
    #[command(subcommand)]
    pub command: CertCommand,
}

#[derive(Debug, Subcommand)]
pub enum CertCommand {
    /// Inspect a certificate file without making network requests
    Inspect(CertInspectArgs),
    /// Inspect and verify a PEM certificate chain in leaf-to-root order
    Chain(CertChainArgs),
}

#[derive(Debug, Args)]
pub struct CertInspectArgs {
    /// PEM, DER, or CRT certificate file
    pub path: PathBuf,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct CertChainArgs {
    /// PEM bundle in leaf-to-root order, or a single DER certificate
    pub path: PathBuf,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct HexdumpArgs {
    #[command(flatten)]
    pub source: SourceArgs,

    /// First byte to show (decimal, or hex with 0x)
    #[arg(long, default_value = "0", value_parser = parse_offset)]
    pub offset: usize,

    /// Number of bytes to show
    #[arg(short = 'n', long, default_value_t = 512, value_parser = clap::value_parser!(u32).range(1..=16_777_216))]
    pub length: u32,

    /// Bytes per line
    #[arg(long, default_value_t = 16, value_parser = clap::value_parser!(u8).range(1..=64))]
    pub width: u8,
}

/// Parses `1234` or `0x4d2`.
fn parse_offset(value: &str) -> Result<usize, String> {
    let parsed = match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => usize::from_str_radix(hex, 16),
        None => value.parse::<usize>(),
    };
    parsed.map_err(|_| format!("'{value}' is not a decimal or 0x-prefixed hex offset"))
}

#[derive(Debug, Args)]
pub struct StringsArgs {
    #[command(flatten)]
    pub source: SourceArgs,

    /// Minimum string length in characters
    #[arg(short = 'n', long, default_value_t = 4, value_parser = clap::value_parser!(u16).range(1..=1024))]
    pub min_length: u16,

    /// Encodings to search for
    #[arg(long, value_enum, default_value_t = crate::strings::EncodingChoice::All)]
    pub encoding: crate::strings::EncodingChoice,

    /// Maximum strings to list; the total is still counted
    #[arg(long, default_value_t = 10_000, value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    pub max_strings: u32,

    /// Print only the strings, one per line, without offsets
    #[arg(long, conflicts_with = "json")]
    pub plain: bool,

    /// Keep only notable strings (URLs, IPs, domains, paths, registry keys, commands, ...)
    #[arg(long)]
    pub interesting: bool,

    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct FileArgs {
    #[command(subcommand)]
    pub command: FileCommand,
}

#[derive(Debug, Subcommand)]
pub enum FileCommand {
    /// Auto-detect and inspect a local file without extracting it
    Inspect(FileInspectArgs),
}

#[derive(Debug, Args)]
pub struct FileInspectArgs {
    /// ZIP, TAR, gzip, XZ, BZip2, PE, ELF, or other local file
    pub path: PathBuf,

    /// Maximum archive entries to list
    #[arg(long, default_value_t = 10_000, value_parser = parse_max_tokens)]
    pub max_entries: usize,

    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RulesArgs {
    #[command(subcommand)]
    pub command: RulesCommand,
}

#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    /// Validate rule syntax, IDs, patterns, and limits without scanning data
    Validate(RulesValidateArgs),
    /// Scan a value, file, or stdin with a local rule file
    Scan(RulesScanArgs),
    /// Convert a local TOML rule file to YARA, marking anything not expressible
    ExportYara(RulesPathArgs),
    /// Convert a supported subset of YARA rules to Banshee TOML
    ImportYara(RulesPathArgs),
    /// Print the built-in starter rule pack as TOML, or list its rules
    Builtin(RulesBuiltinArgs),
}

#[derive(Debug, Args)]
pub struct RulesPathArgs {
    /// Input rule file
    pub path: PathBuf,
}

#[derive(Debug, Args)]
pub struct RulesBuiltinArgs {
    /// List rule IDs, severities and descriptions instead of printing TOML
    #[arg(long)]
    pub list: bool,

    /// Emit machine-readable JSON (with --list)
    #[arg(long, requires = "list")]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RulesValidateArgs {
    /// Local TOML rule file
    pub path: PathBuf,

    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RulesScanArgs {
    /// Local TOML rule file
    #[arg(
        short,
        long,
        value_name = "PATH",
        required_unless_present = "builtin_rules"
    )]
    pub rules: Option<PathBuf>,

    /// Use the starter rule pack built into Banshee (see `rules builtin`)
    #[arg(long, conflicts_with = "rules")]
    pub builtin_rules: bool,

    #[command(flatten)]
    pub source: SourceArgs,

    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct AnalyzeArgs {
    #[command(flatten)]
    pub source: SourceArgs,

    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u8).range(1..=32))]
    pub max_depth: u8,

    /// Maximum unique tokens to inspect
    #[arg(long, default_value_t = 10_000, value_parser = parse_max_tokens)]
    pub max_tokens: usize,

    #[arg(long)]
    pub json: bool,

    /// Output format for structured results
    #[arg(long, value_enum, conflicts_with = "json")]
    pub format: Option<crate::output::OutputFormat>,
}

#[derive(Debug, Args)]
pub struct ReportArgs {
    /// Local file to analyze
    pub path: PathBuf,

    /// Optional local TOML rule file
    #[arg(long, value_name = "PATH")]
    pub rules: Option<PathBuf>,

    /// Use the starter rule pack built into Banshee (see `rules builtin`)
    #[arg(long, conflicts_with = "rules")]
    pub builtin_rules: bool,

    /// Report output format
    #[arg(long, value_enum, default_value_t = crate::report::ReportFormat::Text)]
    pub format: crate::report::ReportFormat,

    /// Maximum archive entries to list
    #[arg(long, default_value_t = 10_000, value_parser = parse_max_tokens)]
    pub max_entries: usize,

    /// Maximum number of unique content tokens to inspect
    #[arg(long, default_value_t = 10_000, value_parser = parse_max_tokens)]
    pub max_tokens: usize,

    /// Maximum number of nested decoding layers
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u8).range(1..=32))]
    pub max_depth: u8,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Local file or directory to scan
    pub path: PathBuf,

    /// Descend into subdirectories
    #[arg(long)]
    pub recursive: bool,

    /// Optional local TOML rule file applied to every selected file
    #[arg(long, value_name = "PATH")]
    pub rules: Option<PathBuf>,

    /// Use the starter rule pack built into Banshee (see `rules builtin`)
    #[arg(long, conflicts_with = "rules")]
    pub builtin_rules: bool,

    /// Include matching relative paths; supports *, **, and ?
    #[arg(long, value_name = "GLOB")]
    pub include: Vec<String>,

    /// Exclude matching relative paths; supports *, **, and ?
    #[arg(long, value_name = "GLOB")]
    pub exclude: Vec<String>,

    /// Scan output format
    #[arg(long, value_enum, default_value_t = crate::scan::ScanFormat::Text)]
    pub format: crate::scan::ScanFormat,

    /// Maximum regular files considered, including filtered files
    #[arg(long, default_value_t = 10_000, value_parser = parse_max_tokens)]
    pub max_files: usize,

    /// Maximum size of an individual file (bytes or KiB/MiB/GiB suffix)
    #[arg(long, default_value = "64MiB", value_parser = parse_file_size)]
    pub max_file_size: u64,

    /// Maximum combined size analyzed (bytes or KiB/MiB/GiB suffix)
    #[arg(long, default_value = "1GiB", value_parser = parse_total_size)]
    pub max_total_size: u64,

    /// Maximum archive entries listed per file
    #[arg(long, default_value_t = 10_000, value_parser = parse_max_tokens)]
    pub max_entries: usize,

    /// Maximum unique content tokens inspected per file
    #[arg(long, default_value_t = 10_000, value_parser = parse_max_tokens)]
    pub max_tokens: usize,

    /// Maximum nested decoding layers per file
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u8).range(1..=32))]
    pub max_depth: u8,

    /// Files analyzed concurrently (0 = available cores, at most 4); results stay in path order
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u16).range(0..=64))]
    pub jobs: u16,
}

#[derive(Debug, Args)]
pub struct EvidenceArgs {
    #[command(subcommand)]
    pub command: EvidenceCommand,
}

#[derive(Debug, Subcommand)]
pub enum EvidenceCommand {
    /// Create a complete evidence directory and write its manifest last
    Create(EvidenceCreateArgs),
    /// Verify bundle file sizes and SHA-256 hashes without network access
    Verify(EvidenceVerifyArgs),
}

#[derive(Debug, Args)]
#[command(
    after_help = "Requires --output BUNDLE_DIR. The source sample is omitted unless --include-sample is supplied."
)]
pub struct EvidenceCreateArgs {
    /// Local source file to analyze
    pub path: PathBuf,

    /// Optional local TOML rule file
    #[arg(long, value_name = "PATH")]
    pub rules: Option<PathBuf>,

    /// Use the starter rule pack built into Banshee (see `rules builtin`)
    #[arg(long, conflicts_with = "rules")]
    pub builtin_rules: bool,

    /// Explicitly copy the source sample into the bundle as source-sample.bin
    #[arg(long)]
    pub include_sample: bool,

    /// Maximum archive entries to list
    #[arg(long, default_value_t = 10_000, value_parser = parse_max_tokens)]
    pub max_entries: usize,

    /// Maximum number of unique content tokens to inspect
    #[arg(long, default_value_t = 10_000, value_parser = parse_max_tokens)]
    pub max_tokens: usize,

    /// Maximum number of nested decoding layers
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u8).range(1..=32))]
    pub max_depth: u8,
}

#[derive(Debug, Args)]
pub struct EvidenceVerifyArgs {
    /// Existing evidence bundle directory
    pub path: PathBuf,

    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Report JSON file or evidence bundle directory
    pub input: PathBuf,

    /// Export format; observables only, never verdicts or redacted secrets
    #[arg(long, value_enum)]
    pub format: crate::export::ExportFormat,
}

#[derive(Debug, Args)]
pub struct DiffArgs {
    /// Earlier report JSON file or evidence bundle directory
    pub left: PathBuf,

    /// Later report JSON file or evidence bundle directory
    pub right: PathBuf,

    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct EncodeArgs {
    /// Output encoding
    #[arg(value_enum)]
    pub format: crate::codec::Codec,

    #[command(flatten)]
    pub source: SourceArgs,
}

#[derive(Debug, Args)]
pub struct DecodeArgs {
    /// Input encoding
    #[arg(value_enum)]
    pub format: crate::codec::Codec,

    #[command(flatten)]
    pub source: SourceArgs,

    /// Write decoded bytes directly without a trailing newline
    #[arg(long)]
    pub raw: bool,
}

#[derive(Debug, Args)]
#[command(
    after_help = "Examples:\n  banshee recipe 'base64|url' 'aGVsbG8lMjB3b3JsZA=='\n  banshee recipe 'base64|gzip|url' --file sample.txt\n  banshee recipe 'rot13|encode:base32' 'Uryyb'\n\nText/byte codecs: base64, base64url, base32, base85, hex, binary, octal, rot13, punycode, url, html, unicode\nCompression codecs: gzip, zlib\nPrefix a codec with encode: to encode instead of decode."
)]
pub struct RecipeArgs {
    /// Pipe-separated operations, applied from left to right
    pub recipe: String,

    #[command(flatten)]
    pub source: SourceArgs,

    /// Write final bytes directly without metadata or a trailing newline
    #[arg(long, conflicts_with = "json")]
    pub raw: bool,

    /// Emit machine-readable step metadata and a Base64-safe final value
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct WatchArgs {
    /// Log file to follow
    pub path: PathBuf,

    /// Analyze existing file contents before following new lines
    #[arg(long)]
    pub from_start: bool,

    /// Analyze once and exit; implicitly starts at the beginning of the file
    #[arg(long)]
    pub once: bool,

    /// Polling interval in milliseconds
    #[arg(long, default_value_t = 1_000, value_parser = clap::value_parser!(u64).range(100..=60_000))]
    pub interval_ms: u64,

    /// Maximum nested decoding depth for each appended batch
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u8).range(1..=32))]
    pub max_depth: u8,

    /// Maximum unique tokens to inspect in each appended batch
    #[arg(long, default_value_t = 10_000, value_parser = parse_max_tokens)]
    pub max_tokens: usize,

    /// Emit a JSON object for every analyzed batch
    #[arg(long, conflicts_with = "format")]
    pub json: bool,

    /// Output format for each analyzed batch
    #[arg(long, value_enum, conflicts_with = "json")]
    pub format: Option<crate::output::OutputFormat>,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct BannerArgs {
    /// Print a smaller banner without the full mask silhouette
    #[arg(long)]
    pub compact: bool,

    /// Print only the mask silhouette
    #[arg(long, conflicts_with = "compact")]
    pub mask_only: bool,
}

#[derive(Debug, Args)]
pub struct CompletionsArgs {
    /// Target shell
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

fn parse_max_tokens(value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| "must be a positive integer".to_owned())?;
    if !(1..=1_000_000).contains(&parsed) {
        return Err("must be between 1 and 1000000".to_owned());
    }
    Ok(parsed)
}

fn parse_context_chars(value: &str) -> Result<usize, String> {
    parse_usize_range(value, 32, 4096)
}

fn parse_locations(value: &str) -> Result<usize, String> {
    parse_usize_range(value, 1, 100)
}

fn parse_matches(value: &str) -> Result<usize, String> {
    parse_usize_range(value, 1, 100_000)
}

fn parse_usize_range(value: &str, minimum: usize, maximum: usize) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| "must be a positive integer".to_owned())?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err(format!("must be between {minimum} and {maximum}"));
    }
    Ok(parsed)
}

fn parse_file_size(value: &str) -> Result<u64, String> {
    parse_size(value, 256 * 1024 * 1024, "256 MiB")
}

fn parse_total_size(value: &str) -> Result<u64, String> {
    parse_size(value, 16 * 1024 * 1024 * 1024, "16 GiB")
}

fn parse_size(value: &str, maximum: u64, maximum_label: &str) -> Result<u64, String> {
    let normalized = value.trim();
    let split = normalized
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(normalized.len());
    let (number, suffix) = normalized.split_at(split);
    let number = number
        .parse::<u64>()
        .map_err(|_| "must start with a positive integer".to_owned())?;
    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "kib" => 1024,
        "mib" => 1024 * 1024,
        "gib" => 1024 * 1024 * 1024,
        _ => return Err("suffix must be B, KiB, MiB, or GiB".to_owned()),
    };
    let bytes = number
        .checked_mul(multiplier)
        .ok_or_else(|| "size is too large".to_owned())?;
    if bytes == 0 || bytes > maximum {
        return Err(format!("must be between 1 byte and {maximum_label}"));
    }
    Ok(bytes)
}

#[derive(Debug, Args)]
pub struct SourceArgs {
    /// Value to analyze. Reads stdin when omitted
    #[arg(value_name = "VALUE", conflicts_with = "file")]
    pub input: Option<String>,

    /// Read the value from a file
    #[arg(short, long, value_name = "PATH")]
    pub file: Option<PathBuf>,
}

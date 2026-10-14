//! Start screen shown when `banshee` runs without arguments: a green-on-black
//! emblem beside a neofetch-style summary of this build, then quick-start
//! commands. Colors are used only for interactive terminals and honor NO_COLOR.

use std::fmt::Write as _;
use std::io::IsTerminal as _;

/// Hooded banshee with an open, wailing mouth.
const EMBLEM: &[&str] = &[
    r"        .-'''''''-.",
    r"      .'  .-----.  '.",
    r"     /   /  _ _  \   \",
    r"    |   |  (o|o)  |   |",
    r"    |   |    ^    |   |",
    r"    |   |  .---.  |   |",
    r"    |    \ (   ) /    |",
    r"     \    '.'-'.'    /",
    r"      '.   \   /   .'",
    r"     .' '. |   | .' '.",
    r"    /  /\  |   |  /\  \",
    r"   /  /  \ |   | /  \  \",
    r"  /__/ /\ \|___|/ /\ \__\",
    r"      ~  ~  ~ ~  ~  ~",
];

/// 256-color greens from bright at the hood to dark at the hem.
const GRADIENT: &[u8] = &[46, 46, 46, 40, 40, 40, 34, 34, 34, 28, 28, 28, 22, 22];
const LABEL_COLOR: u8 = 46;
const SWATCHES: &[u8] = &[16, 22, 28, 34, 40, 46, 82, 120];
const EMBLEM_WIDTH: usize = 28;

/// Values shown in the summary column.
pub struct SplashInfo {
    pub version: &'static str,
    pub profile: &'static str,
    pub platform: String,
    pub xz: bool,
    pub signatures: bool,
    pub tld_snapshot: Option<String>,
}

impl SplashInfo {
    pub fn current() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION"),
            profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
            platform: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
            xz: cfg!(feature = "xz"),
            signatures: cfg!(feature = "crypto-verify"),
            tld_snapshot: crate::tld::snapshot_version()
                .and_then(|version| version.split_whitespace().next())
                .map(|serial| serial.trim_end_matches(',').to_owned()),
        }
    }
}

/// Prints the start screen, choosing color from the terminal and NO_COLOR.
pub fn print() -> anyhow::Result<()> {
    let color = std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal();
    crate::output::write_raw(render(&SplashInfo::current(), color).as_bytes())
}

pub fn render(info: &SplashInfo, color: bool) -> String {
    let yes_no = |enabled: bool| {
        if enabled {
            "yes"
        } else {
            "no (native build only)"
        }
    };
    let title = format!("banshee v{}", info.version);
    let rows: Vec<(&str, String)> = vec![
        ("", title.clone()),
        ("", "-".repeat(title.len())),
        (
            "Mode",
            "offline; inputs never leave this machine".to_owned(),
        ),
        ("Build", format!("{} for {}", info.profile, info.platform)),
        (
            "Features",
            format!(
                "xz {} / signatures {}",
                yes_no(info.xz),
                yes_no(info.signatures)
            ),
        ),
        (
            "TLDs",
            info.tld_snapshot
                .as_deref()
                .map_or_else(|| "unknown".to_owned(), |serial| format!("IANA {serial}")),
        ),
        (
            "Inspects",
            "PE ELF OOXML OLE PDF LNK ZIP TAR gz xz bz2".to_owned(),
        ),
        (
            "Decodes",
            "base64 hex url html unicode utf16 xor scripts".to_owned(),
        ),
        ("Hashes", "md5 sha1 sha256 imphash ssdeep".to_owned()),
        (
            "Reports",
            "text json markdown html; stix misp csv".to_owned(),
        ),
        ("Rules", "toml; yara import/export; ATT&CK tags".to_owned()),
        ("", String::new()),
        ("", swatches(color)),
    ];

    let mut output = String::from("\n");
    for index in 0..EMBLEM.len().max(rows.len()) {
        let art = EMBLEM.get(index).copied().unwrap_or("");
        let padded = format!("{art:<EMBLEM_WIDTH$}");
        if color {
            let shade = GRADIENT[index.min(GRADIENT.len() - 1)];
            write!(output, "\x1b[40;38;5;{shade}m{padded}\x1b[0m").expect("string write");
        } else {
            output.push_str(&padded);
        }
        let row = rows.get(index).filter(|(_, value)| !value.is_empty());
        if row.is_some() {
            output.push_str("   ");
        }
        if let Some((label, value)) = row {
            match (*label, index) {
                ("", 0) if color => {
                    write!(output, "\x1b[1;38;5;{LABEL_COLOR}m{value}\x1b[0m")
                        .expect("string write");
                }
                ("", _) => output.push_str(value),
                (label, _) if color => {
                    write!(
                        output,
                        "\x1b[1;38;5;{LABEL_COLOR}m{label:<9}\x1b[0m {value}"
                    )
                    .expect("string write");
                }
                (label, _) => write!(output, "{label:<9} {value}").expect("string write"),
            }
        }
        if !color {
            // Plain output carries no trailing padding.
            let trimmed = output.trim_end_matches(' ').len();
            output.truncate(trimmed);
        }
        output.push('\n');
    }

    let commands = [
        (
            "banshee whatis <value>",
            "decode and explain an unknown value",
        ),
        (
            "banshee report <file> --format html -o r.html",
            "offline report for one file",
        ),
        (
            "banshee scan <dir> --recursive",
            "bounded scan of a directory",
        ),
        ("banshee doctor", "check this installation"),
        ("banshee --help", "all commands"),
    ];
    output.push('\n');
    for (command, purpose) in commands {
        if color {
            writeln!(
                output,
                "  \x1b[38;5;{LABEL_COLOR}m{command:<47}\x1b[0m {purpose}"
            )
            .expect("string write");
        } else {
            writeln!(output, "  {command:<47} {purpose}").expect("string write");
        }
    }
    output.push_str("\n  Findings are analyst-assistance signals, not malware verdicts.\n\n");
    output
}

fn swatches(color: bool) -> String {
    if !color {
        return String::new();
    }
    SWATCHES
        .iter()
        .map(|shade| format!("\x1b[48;5;{shade}m   "))
        .collect::<String>()
        + "\x1b[0m"
}

#[cfg(test)]
mod tests {
    use super::{EMBLEM, EMBLEM_WIDTH, SplashInfo, render};

    fn info() -> SplashInfo {
        SplashInfo {
            version: "9.9.9",
            profile: "release",
            platform: "x86_64-linux".to_owned(),
            xz: true,
            signatures: false,
            tld_snapshot: Some("2026101200".to_owned()),
        }
    }

    #[test]
    fn plain_screen_has_no_escape_codes_and_aligned_columns() {
        let screen = render(&info(), false);
        assert!(!screen.contains('\x1b'));
        assert!(screen.contains("banshee v9.9.9"));
        assert!(screen.contains("signatures no (native build only)"));
        assert!(screen.contains("IANA 2026101200"));
        assert!(screen.contains("banshee doctor"));
        // Every summary row starts at the same column after the emblem.
        for label in [
            "banshee v9.9.9",
            "Mode",
            "Build",
            "Features",
            "TLDs",
            "Rules",
        ] {
            let line = screen
                .lines()
                .find(|line| {
                    line.get(EMBLEM_WIDTH + 3..)
                        .is_some_and(|rest| rest.starts_with(label))
                })
                .unwrap_or_else(|| panic!("{label} is not aligned"));
            assert!(!line.ends_with(' '), "{line:?}");
        }
        assert!(EMBLEM.iter().all(|line| line.len() <= EMBLEM_WIDTH));
    }

    #[test]
    fn color_screen_uses_green_on_black() {
        let screen = render(&info(), true);
        assert!(screen.contains("\x1b[40;38;5;46m"));
        assert!(screen.contains("\x1b[40;38;5;22m"));
        assert!(screen.contains("\x1b[48;5;16m"));
        assert!(screen.ends_with("verdicts.\n\n"));
    }

    #[test]
    fn current_build_reports_real_values() {
        let current = SplashInfo::current();
        assert_eq!(current.version, env!("CARGO_PKG_VERSION"));
        assert!(
            current
                .tld_snapshot
                .is_some_and(|serial| serial.len() == 10)
        );
    }
}

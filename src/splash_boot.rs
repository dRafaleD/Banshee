//! Animated start screen in the style of the AsphDex terminal: a scan beam
//! descends the finished screen, rows behind it decode from glyph noise, the
//! Braille mask reveals its own dots, and a final glow wave settles the frame.
//! The animation is cosmetic only and makes no claim about analysis readiness.

use std::io::Write as _;

use crate::splash::SplashInfo;
use crate::splash_portrait::PORTRAITS;

const SCRAMBLE: &[char] = &['▒', '░', '0', '1', ':', '·', '+'];
const BAR_PARTS: &[char] = &[' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉'];
const ROTOR: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const DECODE_ROWS: i64 = 5;
const DURATION_MS: u64 = 2_400;
const FRAME_MS: u64 = 55;
/// Width of the side-by-side layout (mask beside the summary).
const WIDE: usize = 90;
/// Narrowest terminal for the stacked layout (mask above the summary).
const MIN_WIDTH: usize = 52;

/// Figlet "standard" rendering of the wordmark, with figlet's smushing.
const WORDMARK: [&str; 5] = [
    r" ____                  _               ",
    r"| __ )  __ _ _ __  ___| |__   ___  ___ ",
    r"|  _ \ / _` | '_ \/ __| '_ \ / _ \/ _ \",
    r"| |_) | (_| | | | \__ \ | | |  __/  __/",
    r"|____/ \__,_|_| |_|___/_| |_|\___|\___|",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tone {
    Brand,
    Portrait,
    Text,
    Muted,
    Border,
    Flash,
    Head,
    Glow,
    Trail,
}

impl Tone {
    pub(crate) fn color(self) -> (u8, u8, u8) {
        match self {
            Self::Brand => (68, 210, 0),
            Self::Portrait => (57, 190, 0),
            Self::Text => (220, 225, 232),
            Self::Muted => (131, 143, 158),
            Self::Border => (65, 80, 92),
            Self::Flash => (225, 255, 205),
            Self::Head => (155, 255, 92),
            Self::Glow => (90, 235, 25),
            Self::Trail => (38, 125, 0),
        }
    }
}

/// One screen row: colored segments, optionally overridden by a boot tone.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Line {
    segments: Vec<(Tone, String)>,
    overlay: Option<Tone>,
}

impl Line {
    fn new(segments: Vec<(Tone, String)>) -> Self {
        Self {
            segments,
            overlay: None,
        }
    }

    fn single(tone: Tone, text: String) -> Self {
        Self::new(vec![(tone, text)])
    }

    #[cfg(test)]
    pub(crate) fn text(&self) -> String {
        self.segments
            .iter()
            .map(|(_, text)| text.as_str())
            .collect()
    }
}

/// The finished screen plus the rows the animation needs to know about.
pub(crate) struct Screen {
    pub(crate) lines: Vec<Line>,
    width: usize,
    first: usize,
    last: usize,
    top_rail: usize,
    bottom_rail: usize,
    progress: usize,
}

fn pad(text: &str, width: usize) -> String {
    let length = text.chars().count();
    if length >= width {
        text.chars().take(width).collect()
    } else {
        format!("{text}{}", " ".repeat(width - length))
    }
}

pub(crate) fn wordmark() -> Vec<String> {
    WORDMARK.iter().map(|row| (*row).to_owned()).collect()
}

pub(crate) fn portrait(rows: usize) -> &'static [&'static str] {
    PORTRAITS
        .iter()
        .rev()
        .find(|(size, _)| *size <= rows)
        .unwrap_or(&PORTRAITS[0])
        .1
}

/// Rows the full screen needs for a portrait of `portrait_rows`.
pub(crate) fn height_for(portrait_rows: usize, width: usize) -> usize {
    compose(&SplashInfo::current(), portrait_rows, width)
        .lines
        .len()
}

/// Screen width for a terminal with `columns` columns, or `None` when it is
/// too narrow. One column is left free so no row wraps.
pub(crate) fn layout_width(columns: usize) -> Option<usize> {
    let usable = columns.checked_sub(1)?;
    (usable >= MIN_WIDTH).then(|| usable.min(WIDE))
}

pub(crate) fn compose(info: &SplashInfo, portrait_rows: usize, width: usize) -> Screen {
    let width = width.clamp(MIN_WIDTH, WIDE);
    let side_by_side = width >= WIDE;
    let mask = portrait(portrait_rows);
    let mask_width = mask.first().map_or(0, |row| row.chars().count());
    let column = if side_by_side { 3 + mask_width + 4 } else { 3 };
    let summary_width = width - column - 2;
    let yes_no = |enabled: bool| {
        if enabled {
            "yes"
        } else {
            "no (native build only)"
        }
    };

    let mut summary: Vec<Vec<(Tone, String)>> = wordmark()
        .into_iter()
        .map(|row| vec![(Tone::Brand, row)])
        .collect();
    summary.push(vec![]);
    summary.push(vec![(
        Tone::Text,
        format!("v{}  ·  offline security analysis toolkit", info.version),
    )]);
    summary.push(vec![(Tone::Border, "─".repeat(summary_width.min(46)))]);
    let rows = [
        (
            "Mode",
            "offline; inputs never leave this machine".to_owned(),
        ),
        ("Build", format!("{} for {}", info.profile, info.platform)),
        (
            "Features",
            format!(
                "xz {} · signatures {}",
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
            "text json markdown html · stix misp csv".to_owned(),
        ),
        ("Rules", "toml · yara import/export · ATT&CK".to_owned()),
    ];
    for (label, value) in rows {
        summary.push(vec![
            (Tone::Brand, format!("{label:<9} ")),
            (Tone::Text, value),
        ]);
    }

    let content = mask.len().max(summary.len());
    let mask_top = (content - mask.len()) / 2;
    let summary_top = (content - summary.len()) / 2;
    let mut lines = vec![
        Line::single(Tone::Text, String::new()),
        Line::new(vec![
            (Tone::Brand, "  ◇  B A N S H E E  ◇".to_owned()),
            (Tone::Muted, "   offline static triage".to_owned()),
        ]),
        Line::single(Tone::Border, format!("╭{}╮", "─".repeat(width - 2))),
    ];
    let first = lines.len();
    if !side_by_side {
        // Stacked: the mask centered on top, then the summary below it.
        let indent = " ".repeat(width.saturating_sub(mask_width) / 2);
        for mask_row in mask {
            lines.push(Line::single(Tone::Portrait, format!("{indent}{mask_row}")));
        }
        lines.push(Line::single(Tone::Text, String::new()));
        for parts in &summary {
            let mut segments = vec![(Tone::Text, "   ".to_owned())];
            segments.extend(parts.iter().cloned());
            lines.push(Line::new(segments));
        }
    }
    for row in 0..if side_by_side { content } else { 0 } {
        let mask_row = row
            .checked_sub(mask_top)
            .and_then(|index| mask.get(index))
            .copied()
            .unwrap_or("");
        let mut segments = vec![(Tone::Portrait, pad(&format!("   {mask_row}"), column))];
        if let Some(parts) = row
            .checked_sub(summary_top)
            .and_then(|index| summary.get(index))
        {
            segments.extend(parts.iter().cloned());
        }
        lines.push(Line::new(segments));
    }
    let last = lines.len() - 1;
    let bottom_rail = lines.len();
    lines.push(Line::single(
        Tone::Border,
        format!("╰{}╯", "─".repeat(width - 2)),
    ));
    let progress = lines.len();
    lines.push(Line::new(vec![
        (Tone::Brand, "  ◆ ready".to_owned()),
        (
            Tone::Muted,
            "  ·  findings are triage signals, not verdicts".to_owned(),
        ),
    ]));
    lines.push(Line::single(Tone::Text, String::new()));
    for (command, purpose) in [
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
    ] {
        // Narrow screens keep the commands and drop their descriptions.
        let mut segments = vec![(Tone::Brand, format!("  {command:<47} "))];
        if side_by_side {
            segments.push((Tone::Muted, purpose.to_owned()));
        }
        lines.push(Line::new(segments));
    }
    lines.push(Line::single(Tone::Text, String::new()));
    for line in &mut lines {
        fit(line, width);
    }
    Screen {
        lines,
        width,
        first,
        last,
        top_rail: 2,
        bottom_rail,
        progress,
    }
}

/// Pads or truncates a line to exactly `width` characters.
fn fit(line: &mut Line, width: usize) {
    let mut remaining = width;
    for (_, text) in &mut line.segments {
        let length = text.chars().count();
        if length > remaining {
            *text = text.chars().take(remaining).collect();
        }
        remaining -= text.chars().count();
    }
    if remaining > 0 {
        line.segments.push((Tone::Text, " ".repeat(remaining)));
    }
}

fn boot_hash(a: i64, b: i64, c: i64) -> u32 {
    (a as u32).wrapping_add(1).wrapping_mul(2_654_435_761)
        ^ (b as u32).wrapping_add(7).wrapping_mul(40_503)
        ^ (c as u32).wrapping_add(13).wrapping_mul(97)
}

/// Applies the boot effect for `progress` in [0, 1); 1 returns the screen.
pub(crate) fn boot_frame(screen: &Screen, progress: f64) -> Vec<Line> {
    let mut lines = screen.lines.clone();
    let p = progress.clamp(0.0, 1.0);
    if p >= 1.0 {
        return lines;
    }
    let width = screen.width as i64;
    let (first, last) = (screen.first as i64, screen.last as i64);
    let span = (last - first).max(1);
    let travel = (p / 0.8).min(1.0);
    let eased = if travel < 0.5 {
        2.0 * travel * travel
    } else {
        1.0 - (-2.0 * travel + 2.0).powi(2) / 2.0
    };
    let beam = first + (eased * (span + DECODE_ROWS + 1) as f64) as i64;
    let step = (p * 60.0) as i64;
    let wave = (p >= 0.8).then(|| first + ((p - 0.8) / 0.2 * (span + 2) as f64) as i64);

    for row in first..=last {
        let behind = beam - row;
        let index = row as usize;
        if behind < 0 {
            // Sparse star dust ahead of the beam.
            let dust = (0..width)
                .map(|column| {
                    if column < 3 || column >= width - 3 {
                        return ' ';
                    }
                    match boot_hash(column, row, (p * 14.0) as i64) % 173 {
                        0 => '◇',
                        1..=3 => '·',
                        _ => ' ',
                    }
                })
                .collect();
            lines[index] = Line::single(Tone::Trail, dust);
            continue;
        }
        if behind == 0 {
            let head = ((p * 3.2) % 1.0 * (width - 6) as f64) as i64;
            let beam_line = (0..width - 4)
                .map(|column| match (column - head).abs() {
                    0 => '◆',
                    1..=4 => '━',
                    _ if column % 2 == 1 => '─',
                    _ => '╌',
                })
                .collect::<String>();
            lines[index] = Line::single(Tone::Head, format!("  {beam_line}  "));
            continue;
        }
        let reveal = (behind as f64 / DECODE_ROWS as f64).min(1.0);
        let mut column = 0_i64;
        let mut has_portrait = false;
        for (_, text) in &mut lines[index].segments {
            *text = text
                .chars()
                .map(|character| {
                    let at = column;
                    column += 1;
                    let code = u32::from(character);
                    if (0x2800..=0x28FF).contains(&code) {
                        // Reveal the mask's own Braille dots, never another shape.
                        has_portrait = true;
                        if reveal >= 1.0 {
                            return character;
                        }
                        let dots = (0..8)
                            .filter(|bit| {
                                (code - 0x2800) & (1 << bit) != 0
                                    && f64::from(boot_hash(at, row, i64::from(*bit)) % 100) / 100.0
                                        < reveal
                            })
                            .fold(0, |dots, bit| dots | (1 << bit));
                        return if dots == 0 {
                            ' '
                        } else {
                            char::from_u32(0x2800 + dots).unwrap_or(' ')
                        };
                    }
                    if reveal >= 1.0
                        || character == ' '
                        || (at as f64) < reveal * width as f64 * 0.9
                    {
                        return character;
                    }
                    if boot_hash(at, row, step) % 100 < 75 {
                        SCRAMBLE[boot_hash(at, row, step + 3) as usize % SCRAMBLE.len()]
                    } else {
                        character
                    }
                })
                .collect();
        }
        let tone = if behind <= 1 {
            Tone::Flash
        } else if behind < DECODE_ROWS {
            Tone::Glow
        } else {
            Tone::Portrait
        };
        if reveal < 1.0 || (has_portrait && behind < DECODE_ROWS * 2) {
            lines[index].overlay = (tone != Tone::Portrait).then_some(tone);
        }
        if let Some(wave) = wave
            && (row - wave).abs() <= 1
        {
            lines[index].overlay = Some(if row == wave { Tone::Flash } else { Tone::Glow });
        }
    }

    if p < 0.96 {
        let shimmer = (p / 0.96 * (width - 3) as f64) as i64;
        let rail = (0..width - 2)
            .map(|column| {
                let mirror = width - 3 - shimmer;
                if column == shimmer || column == mirror {
                    '◆'
                } else if (column - shimmer).abs() < 4 || (column - mirror).abs() < 4 {
                    '━'
                } else {
                    '─'
                }
            })
            .collect::<String>();
        lines[screen.top_rail] = Line::single(Tone::Head, format!("╭{rail}╮"));
        lines[screen.bottom_rail] = Line::single(Tone::Glow, format!("╰{rail}╯"));
    }

    let phase = if p < 0.32 {
        "initializing analyzers"
    } else if p < 0.78 {
        "loading rules and reference data"
    } else {
        "ready"
    };
    let size = 30;
    let units = (p * (size * 8) as f64) as usize;
    let full = units / 8;
    let mut bar = "█".repeat(full);
    if full < size {
        bar.push(BAR_PARTS[units % 8]);
        bar.push_str(&" ".repeat(size - full - 1));
    }
    let rotor = ROTOR[(p * 45.0) as usize % ROTOR.len()];
    lines[screen.progress] = Line::single(
        Tone::Glow,
        format!("  {rotor} ▕{bar}▏{:>3}%  {phase}", (p * 100.0) as u32),
    );
    for line in &mut lines {
        fit(line, screen.width);
    }
    lines
}

fn paint(lines: &[Line]) -> String {
    let mut output = String::new();
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            output.push_str("\r\n");
        }
        output.push_str("\x1b[2K");
        for (tone, text) in &line.segments {
            let (red, green, blue) = line.overlay.unwrap_or(*tone).color();
            output.push_str(&format!("\x1b[38;2;{red};{green};{blue}m{text}"));
        }
        output.push_str("\x1b[0m");
    }
    output
}

/// Plays the boot sequence in place and leaves the finished screen visible.
pub(crate) fn play(info: &SplashInfo, portrait_rows: usize, width: usize) -> std::io::Result<()> {
    let screen = compose(info, portrait_rows, width);
    let height = screen.lines.len();
    let mut stdout = std::io::stdout().lock();
    let started = std::time::Instant::now();
    let mut drawn = false;
    loop {
        let elapsed = started.elapsed().as_millis() as u64;
        let progress = elapsed as f64 / DURATION_MS as f64;
        let frame = boot_frame(&screen, progress);
        if drawn {
            // Return to the first row of the previous frame and redraw.
            write!(stdout, "\x1b[{}A\r", height - 1)?;
        }
        write!(stdout, "{}", paint(&frame))?;
        stdout.flush()?;
        drawn = true;
        if progress >= 1.0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(FRAME_MS));
    }
    writeln!(stdout)?;
    stdout.flush()
}

#[cfg(test)]
mod tests {
    use super::{MIN_WIDTH, Tone, WIDE, boot_frame, compose, layout_width, wordmark};
    use crate::splash::SplashInfo;

    fn info() -> SplashInfo {
        SplashInfo {
            version: "9.9.9",
            profile: "release",
            platform: "x86_64-linux".to_owned(),
            xz: true,
            signatures: true,
            tld_snapshot: Some("2026101200".to_owned()),
        }
    }

    #[test]
    fn finished_screen_has_mask_wordmark_and_fixed_width() {
        for (rows, width) in [
            (12, WIDE),
            (16, WIDE),
            (20, WIDE),
            (12, MIN_WIDTH),
            (20, 59),
        ] {
            let screen = compose(&info(), rows, width);
            assert!(
                screen
                    .lines
                    .iter()
                    .all(|line| line.text().chars().count() == screen.width)
            );
            let text = screen
                .lines
                .iter()
                .map(|line| line.text())
                .collect::<Vec<_>>();
            assert!(text.iter().any(|line| line.contains('⣿')), "mask is drawn");
            assert!(
                text.iter().any(|line| line.contains("|____/")),
                "wordmark is drawn"
            );
            assert!(text.iter().any(|line| line.contains("v9.9.9")));
            assert!(text.iter().any(|line| line.contains("banshee doctor")));
        }
        assert!(wordmark().iter().all(|row| row.chars().count() == 39));
    }

    #[test]
    fn layout_width_leaves_a_free_column_and_rejects_tiny_terminals() {
        assert_eq!(layout_width(200), Some(WIDE));
        assert_eq!(layout_width(91), Some(WIDE));
        assert_eq!(layout_width(60), Some(59));
        assert_eq!(layout_width(MIN_WIDTH + 1), Some(MIN_WIDTH));
        assert_eq!(layout_width(MIN_WIDTH), None);
        assert_eq!(layout_width(0), None);
        // The stacked layout puts the mask above the wordmark.
        let stacked = compose(&info(), 12, 59);
        let text = stacked
            .lines
            .iter()
            .map(|line| line.text())
            .collect::<Vec<_>>();
        let mask = text.iter().position(|line| line.contains('⣿')).unwrap();
        let wordmark = text
            .iter()
            .position(|line| line.contains("|____/"))
            .unwrap();
        assert!(mask < wordmark);
    }

    #[test]
    fn boot_frames_keep_geometry_and_settle_on_the_finished_screen() {
        let screen = compose(&info(), 20, WIDE);
        for step in 0..=40 {
            let frame = boot_frame(&screen, f64::from(step) / 40.0);
            assert_eq!(frame.len(), screen.lines.len());
            assert!(
                frame
                    .iter()
                    .all(|line| line.text().chars().count() == screen.width)
            );
        }
        assert_eq!(boot_frame(&screen, 1.0), screen.lines);

        // At the start the content area is dust and the beam, not the mask.
        let start = boot_frame(&screen, 0.0);
        let content = &start[screen.first + 1..=screen.last];
        assert!(content.iter().all(|line| line.segments[0].0 == Tone::Trail));
        assert!(start[screen.progress].text().contains("  0%"));

        // Midway, rows behind the beam are revealed while later rows are not.
        let middle = boot_frame(&screen, 0.5);
        let tones = middle[screen.first..=screen.last]
            .iter()
            .map(|line| line.segments[0].0)
            .collect::<Vec<_>>();
        assert_ne!(tones[0], Tone::Trail, "the top row is already decoded");
        assert!(tones.contains(&Tone::Head), "the beam is visible");
        assert_eq!(
            *tones.last().unwrap(),
            Tone::Trail,
            "the bottom row is still dust"
        );
        assert!(middle[screen.progress].text().contains("loading rules"));
    }

    #[test]
    fn boot_hash_matches_the_asphdex_formula() {
        // (imul(a+1, 2654435761) ^ imul(b+7, 40503) ^ imul(c+13, 97)) >>> 0
        assert_eq!(super::boot_hash(0, 0, 0), 2_654_435_761 ^ 283_521 ^ 1_261);
        assert_eq!(
            super::boot_hash(5, 9, 2),
            6_u32.wrapping_mul(2_654_435_761) ^ (16 * 40_503) ^ (15 * 97)
        );
    }
}

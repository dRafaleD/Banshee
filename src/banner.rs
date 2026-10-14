//! `banshee banner`: the figlet wordmark and the Braille mask also used by the
//! start screen. Colors follow `--color`/`NO_COLOR` and are off when output is
//! redirected, so files and pipes receive plain text.

use anyhow::Result;

use crate::splash_boot::{Tone, portrait, wordmark};

const TAGLINE: &str = "OFFLINE SECURITY ANALYSIS TOOLKIT";
/// Mask size of the full banner, in rows.
const MASK_ROWS: usize = 20;

pub fn print(compact: bool, mask_only: bool) -> Result<()> {
    let color = crate::output::color_enabled() && crate::terminal::enable_ansi();
    crate::output::write_raw(render(compact, mask_only, color).as_bytes())
}

fn paint(text: &str, tone: Tone, color: bool) -> String {
    if !color {
        return text.to_owned();
    }
    let (red, green, blue) = tone.color();
    format!("\x1b[38;2;{red};{green};{blue}m{text}\x1b[0m")
}

fn centered(text: &str, width: usize) -> String {
    let length = text.chars().count();
    format!("{}{text}", " ".repeat(width.saturating_sub(length) / 2))
}

pub fn render(compact: bool, mask_only: bool, color: bool) -> String {
    let mask = portrait(MASK_ROWS);
    let wordmark = wordmark();
    let tagline = format!("{TAGLINE}  v{}", env!("CARGO_PKG_VERSION"));
    let width = mask
        .iter()
        .map(|row| row.chars().count())
        .chain(wordmark.iter().map(|row| row.chars().count()))
        .chain(std::iter::once(tagline.chars().count()))
        .max()
        .unwrap_or(0);

    let mut output = String::new();
    if mask_only {
        for row in mask {
            output.push_str(&paint(row, Tone::Portrait, color));
            output.push('\n');
        }
        return output;
    }
    for row in &wordmark {
        output.push_str(&paint(&centered(row, width), Tone::Brand, color));
        output.push('\n');
    }
    if !compact {
        output.push('\n');
        for row in mask {
            output.push_str(&paint(&centered(row, width), Tone::Portrait, color));
            output.push('\n');
        }
    }
    output.push('\n');
    output.push_str(&paint(&centered(&tagline, width), Tone::Muted, color));
    output.push('\n');
    output
}

#[cfg(test)]
mod tests {
    use super::render;

    #[test]
    fn default_banner_contains_wordmark_mask_and_tagline() {
        let banner = render(false, false, false);
        assert!(banner.contains("|____/ \\__,_|"));
        assert!(banner.contains('⣿'));
        assert!(banner.contains("OFFLINE SECURITY"));
        assert!(!banner.contains('\x1b'));
    }

    #[test]
    fn compact_and_mask_only_are_distinct() {
        let compact = render(true, false, false);
        assert!(compact.contains("|____/") && !compact.contains('⣿'));
        let mask_only = render(false, true, false);
        assert!(mask_only.contains('⣿') && !mask_only.contains("|____/"));
        assert!(!mask_only.contains("OFFLINE"));
    }

    #[test]
    fn color_wraps_every_line_and_resets() {
        let banner = render(false, false, true);
        assert!(banner.contains("\x1b[38;2;68;210;0m") && banner.contains("\x1b[0m"));
        assert!(
            banner
                .lines()
                .filter(|line| !line.is_empty())
                .all(|line| line.ends_with("\x1b[0m"))
        );
    }
}

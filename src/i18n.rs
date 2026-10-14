//! Output language for human-readable text. English is the default; Turkish is
//! selected with `--lang tr`, the `BANSHEE_LANG=tr` environment variable or the
//! console's `tr` command. Machine-readable output (JSON, JSONL, CSV, Markdown,
//! HTML, STIX, MISP) and finding texts produced by the analyzers always stay
//! English so that other tools can rely on them.

use std::sync::atomic::{AtomicU8, Ordering};

const UNSET: u8 = 0;
const ENGLISH: u8 = 1;
const TURKISH: u8 = 2;
static LANGUAGE: AtomicU8 = AtomicU8::new(UNSET);

/// True when human-readable text is Turkish. The first call reads
/// `BANSHEE_LANG` (`tr` or `en`); `set_turkish` overrides it afterwards.
pub(crate) fn is_turkish() -> bool {
    if LANGUAGE.load(Ordering::Relaxed) == UNSET {
        let turkish = std::env::var("BANSHEE_LANG")
            .is_ok_and(|value| value.trim().eq_ignore_ascii_case("tr"));
        LANGUAGE.store(if turkish { TURKISH } else { ENGLISH }, Ordering::Relaxed);
    }
    LANGUAGE.load(Ordering::Relaxed) == TURKISH
}

pub(crate) fn set_turkish(turkish: bool) {
    LANGUAGE.store(if turkish { TURKISH } else { ENGLISH }, Ordering::Relaxed);
}

/// Picks the English or Turkish text for the current language.
pub(crate) fn t<'a>(english: &'a str, turkish: &'a str) -> &'a str {
    if is_turkish() { turkish } else { english }
}

/// Reads `--lang tr|en` (or `--lang=tr`) from raw arguments, so the language is
/// known before clap renders help. Later occurrences win; other values are
/// ignored here and rejected by the real parser.
pub(crate) fn language_from_arguments<I, S>(arguments: I) -> Option<bool>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut found = None;
    let mut previous_is_flag = false;
    for argument in arguments {
        let argument = argument.as_ref();
        let value = if previous_is_flag {
            Some(argument)
        } else {
            argument.strip_prefix("--lang=")
        };
        previous_is_flag = argument == "--lang";
        match value {
            Some(value) if value.eq_ignore_ascii_case("tr") => found = Some(true),
            Some(value) if value.eq_ignore_ascii_case("en") => found = Some(false),
            _ => {}
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::language_from_arguments as scan;

    #[test]
    fn finds_the_language_flag_in_both_spellings() {
        assert_eq!(scan(["banshee", "--lang", "tr", "--help"]), Some(true));
        assert_eq!(scan(["banshee", "--lang=en"]), Some(false));
        assert_eq!(scan(["banshee", "--lang=TR"]), Some(true));
    }

    #[test]
    fn later_values_win_and_unknown_values_are_ignored() {
        assert_eq!(scan(["b", "--lang", "tr", "--lang", "en"]), Some(false));
        assert_eq!(scan(["b", "--lang", "de"]), None);
        assert_eq!(scan(["b", "whatis", "tr"]), None);
    }
}

//! Lookalike checks for internationalized domain names. A domain whose
//! Unicode form mixes Latin with Cyrillic, Greek or Armenian letters, or
//! whose letters all have Latin twins (`раypal.com` with Cyrillic `р`, `а`),
//! is a common phishing trick. The check is offline and table-based; it does
//! not know which brands exist, so it reports how a name reads, not whom it
//! imitates.

/// Prefix of IOC details for domains that look like another domain.
pub const LOOKALIKE_PREFIX: &str = "possible homoglyph";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Armenian,
    Other,
}

impl Script {
    fn of(character: char) -> Option<Self> {
        match character {
            'a'..='z' | 'A'..='Z' => Some(Self::Latin),
            '0'..='9' | '-' | '.' => None,
            '\u{00C0}'..='\u{024F}' | '\u{1E00}'..='\u{1EFF}' | '\u{0250}'..='\u{02AF}' => {
                Some(Self::Latin)
            }
            '\u{0370}'..='\u{03FF}' | '\u{1F00}'..='\u{1FFF}' => Some(Self::Greek),
            '\u{0400}'..='\u{052F}' => Some(Self::Cyrillic),
            '\u{0530}'..='\u{058F}' => Some(Self::Armenian),
            _ => Some(Self::Other),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Latin => "Latin",
            Self::Cyrillic => "Cyrillic",
            Self::Greek => "Greek",
            Self::Armenian => "Armenian",
            Self::Other => "other",
        }
    }
}

/// The Latin letter a character is easily mistaken for, if any.
fn latin_twin(character: char) -> Option<char> {
    Some(match character {
        // Cyrillic
        'а' => 'a',
        'Ь' | 'ь' => 'b',
        'с' => 'c',
        'ԁ' => 'd',
        'е' | 'ё' => 'e',
        'һ' => 'h',
        'і' | 'ї' => 'i',
        'ј' => 'j',
        'к' => 'k',
        'ӏ' => 'l',
        'о' => 'o',
        'р' => 'p',
        'ԛ' => 'q',
        'ѕ' => 's',
        'у' => 'y',
        'ԝ' => 'w',
        'х' => 'x',
        // Greek
        'α' => 'a',
        'ε' => 'e',
        'ι' => 'i',
        'κ' => 'k',
        'ν' => 'v',
        'ο' => 'o',
        'ρ' => 'p',
        'τ' => 't',
        'υ' => 'u',
        'χ' => 'x',
        // Armenian
        'հ' => 'h',
        'ո' => 'n',
        'ս' => 'u',
        'օ' => 'o',
        // Latin letters that pass for plain ASCII
        'ı' => 'i',
        'ɑ' => 'a',
        'ɡ' => 'g',
        'ɩ' => 'i',
        'ɪ' => 'i',
        'ʏ' => 'y',
        _ => return None,
    })
}

/// The base letter of a common accented Latin letter. Accents are visible,
/// so they make a name international rather than a lookalike.
fn without_accent(character: char) -> Option<char> {
    Some(match character {
        'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' => 'a',
        'è' | 'é' | 'ê' | 'ë' => 'e',
        'ì' | 'í' | 'î' | 'ï' => 'i',
        'ò' | 'ó' | 'ô' | 'õ' | 'ö' => 'o',
        'ù' | 'ú' | 'û' | 'ü' => 'u',
        'ç' => 'c',
        'ğ' => 'g',
        'ñ' => 'n',
        'ş' => 's',
        'ý' | 'ÿ' => 'y',
        _ => return None,
    })
}

/// Describes an internationalized domain in its Unicode form, or returns
/// `None` for a plain ASCII domain. Details for lookalikes start with
/// [`LOOKALIKE_PREFIX`].
pub fn assess(unicode: &str) -> Option<String> {
    if unicode.is_ascii() {
        return None;
    }
    let mut mixed: Option<(Script, Script)> = None;
    for label in unicode.split('.') {
        let scripts: std::collections::BTreeSet<Script> =
            label.chars().filter_map(Script::of).collect();
        if scripts.len() > 1 && scripts.contains(&Script::Latin) {
            let other = scripts
                .iter()
                .copied()
                .find(|script| *script != Script::Latin)
                .unwrap_or(Script::Other);
            mixed.get_or_insert((Script::Latin, other));
        }
    }
    let skeleton: String = unicode
        .chars()
        .map(|character| latin_twin(character).unwrap_or(character))
        .collect();
    let reads_as_ascii = skeleton.is_ascii();

    let mixing = mixed
        .map(|(first, second)| format!("mixes {} and {} letters", first.name(), second.name()));
    match (reads_as_ascii, mixing) {
        (true, Some(mixing)) => Some(format!(
            "{LOOKALIKE_PREFIX}: {unicode} reads as {skeleton} and {mixing}"
        )),
        (true, None) => Some(format!("{LOOKALIKE_PREFIX}: {unicode} reads as {skeleton}")),
        (false, Some(mixing)) => Some(format!("{LOOKALIKE_PREFIX}: {unicode} {mixing}")),
        (false, None) => {
            let plain: String = skeleton
                .chars()
                .map(|character| without_accent(character).unwrap_or(character))
                .collect();
            Some(if plain.is_ascii() {
                format!("internationalized domain: {unicode} (without accents: {plain})")
            } else {
                format!("internationalized domain: {unicode}")
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LOOKALIKE_PREFIX, assess};

    #[test]
    fn flags_cyrillic_and_greek_lookalikes() {
        // Cyrillic р and а.
        let detail = assess("\u{0440}\u{0430}ypal.com").unwrap();
        assert!(detail.starts_with(LOOKALIKE_PREFIX), "{detail}");
        assert!(detail.contains("reads as paypal.com"), "{detail}");
        assert!(detail.contains("mixes Latin and Cyrillic"), "{detail}");

        // All-Cyrillic label that reads as Latin: аррӏе.com.
        let detail = assess("\u{0430}\u{0440}\u{0440}\u{04CF}\u{0435}.com").unwrap();
        assert!(detail.contains("reads as apple.com"), "{detail}");
        assert!(!detail.contains("mixes"), "{detail}");

        // Greek ο in a Latin label.
        let detail = assess("g\u{03BF}\u{03BF}gle.com").unwrap();
        assert!(detail.contains("mixes Latin and Greek"), "{detail}");
    }

    #[test]
    fn ordinary_international_names_are_not_lookalikes() {
        assert_eq!(assess("example.com"), None);
        let detail = assess("пример.рф").unwrap();
        assert_eq!(detail, "internationalized domain: пример.рф");
        let detail = assess("münchen.de").unwrap();
        assert_eq!(
            detail,
            "internationalized domain: münchen.de (without accents: munchen.de)"
        );
        assert!(assess("例え.jp").unwrap().starts_with("internationalized"));
    }
}

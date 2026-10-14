//! Categorized help for the interactive console, in English or Turkish.
//! English command descriptions come from the clap definitions, so the menu
//! cannot drift from the real commands; tests fail when a command is missing
//! from a category or has no Turkish description.

use clap::CommandFactory;

use crate::cli::Cli;

const RULE_WIDTH: usize = 60;
const NAME_WIDTH: usize = 20;

pub(crate) use crate::i18n::{is_turkish, set_turkish, t};

struct Category {
    key: &'static str,
    key_tr: &'static str,
    title: &'static str,
    title_tr: &'static str,
    commands: &'static [&'static str],
    examples: &'static [&'static str],
}

const CATEGORIES: &[Category] = &[
    Category {
        key: "analysis",
        key_tr: "analiz",
        title: "ANALYSIS",
        title_tr: "ANALİZ",
        commands: &["whatis", "entropy", "analyze", "extract", "watch"],
        examples: &[
            "whatis aGVsbG8lMjB3b3JsZA==",
            "entropy aGVsbG8gd29ybGQ=",
            "extract --url --domain --defang --file access.log",
            "analyze --file suspicious.bin",
        ],
    },
    Category {
        key: "files",
        key_tr: "dosyalar",
        title: "FILES & REPORTS",
        title_tr: "DOSYALAR VE RAPORLAR",
        commands: &["file", "report", "scan", "rules"],
        examples: &[
            "file inspect suspicious.zip",
            "report suspicious.exe",
            "report suspicious.zip --format json --output report.json",
        ],
    },
    Category {
        key: "encoding",
        key_tr: "kodlama",
        title: "ENCODING & TOKENS",
        title_tr: "KODLAMA VE TOKENLAR",
        commands: &[
            "encode",
            "decode",
            "recipe",
            "hash",
            "jwt",
            "cert",
            "timestamp",
            "regex",
        ],
        examples: &[
            "decode base64 aGVsbG8=",
            "recipe 'base64|url' 'aGVsbG8lMjB3b3JsZA=='",
            "hash identify d41d8cd98f00b204e9800998ecf8427e",
            "jwt inspect eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature",
            "timestamp to-human 1704067200000",
        ],
    },
    Category {
        key: "case",
        key_tr: "vaka",
        title: "CASE WORK",
        title_tr: "VAKA ÇALIŞMASI",
        commands: &["evidence", "diff", "export"],
        examples: &["evidence verify case-evidence"],
    },
    Category {
        key: "system",
        key_tr: "sistem",
        title: "SYSTEM",
        title_tr: "SİSTEM",
        commands: &["doctor", "banner", "completions", "manpage"],
        examples: &["doctor", "banner --compact"],
    },
];

/// Console built-ins, listed as their own category:
/// (name, Turkish name, description, Turkish description).
const CONSOLE: &[(&str, &str, &str, &str)] = &[
    (
        "help [topic]",
        "help [konu]",
        "Show this menu, a category or one command",
        "Bu menüyü, bir kategoriyi veya tek bir komutu göster",
    ),
    (
        "pwd",
        "pwd",
        "Show the working directory",
        "Çalışma dizinini göster",
    ),
    (
        "cd <directory>",
        "cd <dizin>",
        "Change the working directory",
        "Çalışma dizinini değiştir",
    ),
    (
        "open <file>",
        "open <dosya>",
        "Open a file; then use @ for it, or type report, file, entropy... alone",
        "Dosya aç; sonra @ ile kullan ya da report, file, entropy... tek başına yaz",
    ),
    (
        "close",
        "close",
        "Close the open file",
        "Açık dosyayı kapat",
    ),
    (
        "status",
        "status",
        "Show directory, open file and language",
        "Dizin, açık dosya ve dili göster",
    ),
    (
        "ls [directory]",
        "ls [dizin]",
        "List up to 200 entries",
        "En fazla 200 öğeyi listele",
    ),
    ("clear", "clear", "Clear the screen", "Ekranı temizle"),
    (
        "lang tr|en",
        "lang tr|en",
        "Switch the console language (tr or en alone also work)",
        "Konsol dilini değiştir (tek başına tr veya en de olur)",
    ),
    (
        "exit",
        "exit",
        "Leave the console (also quit, q)",
        "Konsoldan çık (quit ve q da olur)",
    ),
];

/// Subcommands that are intentionally not listed in a category.
#[cfg(test)]
const UNLISTED: &[&str] = &["shell", "help"];

fn describe(name: &str, turkish: bool) -> String {
    if turkish {
        let text = describe_turkish(name);
        if !text.is_empty() {
            return text.to_owned();
        }
    }
    Cli::command()
        .find_subcommand(name)
        .and_then(|command| command.get_about())
        .map(ToString::to_string)
        .unwrap_or_default()
}

fn describe_turkish(name: &str) -> &'static str {
    match name {
        "whatis" => "Bilinmeyen bir değeri algıla ve katman katman çöz",
        "entropy" => "Entropiyi ölç ve bilinmeyen değeri sınıflandır",
        "analyze" => "Toplu girdideki token ve IOC'leri otomatik analiz et",
        "extract" => "Metin, dosya veya stdin'den IOC çıkar ve normalleştir",
        "watch" => "Eklenen log satırlarını izle ve yerelde analiz et",
        "file" => "Arşivleri, sıkıştırılmış akışları ve yürütülebilir başlıkları çevrimdışı incele",
        "report" => "Tek bir yerel dosya için birleşik çevrimdışı analiz raporu oluştur",
        "scan" => "Yerel dosya veya dizini sınırlı çevrimdışı analizle tara",
        "rules" => "Yerel TOML tespit kurallarını doğrula ve kurallarla tara",
        "encode" => "Metni seçilen biçimde kodla",
        "decode" => "Veriyi seçilen biçimden çöz",
        "recipe" => "Boru (|) ile ayrılmış dönüşüm tarifini yerelde uygula",
        "hash" => "Özetleri (hash) çevrimdışı hesapla, tanı veya eşleştir",
        "jwt" => "JSON Web Token'ları hiçbir yere göndermeden incele",
        "cert" => "Yerel PEM veya DER X.509 sertifikalarını incele",
        "timestamp" => "Unix zaman damgaları ile okunur UTC zamanı arasında dönüştür",
        "regex" => "Düzenli ifadeleri test et veya yaygın güvenlik kalıplarını listele",
        "evidence" => "Deterministik çevrimdışı kanıt paketi oluştur veya doğrula",
        "diff" => "İki rapor JSON'unu veya doğrulanmış kanıt paketini karşılaştır",
        "export" => "Kayıtlı rapor gözlemlerini STIX 2.1, MISP veya CSV olarak dışa aktar",
        "doctor" => "Yerel kurulumu çevrimdışı kontrol et (kodekler, veri, PATH, geçici dizin)",
        "banner" => "Banshee ASCII afişini ve maske amblemini yazdır",
        "completions" => "Kabuk tamamlama tanımları üret",
        "manpage" => "stdout'a roff kılavuz sayfası üret",
        _ => "",
    }
}

fn heading(title: &str, color: bool) -> String {
    let title = if color {
        format!("\x1b[1;38;5;46m{title}\x1b[0m")
    } else {
        title.to_owned()
    };
    format!("{title}\n{}", dim(&"─".repeat(RULE_WIDTH), color))
}

/// Muted green used for rules and footnotes.
fn dim(text: &str, color: bool) -> String {
    if color {
        format!("\x1b[38;5;65m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

fn entry(name: &str, about: &str, color: bool) -> String {
    let padded = format!("{name:<NAME_WIDTH$}");
    let name = if color {
        format!("\x1b[38;5;120m{padded}\x1b[0m")
    } else {
        padded
    };
    format!("  {name} {about}")
}

fn category_lines(category: &Category, color: bool, turkish: bool) -> Vec<String> {
    let title = if turkish {
        category.title_tr
    } else {
        category.title
    };
    let mut lines = vec![heading(title, color)];
    for name in category.commands {
        lines.push(entry(name, &describe(name, turkish), color));
    }
    lines
}

fn console_lines(color: bool, turkish: bool) -> Vec<String> {
    let mut lines = vec![heading(if turkish { "KONSOL" } else { "CONSOLE" }, color)];
    for (name, name_tr, about, about_tr) in CONSOLE {
        if turkish {
            lines.push(entry(name_tr, about_tr, color));
        } else {
            lines.push(entry(name, about, color));
        }
    }
    lines
}

fn examples(items: &[&str], color: bool, turkish: bool) -> Vec<String> {
    let mut lines = vec![heading(
        if turkish { "ÖRNEKLER" } else { "EXAMPLES" },
        color,
    )];
    lines.extend(items.iter().map(|item| format!("  {item}")));
    lines
}

/// The categorized command list for `banshee --help`.
pub(crate) fn command_menu(color: bool, turkish: bool) -> String {
    CATEGORIES
        .iter()
        .map(|category| category_lines(category, color, turkish).join("\n"))
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// Help topic names in both languages, for completion.
#[cfg(feature = "line-editor")]
pub(crate) fn topic_keys() -> impl Iterator<Item = &'static str> {
    CATEGORIES
        .iter()
        .flat_map(|category| [category.key, category.key_tr])
        .chain(["console", "konsol"])
}

fn topics(turkish: bool) -> String {
    CATEGORIES
        .iter()
        .map(|category| {
            if turkish {
                category.key_tr
            } else {
                category.key
            }
        })
        .chain(std::iter::once(if turkish { "konsol" } else { "console" }))
        .collect::<Vec<_>>()
        .join(" · ")
}

/// Renders the full menu, or one category, in the current console language.
/// `Err` carries a one-line message for an unknown topic; the caller may then
/// try the word as a command name.
pub(crate) fn render(topic: Option<&str>, color: bool) -> Result<String, String> {
    render_in(topic, color, is_turkish())
}

fn render_in(topic: Option<&str>, color: bool, turkish: bool) -> Result<String, String> {
    let mut sections: Vec<Vec<String>> = Vec::new();
    match topic.map(str::to_ascii_lowercase).as_deref() {
        None => {
            for category in CATEGORIES {
                sections.push(category_lines(category, color, turkish));
            }
            sections.push(console_lines(color, turkish));
            sections.push(examples(
                &[
                    "whatis aGVsbG8=",
                    "extract --file application.log --defang",
                    "report sample.bin --format json",
                ],
                color,
                turkish,
            ));
            let footer = if turkish {
                [
                    format!("Konular: {}", topics(true)),
                    "help <konu> bir kategoriyi, help <komut> komutun seçeneklerini gösterir."
                        .to_owned(),
                    "Komutlar 'banshee' öneki olmadan, komut satırındakiyle aynı çalışır; \
                     komut çıktıları ve seçenek açıklamaları İngilizce kalır."
                        .to_owned(),
                ]
            } else {
                [
                    format!("Topics: {}", topics(false)),
                    "help <topic> lists one category; help <command> shows a command's options."
                        .to_owned(),
                    "Commands work exactly as on the command line, without the 'banshee' prefix."
                        .to_owned(),
                ]
            };
            sections.push(footer.iter().map(|line| dim(line, color)).collect());
        }
        Some("console" | "konsol") => {
            sections.push(console_lines(color, turkish));
            sections.push(examples(
                &["cd samples", "ls", "report sample.bin"],
                color,
                turkish,
            ));
        }
        Some(key) => {
            let Some(category) = CATEGORIES
                .iter()
                .find(|category| category.key == key || category.key_tr == key)
            else {
                return Err(if turkish {
                    format!(
                        "bilinmeyen yardım konusu '{key}'; konular: {}",
                        topics(true)
                    )
                } else {
                    format!("unknown help topic '{key}'; topics: {}", topics(false))
                });
            };
            sections.push(category_lines(category, color, turkish));
            sections.push(examples(category.examples, color, turkish));
        }
    }
    Ok(sections
        .into_iter()
        .map(|lines| lines.join("\n"))
        .collect::<Vec<_>>()
        .join("\n\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_is_in_exactly_one_category() {
        let command = Cli::command();
        for sub in command.get_subcommands() {
            let name = sub.get_name();
            if UNLISTED.contains(&name) {
                continue;
            }
            let count = CATEGORIES
                .iter()
                .filter(|category| category.commands.contains(&name))
                .count();
            assert_eq!(count, 1, "command '{name}' must be in exactly one category");
        }
    }

    #[test]
    fn categories_list_only_real_commands_with_both_descriptions() {
        for category in CATEGORIES {
            for name in category.commands {
                assert!(
                    !describe(name, false).is_empty(),
                    "'{name}' has no description"
                );
                assert!(
                    !describe_turkish(name).is_empty(),
                    "'{name}' has no Turkish description"
                );
            }
        }
    }

    #[test]
    fn command_menu_lists_every_category() {
        let menu = command_menu(false, false);
        for category in CATEGORIES {
            assert!(menu.contains(category.title));
        }
        assert!(!menu.contains("CONSOLE") && !menu.contains('\x1b'));
        let turkish = command_menu(false, true);
        assert!(turkish.contains("ANALİZ") && turkish.contains("SİSTEM"));
    }

    #[test]
    fn overview_and_topics_render_without_color_codes() {
        let overview = render_in(None, false, false).unwrap();
        assert!(overview.contains("ANALYSIS") && overview.contains("CONSOLE"));
        assert!(!overview.contains('\x1b'));
        assert!(
            render_in(Some("FILES"), false, false)
                .unwrap()
                .contains("report")
        );
        assert!(
            render_in(Some("console"), false, false)
                .unwrap()
                .contains("cd <directory>")
        );
        assert!(render_in(Some("nonsense"), false, false).is_err());
        let colored = render_in(None, true, false).unwrap();
        assert!(colored.contains("\x1b[1;38;5;46mANALYSIS") && colored.contains("\x1b[38;5;65m"));
    }

    #[test]
    fn turkish_menu_uses_turkish_titles_descriptions_and_topic_names() {
        let overview = render_in(None, false, true).unwrap();
        assert!(overview.contains("ANALİZ") && overview.contains("KONSOL"));
        assert!(overview.contains("ÖRNEKLER") && overview.contains("Konular:"));
        assert!(overview.contains("Bilinmeyen bir değeri algıla"));
        assert!(!overview.contains("ANALYSIS"));
        // Both spellings open the same category.
        let by_turkish_key = render_in(Some("dosyalar"), false, true).unwrap();
        assert!(by_turkish_key.contains("DOSYALAR VE RAPORLAR"));
        assert!(render_in(Some("files"), false, true).is_ok());
        assert!(
            render_in(Some("zzz"), false, true)
                .unwrap_err()
                .contains("bilinmeyen")
        );
    }
}

//! Categorized help for the interactive console. Command descriptions come
//! from the clap definitions, so this menu cannot drift from the real commands;
//! a test fails when a command is not placed in a category.

use clap::CommandFactory;

use crate::cli::Cli;

const RULE_WIDTH: usize = 60;
const NAME_WIDTH: usize = 20;

struct Category {
    key: &'static str,
    title: &'static str,
    commands: &'static [&'static str],
    examples: &'static [&'static str],
}

const CATEGORIES: &[Category] = &[
    Category {
        key: "analysis",
        title: "ANALYSIS",
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
        title: "FILES & REPORTS",
        commands: &["file", "report", "scan", "rules"],
        examples: &[
            "file inspect suspicious.zip",
            "report suspicious.exe",
            "report suspicious.zip --format json --output report.json",
        ],
    },
    Category {
        key: "encoding",
        title: "ENCODING & TOKENS",
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
        title: "CASE WORK",
        commands: &["evidence", "diff", "export"],
        examples: &["evidence verify case-evidence"],
    },
    Category {
        key: "system",
        title: "SYSTEM",
        commands: &["doctor", "banner", "completions", "manpage"],
        examples: &["doctor", "banner --compact"],
    },
];

/// Console built-ins, listed as their own category.
const CONSOLE: &[(&str, &str)] = &[
    ("help [topic]", "Show this menu, a category or one command"),
    ("pwd", "Show the working directory"),
    ("cd <directory>", "Change the working directory"),
    ("ls [directory]", "List up to 200 entries"),
    ("clear", "Clear the screen"),
    ("exit", "Leave the console (also quit, q)"),
];

/// Subcommands that are intentionally not listed in a category.
#[cfg(test)]
const UNLISTED: &[&str] = &["shell", "help"];

fn describe(name: &str) -> String {
    Cli::command()
        .find_subcommand(name)
        .and_then(|command| command.get_about())
        .map(ToString::to_string)
        .unwrap_or_default()
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

fn category_lines(category: &Category, color: bool) -> Vec<String> {
    let mut lines = vec![heading(category.title, color)];
    for name in category.commands {
        lines.push(entry(name, &describe(name), color));
    }
    lines
}

fn console_lines(color: bool) -> Vec<String> {
    let mut lines = vec![heading("CONSOLE", color)];
    for (name, about) in CONSOLE {
        lines.push(entry(name, about, color));
    }
    lines
}

fn examples(items: &[&str], color: bool) -> Vec<String> {
    let mut lines = vec![heading("EXAMPLES", color)];
    lines.extend(items.iter().map(|item| format!("  {item}")));
    lines
}

/// The categorized command list for `banshee --help`.
pub(crate) fn command_menu(color: bool) -> String {
    CATEGORIES
        .iter()
        .map(|category| {
            category_lines(category, color).join(
                "
",
            )
        })
        .collect::<Vec<_>>()
        .join(
            "

",
        )
}

/// Help topic names: the categories plus the console built-ins.
pub(crate) fn topic_keys() -> impl Iterator<Item = &'static str> {
    CATEGORIES
        .iter()
        .map(|category| category.key)
        .chain(std::iter::once("console"))
}

fn topics() -> String {
    topic_keys().collect::<Vec<_>>().join(" · ")
}

/// Renders the full menu, or one category. `Err` carries a one-line message for
/// an unknown topic; the caller may then try the word as a command name.
pub(crate) fn render(topic: Option<&str>, color: bool) -> Result<String, String> {
    let mut sections: Vec<Vec<String>> = Vec::new();
    match topic.map(str::to_ascii_lowercase).as_deref() {
        None => {
            for category in CATEGORIES {
                sections.push(category_lines(category, color));
            }
            sections.push(console_lines(color));
            sections.push(examples(
                &[
                    "whatis aGVsbG8=",
                    "extract --file application.log --defang",
                    "report sample.bin --format json",
                ],
                color,
            ));
            sections.push(
                [
                    format!("Topics: {}", topics()),
                    "help <topic> lists one category; help <command> shows a command's options."
                        .to_owned(),
                    "Commands work exactly as on the command line, without the 'banshee' prefix."
                        .to_owned(),
                ]
                .iter()
                .map(|line| dim(line, color))
                .collect(),
            );
        }
        Some("console") => {
            sections.push(console_lines(color));
            sections.push(examples(&["cd samples", "ls", "report sample.bin"], color));
        }
        Some(key) => {
            let Some(category) = CATEGORIES.iter().find(|category| category.key == key) else {
                return Err(format!("unknown help topic '{key}'; topics: {}", topics()));
            };
            sections.push(category_lines(category, color));
            sections.push(examples(category.examples, color));
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
    fn categories_list_only_real_commands_with_descriptions() {
        for category in CATEGORIES {
            for name in category.commands {
                assert!(!describe(name).is_empty(), "'{name}' has no description");
            }
        }
    }

    #[test]
    fn command_menu_lists_every_category() {
        let menu = command_menu(false);
        for category in CATEGORIES {
            assert!(menu.contains(category.title));
        }
        assert!(!menu.contains("CONSOLE") && !menu.contains(''));
    }

    #[test]
    fn overview_and_topics_render_without_color_codes() {
        let overview = render(None, false).unwrap();
        assert!(overview.contains("ANALYSIS") && overview.contains("CONSOLE"));
        assert!(!overview.contains('\x1b'));
        assert!(render(Some("FILES"), false).unwrap().contains("report"));
        assert!(
            render(Some("console"), false)
                .unwrap()
                .contains("cd <directory>")
        );
        assert!(render(Some("nonsense"), false).is_err());
        let colored = render(None, true).unwrap();
        assert!(colored.contains("[1;38;5;46mANALYSIS") && colored.contains("[38;5;65m"));
    }
}

//! Interactive console: `banshee` on a terminal opens a `banshee>` prompt where
//! every line is an ordinary command without the `banshee` prefix, so users do
//! not retype it for each analysis. Lines go through the same clap parser and
//! dispatcher as the command line, so the two never drift apart.

use std::io::{self, BufRead as _, IsTerminal as _, Write as _};

use anyhow::Result;
use clap::CommandFactory;

use crate::cli::{Cli, Command};
use crate::shell_help::t;

/// Source of console lines: the line editor (history, Tab completion) on a
/// terminal, plain buffered reads for pipes and builds without the editor.
enum Reader {
    Plain {
        color: bool,
    },
    #[cfg(feature = "line-editor")]
    Editor(
        Box<
            rustyline::Editor<
                crate::shell_complete::ConsoleHelper,
                rustyline::history::DefaultHistory,
            >,
        >,
    ),
}

impl Reader {
    fn new(color: bool) -> Self {
        #[cfg(feature = "line-editor")]
        if io::stdin().is_terminal() && io::stdout().is_terminal() {
            let config = rustyline::Config::builder()
                .completion_type(rustyline::CompletionType::List)
                .auto_add_history(true)
                .history_ignore_dups(true)
                .unwrap_or_default()
                .max_history_size(500)
                .unwrap_or_default()
                .build();
            // History stays in memory only: analyzed values are never written to disk.
            if let Ok(mut editor) = rustyline::Editor::with_config(config) {
                editor.set_helper(Some(crate::shell_complete::ConsoleHelper::new(color)));
                return Self::Editor(Box::new(editor));
            }
        }
        Self::Plain { color }
    }

    /// Reads one line; `None` means end of input.
    fn read(&mut self, prompt: &str) -> Result<Option<String>> {
        match self {
            Self::Plain { color } => {
                if *color {
                    print!("\x1b[38;5;46m{}\x1b[0m> ", prompt.trim_end_matches("> "));
                } else {
                    print!("{prompt}");
                }
                io::stdout().flush()?;
                let mut line = String::new();
                if io::stdin().lock().read_line(&mut line)? == 0 {
                    println!();
                    return Ok(None);
                }
                Ok(Some(line))
            }
            #[cfg(feature = "line-editor")]
            Self::Editor(editor) => match editor.readline(prompt) {
                Ok(line) => Ok(Some(line)),
                // Ctrl+C abandons the current line, like a shell.
                Err(rustyline::error::ReadlineError::Interrupted) => Ok(Some(String::new())),
                Err(rustyline::error::ReadlineError::Eof) => Ok(None),
                Err(error) => Err(error.into()),
            },
        }
    }
}

/// Runs the console until `exit`, `quit` or end of input.
pub fn run() -> Result<()> {
    let color = io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && crate::terminal::enable_ansi();
    println!("{}", welcome());
    let mut reader = Reader::new(color);
    while let Some(line) = reader.read("banshee> ")? {
        let tokens = match tokenize(&line) {
            Ok(tokens) => tokens,
            Err(message) => {
                eprintln!("{} {message}", t("error:", "hata:"));
                continue;
            }
        };
        if !execute(&tokens, color) {
            break;
        }
    }
    Ok(())
}

/// Handles one console line. Returns false when the console should close.
fn execute(tokens: &[String], color: bool) -> bool {
    let Some(first) = tokens.first() else {
        return true;
    };
    // A leading slash is optional, as in the AsphDex terminal: `/help` == `help`.
    let name = first.strip_prefix('/').unwrap_or(first);
    let rest = &tokens[1..];
    match name {
        "exit" | "quit" | "q" | "çıkış" | "cikis" => return false,
        "tr" | "en" => switch_language(name == "tr"),
        "lang" => match rest.first().map(String::as_str) {
            Some("tr") => switch_language(true),
            Some("en") => switch_language(false),
            _ => eprintln!(
                "{}",
                t("error: usage: lang tr|en", "hata: kullanım: lang tr|en")
            ),
        },
        "clear" | "cls" => {
            // ANSI clear is skipped on terminals that did not accept ANSI.
            if color {
                print!("\x1b[2J\x1b[H");
                let _ = io::stdout().flush();
            }
        }
        "help" | "?" | "h" | "yardım" | "yardim" => {
            help(rest.first().map(String::as_str), color);
        }
        "pwd" => match std::env::current_dir() {
            Ok(path) => println!("{}", path.display()),
            Err(error) => eprintln!("{} {error}", t("error:", "hata:")),
        },
        "cd" => change_directory(rest),
        "ls" | "dir" => list_directory(rest),
        "shell" => eprintln!("{}", already_inside()),
        _ => {
            let mut arguments = tokens.to_vec();
            arguments[0] = name.to_owned();
            dispatch(&arguments);
        }
    }
    true
}

fn help(topic: Option<&str>, color: bool) {
    match crate::shell_help::render(topic, color) {
        Ok(text) => println!("{text}"),
        // Not a category: show that command's own options.
        Err(message) => match topic {
            Some(command) if Cli::command().find_subcommand(command).is_some() => {
                dispatch(&[command.to_owned(), "--help".to_owned()]);
            }
            _ => eprintln!("{} {message}", t("error:", "hata:")),
        },
    }
}

fn welcome() -> &'static str {
    t(
        "Type a command without the 'banshee' prefix, e.g. whatis aGVsbG8=. 'help' lists commands by category, Tab completes, 'tr' switches to Turkish, 'exit' leaves.",
        "Komutları 'banshee' öneki olmadan yazın, örn. whatis aGVsbG8=. 'help' komutları kategorilere göre listeler, Tab tamamlar, 'en' İngilizceye geçer, 'exit' çıkar.",
    )
}

fn already_inside() -> &'static str {
    t(
        "error: already inside the console",
        "hata: konsolun zaten içindesiniz",
    )
}

fn switch_language(turkish: bool) {
    crate::shell_help::set_turkish(turkish);
    println!(
        "{}",
        if turkish {
            "Dil: Türkçe"
        } else {
            "Language: English"
        }
    );
    println!("{}", welcome());
}

fn change_directory(arguments: &[String]) {
    let error_label = t("error:", "hata:");
    match arguments {
        [] => match std::env::current_dir() {
            Ok(path) => println!("{}", path.display()),
            Err(error) => eprintln!("{error_label} {error}"),
        },
        [target] => {
            if let Err(error) = std::env::set_current_dir(target) {
                if crate::shell_help::is_turkish() {
                    eprintln!("hata: '{target}' dizinine geçilemedi: {error}");
                } else {
                    eprintln!("error: cannot change directory to '{target}': {error}");
                }
            }
        }
        _ => eprintln!(
            "{}",
            t(
                "error: usage: cd <directory> (quote paths with spaces)",
                "hata: kullanım: cd <dizin> (boşluklu yolları tırnak içine alın)",
            )
        ),
    }
}

fn list_directory(arguments: &[String]) {
    const LIMIT: usize = 200;
    let target = arguments.first().map_or(".", String::as_str);
    let entries = match std::fs::read_dir(target) {
        Ok(entries) => entries,
        Err(error) => {
            if crate::shell_help::is_turkish() {
                eprintln!("hata: '{target}' listelenemedi: {error}");
            } else {
                eprintln!("error: cannot list '{target}': {error}");
            }
            return;
        }
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|entry| {
            let mut name = entry.file_name().to_string_lossy().into_owned();
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                name.push('/');
            }
            crate::output::terminal_safe(&name)
        })
        .collect();
    names.sort_unstable();
    let total = names.len();
    for name in names.iter().take(LIMIT) {
        println!("{name}");
    }
    if total > LIMIT {
        let hidden = total - LIMIT;
        if crate::shell_help::is_turkish() {
            println!("... {hidden} öğe daha gösterilmedi");
        } else {
            println!("... {hidden} more not shown");
        }
    }
}

fn dispatch(tokens: &[String]) {
    let arguments = std::iter::once("banshee".to_owned()).chain(tokens.iter().cloned());
    let cli = match crate::cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(error) => {
            // Help and usage errors print themselves; the console keeps going.
            let _ = error.print();
            return;
        }
    };
    if matches!(cli.command, Command::Shell) {
        eprintln!("{}", already_inside());
        return;
    }
    if let Err(error) = crate::run_with(cli) {
        eprintln!("error: {error:#}");
    }
}

/// Splits a line into arguments. Single quotes are literal, double quotes allow
/// `\"`, and a backslash elsewhere stays literal so Windows paths work.
fn tokenize(line: &str) -> std::result::Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut chars = line.trim_end_matches(['\r', '\n']).chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '\'' => {
                started = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(other) => current.push(other),
                        None => return Err("unterminated single quote".to_owned()),
                    }
                }
            }
            '"' => {
                started = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') if chars.peek() == Some(&'"') => {
                            current.push('"');
                            chars.next();
                        }
                        Some(other) => current.push(other),
                        None => return Err("unterminated double quote".to_owned()),
                    }
                }
            }
            other if other.is_whitespace() => {
                if started {
                    tokens.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            other => {
                started = true;
                current.push(other);
            }
        }
    }
    if started {
        tokens.push(current);
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::tokenize;

    #[test]
    fn splits_on_whitespace_and_keeps_quotes_together() {
        assert_eq!(
            tokenize("extract --file \"my log.txt\" 'a b'\n").unwrap(),
            ["extract", "--file", "my log.txt", "a b"]
        );
    }

    #[test]
    fn keeps_windows_backslashes_and_empty_arguments() {
        assert_eq!(
            tokenize(r"file C:\temp\a.zip ''").unwrap(),
            ["file", r"C:\temp\a.zip", ""]
        );
    }

    #[test]
    fn rejects_unterminated_quotes() {
        assert!(tokenize("whatis \"abc").is_err());
        assert!(tokenize("whatis 'abc").is_err());
    }

    #[test]
    fn blank_lines_yield_no_tokens() {
        assert!(tokenize("   \r\n").unwrap().is_empty());
    }
}

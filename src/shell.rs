//! Interactive console: `banshee` on a terminal opens a `banshee>` prompt where
//! every line is an ordinary command without the `banshee` prefix, so users do
//! not retype it for each analysis. Lines go through the same clap parser and
//! dispatcher as the command line, so the two never drift apart.

use std::io::{self, BufRead as _, IsTerminal as _, Write as _};
use std::path::PathBuf;

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
    let mut session = Session::default();
    loop {
        let Some(line) = reader.read(&session.prompt())? else {
            break;
        };
        if !handle_line(&mut session, &line, color) {
            break;
        }
    }
    Ok(())
}

const MAX_HISTORY: usize = 1_000;
const MAX_SCRIPT_LINES: usize = 1_000;
const MAX_SCRIPT_BYTES: u64 = 1024 * 1024;
const MAX_SCRIPT_DEPTH: usize = 4;

/// Expands `!N`, records the line in the history and runs it. Returns false
/// when the console should close.
fn handle_line(session: &mut Session, line: &str, color: bool) -> bool {
    let mut line = line.trim().to_owned();
    if let Some(number) = line.strip_prefix('!') {
        let previous = number
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|number| number.checked_sub(1))
            .and_then(|index| session.history.get(index))
            .cloned();
        match previous {
            Some(previous) => {
                println!("{previous}");
                line = previous;
            }
            None => {
                eprintln!(
                    "{}",
                    t(
                        "error: no such history entry; see history",
                        "hata: geçmişte böyle bir kayıt yok; bkz. history",
                    )
                );
                return true;
            }
        }
    }
    let tokens = match tokenize(&line) {
        Ok(tokens) => tokens,
        Err(message) => {
            eprintln!("{} {message}", t("error:", "hata:"));
            return true;
        }
    };
    let Some(first) = tokens.first() else {
        return true;
    };
    let name = first.trim_start_matches('/');
    if !matches!(name, "history" | "save") && session.history.len() < MAX_HISTORY {
        session.history.push(line.clone());
    }
    execute(session, &tokens, color)
}

/// Runs the commands in a file as if typed, echoing each one. Blank lines and
/// `#` comments are skipped; `exit` stops the script, not the console.
fn run_script(session: &mut Session, arguments: &[String], color: bool) {
    let [path] = arguments else {
        eprintln!(
            "{}",
            t("error: usage: run <file>", "hata: kullanım: run <dosya>")
        );
        return;
    };
    if session.script_depth >= MAX_SCRIPT_DEPTH {
        eprintln!(
            "{}",
            t(
                "error: scripts are nested too deeply",
                "hata: betikler çok derin iç içe çağrılıyor",
            )
        );
        return;
    }
    let text = match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() && metadata.len() <= MAX_SCRIPT_BYTES => {
            std::fs::read_to_string(path)
        }
        Ok(_) => {
            eprintln!(
                "{}",
                t(
                    "error: run needs a text file of at most 1 MiB",
                    "hata: run en fazla 1 MiB'lik bir metin dosyası ister",
                )
            );
            return;
        }
        Err(error) => Err(error),
    };
    let text = match text {
        Ok(text) => text,
        Err(error) => {
            eprintln!("{} {error}", t("error:", "hata:"));
            return;
        }
    };
    session.script_depth += 1;
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .take(MAX_SCRIPT_LINES)
    {
        println!("{}{}", session.prompt(), crate::output::terminal_safe(line));
        if !handle_line(session, line, color) {
            break;
        }
    }
    session.script_depth -= 1;
}

/// State kept between console lines.
#[derive(Default)]
struct Session {
    /// File chosen with `open`, as an absolute path.
    selected: Option<PathBuf>,
    /// Commands typed this session, in memory only.
    history: Vec<String>,
    /// Nesting of `run` scripts, bounded to stop a script running itself.
    script_depth: usize,
}

impl Session {
    /// `banshee> `, or `banshee (name)> ` while a file is open.
    fn prompt(&self) -> String {
        match self
            .selected
            .as_ref()
            .and_then(|path| path.file_name())
            .map(|name| crate::output::terminal_safe(&name.to_string_lossy()))
        {
            Some(name) => format!("banshee ({name})> "),
            None => "banshee> ".to_owned(),
        }
    }

    fn open(&mut self, arguments: &[String]) {
        let label = t("error:", "hata:");
        let [target] = arguments else {
            match &self.selected {
                Some(path) if arguments.is_empty() => println!("{}", path.display()),
                _ => eprintln!(
                    "{}",
                    t(
                        "error: usage: open <file> (quote paths with spaces)",
                        "hata: kullanım: open <dosya> (boşluklu yolları tırnak içine alın)",
                    )
                ),
            }
            return;
        };
        let path = match std::path::absolute(target) {
            Ok(path) => path,
            Err(error) => {
                eprintln!("{label} {error}");
                return;
            }
        };
        match std::fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => {
                let shown = crate::output::terminal_safe(&path.display().to_string());
                if crate::shell_help::is_turkish() {
                    println!("Açık dosya: {shown} ({} bayt)", metadata.len());
                } else {
                    println!("Open file: {shown} ({} bytes)", metadata.len());
                }
                self.selected = Some(path);
            }
            Ok(_) => {
                if crate::shell_help::is_turkish() {
                    eprintln!("hata: '{target}' bir dosya değil");
                } else {
                    eprintln!("error: '{target}' is not a file");
                }
            }
            Err(error) => {
                if crate::shell_help::is_turkish() {
                    eprintln!("hata: '{target}' açılamadı: {error}");
                } else {
                    eprintln!("error: cannot open '{target}': {error}");
                }
            }
        }
    }

    fn show_history(&self) {
        if self.history.is_empty() {
            println!("{}", t("History is empty", "Geçmiş boş"));
        }
        for (index, line) in self.history.iter().enumerate() {
            println!("{:>4}  {}", index + 1, crate::output::terminal_safe(line));
        }
    }

    /// Writes the history to a new file, one command per line, so `run` can
    /// replay it. An existing file is kept unless `--force` follows the path.
    fn save(&self, arguments: &[String]) {
        let (path, force) = match arguments {
            [path] => (path, false),
            [path, flag] if flag == "--force" => (path, true),
            _ => {
                eprintln!(
                    "{}",
                    t(
                        "error: usage: save <file> [--force]",
                        "hata: kullanım: save <dosya> [--force]",
                    )
                );
                return;
            }
        };
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        if force {
            options.create(true).truncate(true);
        } else {
            options.create_new(true);
        }
        let mut text = self.history.join("\n");
        text.push('\n');
        match options
            .open(path)
            .and_then(|mut file| file.write_all(text.as_bytes()))
        {
            Ok(()) => {
                if crate::shell_help::is_turkish() {
                    println!("{} komut {path} dosyasına kaydedildi", self.history.len());
                } else {
                    println!("Saved {} command(s) to {path}", self.history.len());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => eprintln!(
                "{}",
                t(
                    "error: the file exists; add --force to replace it",
                    "hata: dosya zaten var; üzerine yazmak için --force ekleyin",
                )
            ),
            Err(error) => eprintln!("{} {error}", t("error:", "hata:")),
        }
    }

    fn close(&mut self) {
        let closed = self.selected.take().is_some();
        println!(
            "{}",
            match (closed, crate::shell_help::is_turkish()) {
                (true, false) => "File closed",
                (true, true) => "Dosya kapatıldı",
                (false, false) => "No file is open",
                (false, true) => "Açık dosya yok",
            }
        );
    }

    fn status(&self) {
        let none = t("none", "yok");
        let directory = std::env::current_dir()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "?".to_owned());
        let file = self
            .selected
            .as_ref()
            .map_or_else(|| none.to_owned(), |path| path.display().to_string());
        let language = if crate::shell_help::is_turkish() {
            "Türkçe"
        } else {
            "English"
        };
        let rows = [
            (t("Directory", "Dizin"), directory),
            (t("Open file", "Açık dosya"), file),
            (t("Language", "Dil"), language.to_owned()),
            (t("Version", "Sürüm"), env!("CARGO_PKG_VERSION").to_owned()),
        ];
        for (label, value) in rows {
            println!("{label:<12} {}", crate::output::terminal_safe(&value));
        }
    }

    /// Fills in the open file (`@`, or a lone command) and runs the command.
    fn run_command(&self, tokens: &[String]) {
        let selected = self
            .selected
            .as_ref()
            .map(|path| path.display().to_string());
        match crate::shell_session::expand(tokens, selected.as_deref()) {
            Ok((expanded, implicit)) => {
                if implicit && let Some(path) = &self.selected {
                    let name = path.file_name().map(|name| name.to_string_lossy());
                    println!(
                        "{} {}",
                        t("using open file:", "açık dosya kullanılıyor:"),
                        crate::output::terminal_safe(&name.unwrap_or_default())
                    );
                }
                dispatch(&expanded);
            }
            Err(crate::shell_session::ExpandError::NothingOpen) => eprintln!(
                "{}",
                t(
                    "error: '@' needs an open file; use: open <file>",
                    "hata: '@' için açık dosya gerekir; önce: open <dosya>",
                )
            ),
        }
    }
}

/// Handles one console line. Returns false when the console should close.
fn execute(session: &mut Session, tokens: &[String], color: bool) -> bool {
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
        "open" => session.open(rest),
        "close" => session.close(),
        "status" => session.status(),
        "history" => session.show_history(),
        "save" => session.save(rest),
        "run" => run_script(session, rest, color),
        "shell" => eprintln!("{}", already_inside()),
        _ => {
            let mut arguments = tokens.to_vec();
            arguments[0] = name.to_owned();
            session.run_command(&arguments);
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

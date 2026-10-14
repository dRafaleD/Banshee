//! Tab completion for the interactive console. Candidates come from the clap
//! command tree (commands, subcommands, long flags and enumerated flag values)
//! plus the console built-ins, so they follow the real command line. Anything
//! else, such as a path argument, falls back to file name completion.

use std::borrow::Cow;

use clap::CommandFactory;
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};

use crate::cli::Cli;

const BUILTINS: &[&str] = &[
    "help", "pwd", "cd", "ls", "clear", "lang", "tr", "en", "exit", "quit",
];

/// Completes the last word of `prefix` (the line up to the cursor). Returns the
/// byte offset where that word starts and the candidates, or `None` when the
/// word should be completed as a file name.
pub(crate) fn candidates(prefix: &str) -> Option<(usize, Vec<String>)> {
    // Inside an open quote the word is a path with spaces.
    if prefix.matches(['"', '\'']).count() % 2 == 1 {
        return None;
    }
    let start = prefix
        .char_indices()
        .rev()
        .find(|(_, character)| character.is_whitespace())
        .map_or(0, |(index, character)| index + character.len_utf8());
    let word = &prefix[start..];
    let done: Vec<&str> = prefix[..start].split_whitespace().collect();
    let matching = |names: Vec<String>| -> Vec<String> {
        let mut names: Vec<String> = names
            .into_iter()
            .filter(|name| name.starts_with(word))
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    };

    let mut root = Cli::command();
    root.build();
    let command_names = || -> Vec<String> {
        root.get_subcommands()
            .filter(|command| !command.is_hide_set() && command.get_name() != "help")
            .map(|command| command.get_name().to_owned())
            .collect()
    };

    let Some(first) = done.first().map(|token| token.trim_start_matches('/')) else {
        // First word: a command, optionally with the slash prefix.
        let (lead, stem) = word
            .strip_prefix('/')
            .map_or(("", word), |stem| ("/", stem));
        let mut names = command_names();
        names.extend(BUILTINS.iter().map(|name| (*name).to_owned()));
        names.retain(|name| name != "shell" && name.starts_with(stem));
        names.sort_unstable();
        names.dedup();
        let names = names
            .into_iter()
            .map(|name| format!("{lead}{name} "))
            .collect();
        return Some((start, names));
    };

    match first {
        "help" | "?" | "h" => {
            if done.len() > 1 {
                return Some((start, Vec::new()));
            }
            let mut names = command_names();
            names.extend(crate::shell_help::topic_keys().map(str::to_owned));
            return Some((start, spaced(matching(names))));
        }
        "cd" | "ls" | "dir" => return None,
        "lang" => {
            let languages = if done.len() == 1 {
                matching(vec!["tr".to_owned(), "en".to_owned()])
            } else {
                Vec::new()
            };
            return Some((start, spaced(languages)));
        }
        name if BUILTINS.contains(&name) || name == "cls" || name == "q" => {
            return Some((start, Vec::new()));
        }
        _ => {}
    }

    let mut current = root.find_subcommand(first)?;
    for token in &done[1..] {
        if let Some(sub) = current.find_subcommand(token) {
            current = sub;
        }
    }
    // Value of an enumerated flag such as `--format`.
    if let Some(flag) = done.last().and_then(|token| token.strip_prefix("--"))
        && let Some(argument) = current
            .get_arguments()
            .find(|argument| argument.get_long() == Some(flag))
    {
        let values: Vec<String> = argument
            .get_possible_values()
            .iter()
            .filter(|value| !value.is_hide_set())
            .map(|value| value.get_name().to_owned())
            .collect();
        if !values.is_empty() {
            return Some((start, spaced(matching(values))));
        }
    }
    if word.starts_with('-') {
        let mut flags: Vec<String> = current
            .get_arguments()
            .filter(|argument| !argument.is_hide_set())
            .filter_map(|argument| argument.get_long().map(|long| format!("--{long}")))
            .collect();
        flags.push("--help".to_owned());
        return Some((start, spaced(matching(flags))));
    }
    let subcommands: Vec<String> = current
        .get_subcommands()
        .filter(|command| !command.is_hide_set() && command.get_name() != "help")
        .map(|command| command.get_name().to_owned())
        .collect();
    let subcommands = matching(subcommands);
    if subcommands.is_empty() {
        None
    } else {
        Some((start, spaced(subcommands)))
    }
}

fn spaced(names: Vec<String>) -> Vec<String> {
    names.into_iter().map(|name| format!("{name} ")).collect()
}

/// rustyline helper: command-tree completion, file fallback and a colored
/// prompt (the prompt is passed plain so its width is measured correctly).
pub(crate) struct ConsoleHelper {
    files: FilenameCompleter,
    color: bool,
}

impl ConsoleHelper {
    pub(crate) fn new(color: bool) -> Self {
        Self {
            files: FilenameCompleter::new(),
            color,
        }
    }
}

impl Completer for ConsoleHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        context: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        match candidates(&line[..pos]) {
            Some((start, words)) => Ok((
                start,
                words
                    .into_iter()
                    .map(|word| Pair {
                        display: word.trim_end().to_owned(),
                        replacement: word,
                    })
                    .collect(),
            )),
            None => self.files.complete(line, pos, context),
        }
    }
}

impl Hinter for ConsoleHelper {
    type Hint = String;
}

impl Validator for ConsoleHelper {}

impl Highlighter for ConsoleHelper {
    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        _default: bool,
    ) -> Cow<'b, str> {
        match prompt.strip_suffix("> ") {
            Some(name) if self.color => Cow::Owned(format!("\x1b[38;5;46m{name}\x1b[0m> ")),
            _ => Cow::Borrowed(prompt),
        }
    }
}

impl Helper for ConsoleHelper {}

#[cfg(test)]
mod tests {
    use super::candidates;

    fn words(prefix: &str) -> Vec<String> {
        candidates(prefix)
            .map(|(_, words)| words.into_iter().map(|w| w.trim().to_owned()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn completes_command_names_and_builtins() {
        assert_eq!(words("wha"), ["whatis"]);
        assert!(words("").contains(&"report".to_owned()) && words("").contains(&"cd".to_owned()));
        assert!(!words("").contains(&"shell".to_owned()));
        assert_eq!(candidates("/wha").unwrap().1, ["/whatis "]);
    }

    #[test]
    fn completes_subcommands_flags_and_flag_values() {
        assert_eq!(words("hash ide"), ["identify"]);
        assert!(words("extract --fi").contains(&"--file".to_owned()));
        assert!(!words("report x --format ").is_empty());
        assert!(words("report x --format j").contains(&"json".to_owned()));
    }

    #[test]
    fn completes_help_topics_and_falls_back_to_files() {
        assert!(words("help fi").contains(&"files".to_owned()));
        assert!(words("help fi").contains(&"file".to_owned()));
        assert!(candidates("report sam").is_none());
        assert!(candidates("cd sr").is_none());
        assert!(candidates("report \"my fi").is_none());
    }

    #[test]
    fn offsets_point_at_the_current_word() {
        assert_eq!(candidates("hash ide").unwrap().0, 5);
        assert_eq!(words("lang t"), ["tr"]);
        assert!(words("help dos").contains(&"dosyalar".to_owned()));
    }
}

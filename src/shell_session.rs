//! Selected-file support for the console. After `open sample.bin`, the token
//! `@` stands for that file in any command, and a few commands typed alone use
//! it directly, so `report` is enough to build a report for the open file.

/// Why a line could not be expanded.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExpandError {
    /// The line uses `@` but no file is open.
    NothingOpen,
}

/// Commands that take the open file when typed without arguments, as the
/// argument list that precedes the file.
fn implicit_arguments(command: &str) -> Option<&'static [&'static str]> {
    Some(match command {
        "report" | "scan" => &[],
        "file" => &["inspect"],
        "cert" => &["inspect"],
        "entropy" | "whatis" | "analyze" | "extract" => &["--file"],
        _ => return None,
    })
}

/// Replaces every `@` token with the open file and, for a lone command from
/// the table above, appends the open file. Returns the new tokens and whether
/// the open file was supplied implicitly (so the console can say so).
pub(crate) fn expand(
    tokens: &[String],
    selected: Option<&str>,
) -> Result<(Vec<String>, bool), ExpandError> {
    let uses_placeholder = tokens.iter().skip(1).any(|token| token == "@");
    if uses_placeholder {
        let path = selected.ok_or(ExpandError::NothingOpen)?;
        // These commands take a value or `--file`; a bare `@` must mean the
        // file's contents, not the path text.
        let takes_file_flag =
            implicit_arguments(&tokens[0]).is_some_and(|prefix| prefix == ["--file"]);
        let mut expanded = Vec::with_capacity(tokens.len() + 1);
        for (index, token) in tokens.iter().enumerate() {
            if index == 0 || token != "@" {
                expanded.push(token.clone());
                continue;
            }
            let after_flag = matches!(expanded.last().map(String::as_str), Some("--file" | "-f"));
            if takes_file_flag && !after_flag {
                expanded.push("--file".to_owned());
            }
            expanded.push(path.to_owned());
        }
        return Ok((expanded, false));
    }
    if let ([command], Some(path)) = (tokens, selected)
        && let Some(prefix) = implicit_arguments(command)
    {
        let mut expanded = vec![command.clone()];
        expanded.extend(prefix.iter().map(|argument| (*argument).to_owned()));
        expanded.push(path.to_owned());
        return Ok((expanded, true));
    }
    Ok((tokens.to_vec(), false))
}

#[cfg(test)]
mod tests {
    use super::{ExpandError, expand};

    fn words(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn placeholder_is_replaced_in_any_position() {
        let (tokens, implicit) = expand(
            &words(&["report", "@", "--format", "json"]),
            Some("C:\\s\\a.bin"),
        )
        .unwrap();
        assert_eq!(tokens, ["report", "C:\\s\\a.bin", "--format", "json"]);
        assert!(!implicit);
        let (tokens, _) = expand(&words(&["whatis", "--file", "@"]), Some("a.bin")).unwrap();
        assert_eq!(tokens, ["whatis", "--file", "a.bin"]);
    }

    #[test]
    fn bare_placeholder_means_the_file_for_value_or_file_commands() {
        assert_eq!(
            expand(&words(&["whatis", "@"]), Some("a.bin")).unwrap().0,
            ["whatis", "--file", "a.bin"]
        );
        assert_eq!(
            expand(&words(&["extract", "--defang", "@"]), Some("a.log"))
                .unwrap()
                .0,
            ["extract", "--defang", "--file", "a.log"]
        );
        // Already preceded by the flag: no second `--file`.
        assert_eq!(
            expand(&words(&["entropy", "-f", "@"]), Some("a.bin"))
                .unwrap()
                .0,
            ["entropy", "-f", "a.bin"]
        );
        // Commands with a path argument keep the plain path.
        assert_eq!(
            expand(&words(&["cert", "inspect", "@"]), Some("c.pem"))
                .unwrap()
                .0,
            ["cert", "inspect", "c.pem"]
        );
    }

    #[test]
    fn placeholder_without_an_open_file_is_an_error() {
        assert_eq!(
            expand(&words(&["report", "@"]), None),
            Err(ExpandError::NothingOpen)
        );
    }

    #[test]
    fn lone_commands_use_the_open_file() {
        assert_eq!(
            expand(&words(&["report"]), Some("a.bin")).unwrap(),
            (words(&["report", "a.bin"]), true)
        );
        assert_eq!(
            expand(&words(&["file"]), Some("a.bin")).unwrap().0,
            ["file", "inspect", "a.bin"]
        );
        assert_eq!(
            expand(&words(&["entropy"]), Some("a.bin")).unwrap().0,
            ["entropy", "--file", "a.bin"]
        );
    }

    #[test]
    fn explicit_arguments_and_other_commands_are_left_alone() {
        assert_eq!(
            expand(&words(&["report", "other.bin"]), Some("a.bin")).unwrap(),
            (words(&["report", "other.bin"]), false)
        );
        assert_eq!(
            expand(&words(&["doctor"]), Some("a.bin")).unwrap().0,
            ["doctor"]
        );
        assert_eq!(expand(&words(&["report"]), None).unwrap().0, ["report"]);
    }

    #[test]
    fn a_command_named_at_is_not_expanded() {
        // Only arguments are replaced, never the command position.
        assert_eq!(expand(&words(&["@"]), Some("a.bin")).unwrap().0, ["@"]);
    }
}

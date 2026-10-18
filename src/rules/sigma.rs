//! Import of Sigma detection rules as Banshee TOML.
//!
//! Sigma rules match fields of parsed log events; Banshee rules match the
//! content of a value, file or log. The import therefore searches for each
//! field's values anywhere in the scanned content and ignores field names,
//! which makes converted rules broader than the originals. Every import says
//! so in a warning. Constructs without a content equivalent (`not`,
//! aggregations, `base64`, `cidr`, numeric comparisons, null checks) skip the
//! rule with a reason instead of being approximated further.
//!
//! The YAML reader understands the subset Sigma rules use: block mappings
//! and sequences, flow sequences, plain and quoted scalars, block scalars,
//! comments and multiple documents.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use super::compile_source;
use super::yara::{Conversion, SkippedRule, toml_string};

const MAX_SIGMA_FILE_BYTES: u64 = 1024 * 1024;
/// Rules one Sigma rule may expand into through `or` and `1 of`.
const MAX_ALTERNATIVES: usize = 16;
/// Conditions per Banshee rule: the primary pattern plus 16 `all` entries.
const MAX_CONDITIONS: usize = 17;
const WILDCARD: &str = "[^\\r\\n]{0,256}";

// ---------------------------------------------------------------------------
// YAML subset

#[derive(Debug, Clone, PartialEq)]
enum Yaml {
    Null,
    Scalar(String),
    List(Vec<Yaml>),
    Map(Vec<(String, Yaml)>),
}

impl Yaml {
    fn get(&self, key: &str) -> Option<&Yaml> {
        match self {
            Self::Map(entries) => entries
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    fn text(&self) -> Option<&str> {
        match self {
            Self::Scalar(text) => Some(text),
            _ => None,
        }
    }

    fn texts(&self) -> Vec<&str> {
        match self {
            Self::Scalar(text) => vec![text],
            Self::List(items) => items.iter().filter_map(Self::text).collect(),
            _ => Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct Line {
    indent: usize,
    text: String,
}

/// Removes a `#` comment that is outside quotes and preceded by a space.
fn strip_comment(line: &str) -> &str {
    let mut quote = None;
    let mut previous = ' ';
    for (index, character) in line.char_indices() {
        match (quote, character) {
            (None, '\'' | '"') => quote = Some(character),
            (Some(open), _) if character == open => quote = None,
            (None, '#') if previous.is_whitespace() => return &line[..index],
            _ => {}
        }
        previous = character;
    }
    line
}

fn unquote(value: &str) -> Result<String> {
    let value = value.trim();
    if let Some(inner) = value.strip_prefix('\'') {
        let inner = inner
            .strip_suffix('\'')
            .ok_or_else(|| anyhow!("unterminated quoted value {value}"))?;
        return Ok(inner.replace("''", "'"));
    }
    if let Some(inner) = value.strip_prefix('"') {
        let inner = inner
            .strip_suffix('"')
            .ok_or_else(|| anyhow!("unterminated quoted value {value}"))?;
        let mut output = String::new();
        let mut characters = inner.chars();
        while let Some(character) = characters.next() {
            if character != '\\' {
                output.push(character);
                continue;
            }
            let escaped = match characters.next() {
                Some('0') => '\0',
                Some('a') => '\u{7}',
                Some('b') => '\u{8}',
                Some('t' | '\t') => '\t',
                Some('n') => '\n',
                Some('v') => '\u{b}',
                Some('f') => '\u{c}',
                Some('r') => '\r',
                Some('e') => '\u{1b}',
                Some('N') => '\u{85}',
                Some('_') => '\u{a0}',
                Some('L') => '\u{2028}',
                Some('P') => '\u{2029}',
                Some(digits @ ('x' | 'u' | 'U')) => {
                    let length = match digits {
                        'x' => 2,
                        'u' => 4,
                        _ => 8,
                    };
                    let hex: String = characters.by_ref().take(length).collect();
                    u32::from_str_radix(&hex, 16)
                        .ok()
                        .filter(|_| hex.len() == length)
                        .and_then(char::from_u32)
                        .ok_or_else(|| anyhow!("invalid escape \\{digits}{hex} in {value}"))?
                }
                Some(other @ (' ' | '"' | '/' | '\\')) => other,
                Some(other) => bail!("invalid escape \\{other} in {value}"),
                None => bail!("unterminated escape in {value}"),
            };
            output.push(escaped);
        }
        return Ok(output);
    }
    Ok(value.to_owned())
}

/// Splits at the first `: ` (or a trailing `:`) outside quotes.
fn split_key(text: &str) -> Option<(&str, &str)> {
    let mut quote = None;
    let bytes = text.as_bytes();
    for (index, character) in text.char_indices() {
        match (quote, character) {
            (None, '\'' | '"') if index == 0 => quote = Some(character),
            (Some(open), _) if character == open => quote = None,
            (None, ':') if bytes.get(index + 1).is_none_or(|next| *next == b' ') => {
                return Some((&text[..index], text[index + 1..].trim()));
            }
            _ => {}
        }
    }
    None
}

fn scalar(value: &str) -> Result<Yaml> {
    let value = value.trim();
    if value.is_empty() || value == "~" || value == "null" {
        return Ok(Yaml::Null);
    }
    if let Some(inner) = value.strip_prefix('[') {
        let inner = inner
            .strip_suffix(']')
            .ok_or_else(|| anyhow!("unterminated flow sequence {value}"))?;
        let mut items = Vec::new();
        let mut current = String::new();
        let mut quote = None;
        for character in inner.chars() {
            match (quote, character) {
                (None, '\'' | '"') => {
                    quote = Some(character);
                    current.push(character);
                }
                (Some(open), _) if character == open => {
                    quote = None;
                    current.push(character);
                }
                (None, ',') => {
                    items.push(scalar(&current)?);
                    current.clear();
                }
                _ => current.push(character),
            }
        }
        if !current.trim().is_empty() {
            items.push(scalar(&current)?);
        }
        return Ok(Yaml::List(items));
    }
    if value.starts_with('{') {
        bail!("flow mappings are not supported");
    }
    Ok(Yaml::Scalar(unquote(value)?))
}

struct Parser {
    lines: Vec<Line>,
    position: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Line> {
        self.lines.get(self.position)
    }

    fn block(&mut self, indent: usize) -> Result<Yaml> {
        let Some(line) = self.peek() else {
            return Ok(Yaml::Null);
        };
        if line.indent < indent {
            return Ok(Yaml::Null);
        }
        let indent = line.indent;
        if line.text == "-" || line.text.starts_with("- ") {
            self.list(indent)
        } else {
            self.map(indent)
        }
    }

    fn list(&mut self, indent: usize) -> Result<Yaml> {
        let mut items = Vec::new();
        while let Some(line) = self.peek().cloned() {
            if line.indent != indent || !(line.text == "-" || line.text.starts_with("- ")) {
                break;
            }
            let content = line.text[1..].trim_start();
            let offset = line.text.len() - content.len();
            if content.is_empty() {
                self.position += 1;
                items.push(self.block(indent + 1)?);
            } else if split_key(content).is_some() && !content.starts_with(['\'', '"', '[']) {
                // "- key: value" starts a mapping indented to the key.
                self.lines[self.position] = Line {
                    indent: indent + offset,
                    text: content.to_owned(),
                };
                items.push(self.map(indent + offset)?);
            } else {
                self.position += 1;
                let text = self.continuation(content, indent);
                items.push(scalar(&text)?);
            }
        }
        Ok(Yaml::List(items))
    }

    /// Joins the deeper lines that continue a plain or quoted scalar.
    fn continuation(&mut self, first: &str, indent: usize) -> String {
        let mut text = first.to_owned();
        while let Some(next) = self.peek() {
            if next.indent <= indent {
                break;
            }
            text.push(' ');
            text.push_str(&next.text);
            self.position += 1;
        }
        text
    }

    fn map(&mut self, indent: usize) -> Result<Yaml> {
        let mut entries = Vec::new();
        while let Some(line) = self.peek().cloned() {
            if line.indent != indent {
                if line.indent > indent {
                    bail!("unexpected indentation at '{}'", line.text);
                }
                break;
            }
            let (key, value) = split_key(&line.text)
                .ok_or_else(|| anyhow!("expected 'key: value' at '{}'", line.text))?;
            let key = unquote(key)?;
            self.position += 1;
            let value = if matches!(value, "|" | ">" | "|-" | ">-" | "|+" | ">+") {
                let mut parts = Vec::new();
                while let Some(next) = self.peek() {
                    if next.indent <= indent {
                        break;
                    }
                    parts.push(next.text.clone());
                    self.position += 1;
                }
                Yaml::Scalar(parts.join(if value.starts_with('|') { "\n" } else { " " }))
            } else if value.is_empty() {
                match self.peek() {
                    Some(next) if next.indent > indent => self.block(indent + 1)?,
                    Some(next)
                        if next.indent == indent
                            && (next.text == "-" || next.text.starts_with("- ")) =>
                    {
                        self.list(indent)?
                    }
                    _ => Yaml::Null,
                }
            } else {
                scalar(&self.continuation(value, indent))?
            };
            entries.push((key, value));
        }
        Ok(Yaml::Map(entries))
    }
}

/// Parses each `---`-separated document.
fn parse_documents(source: &str) -> Result<Vec<Yaml>> {
    let mut documents = Vec::new();
    let mut current = Vec::new();
    for raw in source.lines() {
        if raw.trim_end() == "---" {
            documents.push(std::mem::take(&mut current));
            continue;
        }
        if raw
            .chars()
            .take_while(|character| character.is_whitespace())
            .any(|character| character == '\t')
        {
            bail!("tab indentation is not valid YAML");
        }
        let text = strip_comment(raw).trim_end();
        if text.trim().is_empty() {
            continue;
        }
        let indent = text.len() - text.trim_start().len();
        current.push(Line {
            indent,
            text: text.trim_start().to_owned(),
        });
    }
    documents.push(current);
    documents
        .into_iter()
        .filter(|lines| !lines.is_empty())
        .map(|lines| {
            let mut parser = Parser { lines, position: 0 };
            let value = parser.block(0)?;
            if let Some(line) = parser.peek() {
                bail!("could not parse YAML at '{}'", line.text);
            }
            Ok(value)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Sigma detection logic

/// One way for a rule to match: every regex must match.
type Term = Vec<String>;

fn value_regex(value: &str, modifiers: &[&str]) -> Result<String> {
    if modifiers.contains(&"re") {
        regex::Regex::new(value).with_context(|| format!("invalid regex {value}"))?;
        return Ok(value.to_owned());
    }
    // Leading and trailing wildcards add nothing to a substring search.
    let mut text = value;
    while let Some(rest) = text.strip_prefix('*') {
        text = rest;
    }
    while text.ends_with('*') && !text.ends_with("\\*") {
        text = &text[..text.len() - 1];
    }
    if text.is_empty() {
        bail!("value '{value}' matches anything");
    }
    let mut pattern = String::new();
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\\' if matches!(characters.peek(), Some('*' | '?' | '\\')) => {
                let next = characters.next().expect("peeked");
                pattern.push_str(&regex::escape(&next.to_string()));
            }
            '*' => pattern.push_str(WILDCARD),
            '?' => pattern.push('.'),
            '-' if modifiers.contains(&"windash") => {
                pattern.push_str("[-/\u{2013}\u{2014}\u{2015}]");
            }
            other => pattern.push_str(&regex::escape(&other.to_string())),
        }
    }
    Ok(pattern)
}

fn field_terms(key: &str, value: &Yaml) -> Result<Vec<String>> {
    let mut parts = key.split('|');
    let _field = parts.next();
    let modifiers: Vec<&str> = parts.collect();
    for modifier in &modifiers {
        if !matches!(
            *modifier,
            "contains"
                | "startswith"
                | "endswith"
                | "all"
                | "re"
                | "cased"
                | "windash"
                | "i"
                | "m"
                | "s"
        ) {
            bail!("field modifier '{modifier}' has no content equivalent");
        }
    }
    let values: Vec<String> = match value {
        Yaml::Scalar(text) => vec![text.clone()],
        Yaml::List(items) => items
            .iter()
            .map(|item| match item {
                Yaml::Scalar(text) => Ok(text.clone()),
                Yaml::Null => bail!("null values (field must be empty) are not supported"),
                _ => bail!("nested values are not supported"),
            })
            .collect::<Result<_>>()?,
        Yaml::Null => bail!("null values (field must be empty) are not supported"),
        Yaml::Map(_) => bail!("nested mappings are not supported"),
    };
    if values.is_empty() {
        bail!("field '{key}' has no values");
    }
    let flags = if modifiers.contains(&"cased") {
        ""
    } else {
        "(?i)"
    };
    let patterns = values
        .iter()
        .map(|value| value_regex(value, &modifiers))
        .collect::<Result<Vec<_>>>()?;
    Ok(if modifiers.contains(&"all") {
        patterns
            .into_iter()
            .map(|pattern| format!("{flags}{pattern}"))
            .collect()
    } else if patterns.len() == 1 {
        vec![format!("{flags}{}", patterns[0])]
    } else {
        vec![format!("{flags}(?:{})", patterns.join("|"))]
    })
}

/// Alternatives a named selection matches: a map is one term, a list of
/// maps or keywords is one term per item (keywords join into one regex).
fn selection_terms(name: &str, selection: &Yaml) -> Result<Vec<Term>> {
    match selection {
        Yaml::Map(fields) => {
            let mut term = Vec::new();
            for (key, value) in fields {
                term.extend(field_terms(key, value)?);
            }
            Ok(vec![term])
        }
        Yaml::List(items) if items.iter().all(|item| matches!(item, Yaml::Scalar(_))) => {
            Ok(vec![field_terms("keywords", selection)?])
        }
        Yaml::List(items) => items
            .iter()
            .map(|item| match item {
                Yaml::Map(_) => Ok(selection_terms(name, item)?.remove(0)),
                _ => bail!("selection '{name}' mixes keywords and field maps"),
            })
            .collect(),
        Yaml::Scalar(_) => Ok(vec![field_terms("keywords", selection)?]),
        Yaml::Null => bail!("selection '{name}' is empty"),
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Word(String),
    Open,
    Close,
}

fn tokenize(condition: &str) -> Vec<Token> {
    let spaced = condition.replace('(', " ( ").replace(')', " ) ");
    spaced
        .split_whitespace()
        .map(|word| match word {
            "(" => Token::Open,
            ")" => Token::Close,
            other => Token::Word(other.to_owned()),
        })
        .collect()
}

struct Condition<'a> {
    tokens: Vec<Token>,
    position: usize,
    selections: &'a [(String, Vec<Term>)],
}

fn combine(left: Vec<Term>, right: Vec<Term>) -> Result<Vec<Term>> {
    if left.len() * right.len() > MAX_ALTERNATIVES {
        bail!("condition expands into more than {MAX_ALTERNATIVES} rules");
    }
    Ok(left
        .iter()
        .flat_map(|a| right.iter().map(move |b| [a.clone(), b.clone()].concat()))
        .collect())
}

fn glob_matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

impl Condition<'_> {
    fn word(&self) -> Option<&str> {
        match self.tokens.get(self.position) {
            Some(Token::Word(word)) => Some(word),
            _ => None,
        }
    }

    fn or(&mut self) -> Result<Vec<Term>> {
        let mut terms = self.and()?;
        while self.word() == Some("or") {
            self.position += 1;
            terms.extend(self.and()?);
            if terms.len() > MAX_ALTERNATIVES {
                bail!("condition expands into more than {MAX_ALTERNATIVES} rules");
            }
        }
        Ok(terms)
    }

    fn and(&mut self) -> Result<Vec<Term>> {
        let mut terms = self.unary()?;
        while self.word() == Some("and") {
            self.position += 1;
            terms = combine(terms, self.unary()?)?;
        }
        Ok(terms)
    }

    fn unary(&mut self) -> Result<Vec<Term>> {
        match self.tokens.get(self.position).cloned() {
            Some(Token::Open) => {
                self.position += 1;
                let terms = self.or()?;
                if self.tokens.get(self.position) != Some(&Token::Close) {
                    bail!("unbalanced parentheses in condition");
                }
                self.position += 1;
                Ok(terms)
            }
            Some(Token::Word(word)) if word == "not" => {
                bail!("'not' has no content equivalent")
            }
            Some(Token::Word(word)) if matches!(word.as_str(), "1" | "any" | "all") => {
                self.position += 1;
                if self.word() != Some("of") {
                    bail!("expected 'of' after '{word}'");
                }
                self.position += 1;
                let target = self
                    .word()
                    .ok_or_else(|| anyhow!("expected a selection after 'of'"))?
                    .to_owned();
                self.position += 1;
                let matched: Vec<&Vec<Term>> = self
                    .selections
                    .iter()
                    .filter(|(name, _)| target == "them" || glob_matches(&target, name))
                    .map(|(_, terms)| terms)
                    .collect();
                if matched.is_empty() {
                    bail!("'{word} of {target}' names no selection");
                }
                if word == "all" {
                    matched
                        .into_iter()
                        .try_fold(vec![Vec::new()], |terms, next| combine(terms, next.clone()))
                } else {
                    let terms: Vec<Term> = matched.into_iter().flatten().cloned().collect();
                    if terms.len() > MAX_ALTERNATIVES {
                        bail!("condition expands into more than {MAX_ALTERNATIVES} rules");
                    }
                    Ok(terms)
                }
            }
            Some(Token::Word(word)) => {
                self.position += 1;
                self.selections
                    .iter()
                    .find(|(name, _)| *name == word)
                    .map(|(_, terms)| terms.clone())
                    .ok_or_else(|| anyhow!("condition names unknown selection '{word}'"))
            }
            Some(Token::Close) | None => bail!("incomplete condition"),
        }
    }
}

fn detection_terms(detection: &Yaml) -> Result<Vec<Term>> {
    let Yaml::Map(entries) = detection else {
        bail!("detection must be a mapping");
    };
    if detection.get("timeframe").is_some() {
        bail!("timeframe correlations have no content equivalent");
    }
    let mut selections = Vec::new();
    for (name, value) in entries {
        if name != "condition" {
            selections.push((name.clone(), selection_terms(name, value)?));
        }
    }
    let conditions = detection
        .get("condition")
        .map(Yaml::texts)
        .filter(|conditions| !conditions.is_empty())
        .ok_or_else(|| anyhow!("detection has no condition"))?;
    let mut terms = Vec::new();
    for condition in conditions {
        if condition.contains('|') {
            bail!("aggregation conditions have no content equivalent");
        }
        let mut parser = Condition {
            tokens: tokenize(condition),
            position: 0,
            selections: &selections,
        };
        terms.extend(parser.or()?);
        if parser.position != parser.tokens.len() {
            bail!("could not parse condition '{condition}'");
        }
    }
    if terms.len() > MAX_ALTERNATIVES {
        bail!("condition expands into more than {MAX_ALTERNATIVES} rules");
    }
    for term in &terms {
        if term.is_empty() {
            bail!("a condition branch has no values");
        }
        if term.len() > MAX_CONDITIONS {
            bail!("a condition branch needs more than {MAX_CONDITIONS} patterns");
        }
    }
    Ok(terms)
}

// ---------------------------------------------------------------------------
// TOML output

fn slug(text: &str) -> String {
    let mut slug = String::new();
    for character in text.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
            slug.push(character.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    slug.trim_matches('-').chars().take(100).collect()
}

fn severity(level: Option<&str>) -> &'static str {
    match level.unwrap_or("medium") {
        "informational" => "info",
        "low" => "low",
        "high" => "high",
        "critical" => "critical",
        _ => "medium",
    }
}

fn confidence(status: Option<&str>) -> &'static str {
    match status.unwrap_or_default() {
        "stable" => "high",
        "test" => "medium",
        _ => "low",
    }
}

/// ATT&CK technique and tactic IDs from Sigma `attack.*` tags; other tags
/// are kept as Banshee tags.
fn split_tags(tags: &[&str]) -> (Vec<String>, Vec<String>) {
    let mut attack = Vec::new();
    let mut other = Vec::new();
    for tag in tags {
        let id = tag
            .strip_prefix("attack.")
            .map(str::to_ascii_uppercase)
            .filter(|id| super::is_attack_identifier(id));
        match id {
            Some(id) if !attack.contains(&id) => attack.push(id),
            Some(_) => {}
            None if tag.len() <= 128 && other.len() < 32 => other.push((*tag).to_owned()),
            None => {}
        }
    }
    attack.truncate(16);
    (attack, other)
}

fn toml_list(values: &[String]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| toml_string(value))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn convert(document: &Yaml) -> Result<Vec<String>> {
    if document.get("action").is_some() {
        bail!("Sigma rule collections (action:) are not supported");
    }
    let title = document
        .get("title")
        .and_then(Yaml::text)
        .ok_or_else(|| anyhow!("rule has no title"))?;
    let detection = document
        .get("detection")
        .ok_or_else(|| anyhow!("rule has no detection"))?;
    let terms = detection_terms(detection)?;
    let base = document
        .get("id")
        .and_then(Yaml::text)
        .map(slug)
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| slug(title));
    let level = document.get("level").and_then(Yaml::text);
    let status = document.get("status").and_then(Yaml::text);
    let tags = document.get("tags").map(Yaml::texts).unwrap_or_default();
    let (attack, tags) = split_tags(&tags);
    let references: Vec<String> = document
        .get("references")
        .map(Yaml::texts)
        .unwrap_or_default()
        .into_iter()
        .filter(|reference| reference.len() <= 512)
        .take(16)
        .map(str::to_owned)
        .collect();
    let logsource = document.get("logsource");
    let category = ["category", "product", "service"]
        .iter()
        .find_map(|key| {
            logsource
                .and_then(|source| source.get(key))
                .and_then(Yaml::text)
        })
        .filter(|category| category.len() <= 128);
    let mut description = format!("Sigma: {title}");
    if let Some(text) = document.get("description").and_then(Yaml::text) {
        write!(description, ". {}", text.trim()).expect("string write");
    }
    let description: String = description.chars().take(1000).collect();

    let mut rules = Vec::new();
    for (index, term) in terms.iter().enumerate() {
        let id = if index == 0 {
            format!("sigma.{base}")
        } else {
            format!("sigma.{base}-{}", index + 1)
        };
        let mut toml = String::new();
        writeln!(toml, "[[rules]]").expect("string write");
        writeln!(toml, "id = {}", toml_string(&id)).expect("string write");
        writeln!(toml, "description = {}", toml_string(&description)).expect("string write");
        writeln!(toml, "severity = \"{}\"", severity(level)).expect("string write");
        writeln!(toml, "kind = \"regex\"").expect("string write");
        writeln!(toml, "pattern = {}", toml_string(&term[0])).expect("string write");
        writeln!(toml, "confidence = \"{}\"", confidence(status)).expect("string write");
        if let Some(category) = category {
            writeln!(toml, "category = {}", toml_string(category)).expect("string write");
        }
        let mut all_tags = vec!["sigma".to_owned()];
        all_tags.extend(tags.iter().cloned());
        writeln!(toml, "tags = {}", toml_list(&all_tags)).expect("string write");
        if !attack.is_empty() {
            writeln!(toml, "attack = {}", toml_list(&attack)).expect("string write");
        }
        if !references.is_empty() {
            writeln!(toml, "references = {}", toml_list(&references)).expect("string write");
        }
        for pattern in &term[1..] {
            writeln!(toml, "\n[[rules.all]]").expect("string write");
            writeln!(toml, "kind = \"regex\"").expect("string write");
            writeln!(toml, "pattern = {}", toml_string(pattern)).expect("string write");
        }
        compile_source(&format!("version = 1\n{toml}"))
            .context("converted rule failed Banshee validation")?;
        rules.push(toml);
    }
    Ok(rules)
}

pub fn import_file(path: &Path) -> Result<Conversion> {
    let source =
        crate::input::read_regular_text_file_limited(path, MAX_SIGMA_FILE_BYTES, "Sigma file")?;
    import_source(&source)
}

pub fn import_source(source: &str) -> Result<Conversion> {
    let documents = parse_documents(source).context("invalid Sigma YAML")?;
    let mut converted = Vec::new();
    let mut skipped = Vec::new();
    let mut ids = std::collections::HashSet::new();
    for (index, document) in documents.iter().enumerate() {
        let name = document
            .get("title")
            .and_then(Yaml::text)
            .map_or_else(|| format!("document {}", index + 1), str::to_owned);
        match convert(document) {
            Ok(rules) => {
                for rule in rules {
                    let id = rule.lines().nth(1).unwrap_or_default().to_owned();
                    if ids.insert(id) {
                        converted.push(rule);
                    } else {
                        skipped.push(SkippedRule {
                            rule: name.clone(),
                            reason: "duplicate rule ID".to_owned(),
                        });
                    }
                }
            }
            Err(reason) => skipped.push(SkippedRule {
                rule: name,
                reason: format!("{reason:#}"),
            }),
        }
    }
    let mut output = String::from(
        "# Generated by Banshee from Sigma rules. Field names are ignored: values\n\
         # are searched anywhere in the content, so matches are broader than in a\n\
         # SIEM. Review before use; matches are triage signals, not verdicts.\n\
         version = 1\n",
    );
    for rule in &skipped {
        writeln!(output, "# skipped {}: {}", rule.rule, rule.reason).expect("string write");
    }
    for rule in &converted {
        output.push('\n');
        output.push_str(rule);
    }
    if !converted.is_empty() {
        compile_source(&output).context("converted rules failed Banshee validation")?;
    }
    Ok(Conversion {
        output,
        converted: converted.len(),
        skipped,
        warnings: vec![
            "Sigma field names are ignored; converted rules match values anywhere in the content"
                .to_owned(),
        ],
    })
}

#[cfg(test)]
mod tests;

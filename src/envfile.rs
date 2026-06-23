//! Parsing and writing of dotenv-style `KEY=VALUE` files, plus the small
//! shared helpers (quoting, identifier checks) used across the crate.

#[derive(Debug, thiserror::Error)]
#[error("env file parse error on line {line}: {msg}")]
pub struct EnvFileError {
    pub line: usize,
    pub msg: String,
}

/// An insertion-ordered string map. Later writes to an existing key overwrite
/// in place (preserving position); new keys are appended.
#[derive(Debug, Clone, Default)]
pub struct EnvMap {
    entries: Vec<(String, String)>,
}

impl EnvMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        if let Some(slot) = self.entries.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value.into();
        } else {
            self.entries.push((key, value.into()));
        }
    }

    pub fn contains(&self, key: &str) -> bool {
        self.entries.iter().any(|(k, _)| k == key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(k, _)| k.as_str())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Parse a dotenv document into an ordered map.
pub fn parse(text: &str) -> Result<EnvMap, EnvFileError> {
    let mut map = EnvMap::new();
    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let line = raw.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let eq = line.find('=').ok_or_else(|| EnvFileError {
            line: line_no,
            msg: format!("missing `=` in `{}`", raw.trim()),
        })?;
        let key = line[..eq].trim();
        if !valid_key(key) {
            return Err(EnvFileError {
                line: line_no,
                msg: format!("invalid key `{key}`"),
            });
        }
        let value = parse_value(&line[eq + 1..]);
        map.set(key.to_string(), value);
    }
    Ok(map)
}

/// Serialize a map back to dotenv text (values quoted only when necessary).
pub fn to_dotenv(map: &EnvMap) -> String {
    let mut out = String::new();
    for (k, v) in map.iter() {
        out.push_str(k);
        out.push('=');
        out.push_str(&quote_if_needed(v));
        out.push('\n');
    }
    out
}

fn parse_value(raw: &str) -> String {
    let s = raw.trim_start();
    if let Some(rest) = s.strip_prefix('"') {
        let (inner, _) = take_quoted(rest, '"');
        unescape_double(&inner)
    } else if let Some(rest) = s.strip_prefix('\'') {
        let (inner, _) = take_quoted(rest, '\'');
        inner
    } else {
        strip_unquoted_comment(s).trim_end().to_string()
    }
}

/// Read the contents of a quoted region up to the closing quote `q`.
/// For double quotes, a backslash escapes the next character (kept verbatim
/// here and resolved later by [`unescape_double`]).
fn take_quoted(s: &str, q: char) -> (String, usize) {
    let mut out = String::new();
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        if c == '\\' && q == '"' {
            if let Some((_, n)) = chars.next() {
                out.push('\\');
                out.push(n);
                continue;
            } else {
                out.push('\\');
                return (out, s.len());
            }
        }
        if c == q {
            return (out, i + c.len_utf8());
        }
        out.push(c);
    }
    (out, s.len())
}

fn strip_unquoted_comment(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return &s[..i];
        }
        i += 1;
    }
    s
}

fn quote_if_needed(v: &str) -> String {
    let needs = v.is_empty()
        || v.chars()
            .any(|c| c.is_whitespace() || matches!(c, '#' | '"' | '\'' | '\\' | '$' | '`'));
    if needs {
        let escaped = v
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\t', "\\t")
            .replace('\r', "\\r");
        format!("\"{escaped}\"")
    } else {
        v.to_string()
    }
}

/// Remove one layer of surrounding quotes (double or single) if present,
/// unescaping double-quoted content.
pub fn unquote(s: &str) -> String {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() >= 2 {
        if b[0] == b'"' && b[b.len() - 1] == b'"' {
            return unescape_double(&s[1..s.len() - 1]);
        }
        if b[0] == b'\'' && b[b.len() - 1] == b'\'' {
            return s[1..s.len() - 1].to_string();
        }
    }
    s.to_string()
}

/// Resolve backslash escapes inside double-quoted content.
pub fn unescape_double(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('0') => out.push('\0'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('\'') => out.push('\''),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A valid shell/env identifier: starts with a letter or `_`, then letters,
/// digits or `_`.
pub fn valid_key(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic() {
        let m = parse("FOO=bar\nBAZ=qux\n").unwrap();
        assert_eq!(m.get("FOO"), Some("bar"));
        assert_eq!(m.get("BAZ"), Some("qux"));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn handles_export_and_comments() {
        let m = parse("# header\nexport PORT=3000 # inline\n\nNAME=hi\n").unwrap();
        assert_eq!(m.get("PORT"), Some("3000"));
        assert_eq!(m.get("NAME"), Some("hi"));
    }

    #[test]
    fn quoted_values() {
        let m = parse("A=\"hello world\"\nB='raw # not comment'\nC=\"line\\nbreak\"\n").unwrap();
        assert_eq!(m.get("A"), Some("hello world"));
        assert_eq!(m.get("B"), Some("raw # not comment"));
        assert_eq!(m.get("C"), Some("line\nbreak"));
    }

    #[test]
    fn later_key_overwrites_in_place() {
        let mut m = EnvMap::new();
        m.set("X", "1");
        m.set("Y", "2");
        m.set("X", "3");
        let keys: Vec<_> = m.keys().collect();
        assert_eq!(keys, vec!["X", "Y"]);
        assert_eq!(m.get("X"), Some("3"));
    }

    #[test]
    fn roundtrip_quoting() {
        let mut m = EnvMap::new();
        m.set("PLAIN", "value");
        m.set("SPACED", "a b");
        let text = to_dotenv(&m);
        let back = parse(&text).unwrap();
        assert_eq!(back.get("PLAIN"), Some("value"));
        assert_eq!(back.get("SPACED"), Some("a b"));
    }

    #[test]
    fn rejects_bad_key() {
        assert!(parse("1BAD=x\n").is_err());
        assert!(parse("noequals\n").is_err());
    }
}

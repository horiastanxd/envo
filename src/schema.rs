//! The `.envo` schema: a tiny typed declaration language for environment
//! variables. Each non-empty, non-comment line is `NAME: type [= default]`,
//! with an optional trailing `?` to mark the variable optional.

use crate::envfile::{unquote, valid_key};

#[derive(Debug, thiserror::Error)]
#[error("schema parse error on line {line}: {msg}")]
pub struct SchemaError {
    pub line: usize,
    pub msg: String,
}

fn err(line: usize, msg: impl Into<String>) -> SchemaError {
    SchemaError {
        line,
        msg: msg.into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarType {
    String,
    Int,
    Number,
    Bool,
    Port,
    Url,
    Secret,
    Enum(Vec<String>),
}

impl VarType {
    pub fn name(&self) -> String {
        match self {
            VarType::String => "string".into(),
            VarType::Int => "int".into(),
            VarType::Number => "number".into(),
            VarType::Bool => "bool".into(),
            VarType::Port => "port".into(),
            VarType::Url => "url".into(),
            VarType::Secret => "secret".into(),
            VarType::Enum(vs) => format!("enum({})", vs.join(", ")),
        }
    }

    pub fn is_secret(&self) -> bool {
        matches!(self, VarType::Secret)
    }
}

#[derive(Debug, Clone)]
pub struct VarSpec {
    pub name: String,
    pub ty: VarType,
    pub default: Option<String>,
    pub optional: bool,
}

impl VarSpec {
    /// A variable is required when it is neither optional nor has a default.
    pub fn required(&self) -> bool {
        !self.optional && self.default.is_none()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Schema {
    pub vars: Vec<VarSpec>,
}

impl Schema {
    pub fn get(&self, name: &str) -> Option<&VarSpec> {
        self.vars.iter().find(|v| v.name == name)
    }

    pub fn parse(text: &str) -> Result<Schema, SchemaError> {
        let mut vars: Vec<VarSpec> = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let line_no = i + 1;
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            let spec = parse_line(line, line_no)?;
            if vars.iter().any(|v| v.name == spec.name) {
                return Err(err(line_no, format!("duplicate variable `{}`", spec.name)));
            }
            vars.push(spec);
        }
        Ok(Schema { vars })
    }
}

/// Validate that a concrete string value conforms to a declared type.
/// Returns a human-readable reason on failure.
pub fn validate_value(ty: &VarType, value: &str) -> Result<(), String> {
    let v = value.trim();
    match ty {
        VarType::String | VarType::Secret => Ok(()),
        VarType::Int => v
            .parse::<i64>()
            .map(|_| ())
            .map_err(|_| format!("`{value}` is not an integer")),
        VarType::Number => v
            .parse::<f64>()
            .map(|_| ())
            .map_err(|_| format!("`{value}` is not a number")),
        VarType::Bool => match v.to_ascii_lowercase().as_str() {
            "true" | "false" | "1" | "0" | "yes" | "no" | "on" | "off" => Ok(()),
            _ => Err(format!(
                "`{value}` is not a bool (true/false/1/0/yes/no/on/off)"
            )),
        },
        VarType::Port => match v.parse::<u32>() {
            Ok(p) if (1..=65535).contains(&p) => Ok(()),
            _ => Err(format!("`{value}` is not a valid port (1-65535)")),
        },
        VarType::Url => {
            if is_url(v) {
                Ok(())
            } else {
                Err(format!(
                    "`{value}` is not a valid URL (expected scheme://...)"
                ))
            }
        }
        VarType::Enum(vs) => {
            if vs.iter().any(|x| x == v) {
                Ok(())
            } else {
                Err(format!(
                    "`{value}` not allowed (expected one of: {})",
                    vs.join(", ")
                ))
            }
        }
    }
}

fn is_url(s: &str) -> bool {
    if let Some(idx) = s.find("://") {
        let scheme = &s[..idx];
        let rest = &s[idx + 3..];
        !scheme.is_empty()
            && scheme
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
            && !rest.is_empty()
    } else {
        false
    }
}

/// Strip a trailing `#` comment that is not inside quotes.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let (mut in_s, mut in_d) = (false, false);
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' if !in_d => in_s = !in_s,
            b'"' if !in_s => in_d = !in_d,
            b'#' if !in_s && !in_d => return &line[..i],
            _ => {}
        }
        i += 1;
    }
    line
}

fn parse_line(line: &str, ln: usize) -> Result<VarSpec, SchemaError> {
    let colon = line
        .find(':')
        .ok_or_else(|| err(ln, "expected `NAME: type`"))?;
    let name = line[..colon].trim().to_string();
    if !valid_key(&name) {
        return Err(err(ln, format!("invalid variable name `{name}`")));
    }
    let rhs = line[colon + 1..].trim();
    if rhs.is_empty() {
        return Err(err(ln, "missing type"));
    }

    let (type_part, default_part) = split_default(rhs);
    let mut type_str = type_part.trim().to_string();
    let mut optional = false;
    if let Some(stripped) = type_str.strip_suffix('?') {
        optional = true;
        type_str = stripped.trim().to_string();
    }
    let ty = parse_type(&type_str).map_err(|m| err(ln, m))?;

    let default = match default_part {
        Some(d) => {
            let value = unquote(d.trim());
            if let Err(reason) = validate_value(&ty, &value) {
                return Err(err(ln, format!("default value invalid: {reason}")));
            }
            Some(value)
        }
        None => None,
    };

    Ok(VarSpec {
        name,
        ty,
        default,
        optional,
    })
}

/// Split `type [= default]` at the first top-level `=` (ignoring `=` inside
/// quotes or `enum(...)` parentheses).
fn split_default(s: &str) -> (&str, Option<&str>) {
    let b = s.as_bytes();
    let (mut in_s, mut in_d) = (false, false);
    let mut depth = 0i32;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\'' if !in_d => in_s = !in_s,
            b'"' if !in_s => in_d = !in_d,
            b'(' if !in_s && !in_d => depth += 1,
            b')' if !in_s && !in_d => depth -= 1,
            b'=' if !in_s && !in_d && depth == 0 => return (&s[..i], Some(&s[i + 1..])),
            _ => {}
        }
        i += 1;
    }
    (s, None)
}

fn parse_type(s: &str) -> Result<VarType, String> {
    let s = s.trim();
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("enum(") && s.ends_with(')') {
        let inner = &s[5..s.len() - 1];
        let vals: Vec<String> = inner
            .split(',')
            .map(|v| unquote(v.trim()))
            .filter(|v| !v.is_empty())
            .collect();
        if vals.is_empty() {
            return Err("enum needs at least one value".into());
        }
        return Ok(VarType::Enum(vals));
    }
    Ok(match lower.as_str() {
        "string" | "str" => VarType::String,
        "int" | "integer" => VarType::Int,
        "number" | "num" | "float" => VarType::Number,
        "bool" | "boolean" => VarType::Bool,
        "port" => VarType::Port,
        "url" | "uri" => VarType::Url,
        "secret" | "password" => VarType::Secret,
        other => return Err(format!("unknown type `{other}`")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_types_and_defaults() {
        let s = Schema::parse(
            "PORT: port = 3000\nHOST: string = \"localhost\"\nKEY: secret\nMODE: enum(a, b) = a\n",
        )
        .unwrap();
        assert_eq!(s.vars.len(), 4);
        let port = s.get("PORT").unwrap();
        assert_eq!(port.ty, VarType::Port);
        assert_eq!(port.default.as_deref(), Some("3000"));
        assert!(!port.required());
        let key = s.get("KEY").unwrap();
        assert!(key.ty.is_secret());
        assert!(key.required());
        let mode = s.get("MODE").unwrap();
        assert_eq!(mode.ty, VarType::Enum(vec!["a".into(), "b".into()]));
    }

    #[test]
    fn optional_marker() {
        let s = Schema::parse("DSN: url?\n").unwrap();
        let dsn = s.get("DSN").unwrap();
        assert!(dsn.optional);
        assert!(!dsn.required());
    }

    #[test]
    fn rejects_unknown_type_and_dupes() {
        assert!(Schema::parse("X: banana\n").is_err());
        assert!(Schema::parse("X: int\nX: int\n").is_err());
        assert!(Schema::parse("PORT: port = 70000\n").is_err());
    }

    #[test]
    fn value_validation() {
        assert!(validate_value(&VarType::Port, "8080").is_ok());
        assert!(validate_value(&VarType::Port, "0").is_err());
        assert!(validate_value(&VarType::Bool, "YES").is_ok());
        assert!(validate_value(&VarType::Url, "postgres://h/db").is_ok());
        assert!(validate_value(&VarType::Url, "notaurl").is_err());
        assert!(validate_value(&VarType::Int, "12").is_ok());
        assert!(validate_value(&VarType::Int, "1.2").is_err());
        assert!(validate_value(&VarType::Enum(vec!["a".into()]), "b").is_err());
    }
}

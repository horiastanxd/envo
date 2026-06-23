//! Validate a resolved environment against a schema.

use crate::resolve::Resolved;
use crate::schema::{self, Schema};

#[derive(Debug, Default)]
pub struct Report {
    /// Required variables with no value.
    pub missing: Vec<String>,
    /// Present variables whose value does not match the declared type.
    pub invalid: Vec<(String, String)>,
    /// Variables present in the environment but absent from the schema.
    pub extra: Vec<String>,
}

impl Report {
    /// Passing means no missing-required and no type errors. `extra` is only a
    /// hard failure in strict mode (decided by the caller via [`Report::failed`]).
    pub fn passed(&self) -> bool {
        self.missing.is_empty() && self.invalid.is_empty()
    }

    pub fn failed(&self, strict: bool) -> bool {
        !self.passed() || (strict && !self.extra.is_empty())
    }
}

pub fn validate(schema: &Schema, resolved: &Resolved) -> Report {
    let mut report = Report::default();

    for spec in &schema.vars {
        match resolved.values.get(&spec.name) {
            None => {
                if spec.required() {
                    report.missing.push(spec.name.clone());
                }
            }
            Some(value) => {
                if let Err(reason) = schema::validate_value(&spec.ty, value) {
                    report.invalid.push((spec.name.clone(), reason));
                }
            }
        }
    }

    for key in resolved.values.keys() {
        if schema.get(key).is_none() {
            report.extra.push(key.to_string());
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::Resolved;

    fn resolved_from(pairs: &[(&str, &str)]) -> Resolved {
        let mut r = Resolved::default();
        for (k, v) in pairs {
            r.values.set(k.to_string(), v.to_string());
        }
        r
    }

    #[test]
    fn flags_missing_and_invalid_and_extra() {
        let schema = Schema::parse("PORT: port\nKEY: secret\nDEBUG: bool = false\n").unwrap();
        let resolved = resolved_from(&[("PORT", "not-a-port"), ("EXTRA", "1")]);
        let report = validate(&schema, &resolved);

        assert!(report.missing.contains(&"KEY".to_string()));
        assert!(report.invalid.iter().any(|(n, _)| n == "PORT"));
        assert!(report.extra.contains(&"EXTRA".to_string()));
        assert!(!report.passed());
        assert!(report.failed(false));
    }

    #[test]
    fn passes_when_satisfied() {
        let schema = Schema::parse("PORT: port = 3000\nDEBUG: bool = false\n").unwrap();
        let resolved = resolved_from(&[("PORT", "8080"), ("DEBUG", "true")]);
        let report = validate(&schema, &resolved);
        assert!(report.passed());
        assert!(!report.failed(false));
    }
}

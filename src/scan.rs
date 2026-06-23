//! Secret-leak detection: regex rules for well-known credential formats, plus
//! verbatim matching of the values of `secret`-typed schema variables.

use regex::{Regex, RegexBuilder};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub rule: String,
    pub severity: Severity,
    pub snippet: String,
}

struct Rule {
    name: &'static str,
    severity: Severity,
    re: Regex,
    /// For rules whose capture group 1 holds the candidate secret, skip the
    /// match if that value looks like an obvious placeholder.
    placeholder_guarded: bool,
}

pub struct Scanner {
    rules: Vec<Rule>,
    secret_values: Vec<String>,
}

impl Scanner {
    /// Build a scanner. `secret_values` are concrete values of secret-typed
    /// variables that should never appear in scanned files.
    pub fn new(secret_values: Vec<String>) -> Self {
        let secret_values = secret_values
            .into_iter()
            .filter(|v| v.len() >= 4 && !is_placeholder(v))
            .collect();
        Scanner {
            rules: build_rules(),
            secret_values,
        }
    }

    pub fn scan_text(&self, file: &str, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (idx, line) in content.lines().enumerate() {
            let line_no = idx + 1;
            // Skip pathologically long lines (minified bundles) to bound regex cost.
            if line.len() > 4000 {
                continue;
            }
            for rule in &self.rules {
                if rule.placeholder_guarded {
                    if let Some(caps) = rule.re.captures(line) {
                        let candidate = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
                        if is_placeholder(candidate) {
                            continue;
                        }
                        let whole = caps.get(0).unwrap().as_str();
                        findings.push(self.finding(file, line_no, rule, line, whole));
                    }
                } else if let Some(m) = rule.re.find(line) {
                    findings.push(self.finding(file, line_no, rule, line, m.as_str()));
                }
            }
            for value in &self.secret_values {
                if line.contains(value.as_str()) {
                    findings.push(Finding {
                        file: file.to_string(),
                        line: line_no,
                        rule: "Known secret value".to_string(),
                        severity: Severity::Critical,
                        snippet: redact(line, value),
                    });
                }
            }
        }
        findings
    }

    fn finding(
        &self,
        file: &str,
        line_no: usize,
        rule: &Rule,
        line: &str,
        matched: &str,
    ) -> Finding {
        Finding {
            file: file.to_string(),
            line: line_no,
            rule: rule.name.to_string(),
            severity: rule.severity,
            snippet: redact(line, matched),
        }
    }
}

/// Flag a committed file whose *name* implies it carries secrets.
///
/// Deliberately high-confidence: a bare `.env`, any `*.local`, plaintext
/// `*.secrets`, and private-key material. Profile files like `.env.staging`
/// are legitimately committed, so they are caught by content scanning only.
/// Encrypted (`.enc`), example, and schema files are always allowed.
pub fn sensitive_file_finding(path: &str) -> Option<Finding> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let lower = name.to_ascii_lowercase();

    let allowed = lower.ends_with(".enc")
        || lower == ".envo"
        || lower.ends_with(".envo")
        || lower.contains("example")
        || lower.contains("sample")
        || lower.contains("template")
        || lower.ends_with(".pub");
    if allowed {
        return None;
    }

    let sensitive = lower == ".env"
        || lower == ".env.local"
        || (lower.starts_with(".env.") && lower.ends_with(".local"))
        || lower.ends_with(".secrets")
        || lower.ends_with(".pem")
        || lower.ends_with(".key")
        || lower == "id_rsa"
        || lower == "id_dsa"
        || lower == "id_ecdsa"
        || lower == "id_ed25519";

    if sensitive {
        Some(Finding {
            file: path.to_string(),
            line: 0,
            rule: "Sensitive file committed".to_string(),
            severity: Severity::Critical,
            snippet: format!("`{path}` looks like a secrets file - it should be gitignored"),
        })
    } else {
        None
    }
}

fn build_rules() -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut ci = |name, severity, pattern: &str| {
        rules.push(Rule {
            name,
            severity,
            re: RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .expect("valid regex"),
            placeholder_guarded: false,
        });
    };
    ci(
        "AWS secret access key",
        Severity::Critical,
        r#"aws_secret_access_key\s*[:=]\s*['"]?[A-Za-z0-9/+]{40}"#,
    );

    let mut cs = |name, severity, pattern: &str, guarded: bool| {
        rules.push(Rule {
            name,
            severity,
            re: Regex::new(pattern).expect("valid regex"),
            placeholder_guarded: guarded,
        });
    };
    cs(
        "AWS access key ID",
        Severity::Critical,
        r"AKIA[0-9A-Z]{16}",
        false,
    );
    cs(
        "GitHub token",
        Severity::Critical,
        r"gh[pousr]_[A-Za-z0-9]{36,}",
        false,
    );
    cs(
        "GitHub fine-grained PAT",
        Severity::Critical,
        r"github_pat_[A-Za-z0-9_]{22,}",
        false,
    );
    cs(
        "Slack token",
        Severity::High,
        r"xox[baprs]-[A-Za-z0-9-]{10,}",
        false,
    );
    cs(
        "Slack webhook",
        Severity::High,
        r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
        false,
    );
    cs(
        "Google API key",
        Severity::High,
        r"AIza[0-9A-Za-z_\-]{35}",
        false,
    );
    cs(
        "Google OAuth client secret",
        Severity::High,
        r"GOCSPX-[A-Za-z0-9_\-]{20,}",
        false,
    );
    cs(
        "Stripe secret key",
        Severity::Critical,
        r"sk_live_[0-9A-Za-z]{16,}",
        false,
    );
    cs(
        "Stripe restricted key",
        Severity::High,
        r"rk_live_[0-9A-Za-z]{16,}",
        false,
    );
    cs(
        "Private key block",
        Severity::Critical,
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        false,
    );
    cs(
        "JSON Web Token",
        Severity::Medium,
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        false,
    );

    // Generic "NAME = value" assignment of something secret-looking. Lower
    // severity and placeholder-guarded because it is the most false-positive
    // prone rule.
    rules.push(Rule {
        name: "Generic assigned secret",
        severity: Severity::Medium,
        re: RegexBuilder::new(
            r##"(?:api[_-]?key|secret|token|password|passwd|access[_-]?key|auth[_-]?token)\s*[:=]\s*['"]?([^\s'"#]{8,})"##,
        )
        .case_insensitive(true)
        .build()
        .expect("valid regex"),
        placeholder_guarded: true,
    });

    rules
}

fn is_placeholder(value: &str) -> bool {
    let v = value.trim().trim_matches(|c| c == '"' || c == '\'');
    if v.is_empty() {
        return true;
    }
    // Template/interpolation markers are never real secrets.
    if v.starts_with("${") || v.starts_with('<') || v.starts_with("{{") || v.contains("$(") {
        return true;
    }
    let lower = v.to_ascii_lowercase();
    const NEEDLES: &[&str] = &[
        "changeme",
        "change-me",
        "your_",
        "your-",
        "yourkey",
        "placeholder",
        "example",
        "sample",
        "dummy",
        "redacted",
        "xxxx",
        "todo",
        "secret_here",
        "replace",
        "notreal",
        "fake",
    ];
    if NEEDLES.iter().any(|n| lower.contains(n)) {
        return true;
    }
    // All one repeated char (e.g. "********").
    let first = v.chars().next().unwrap();
    v.chars().all(|c| c == first)
}

/// Replace the sensitive substring inside `line` with a redacted form so the
/// reported snippet never echoes a full secret.
fn redact(line: &str, secret: &str) -> String {
    let masked = mask(secret);
    let replaced = line.replacen(secret, &masked, 1);
    let trimmed = replaced.trim();
    if trimmed.len() > 120 {
        format!("{}...", &trimmed[..117])
    } else {
        trimmed.to_string()
    }
}

fn mask(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 6 {
        return "*".repeat(chars.len().max(3));
    }
    let head: String = chars[..3].iter().collect();
    let tail: String = chars[chars.len() - 2..].iter().collect();
    format!("{head}***{tail}")
}

/// Highest severity in a set of findings, if any.
pub fn max_severity(findings: &[Finding]) -> Option<Severity> {
    findings.iter().map(|f| f.severity).max()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_and_github() {
        let s = Scanner::new(vec![]);
        let text = "key=AKIAIOSFODNN7EXAMPLE\ntoken=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n";
        let f = s.scan_text("x", text);
        assert!(f.iter().any(|x| x.rule == "AWS access key ID"));
        assert!(f.iter().any(|x| x.rule == "GitHub token"));
        // Snippet must not contain the raw secret.
        assert!(f
            .iter()
            .all(|x| !x.snippet.contains("AKIAIOSFODNN7EXAMPLE")));
    }

    #[test]
    fn detects_known_secret_value() {
        let s = Scanner::new(vec!["sup3r-s3cret-db-pass".to_string()]);
        let f = s.scan_text("cfg", "url=postgres://u:sup3r-s3cret-db-pass@host/db");
        assert!(f.iter().any(|x| x.rule == "Known secret value"));
        assert!(f
            .iter()
            .all(|x| !x.snippet.contains("sup3r-s3cret-db-pass")));
    }

    #[test]
    fn ignores_placeholders() {
        let s = Scanner::new(vec!["changeme".to_string()]);
        let f = s.scan_text("x", "API_KEY=changeme\nPASSWORD=your_password_here\n");
        assert!(f.is_empty(), "placeholders should not be flagged: {f:?}");
    }

    #[test]
    fn sensitive_filenames() {
        assert!(sensitive_file_finding(".env").is_some());
        assert!(sensitive_file_finding("config/.env.local").is_some());
        assert!(sensitive_file_finding(".env.production.local").is_some());
        assert!(sensitive_file_finding(".env.secrets").is_some());
        assert!(sensitive_file_finding("server.pem").is_some());
        // Profile files are committed intentionally; content scan covers them.
        assert!(sensitive_file_finding(".env.staging").is_none());
        assert!(sensitive_file_finding(".env.secrets.enc").is_none());
        assert!(sensitive_file_finding(".env.example").is_none());
        assert!(sensitive_file_finding(".envo").is_none());
    }
}

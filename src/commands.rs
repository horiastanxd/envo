//! Command handlers. Each returns the process exit code to use.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;

use anyhow::{bail, Context, Result};

use crate::cli::{
    CheckArgs, Cli, Command, CryptoArgs, ExportArgs, ExportFormat, HookAction, HookArgs, InitArgs,
    ListArgs, RunArgs, ScanArgs,
};
use crate::envfile::{self, EnvMap};
use crate::resolve::{self, ResolveOptions, Resolved};
use crate::schema::Schema;
use crate::{crypto, hook, output as out, scan, validate};

pub fn dispatch(cli: Cli) -> Result<i32> {
    let dir = match &cli.dir {
        Some(d) => d.clone(),
        None => std::env::current_dir().context("getting current directory")?,
    };

    match cli.command {
        Command::Init(args) => cmd_init(&dir, args),
        Command::Check(args) => cmd_check(&dir, args),
        Command::List(args) => cmd_list(&dir, args),
        Command::Run(args) => cmd_run(&dir, args),
        Command::Export(args) => cmd_export(&dir, args),
        Command::Encrypt(args) => cmd_encrypt(&dir, args),
        Command::Decrypt(args) => cmd_decrypt(&dir, args),
        Command::Scan(args) => cmd_scan(&dir, args),
        Command::Hook(args) => cmd_hook(&dir, args),
    }
}

// --- schema loading -------------------------------------------------------

fn schema_path(dir: &Path) -> PathBuf {
    dir.join(".envo")
}

fn load_schema(dir: &Path) -> Result<Schema> {
    let path = schema_path(dir);
    let text = fs::read_to_string(&path).map_err(|_| {
        anyhow::anyhow!(
            "no .envo schema found at {}. Run `envo init` to create one.",
            path.display()
        )
    })?;
    Schema::parse(&text).with_context(|| format!("parsing {}", path.display()))
}

fn load_schema_opt(dir: &Path) -> Result<Option<Schema>> {
    let path = schema_path(dir);
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path)?;
    Ok(Some(
        Schema::parse(&text).with_context(|| format!("parsing {}", path.display()))?,
    ))
}

fn print_warnings(resolved: &Resolved) {
    for w in &resolved.warnings {
        eprintln!("{} {}", out::yellow("warning:"), w);
    }
}

// --- init -----------------------------------------------------------------

const SAMPLE_ENVO: &str = "\
# .envo - typed schema for your environment variables.
# syntax:  NAME: type [= default]   (append ? to mark a variable optional)
# types:   string int number bool port url secret enum(a, b, c)

NODE_ENV: enum(development, staging, production) = development
PORT: port = 3000
HOST: string = \"127.0.0.1\"
DATABASE_URL: url
LOG_LEVEL: enum(debug, info, warn, error) = info
DEBUG: bool = false
API_KEY: secret
SENTRY_DSN: url?
";

const SAMPLE_ENV: &str = "\
# Local values (gitignored). Committed defaults live in .envo; profile config
# in .env.<profile>; secrets in .env.secrets (encrypt to .env.secrets.enc).
DATABASE_URL=postgres://localhost:5432/app
";

const GITIGNORE_LINES: &[&str] = &[".env", ".env.local", "*.secrets", ".envo.key"];

fn cmd_init(dir: &Path, args: InitArgs) -> Result<i32> {
    let envo = schema_path(dir);
    let env = dir.join(".env");
    let mut created = Vec::new();

    write_unless_exists(&envo, SAMPLE_ENVO, args.force, &mut created)?;
    write_unless_exists(&env, SAMPLE_ENV, args.force, &mut created)?;
    let added = ensure_gitignore(dir)?;

    if created.is_empty() && added.is_empty() {
        println!(
            "{} nothing to do (use --force to overwrite .envo / .env)",
            out::yellow("•")
        );
        return Ok(0);
    }
    for path in &created {
        println!("{} created {}", out::green("✓"), rel(dir, path));
    }
    if !added.is_empty() {
        println!(
            "{} updated .gitignore ({})",
            out::green("✓"),
            added.join(", ")
        );
    }
    println!(
        "\nNext: edit {}, then run {}",
        out::bold(".envo"),
        out::bold("envo check")
    );
    Ok(0)
}

fn write_unless_exists(
    path: &Path,
    content: &str,
    force: bool,
    created: &mut Vec<PathBuf>,
) -> Result<()> {
    if path.exists() && !force {
        return Ok(());
    }
    fs::write(path, content).with_context(|| format!("writing {}", path.display()))?;
    created.push(path.to_path_buf());
    Ok(())
}

fn ensure_gitignore(dir: &Path) -> Result<Vec<String>> {
    let path = dir.join(".gitignore");
    let existing = fs::read_to_string(&path).unwrap_or_default();
    let present: Vec<&str> = existing.lines().map(|l| l.trim()).collect();
    let mut to_add = Vec::new();
    for line in GITIGNORE_LINES {
        if !present.iter().any(|l| l == line) {
            to_add.push(line.to_string());
        }
    }
    if to_add.is_empty() {
        return Ok(to_add);
    }
    let mut content = existing;
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str("\n# envo\n");
    for line in &to_add {
        content.push_str(line);
        content.push('\n');
    }
    fs::write(&path, content).with_context(|| format!("writing {}", path.display()))?;
    Ok(to_add)
}

// --- check ----------------------------------------------------------------

fn cmd_check(dir: &Path, args: CheckArgs) -> Result<i32> {
    let schema = load_schema(dir)?;
    let resolved = resolve::resolve(
        &schema,
        &ResolveOptions {
            dir,
            profile: args.profile.as_deref(),
            include_process_env: !args.no_process_env,
            decrypt_secrets: true,
            key_file: args.key_file.as_deref(),
        },
    )?;
    print_warnings(&resolved);

    let report = validate::validate(&schema, &resolved);

    for name in &report.missing {
        let spec = schema.get(name).unwrap();
        println!(
            "{} {} {}",
            out::red("✗"),
            out::bold(name),
            out::dim(&format!("missing (required {})", spec.ty.name())),
        );
    }
    for (name, reason) in &report.invalid {
        println!("{} {} {}", out::red("✗"), out::bold(name), out::dim(reason),);
    }
    if args.strict {
        for name in &report.extra {
            println!(
                "{} {} {}",
                out::yellow("!"),
                out::bold(name),
                out::dim("not declared in schema"),
            );
        }
    } else if !report.extra.is_empty() {
        println!(
            "{} {} undeclared variable(s): {}",
            out::dim("•"),
            out::dim(&report.extra.len().to_string()),
            out::dim(&report.extra.join(", ")),
        );
    }

    if report.failed(args.strict) {
        let problems = report.missing.len() + report.invalid.len();
        println!(
            "\n{} {} problem(s) found",
            out::red("✗"),
            out::bold(&problems.to_string())
        );
        Ok(1)
    } else {
        let checked = schema.vars.len();
        println!(
            "{} all {} variable(s) valid",
            out::green("✓"),
            out::bold(&checked.to_string())
        );
        Ok(0)
    }
}

// --- list -----------------------------------------------------------------

fn cmd_list(dir: &Path, args: ListArgs) -> Result<i32> {
    let schema = load_schema(dir)?;
    let resolved = resolve::resolve(
        &schema,
        &ResolveOptions {
            dir,
            profile: args.profile.as_deref(),
            include_process_env: args.process_env,
            decrypt_secrets: true,
            key_file: args.key_file.as_deref(),
        },
    )?;
    print_warnings(&resolved);

    if args.json {
        print_json_object(resolved.values.iter().map(|(k, v)| {
            let display = if is_secret(&schema, k) && !args.show_secrets {
                "<hidden>".to_string()
            } else {
                v.to_string()
            };
            (k.to_string(), display)
        }));
        return Ok(0);
    }

    if resolved.values.is_empty() {
        println!("{}", out::dim("(no variables resolved)"));
        return Ok(0);
    }

    let name_w = resolved.values.keys().map(|k| k.len()).max().unwrap_or(0);
    for (k, v) in resolved.values.iter() {
        let value = if is_secret(&schema, k) && !args.show_secrets {
            out::dim("<hidden>")
        } else {
            v.to_string()
        };
        let src = resolved
            .source_of(k)
            .map(|s| s.label())
            .unwrap_or("unknown");
        println!(
            "{:<width$}  {}  {}",
            out::bold(k),
            value,
            out::dim(&format!("({src})")),
            width = name_w + bold_pad(k),
        );
    }
    Ok(0)
}

fn is_secret(schema: &Schema, name: &str) -> bool {
    schema.get(name).map(|s| s.ty.is_secret()).unwrap_or(false)
}

/// `out::bold` wraps the key in ANSI codes (when enabled), which throws off the
/// `{:<width}` padding. Compensate by adding the invisible byte count.
fn bold_pad(key: &str) -> usize {
    if out::color_enabled() {
        out::bold(key).len() - key.len()
    } else {
        0
    }
}

// --- run ------------------------------------------------------------------

fn cmd_run(dir: &Path, args: RunArgs) -> Result<i32> {
    let schema = load_schema(dir)?;
    let resolved = resolve::resolve(
        &schema,
        &ResolveOptions {
            dir,
            profile: args.profile.as_deref(),
            include_process_env: true,
            decrypt_secrets: true,
            key_file: args.key_file.as_deref(),
        },
    )?;
    print_warnings(&resolved);

    if !args.no_validate {
        let report = validate::validate(&schema, &resolved);
        if !report.passed() {
            for name in &report.missing {
                eprintln!("{} {} missing", out::red("✗"), out::bold(name));
            }
            for (name, reason) in &report.invalid {
                eprintln!("{} {} {}", out::red("✗"), out::bold(name), out::dim(reason));
            }
            eprintln!(
                "{} refusing to run with an invalid environment (use --no-validate to override)",
                out::red("error:")
            );
            return Ok(1);
        }
    }

    let (program, rest) = args
        .cmd
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("no command given"))?;

    let mut command = ProcCommand::new(program);
    command.args(rest).current_dir(dir);
    for (k, v) in resolved.values.iter() {
        command.env(k, v);
    }

    let status = command
        .status()
        .with_context(|| format!("failed to run `{program}`"))?;
    Ok(status.code().unwrap_or(1))
}

// --- export ---------------------------------------------------------------

fn cmd_export(dir: &Path, args: ExportArgs) -> Result<i32> {
    let schema = load_schema(dir)?;
    let resolved = resolve::resolve(
        &schema,
        &ResolveOptions {
            dir,
            profile: args.profile.as_deref(),
            include_process_env: false,
            decrypt_secrets: true,
            key_file: args.key_file.as_deref(),
        },
    )?;
    print_warnings(&resolved);

    match args.format {
        ExportFormat::Dotenv => {
            let mut map = EnvMap::new();
            for (k, v) in resolved.values.iter() {
                map.set(k.to_string(), v.to_string());
            }
            print!("{}", envfile::to_dotenv(&map));
        }
        ExportFormat::Shell => {
            for (k, v) in resolved.values.iter() {
                println!("export {k}={}", shell_quote(v));
            }
        }
        ExportFormat::Json => {
            print_json_object(
                resolved
                    .values
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string())),
            );
        }
    }
    Ok(0)
}

fn shell_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', "'\\''"))
}

// --- encrypt / decrypt ----------------------------------------------------

fn cmd_encrypt(dir: &Path, args: CryptoArgs) -> Result<i32> {
    let input = args.input.unwrap_or_else(|| dir.join(".env.secrets"));
    if !input.exists() {
        bail!("input file {} does not exist", input.display());
    }
    let output = args.output.unwrap_or_else(|| with_enc_suffix(&input));
    let plaintext = fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
    let pass = crypto::resolve_passphrase(dir, args.key_file.as_deref())?;
    let envelope = crypto::encrypt(&plaintext, pass.as_bytes())?;
    fs::write(&output, envelope).with_context(|| format!("writing {}", output.display()))?;
    println!(
        "{} encrypted {} -> {}",
        out::green("✓"),
        rel(dir, &input),
        rel(dir, &output)
    );
    println!(
        "{} keep {} out of git (it holds plaintext secrets)",
        out::dim("•"),
        rel(dir, &input)
    );
    Ok(0)
}

fn cmd_decrypt(dir: &Path, args: CryptoArgs) -> Result<i32> {
    let input = args.input.unwrap_or_else(|| dir.join(".env.secrets.enc"));
    if !input.exists() {
        bail!("input file {} does not exist", input.display());
    }
    let output = args.output.unwrap_or_else(|| strip_enc_suffix(&input));
    let envelope =
        fs::read_to_string(&input).with_context(|| format!("reading {}", input.display()))?;
    let pass = crypto::resolve_passphrase(dir, args.key_file.as_deref())?;
    let plaintext = crypto::decrypt(&envelope, pass.as_bytes())?;
    fs::write(&output, &plaintext).with_context(|| format!("writing {}", output.display()))?;
    println!(
        "{} decrypted {} -> {}",
        out::green("✓"),
        rel(dir, &input),
        rel(dir, &output)
    );
    Ok(0)
}

fn with_enc_suffix(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".enc");
    PathBuf::from(s)
}

fn strip_enc_suffix(path: &Path) -> PathBuf {
    match path.extension().and_then(|e| e.to_str()) {
        Some("enc") => path.with_extension(""),
        _ => with_extension_suffix(path, ".dec"),
    }
}

fn with_extension_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

// --- scan -----------------------------------------------------------------

fn cmd_scan(dir: &Path, args: ScanArgs) -> Result<i32> {
    // Secret values from the schema make leak detection precise.
    let secret_values = collect_secret_values(dir).unwrap_or_default();
    let scanner = scan::Scanner::new(secret_values);

    let (files, check_sensitive) = gather_scan_targets(dir, &args)?;
    let mut findings = Vec::new();

    for (label, content) in &files {
        findings.extend(scanner.scan_text(label, content));
    }
    if check_sensitive {
        for (label, _) in &files {
            if let Some(f) = scan::sensitive_file_finding(label) {
                findings.push(f);
            }
        }
    }

    if findings.is_empty() {
        println!(
            "{} no secrets detected in {} file(s)",
            out::green("✓"),
            files.len()
        );
        return Ok(0);
    }

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    for f in &findings {
        let loc = if f.line > 0 {
            format!("{}:{}", f.file, f.line)
        } else {
            f.file.clone()
        };
        println!(
            "{} {} {}\n    {}",
            severity_tag(f.severity),
            out::bold(&loc),
            out::dim(&f.rule),
            f.snippet,
        );
    }

    let max = scan::max_severity(&findings).unwrap();
    let fail = max >= scan::Severity::High || (args.strict && max >= scan::Severity::Medium);
    println!(
        "\n{} {} finding(s)",
        if fail {
            out::red("✗")
        } else {
            out::yellow("!")
        },
        out::bold(&findings.len().to_string()),
    );
    Ok(if fail { 1 } else { 0 })
}

fn severity_tag(sev: scan::Severity) -> String {
    match sev {
        scan::Severity::Critical => out::red("[critical]"),
        scan::Severity::High => out::red("[high]"),
        scan::Severity::Medium => out::yellow("[medium]"),
    }
}

fn collect_secret_values(dir: &Path) -> Result<Vec<String>> {
    let schema = match load_schema_opt(dir)? {
        Some(s) => s,
        None => return Ok(Vec::new()),
    };
    let resolved = resolve::resolve(
        &schema,
        &ResolveOptions {
            dir,
            profile: None,
            include_process_env: false,
            decrypt_secrets: true,
            key_file: None,
        },
    )?;
    let mut values = Vec::new();
    for spec in &schema.vars {
        if spec.ty.is_secret() {
            if let Some(v) = resolved.values.get(&spec.name) {
                values.push(v.to_string());
            }
        }
    }
    Ok(values)
}

/// Returns `(labelled file contents, whether to apply the sensitive-filename
/// check)`. The sensitive check only applies when the files are tracked/staged
/// (i.e. actually committed), not for ad-hoc path scans.
fn gather_scan_targets(dir: &Path, args: &ScanArgs) -> Result<(Vec<(String, String)>, bool)> {
    if args.staged {
        return Ok((staged_files(dir)?, true));
    }
    if !args.paths.is_empty() {
        let mut files = Vec::new();
        for p in &args.paths {
            collect_path(p, &mut files);
        }
        return Ok((files, false));
    }
    if let Some(files) = tracked_files(dir)? {
        return Ok((files, true));
    }
    // Not a git repo: walk the directory.
    let mut files = Vec::new();
    walk_dir(dir, dir, &mut files);
    Ok((files, false))
}

fn staged_files(dir: &Path) -> Result<Vec<(String, String)>> {
    let list = git(
        dir,
        &["diff", "--cached", "--name-only", "--diff-filter=ACMR"],
    )
    .context("listing staged files (is this a git repo with staged changes?)")?;
    let mut files = Vec::new();
    for name in list.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Some(content) = git(dir, &["show", &format!(":{name}")]) {
            if !is_binary(content.as_bytes()) {
                files.push((name.to_string(), content));
            }
        }
    }
    Ok(files)
}

fn tracked_files(dir: &Path) -> Result<Option<Vec<(String, String)>>> {
    let root = match git(dir, &["rev-parse", "--show-toplevel"]) {
        Some(r) => PathBuf::from(r.trim()),
        None => return Ok(None),
    };
    let list = git(dir, &["ls-files"]).unwrap_or_default();
    let mut files = Vec::new();
    for name in list.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let path = root.join(name);
        if let Some(content) = read_text_file(&path) {
            files.push((name.to_string(), content));
        }
    }
    Ok(Some(files))
}

fn collect_path(path: &Path, files: &mut Vec<(String, String)>) {
    if path.is_dir() {
        let base = path.to_path_buf();
        walk_dir(&base, &base, files);
    } else if let Some(content) = read_text_file(path) {
        files.push((path.display().to_string(), content));
    }
}

const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".next",
    "dist",
    "build",
    "vendor",
    ".venv",
    "__pycache__",
];

fn walk_dir(base: &Path, current: &Path, files: &mut Vec<(String, String)>) {
    let entries = match fs::read_dir(current) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            walk_dir(base, &path, files);
        } else if let Some(content) = read_text_file(&path) {
            let label = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .display()
                .to_string();
            files.push((label, content));
        }
    }
}

fn read_text_file(path: &Path) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if meta.len() > 1_048_576 {
        return None; // skip files larger than 1 MiB
    }
    let bytes = fs::read(path).ok()?;
    if is_binary(&bytes) {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn is_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8000).any(|&b| b == 0)
}

/// Run a git command in `dir`, returning stdout on success, `None` otherwise.
fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let output = ProcCommand::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        None
    }
}

// --- hook -----------------------------------------------------------------

fn cmd_hook(dir: &Path, args: HookArgs) -> Result<i32> {
    match args.action {
        HookAction::Install(install) => {
            let path = hook::install(dir, install.with_check)?;
            println!(
                "{} installed pre-commit hook at {}",
                out::green("✓"),
                path.display()
            );
            if install.with_check {
                println!(
                    "{} hook runs: envo check && envo scan --staged",
                    out::dim("•")
                );
            } else {
                println!("{} hook runs: envo scan --staged", out::dim("•"));
            }
            Ok(0)
        }
        HookAction::Uninstall => {
            if hook::uninstall(dir)? {
                println!("{} removed envo pre-commit hook", out::green("✓"));
            } else {
                println!("{} no envo hook found", out::yellow("•"));
            }
            Ok(0)
        }
    }
}

// --- shared helpers -------------------------------------------------------

fn rel(dir: &Path, path: &Path) -> String {
    path.strip_prefix(dir).unwrap_or(path).display().to_string()
}

fn print_json_object<I: Iterator<Item = (String, String)>>(pairs: I) {
    let items: Vec<(String, String)> = pairs.collect();
    if items.is_empty() {
        println!("{{}}");
        return;
    }
    let mut out = String::from("{\n");
    for (i, (k, v)) in items.iter().enumerate() {
        out.push_str("  \"");
        out.push_str(&json_escape(k));
        out.push_str("\": \"");
        out.push_str(&json_escape(v));
        out.push('"');
        if i + 1 < items.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push('}');
    println!("{out}");
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

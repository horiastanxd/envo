//! Layered resolution of environment values.
//!
//! Precedence, lowest to highest (later layers win):
//!   1. schema defaults
//!   2. `.env`                (committed base values)
//!   3. `.env.<profile>`      (per-profile overrides)
//!   4. `.env.local`          (gitignored local overrides)
//!   5. secret files (`.env.secrets`, `.env.<profile>.secrets`, plaintext/.enc)
//!   6. process environment   (optional; for `check`/`run`)

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::crypto;
use crate::envfile::{self, EnvMap};
use crate::schema::Schema;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Default,
    Base,
    Profile,
    Local,
    Secret,
    Process,
}

impl Source {
    pub fn label(&self) -> &'static str {
        match self {
            Source::Default => "default",
            Source::Base => ".env",
            Source::Profile => "profile",
            Source::Local => ".env.local",
            Source::Secret => "secret",
            Source::Process => "process-env",
        }
    }
}

#[derive(Debug, Default)]
pub struct Resolved {
    pub values: EnvMap,
    pub provenance: HashMap<String, Source>,
    /// Non-fatal issues encountered while resolving (e.g. an encrypted secrets
    /// file present but no key available).
    pub warnings: Vec<String>,
}

impl Resolved {
    pub fn source_of(&self, key: &str) -> Option<Source> {
        self.provenance.get(key).copied()
    }
}

pub struct ResolveOptions<'a> {
    pub dir: &'a Path,
    pub profile: Option<&'a str>,
    pub include_process_env: bool,
    pub decrypt_secrets: bool,
    pub key_file: Option<&'a Path>,
}

/// Resolve all layers into a single ordered map plus provenance.
pub fn resolve(schema: &Schema, opts: &ResolveOptions) -> Result<Resolved> {
    let mut out = Resolved::default();

    // 1. schema defaults
    for spec in &schema.vars {
        if let Some(def) = &spec.default {
            out.values.set(spec.name.clone(), def.clone());
            out.provenance.insert(spec.name.clone(), Source::Default);
        }
    }

    // 2-4. plaintext layer files
    apply_file(&opts.dir.join(".env"), Source::Base, &mut out)?;
    if let Some(profile) = opts.profile {
        apply_file(
            &opts.dir.join(format!(".env.{profile}")),
            Source::Profile,
            &mut out,
        )?;
    }
    apply_file(&opts.dir.join(".env.local"), Source::Local, &mut out)?;

    // 5. secret files (plaintext or encrypted)
    if opts.decrypt_secrets {
        let mut secret_bases = vec![".env.secrets".to_string()];
        if let Some(profile) = opts.profile {
            secret_bases.push(format!(".env.{profile}.secrets"));
        }
        secret_bases.push(".env.local.secrets".to_string());
        for base in secret_bases {
            apply_secret_file(opts.dir, &base, opts.key_file, &mut out)?;
        }
    }

    // 6. process environment (declared keys only, to avoid polluting output)
    if opts.include_process_env {
        for spec in &schema.vars {
            if let Ok(val) = std::env::var(&spec.name) {
                out.values.set(spec.name.clone(), val);
                out.provenance.insert(spec.name.clone(), Source::Process);
            }
        }
    }

    Ok(out)
}

fn apply_file(path: &Path, src: Source, out: &mut Resolved) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let map = envfile::parse(&text).with_context(|| format!("parsing {}", path.display()))?;
    merge(&map, src, out);
    Ok(true)
}

fn apply_secret_file(
    dir: &Path,
    base: &str,
    key_file: Option<&Path>,
    out: &mut Resolved,
) -> Result<()> {
    let plain = dir.join(base);
    let enc = dir.join(format!("{base}.enc"));

    if plain.exists() {
        let text =
            fs::read_to_string(&plain).with_context(|| format!("reading {}", plain.display()))?;
        let map = envfile::parse(&text).with_context(|| format!("parsing {}", plain.display()))?;
        merge(&map, Source::Secret, out);
        return Ok(());
    }

    if enc.exists() {
        let envelope =
            fs::read_to_string(&enc).with_context(|| format!("reading {}", enc.display()))?;
        match crypto::resolve_passphrase(dir, key_file) {
            Ok(pass) => match crypto::decrypt(&envelope, pass.as_bytes()) {
                Ok(plaintext) => {
                    let text = String::from_utf8_lossy(&plaintext);
                    let map = envfile::parse(&text)
                        .with_context(|| format!("parsing decrypted {}", enc.display()))?;
                    merge(&map, Source::Secret, out);
                }
                Err(e) => out
                    .warnings
                    .push(format!("could not decrypt {}: {e}", enc.display())),
            },
            Err(e) => out
                .warnings
                .push(format!("{} present but {e}", enc.display())),
        }
    }
    Ok(())
}

fn merge(map: &EnvMap, src: Source, out: &mut Resolved) {
    for (k, v) in map.iter() {
        out.values.set(k.to_string(), v.to_string());
        out.provenance.insert(k.to_string(), src);
    }
}

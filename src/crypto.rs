//! Encryption at rest for secrets files.
//!
//! A passphrase is stretched into a 32-byte key with Argon2id (memory-hard),
//! then the plaintext is sealed with XChaCha20-Poly1305 (authenticated, 24-byte
//! random nonce). The on-disk envelope is a small text format so encrypted
//! secrets can be committed and diffed line by line.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::Zeroizing;

const MAGIC: &str = "ENVO-ENC-v1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Encrypt `plaintext` with `passphrase`, returning the text envelope.
pub fn encrypt(plaintext: &[u8], passphrase: &[u8]) -> Result<String> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow!("encryption failed"))?;

    Ok(format!(
        "{MAGIC}\n{}\n{}\n{}\n",
        B64.encode(salt),
        B64.encode(nonce_bytes),
        B64.encode(ciphertext),
    ))
}

/// Decrypt an envelope produced by [`encrypt`].
pub fn decrypt(envelope: &str, passphrase: &[u8]) -> Result<Vec<u8>> {
    let mut lines = envelope.lines();
    let magic = lines.next().unwrap_or_default().trim();
    if magic != MAGIC {
        bail!("not an envo-encrypted file (missing `{MAGIC}` header)");
    }
    let salt = B64
        .decode(next_field(&mut lines)?)
        .context("invalid base64 salt")?;
    let nonce = B64
        .decode(next_field(&mut lines)?)
        .context("invalid base64 nonce")?;
    let ciphertext = B64
        .decode(next_field(&mut lines)?)
        .context("invalid base64 ciphertext")?;
    if nonce.len() != NONCE_LEN {
        bail!("corrupt envelope: bad nonce length");
    }

    let key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow!("decryption failed (wrong key or corrupted data)"))
}

fn next_field<'a>(lines: &mut std::str::Lines<'a>) -> Result<&'a str> {
    loop {
        let line = lines.next().ok_or_else(|| anyhow!("truncated envelope"))?;
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
}

/// Quick check used by tooling to decide whether a file is an envo envelope.
pub fn looks_encrypted(text: &str) -> bool {
    text.trim_start().starts_with(MAGIC)
}

/// Find the passphrase for crypto operations, in priority order:
/// 1. an explicit `--key-file`
/// 2. the `ENVO_KEY` environment variable
/// 3. `<project>/.envo.key`
/// 4. `$XDG_CONFIG_HOME/envo/key` (or `~/.config/envo/key`)
pub fn resolve_passphrase(
    project_dir: &Path,
    key_file: Option<&Path>,
) -> Result<Zeroizing<String>> {
    if let Some(path) = key_file {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading key file {}", path.display()))?;
        return Ok(Zeroizing::new(raw.trim().to_string()));
    }
    if let Ok(val) = std::env::var("ENVO_KEY") {
        if !val.is_empty() {
            return Ok(Zeroizing::new(val));
        }
    }
    let local = project_dir.join(".envo.key");
    if local.exists() {
        let raw = std::fs::read_to_string(&local)
            .with_context(|| format!("reading {}", local.display()))?;
        return Ok(Zeroizing::new(raw.trim().to_string()));
    }
    if let Some(global) = global_key_path() {
        if global.exists() {
            let raw = std::fs::read_to_string(&global)
                .with_context(|| format!("reading {}", global.display()))?;
            return Ok(Zeroizing::new(raw.trim().to_string()));
        }
    }
    bail!(
        "no encryption key found. Set ENVO_KEY, pass --key-file <path>, \
         or create a .envo.key file"
    )
}

fn global_key_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("envo").join("key"));
        }
    }
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".config").join("envo").join("key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let pt = b"API_KEY=super-secret-value\nTOKEN=abc123\n";
        let env = encrypt(pt, b"correct horse battery staple").unwrap();
        assert!(looks_encrypted(&env));
        let back = decrypt(&env, b"correct horse battery staple").unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn wrong_key_fails() {
        let env = encrypt(b"secret", b"right-key").unwrap();
        assert!(decrypt(&env, b"wrong-key").is_err());
    }

    #[test]
    fn distinct_ciphertexts() {
        // Random salt + nonce => same plaintext encrypts differently each time.
        let a = encrypt(b"x", b"k").unwrap();
        let b = encrypt(b"x", b"k").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_non_envelope() {
        assert!(decrypt("just some text", b"k").is_err());
    }
}

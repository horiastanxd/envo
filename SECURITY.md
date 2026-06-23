# Security Policy

envo's job is to keep secrets typed, encrypted, and out of commits, so its own
security matters.

## Reporting a vulnerability

Please report security issues privately via
[GitHub Security Advisories](https://github.com/horiastanxd/envo/security/advisories/new)
rather than a public issue. You will get an acknowledgement within a few days.

## Scope

Particularly interested in reports where:

- `envo scan` fails to flag a known secret (a false negative), or a `secret`
  value leaks into output unredacted.
- A weakness in the encryption envelope (`envo encrypt`): nonce/salt handling,
  key derivation, or the file format.
- The npm installer or `install.sh` could be tricked into running or installing
  untrusted code.

## Good to know

- The binary makes **no network calls**. It only reads and writes the local
  filesystem and runs the command you pass to `envo run`.
- Encryption uses XChaCha20-Poly1305 (AEAD) with a key derived from your
  passphrase via Argon2id. Salt and nonce are random per encryption.
- The npm package downloads a prebuilt binary from this repository's GitHub
  Releases over HTTPS; SHA-256 checksums are published alongside the binaries.

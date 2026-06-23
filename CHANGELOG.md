# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-06-23

Initial release.

### Added
- Typed `.envo` schema: `string`, `int`, `number`, `bool`, `port`, `url`,
  `secret`, and `enum(...)` types, with defaults and optional (`?`) markers.
- Layered resolution across schema defaults, `.env`, `.env.<profile>`,
  `.env.local`, secret files, and the process environment, with per-variable
  provenance.
- `envo check` - validate the resolved environment against the schema.
- `envo run` - validate then execute a command with the env injected.
- `envo list` / `envo export` (`dotenv` / `shell` / `json`).
- Encryption at rest with XChaCha20-Poly1305 + Argon2id (`envo encrypt` /
  `envo decrypt`); encrypted secrets decrypt transparently during resolution.
- `envo scan` - secret-leak detection for common credential formats plus the
  literal values of `secret` variables, with redacted output.
- `envo hook install` / `uninstall` - managed git pre-commit hook.
- `envo init` - scaffold a schema and safe `.gitignore` entries.

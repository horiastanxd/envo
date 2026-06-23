# Contributing

Thanks for considering a contribution. envo is a small, focused Rust CLI - easy
to hack on.

## Setup

```bash
git clone https://github.com/horiastanxd/envo
cd envo
cargo test        # runs the full suite (unit + integration)
cargo run -- --help
```

## Before opening a PR

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all
```

CI runs exactly these three.

## Especially welcome

- **Leak-detection patterns** for `envo scan` - add a rule in `build_rules()`
  in `src/scan.rs` plus a test. Keep false positives low (placeholder-guard the
  generic ones).
- **New schema types** - extend `VarType` in `src/schema.rs` with parsing and a
  `validate_value` arm, and a test.
- **Output formats** for `envo export`.

## Conventions

- Tests first - every behavior change ships with a test (see `tests/` and the
  `#[cfg(test)]` modules).
- Keep the binary dependency-light and the default output friendly.
- Crypto stays standard: XChaCha20-Poly1305 + Argon2id. No home-rolled schemes.

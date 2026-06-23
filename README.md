# envo

**A typed `.env` manager.** Schema with types, profile inheritance, secret-leak
detection, and encryption at rest - in one fast, dependency-free binary.

`dotenv` loads a file. `envo` gives `.env` a *contract*: declare each variable
once with a type, layer values across environments, keep secrets encrypted, and
stop them from ever reaching a commit.

```
$ envo check
✗ DATABASE_URL  `notaurl` is not a valid URL (expected scheme://...)
✗ API_KEY       missing (required secret)
✗ 2 problem(s) found
```

---

## Why

Every project re-invents the same broken `.env` ritual:

- **No schema.** Nothing says which variables exist, what type they are, or
  which are required. A typo'd `PROT=3000` fails at runtime, in production.
- **No inheritance.** `base` / `staging` / `local` are copy-pasted files that
  drift apart.
- **Secrets leak.** `.env` gets `git add .`-ed by accident roughly once per
  career. There is no guardrail.
- **Plaintext at rest.** Secrets sit unencrypted on disk and in dotfiles.

`envo` fixes all four with a single schema file and a handful of subcommands.

## Install

```sh
cargo install envo-cli      # installs the `envo` binary
```

Or build from source:

```sh
git clone https://github.com/horiastanxd/envo
cd envo && cargo build --release
# binary at target/release/envo
```

## Quick start

```sh
envo init          # creates .envo (schema) + .env + .gitignore entries
envo check         # validate the resolved environment
envo run -- npm start   # validate, then run with the env injected
```

## The `.envo` schema

One line per variable: `NAME: type [= default]`. Append `?` to make a variable
optional. Anything without a default and without `?` is **required**.

```ini
# .envo
NODE_ENV: enum(development, staging, production) = development
PORT: port = 3000
HOST: string = "127.0.0.1"
DATABASE_URL: url
LOG_LEVEL: enum(debug, info, warn, error) = info
DEBUG: bool = false
API_KEY: secret
SENTRY_DSN: url?            # optional
```

### Types

| Type            | Accepts                                              |
|-----------------|------------------------------------------------------|
| `string`        | any value                                            |
| `int`           | integers                                             |
| `number`        | integers or floats                                   |
| `bool`          | `true`/`false`/`1`/`0`/`yes`/`no`/`on`/`off`         |
| `port`          | `1`-`65535`                                           |
| `url`           | `scheme://...`                                       |
| `secret`        | any value, but hidden from output and leak-scanned   |
| `enum(a, b, c)` | one of the listed values                             |

## Layered resolution

Values resolve through layers - **later layers win** - and `envo` remembers
where each value came from:

| Order | Source                | Committed? | Purpose                         |
|-------|-----------------------|------------|---------------------------------|
| 1     | schema defaults       | yes (`.envo`) | safe baseline                |
| 2     | `.env`                | no         | your local values               |
| 3     | `.env.<profile>`      | yes        | per-environment config          |
| 4     | `.env.local`          | no         | local overrides                 |
| 5     | secrets (`.env.secrets` / `.env.secrets.enc`) | only `.enc` | encrypted secrets |
| 6     | process environment   | -          | CI / shell overrides            |

```sh
$ envo list --profile staging
NODE_ENV      staging         (profile)
PORT          8080            (profile)
DATABASE_URL  postgres://...  (.env)
API_KEY       <hidden>        (secret)
```

## Encryption at rest

Secrets are sealed with **XChaCha20-Poly1305** using a key stretched from your
passphrase with **Argon2id**. The encrypted envelope is text, so it diffs
cleanly and is safe to commit.

```sh
export ENVO_KEY="your-team-passphrase"     # or use --key-file / .envo.key

echo 'API_KEY=sk_live_...' > .env.secrets
envo encrypt                                # -> .env.secrets.enc (commit this)
rm .env.secrets                             # the plaintext is gitignored anyway

envo check                                  # decrypts .enc transparently
envo decrypt                                # -> .env.secrets when you need it
```

Key lookup order: `--key-file` → `ENVO_KEY` → `./.envo.key` → `~/.config/envo/key`.

## Secret-leak detection

`envo scan` catches credentials before they are committed: AWS keys, GitHub
tokens, Slack tokens, Stripe keys, Google API keys, private-key blocks, JWTs,
generic `SECRET=...` assignments - **plus the actual values of your `secret`
variables**, so a leaked password is caught even with no recognizable prefix.
Matches are redacted in the output.

```sh
envo scan                 # scan tracked files
envo scan --staged        # scan what's staged (used by the hook)
envo scan src/ config/    # scan specific paths
```

```
[critical] src/db.js:12  GitHub token
    const t = "ghp***yz";
[critical] .env.local     Sensitive file committed
    `.env.local` looks like a secrets file - it should be gitignored
✗ 2 finding(s)
```

### Pre-commit hook

```sh
envo hook install              # runs `envo scan --staged` before every commit
envo hook install --with-check # also run `envo check`
envo hook uninstall
```

The hook is written as a managed block, so it coexists with any existing
`pre-commit` script and is removed cleanly.

## Commands

| Command        | Description                                               |
|----------------|-----------------------------------------------------------|
| `envo init`    | create a starter `.envo`, `.env`, and `.gitignore` entries |
| `envo check`   | validate the resolved environment against the schema      |
| `envo list`    | print resolved variables and their source                 |
| `envo run`     | validate, then run a command with the env injected         |
| `envo export`  | emit the env as `dotenv`, `shell`, or `json`              |
| `envo encrypt` | encrypt a plaintext secrets file                          |
| `envo decrypt` | decrypt an encrypted secrets file                         |
| `envo scan`    | scan files for leaked secrets                             |
| `envo hook`    | install / uninstall the git pre-commit hook              |

Global flags: `-C, --dir <DIR>` (project directory), `--no-color`.
`check` / `list` / `run` / `export` take `-p, --profile <NAME>`.

## Exit codes

| Code | Meaning                                  |
|------|------------------------------------------|
| `0`  | success / clean                          |
| `1`  | validation failed or secrets detected    |
| `2`  | usage or I/O error                       |

Suitable for CI: `envo check && envo scan` gates a pipeline.

## License

MIT © Horia Stan

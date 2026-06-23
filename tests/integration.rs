//! End-to-end tests that drive the compiled `envo` binary.

use std::fs;
use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn envo(dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("envo").unwrap();
    cmd.current_dir(dir).arg("--no-color");
    cmd
}

fn write(dir: &Path, name: &str, content: &str) {
    fs::write(dir.join(name), content).unwrap();
}

#[test]
fn init_creates_schema_and_gitignore() {
    let tmp = TempDir::new().unwrap();
    envo(tmp.path()).arg("init").assert().success();
    assert!(tmp.path().join(".envo").exists());
    assert!(tmp.path().join(".env").exists());
    let gitignore = fs::read_to_string(tmp.path().join(".gitignore")).unwrap();
    assert!(gitignore.contains(".env.local"));
    assert!(gitignore.contains("*.secrets"));
}

#[test]
fn check_fails_when_required_missing_then_passes() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), ".envo", "PORT: port = 3000\nAPI_KEY: secret\n");

    // No API_KEY -> failure.
    envo(tmp.path())
        .arg("check")
        .assert()
        .failure()
        .stdout(predicate::str::contains("API_KEY"));

    // Provide it -> success.
    write(tmp.path(), ".env", "API_KEY=abc123\n");
    envo(tmp.path())
        .arg("check")
        .assert()
        .success()
        .stdout(predicate::str::contains("valid"));
}

#[test]
fn check_rejects_invalid_type() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), ".envo", "PORT: port\n");
    write(tmp.path(), ".env", "PORT=99999\n");
    envo(tmp.path())
        .arg("check")
        .assert()
        .failure()
        .stdout(predicate::str::contains("not a valid port"));
}

#[test]
fn profile_overrides_base() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), ".envo", "PORT: port = 3000\n");
    write(tmp.path(), ".env.staging", "PORT=8080\n");
    envo(tmp.path())
        .args(["list", "--profile", "staging"])
        .assert()
        .success()
        .stdout(predicate::str::contains("8080").and(predicate::str::contains("profile")));
}

#[test]
fn encrypt_decrypt_roundtrip_via_cli() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), ".envo", "API_KEY: secret\n");
    write(tmp.path(), ".env.secrets", "API_KEY=top-secret-value\n");

    envo(tmp.path())
        .arg("encrypt")
        .env("ENVO_KEY", "passphrase")
        .assert()
        .success();
    let enc = fs::read_to_string(tmp.path().join(".env.secrets.enc")).unwrap();
    assert!(enc.starts_with("ENVO-ENC-v1"));
    assert!(!enc.contains("top-secret-value"));

    fs::remove_file(tmp.path().join(".env.secrets")).unwrap();
    envo(tmp.path())
        .arg("decrypt")
        .env("ENVO_KEY", "passphrase")
        .assert()
        .success();
    let dec = fs::read_to_string(tmp.path().join(".env.secrets")).unwrap();
    assert_eq!(dec, "API_KEY=top-secret-value\n");

    // check resolves the secret straight from the encrypted file.
    fs::remove_file(tmp.path().join(".env.secrets")).unwrap();
    envo(tmp.path())
        .arg("check")
        .env("ENVO_KEY", "passphrase")
        .assert()
        .success();
}

#[test]
fn decrypt_with_wrong_key_fails() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), ".env.secrets", "X=1\n");
    envo(tmp.path())
        .arg("encrypt")
        .env("ENVO_KEY", "right")
        .assert()
        .success();
    fs::remove_file(tmp.path().join(".env.secrets")).unwrap();
    envo(tmp.path())
        .arg("decrypt")
        .env("ENVO_KEY", "wrong")
        .assert()
        .failure()
        .stderr(predicate::str::contains("decryption failed"));
}

#[test]
fn scan_detects_secret_in_path() {
    let tmp = TempDir::new().unwrap();
    write(
        tmp.path(),
        "leak.js",
        "const t = 'ghp_0123456789abcdefghijklmnopqrstuvwxyz';\n",
    );
    envo(tmp.path())
        .args(["scan", "leak.js"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("GitHub token"))
        .stdout(predicate::str::contains("ghp_0123456789").not());
}

#[test]
fn scan_clean_path_succeeds() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), "ok.txt", "nothing secret here\n");
    envo(tmp.path())
        .args(["scan", "ok.txt"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no secrets detected"));
}

#[test]
fn run_injects_env_and_blocks_on_invalid() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), ".envo", "PORT: port = 3000\nAPI_KEY: secret\n");

    // API_KEY supplied via process env -> valid -> command runs.
    envo(tmp.path())
        .args(["run", "--", "sh", "-c", "echo got-$PORT"])
        .env("API_KEY", "x")
        .assert()
        .success()
        .stdout(predicate::str::contains("got-3000"));

    // Without API_KEY -> validation blocks the run.
    envo(tmp.path())
        .args(["run", "--", "sh", "-c", "echo SHOULD_NOT_RUN"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("SHOULD_NOT_RUN").not());
}

#[test]
fn export_json_emits_resolved_values() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), ".envo", "PORT: port = 3000\n");
    envo(tmp.path())
        .args(["export", "--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"PORT\": \"3000\""));
}

#[test]
fn missing_schema_is_a_clear_error() {
    let tmp = TempDir::new().unwrap();
    envo(tmp.path())
        .arg("check")
        .assert()
        .failure()
        .stderr(predicate::str::contains("envo init"));
}

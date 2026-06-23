//! Install/remove a managed `pre-commit` hook that runs `envo scan --staged`.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

const BEGIN: &str = "# >>> envo >>>";
const END: &str = "# <<< envo <<<";

/// Install (or update) the managed block in `.git/hooks/pre-commit`.
/// Returns the path to the hook file.
pub fn install(dir: &Path, with_check: bool) -> Result<PathBuf> {
    let git_dir = find_git_dir(dir).context("not inside a git repository")?;
    let hooks = git_dir.join("hooks");
    std::fs::create_dir_all(&hooks).with_context(|| format!("creating {}", hooks.display()))?;
    let hook_path = hooks.join("pre-commit");

    let block = managed_block(with_check);
    let new_content = if hook_path.exists() {
        let current = std::fs::read_to_string(&hook_path)
            .with_context(|| format!("reading {}", hook_path.display()))?;
        insert_or_replace(&current, &block)
    } else {
        format!("#!/bin/sh\n{block}")
    };

    std::fs::write(&hook_path, new_content)
        .with_context(|| format!("writing {}", hook_path.display()))?;
    set_executable(&hook_path)?;
    Ok(hook_path)
}

/// Remove the managed block. Returns whether a block was present.
pub fn uninstall(dir: &Path) -> Result<bool> {
    let git_dir = find_git_dir(dir).context("not inside a git repository")?;
    let hook_path = git_dir.join("hooks").join("pre-commit");
    if !hook_path.exists() {
        return Ok(false);
    }
    let current = std::fs::read_to_string(&hook_path)
        .with_context(|| format!("reading {}", hook_path.display()))?;
    let (stripped, removed) = remove_block(&current);
    if removed {
        std::fs::write(&hook_path, stripped)
            .with_context(|| format!("writing {}", hook_path.display()))?;
    }
    Ok(removed)
}

fn managed_block(with_check: bool) -> String {
    let check_line = if with_check {
        "  envo check || exit 1\n"
    } else {
        ""
    };
    format!(
        "{BEGIN}\n# Managed by envo - do not edit between these markers.\n\
         if command -v envo >/dev/null 2>&1; then\n\
         {check_line}  envo scan --staged || exit 1\nfi\n{END}\n"
    )
}

fn insert_or_replace(current: &str, block: &str) -> String {
    if current.contains(BEGIN) && current.contains(END) {
        let (stripped, _) = remove_block(current);
        let mut base = stripped.trim_end().to_string();
        base.push('\n');
        base.push_str(block);
        base
    } else {
        let mut base = current.trim_end().to_string();
        base.push('\n');
        base.push('\n');
        base.push_str(block);
        base
    }
}

fn remove_block(current: &str) -> (String, bool) {
    let Some(start) = current.find(BEGIN) else {
        return (current.to_string(), false);
    };
    let Some(end_rel) = current[start..].find(END) else {
        return (current.to_string(), false);
    };
    let end = start + end_rel + END.len();
    let mut result = String::new();
    result.push_str(current[..start].trim_end());
    let tail = current[end..].trim_start_matches('\n');
    if !tail.is_empty() {
        result.push('\n');
        result.push_str(tail);
    } else {
        result.push('\n');
    }
    (result, true)
}

/// Locate the `.git` directory, walking up from `dir`. Handles the common
/// gitdir-file case used by worktrees and submodules.
fn find_git_dir(dir: &Path) -> Result<PathBuf> {
    let start = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let mut cur: Option<&Path> = Some(start.as_path());
    while let Some(c) = cur {
        let candidate = c.join(".git");
        if candidate.is_dir() {
            return Ok(candidate);
        }
        if candidate.is_file() {
            let content = std::fs::read_to_string(&candidate)
                .with_context(|| format!("reading {}", candidate.display()))?;
            if let Some(rest) = content.trim().strip_prefix("gitdir:") {
                let p = PathBuf::from(rest.trim());
                let resolved = if p.is_absolute() { p } else { c.join(p) };
                return Ok(resolved);
            }
        }
        cur = c.parent();
    }
    bail!("no .git directory found from {}", dir.display())
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_roundtrip() {
        let original = "#!/bin/sh\necho existing\n";
        let block = managed_block(false);
        let installed = insert_or_replace(original, &block);
        assert!(installed.contains("echo existing"));
        assert!(installed.contains(BEGIN));
        assert!(installed.contains("envo scan --staged"));

        let (removed, did) = remove_block(&installed);
        assert!(did);
        assert!(!removed.contains(BEGIN));
        assert!(removed.contains("echo existing"));
    }

    #[test]
    fn replace_is_idempotent() {
        let block = managed_block(false);
        let once = insert_or_replace("#!/bin/sh\n", &block);
        let twice = insert_or_replace(&once, &block);
        assert_eq!(once.matches(BEGIN).count(), 1);
        assert_eq!(twice.matches(BEGIN).count(), 1);
    }
}

//! Command-line surface (clap derive).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "envo",
    version,
    about = "Typed .env manager: schema, profile inheritance, leak detection, encryption",
    propagate_version = true
)]
pub struct Cli {
    /// Project directory (defaults to the current directory)
    #[arg(short = 'C', long, global = true, value_name = "DIR")]
    pub dir: Option<PathBuf>,

    /// Disable colored output
    #[arg(long, global = true)]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create a starter .envo schema (and supporting files)
    Init(InitArgs),
    /// Validate the resolved environment against the schema
    Check(CheckArgs),
    /// Print the resolved variables and where each came from
    List(ListArgs),
    /// Resolve + validate, then run a command with the env injected
    Run(RunArgs),
    /// Export the resolved environment in a chosen format
    Export(ExportArgs),
    /// Encrypt a plaintext secrets file
    Encrypt(CryptoArgs),
    /// Decrypt an encrypted secrets file
    Decrypt(CryptoArgs),
    /// Scan files for leaked secrets
    Scan(ScanArgs),
    /// Manage the git pre-commit hook
    Hook(HookArgs),
}

#[derive(Args)]
pub struct InitArgs {
    /// Overwrite existing .envo / .env files
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct CheckArgs {
    /// Profile to layer in (loads .env.<profile>)
    #[arg(short, long, value_name = "NAME")]
    pub profile: Option<String>,
    /// Treat variables outside the schema as errors
    #[arg(long)]
    pub strict: bool,
    /// Ignore the current process environment when resolving
    #[arg(long)]
    pub no_process_env: bool,
    /// Path to the encryption key file (for encrypted secrets)
    #[arg(long, value_name = "FILE")]
    pub key_file: Option<PathBuf>,
}

#[derive(Args)]
pub struct ListArgs {
    /// Profile to layer in
    #[arg(short, long, value_name = "NAME")]
    pub profile: Option<String>,
    /// Reveal secret values instead of hiding them
    #[arg(long)]
    pub show_secrets: bool,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Include the current process environment
    #[arg(long)]
    pub process_env: bool,
    /// Path to the encryption key file
    #[arg(long, value_name = "FILE")]
    pub key_file: Option<PathBuf>,
}

#[derive(Args)]
pub struct RunArgs {
    /// Profile to layer in
    #[arg(short, long, value_name = "NAME")]
    pub profile: Option<String>,
    /// Skip validation before running
    #[arg(long)]
    pub no_validate: bool,
    /// Path to the encryption key file
    #[arg(long, value_name = "FILE")]
    pub key_file: Option<PathBuf>,
    /// Command to run (everything after `--`)
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required = true,
        value_name = "CMD"
    )]
    pub cmd: Vec<String>,
}

#[derive(Args)]
pub struct ExportArgs {
    /// Profile to layer in
    #[arg(short, long, value_name = "NAME")]
    pub profile: Option<String>,
    /// Output format
    #[arg(long, value_enum, default_value_t = ExportFormat::Dotenv)]
    pub format: ExportFormat,
    /// Path to the encryption key file
    #[arg(long, value_name = "FILE")]
    pub key_file: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ExportFormat {
    Dotenv,
    Shell,
    Json,
}

#[derive(Args)]
pub struct CryptoArgs {
    /// Input file (defaults: encrypt=.env.secrets, decrypt=.env.secrets.enc)
    #[arg(short, long, value_name = "FILE")]
    pub input: Option<PathBuf>,
    /// Output file (defaults to input with/without the .enc suffix)
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Path to the encryption key file
    #[arg(long, value_name = "FILE")]
    pub key_file: Option<PathBuf>,
}

#[derive(Args)]
pub struct ScanArgs {
    /// Scan only files staged for commit
    #[arg(long)]
    pub staged: bool,
    /// Fail on medium-severity findings too
    #[arg(long)]
    pub strict: bool,
    /// Files or directories to scan (defaults to tracked files)
    #[arg(value_name = "PATH")]
    pub paths: Vec<PathBuf>,
}

#[derive(Args)]
pub struct HookArgs {
    #[command(subcommand)]
    pub action: HookAction,
}

#[derive(Subcommand)]
pub enum HookAction {
    /// Install the pre-commit hook
    Install(HookInstallArgs),
    /// Remove the pre-commit hook
    Uninstall,
}

#[derive(Args)]
pub struct HookInstallArgs {
    /// Also run `envo check` in the hook
    #[arg(long)]
    pub with_check: bool,
}

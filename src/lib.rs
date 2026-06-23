//! envo - a typed `.env` manager.
//!
//! Modules:
//! - [`schema`]   - parse the `.envo` typed schema
//! - [`envfile`]  - parse/write dotenv files
//! - [`resolve`]  - layer schema defaults, env files, secrets, process env
//! - [`validate`] - check a resolved environment against the schema
//! - [`crypto`]   - encrypt/decrypt secrets at rest
//! - [`scan`]     - detect leaked secrets
//! - [`hook`]     - manage the git pre-commit hook

pub mod cli;
pub mod commands;
pub mod crypto;
pub mod envfile;
pub mod hook;
pub mod output;
pub mod resolve;
pub mod scan;
pub mod schema;
pub mod validate;

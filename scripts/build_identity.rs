//! Shared build script for crates that display a build identity.
//!
//! Embeds `HARDENER_BUILD_IDENTITY` (git short SHA + build date) so a stale
//! installed binary is visible at a glance next to the unchanged semantic
//! version. Referenced via `build = "../../scripts/build_identity.rs"` from
//! each consuming crate's Cargo.toml; keep this file crate-agnostic.

use std::process::Command;

fn command_line(program: &str, arguments: &[&str]) -> Option<String> {
    Command::new(program)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

fn main() {
    // Tarball builds (e.g. AUR) have no .git; fall back to a neutral marker.
    let commit = command_line("git", &["rev-parse", "--short", "HEAD"])
        .unwrap_or_else(|| "release".to_string());

    // Honour SOURCE_DATE_EPOCH so packaged builds stay reproducible.
    let date = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(epoch) => command_line("date", &["-u", "-d", &format!("@{epoch}"), "+%Y-%m-%d"]),
        Err(_) => command_line("date", &["-u", "+%Y-%m-%d"]),
    }
    .unwrap_or_default();

    let identity = if date.is_empty() {
        commit
    } else {
        format!("{commit} {date}")
    };

    println!("cargo:rustc-env=HARDENER_BUILD_IDENTITY={identity}");
    // Re-run when the checked-out commit moves; harmless no-ops elsewhere.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}

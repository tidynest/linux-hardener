//! Keeps the time library behind one module.
//!
//! `hardener_types::time` is the only place allowed to name `jiff` or
//! `chrono`. This test reads every other workspace crate as text, so it goes
//! red for a `use` line or a manifest entry the compiler would accept.

use std::fs;
use std::path::{Path, PathBuf};

/// Directories that hold generated or third-party files, not the project's own.
const SKIPPED_DIRECTORIES: [&str; 4] = ["target", "node_modules", "dist", "gen"];

/// The crate that owns the time module, which is allowed to name the library.
const OWNER: &str = "hardener-types";

#[derive(Default)]
struct Walk {
    offenders: Vec<String>,
    files_read: usize,
}

/// Lists the entries of a directory in a stable order.
fn entries(directory: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()))
        .map(|entry| entry.expect("directory entry is readable").path())
        .collect();
    paths.sort();
    paths
}

/// Records every line in one file that names the library.
fn scan_file(path: &Path, root: &Path, walk: &mut Walk) {
    let is_manifest = path.file_name().is_some_and(|name| name == "Cargo.toml");
    let is_source = path.extension().is_some_and(|extension| extension == "rs");
    if !is_manifest && !is_source {
        return;
    }
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    walk.files_read += 1;
    for (index, line) in text.lines().enumerate() {
        let names_library = if is_manifest {
            let start = line.trim_start();
            start.starts_with("jiff") || start.starts_with("chrono")
        } else {
            line.contains("jiff::") || line.contains("chrono::")
        };
        if names_library {
            let shown = path.strip_prefix(root).unwrap_or(path);
            walk.offenders.push(format!(
                "{}:{}: {}",
                shown.display(),
                index + 1,
                line.trim()
            ));
        }
    }
}

fn scan_directory(directory: &Path, root: &Path, walk: &mut Walk) {
    for path in entries(directory) {
        if path.is_dir() {
            let skipped = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| SKIPPED_DIRECTORIES.contains(&name));
            if !skipped {
                scan_directory(&path, root, walk);
            }
        } else {
            scan_file(&path, root, walk);
        }
    }
}

#[test]
fn only_this_crate_names_the_time_library() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut roots: Vec<PathBuf> = entries(&root.join("crates"))
        .into_iter()
        .filter(|path| path.is_dir() && path.file_name().is_some_and(|name| name != OWNER))
        .collect();
    roots.push(root.join("src-tauri"));

    let mut walk = Walk::default();
    for crate_directory in &roots {
        scan_directory(crate_directory, &root, &mut walk);
    }

    // A wrong path or a walk that skips everything finds nothing, and nothing
    // looks the same as a clean tree. The workspace has nine crates besides
    // the owner, and the desktop backend makes ten.
    assert!(
        roots.len() >= 8,
        "walk visited {} crate directories, expected at least 8",
        roots.len()
    );
    assert!(
        walk.files_read >= 200,
        "walk read {} source and manifest files, expected at least 200",
        walk.files_read
    );
    assert!(
        walk.offenders.is_empty(),
        "only `{OWNER}` may name `jiff` or `chrono`, but these lines do:\n{}",
        walk.offenders.join("\n")
    );
}

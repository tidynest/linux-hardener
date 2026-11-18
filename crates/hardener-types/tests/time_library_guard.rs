//! Keeps the time library behind one module.
//!
//! `hardener_types::time` is the only place allowed to name `jiff` or
//! `chrono`. One test reads every other workspace crate as text, so it goes
//! red for a `use` line or a manifest entry the compiler would accept. The
//! other reads `Cargo.lock`, which lists each crate's real dependencies, so a
//! renamed dependency or a `[dependencies.jiff]` table that the text scan
//! cannot see still turns it red.

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

/// The workspace root, two levels above this crate's manifest.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// One `[[package]]` block of `Cargo.lock`.
struct LockedPackage {
    name: String,
    /// A workspace member has no `source` line; everything fetched has one.
    is_member: bool,
    dependencies: Vec<String>,
}

/// Reads the package blocks of a lockfile. A dependency entry is written as
/// `"name"`, or as `"name version"` or `"name version (source)"` when the
/// lockfile holds more than one of that name, so only the first word is kept.
fn locked_packages(lockfile: &str) -> Vec<LockedPackage> {
    lockfile
        .split("[[package]]")
        .skip(1)
        .map(|block| {
            // A block ends at the next table header, such as `[metadata]`.
            let lines: Vec<&str> = block
                .lines()
                .skip(1)
                .take_while(|line| !line.starts_with('['))
                .collect();
            let name = lines
                .iter()
                .find_map(|line| line.strip_prefix("name = \""))
                .map(|rest| rest.trim_end_matches('"').to_owned())
                .unwrap_or_default();
            let dependencies = lines
                .iter()
                .skip_while(|line| **line != "dependencies = [")
                .skip(1)
                .take_while(|line| **line != "]")
                .filter_map(|line| {
                    line.trim()
                        .trim_matches(|character| character == '"' || character == ',')
                        .split(' ')
                        .next()
                })
                .map(str::to_owned)
                .collect();
            LockedPackage {
                name,
                is_member: !lines.iter().any(|line| line.starts_with("source = ")),
                dependencies,
            }
        })
        .collect()
}

/// `jiff`, a crate of its family such as `jiff-tzdb`, or any `chrono` crate.
fn is_time_library(name: &str) -> bool {
    name == "jiff" || name.starts_with("jiff-") || name.starts_with("chrono")
}

#[test]
fn no_other_workspace_crate_depends_on_the_time_library() {
    let path = workspace_root().join("Cargo.lock");
    let lockfile = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let packages = locked_packages(&lockfile);

    let members: Vec<&LockedPackage> = packages
        .iter()
        .filter(|package| package.is_member)
        .collect();
    let offenders: Vec<String> = members
        .iter()
        .filter(|package| package.name != OWNER)
        .flat_map(|package| {
            package
                .dependencies
                .iter()
                .filter(|dependency| is_time_library(dependency))
                .map(move |dependency| format!("{} depends on {dependency}", package.name))
        })
        .collect();

    // A parse that finds no member block finds no offender either, so the
    // members must be there before an empty list means a clean workspace.
    assert!(
        members.len() >= 8,
        "found {} workspace members in Cargo.lock, expected at least 8",
        members.len()
    );
    assert!(
        offenders.is_empty(),
        "only `{OWNER}` may depend on `jiff` or `chrono`, but Cargo.lock says:\n{}",
        offenders.join("\n")
    );

    // The `clock` feature reads the system's own zoneinfo, so a copy of the
    // time zone database compiled into a binary would only add size, and to
    // the WASM interface too if a feature ever reached it.
    let bundled: Vec<&str> = packages
        .iter()
        .map(|package| package.name.as_str())
        .filter(|name| matches!(*name, "jiff-tzdb" | "jiff-tzdb-platform"))
        .collect();
    assert!(
        bundled.is_empty(),
        "no time zone database may be compiled in, but Cargo.lock holds {bundled:?}"
    );
}

#[test]
fn only_this_crate_names_the_time_library() {
    let root = workspace_root();
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

//! Fuzzes `with_include_line`, the pure half of the nftables boot-file
//! append.
//!
//! The content it sees is the distribution's own boot ruleset, read from a
//! remote host over the SSH executor: input the operator does not control,
//! and input an append must never mangle. The write itself is
//! executor-bound and unfuzzed here; every property that makes the write
//! safe is decided by this function, and each is asserted:
//!
//! - Idempotence: applying it twice produces exactly what applying it once
//!   produced, so no run appends a second include line to a file that
//!   already carries one.
//! - Presence: the result always contains the include line as a whole
//!   trimmed line.
//! - No loss: the result is the original content plus at most one separator
//!   newline and the include line, never a rewrite of anything above it.

#![no_main]

use hardener_plugins::fuzz_seams::nftables_include::with_include_line;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    const INCLUDE: &str = "include \"/etc/linux-hardener/nftables/50-linux-hardener.nft\"";
    let existing = String::from_utf8_lossy(data).into_owned();

    let once = with_include_line(&existing, INCLUDE);
    let twice = with_include_line(&once, INCLUDE);

    assert_eq!(once, twice, "appending twice is appending once");

    assert!(
        once.lines().any(|line| line.trim() == INCLUDE),
        "the result carries the include line"
    );

    assert!(
        once.starts_with(&existing),
        "nothing above the append point changes"
    );
    let added = &once[existing.len()..];
    let bare = format!("{INCLUDE}\n");
    let separated = format!("\n{INCLUDE}\n");
    assert!(
        added.is_empty() || added == bare || added == separated,
        "the most the append adds is one separator and the include line, got {added:?}"
    );
    assert!(
        added.is_empty() == (once == existing),
        "unchanged in and unchanged out agree"
    );
});

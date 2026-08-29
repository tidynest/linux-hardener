# Fuzz targets

Five targets cover the parsers on both sides of `apply`: the write path
(`set_config_directive`, `parse_config_value` and `global_scope` in
`hardener-common`'s `file_utils`, plus `vendor_path_for` in
`vendor_config`) and the reading half that motivated fuzzing here at all
(sshd_config include resolution, PAM stack lines, the nftables include
append). They are the right subjects because they consume configuration
files that arrive from remote hosts over the SSH executor as well as
local ones, which is input the operator does not control and the case
fuzzing exists for.

Beyond surviving, the targets assert the parsers' documented invariants:
`set_config_directive` always newline-terminates (something appends to the
file afterwards), `global_scope` returns a prefix on a line boundary, a
set-then-parse round trip returns the value that was set for unambiguous
keys and values, sshd's first-wins include order holds, a commented PAM
line never counts as loading anything, and appending the nftables include
line twice appends it once. Each target's header comment states the full
list it asserts.

## Running

```bash
cd fuzz
cargo fuzz run config_directives        # directive write-path parsers
cargo fuzz run vendor_path_for          # /etc -> /usr/etc mapping
cargo fuzz run ssh_include_resolution   # sshd_config Include handling
cargo fuzz run pam_stack_parsing        # PAM stack line semantics
cargo fuzz run nftables_include_line    # boot-ruleset include append
```

`fuzz/rust-toolchain.toml` pins nightly for this directory, because the
sanitizer flags cargo-fuzz passes are nightly-only and its inner `cargo`
build resolves the toolchain from where it runs. The crate is detached
from the root workspace on purpose: sanitizer builds have no business
inheriting the release profile (LTO, strip).

CI runs every target for a 60-second burst on every push (`fuzz-run` job),
so the targets cannot silently rot and the invariants are executed, not
only compiled. The job accumulates each target's corpus across runs
through the Actions cache; locally, corpora and crash files are
gitignored and machine-local. The targets' invariants also run on fixed
inputs in `tests/invariant_smoke.rs`, under
`RUSTFLAGS="--cfg fuzzing" cargo test` in this directory, which is the
ceiling on a machine where cargo-fuzz itself cannot run.

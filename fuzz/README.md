# Fuzz targets

These targets fuzz the directive parsers `apply` writes through:
`set_config_directive`, `parse_config_value` and `global_scope` in
`hardener-common`'s `file_utils`, and `vendor_path_for` in `vendor_config`.
They are the right subjects because they consume configuration files that
arrive from remote hosts over the SSH executor as well as local ones,
which is input the operator does not control and the case fuzzing exists
for.

Beyond surviving, the targets assert the parsers' documented invariants:
`set_config_directive` always newline-terminates (something appends to the
file afterwards), `global_scope` returns a prefix on a line boundary, and a
set-then-parse round trip returns the value that was set for unambiguous
keys and values.

## Running

```bash
cd fuzz
cargo fuzz run config_directives        # directive parsers
cargo fuzz run vendor_path_for          # /etc -> /usr/etc mapping
```

`fuzz/rust-toolchain.toml` pins nightly for this directory, because the
sanitizer flags cargo-fuzz passes are nightly-only and its inner `cargo
build` resolves the toolchain from where it runs. The crate is detached
from the root workspace on purpose: sanitizer builds have no business
inheriting the release profile (LTO, strip).

CI builds both targets on every push (`fuzz-build` job) so they cannot
silently rot; corpora and crash files are gitignored and machine-local.

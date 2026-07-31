# Documentation Commands

Commands for validating and auto-updating project documentation.

All scripts are Python 3 and located in `scripts/`.

---

## Master Validator

### Full validation

```bash
./scripts/validate/validate_all.py
```

Runs the individual validators listed below in sequence (all except the standalone naming validator). Exits non-zero if any check fails. Includes slower checks (CLI doc verification, compliance framework list).

### Quick validation

```bash
./scripts/validate/validate_all.py --quick
```

Skips the slower validators (`validate_cli_docs.py` and `validate_compliance_docs.py`). Suitable for pre-commit checks where speed matters.

### Auto-fix mode

```bash
./scripts/validate/validate_all.py --fix
```

Where possible, automatically corrects issues (e.g. outdated "Last Updated" dates). Not all validators support auto-fix; those that don't will still report errors for manual resolution.

---

## Auto-Update Documentation

### Preview changes (dry run)

```bash
./scripts/validate/update_all_docs.py
```

Scans all documentation and reports what would be updated, without modifying any files. Shows:
- "Last Updated" dates that are older than the file's last git commit
- Missing entries in `docs/reference/file-map.md` for new source files
- Compliance framework control counts that are out of sync
- Version references that don't match `Cargo.toml`

### Apply changes

```bash
./scripts/validate/update_all_docs.py --apply
```

Same scan as above, but writes the fixes. This is what `release.sh` runs during the release process.

---

## Individual Validators

Most of these are called by `validate_all.py`, and each can also be run standalone for targeted checks. The naming validator is the exception: it is not part of `validate_all.py` and is only run standalone.

### Naming conventions

```bash
./scripts/validate/validate_naming.py
```

Checks that Rust identifiers follow the naming conventions in `docs/reference/naming-conventions.md`: PascalCase for types, snake_case for functions, SCREAMING_SNAKE_CASE for constants.

### File map completeness

```bash
python3 scripts/validate/validate_file_map.py
```

Verifies that every source file in the workspace has an entry in `docs/reference/file-map.md`. Reports missing entries.

### Plugin documentation

```bash
python3 scripts/validate/validate_plugin_docs.py
```

Checks that each plugin in `crates/hardener-plugins/` has corresponding documentation and that plugin IDs, names, and descriptions match the README plugin table, the `docs/ROADMAP.md` checklist, and the `docs/architecture/architecture.md` plugin table.

### Tauri command documentation

```bash
./scripts/validate/validate_tauri_docs.py
```

Verifies that every `#[tauri::command]` function in `src-tauri/src/commands.rs` is documented and that the IPC command names match between code and documentation.

### Last Updated dates

```bash
./scripts/validate/validate_last_updated.py
```

Checks that "Last Updated" dates in documentation files match (or are close to) the file's last git modification date. Reports files with stale dates.

### Doc comment attachment

```bash
python3 scripts/validate/validate_doc_attachment.py
```

Reports a free function with no doc comment of its own sitting immediately
after an item that carries a long one. Rust attaches a `///` block to the item
that follows it, so inserting a new item between a comment and its function
silently hands the comment over: one function is then documented as two things
and the other as nothing, and nothing warns. It has happened eight times here,
once to the rollback contract that decides whether a file may be deleted.

Fix a report either by moving the stolen half of the neighbour's doc down onto
the function it describes, or by writing the function a line of its own. The
script's own docstring records the threshold, what the rule cannot see, and the
sharper rule that was measured and rejected for reporting eighty-one innocent
functions.

### File creation sites

```bash
python3 scripts/validate/validate_write_sites.py
```

Holds every file-creating call site under `crates/hardener-plugins/src` to two
written answers, one per defect the tree has repeated, then asserts a third
thing of the `cp` sites alone.

The first is why the write can land at all, classifying each site as `ensured`
(a `crate::ensure_directory` for that parent, named by the entry) or `exempt`
(the parent is guaranteed by something else, and the entry says what). The same
defect was fixed three times in three commits before this existed: a file
written into a directory nothing ensures, which `write_file` cannot create
because it lands its content through a temporary file in the target directory.
All three were findable the moment the first was understood, but nothing swept
for them, so they arrived one at a time across a day.

The second is whether a rollback reaches what the write created, classifying
each site as `declared` (the path is named to this plugin's pre-apply
checkpoint, and the entry names the tokens the path list has to contain) or
`exempt` (nothing declares it, and the entry says why no state of ours outlives
the rollback). A checkpoint captures a declared directory recursively, so it
records only the children present when it runs, and a rollback walks only the
rows it holds. A file the apply is about to create therefore has no row and
survives the rollback meant to undo it, unless its path is declared in its own
right: a declared path that is absent at capture is stored with a zero mode,
which the restore reads as "remove this". That defect has been found twice, in
the `systemctl mask` link and in the audit rules file.

The third is not a classification but an assertion, and applies only to the
sites whose argv[0] is the literal `cp`: every one of them must pass both `-p`
and `--no-dereference` before the source and destination. Three plugins take a
backup copy and all three answered that differently, pam passing neither flag,
ssh only `-p` and audit only `--no-dereference`, so each lost what the others
kept. A copy without `-p` records none of the source's mode, ownership or
timestamps, so restoring it hands the operator the file at whatever the umask
gives; a copy without `--no-dereference` follows a symlink and records the
target, so a config that is a link is backed up as some other file and the one
about to be overwritten has no backup at all. It is asserted rather than
registered because, unlike the other two questions, it has a single correct
answer at every site: there is nothing for an entry to decide, and a column
would only offer somewhere to write "exempt".

Fix a report on either of the first two questions by deciding both
classifications for the new site and adding its entry as a pair of pairs, then
moving `EXPECTED_SITE_COUNT` to match. A report on the third is fixed by
passing the flag. The count
is pinned as a literal on purpose: a registry that counts its own size cannot
fail when a site is added, which is the one thing this check exists to do. The
second question needs no pin of its own, because an entry that does not answer
it is rejected as malformed and the registry's length is already held to the
pin.

What it proves is narrow, and the script's own docstring says so at length. It
proves no site is unclassified on either question and that no literal `cp`
copies without both flags. It does not prove any ensure
is correct, covers the right parent, or runs before the write; it does not prove
any declaration reaches the right path or is captured before the write; and it
cannot see a file created by shell redirection, by a program named through a
variable, or by a direct `std::fs` call. The flag assertion inherits that last
blind spot exactly: a copy made through a variable, a shell, or any program
other than a literal `cp` is not held to it. Most sharply, it cannot see the
`systemctl mask` link that prompted the second question at all, because that
file is created through `execute_command("systemctl", ...)` and admitting
`systemctl` would admit every `start`, `stop` and `daemon-reload` beside it. The
same blind spot covers `systemctl enable`, `augenrules --load`, and the firewall
backends writing their persistence through `firewall-cmd --permanent` and `ufw`.

### CLI documentation (slower)

```bash
./scripts/validate/validate_cli_docs.py
```

Parses the CLI command definitions in `crates/hardener-cli/src/cli.rs` and cross-references them against the CLI examples in `README.md`. Reports commands, subcommands, or global flags that are missing from the README. Slower because it parses Rust source.

### Compliance documentation (slower)

```bash
./scripts/validate/validate_compliance_docs.py
```

Checks that every framework defined in the `ComplianceFramework` enum (`crates/hardener-types/src/lib.rs`) appears in each documented framework table (`docs/architecture/architecture.md` and `docs/ROADMAP.md`), and that no table lists a framework the code does not define. It validates the framework list rather than per-control counts, because post-rework catalogues are plugin-declared and aggregated at runtime (static per-control counts are no longer meaningful here). Grouped with the slower checks.

### Version consistency

```bash
./scripts/release/release.sh --verify
```

Checks that the version in `Cargo.toml` matches `tauri.conf.json` and all documentation references. Also invoked by `validate_all.py`.

**Last Updated**: 2026-07-31

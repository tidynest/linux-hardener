# Documentation Commands

Commands for validating and auto-updating project documentation.

`scripts/validate/` holds eighteen Python 3 scripts: the master runner
`validate_all.py`, the auto-updater `update_all_docs.py`, the fifteen
validators `validate_all.py` runs, and `validate_naming.py`, which is
standalone and runs from the pre-commit hook instead. The one check that is not
Python lives elsewhere: version consistency is
`scripts/release/release.sh --verify`, which `validate_all.py` shells out to,
and it is why the run reports sixteen checks against fifteen Python
validators.

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

Verifies that every `.rs` file under `crates/` and `src-tauri/src` has an entry
in `docs/reference/file-map.md`, and that no entry names a file that is gone.
`EXCLUDE_PATTERNS` holds the exceptions, and it is narrower than it looks: only
`/target/`, `/tests/common/` and editor temp files are skipped, so an ordinary
`tests/` file is expected to be documented. `--fix` prints stub rows for what is
missing rather than writing them.

### Plugin documentation

```bash
python3 scripts/validate/validate_plugin_docs.py
```

Reads each plugin's `metadata()` in `crates/hardener-plugins/src/*/mod.rs` and
makes three comparisons: the plugin **names** against the README plugin table,
the derived **struct names** against the `docs/architecture/architecture.md`
plugin table, and the number of plugins registered in `create_plugin_registry()`
against the number found in source. Both table comparisons report in each
direction, missing and extra.

Its module docstring also mentions a `docs/ROADMAP.md` checklist; `main()` does
not check one, so a plugin missing from the ROADMAP passes here. Descriptions are
parsed out of `metadata()` but nothing compares them either.

### Tauri command documentation

```bash
./scripts/validate/validate_tauri_docs.py
```

Verifies that every `#[tauri::command]` function in `src-tauri/src/commands.rs`
is documented in `docs/reference/file-map.md` with a matching signature, and that
every `invoke_command()` call in `crates/hardener-ui/src/tauri_bindings.rs` names
a command that actually exists.

### Last Updated dates

```bash
./scripts/validate/validate_last_updated.py
```

Checks the "Last Updated" date in every `.md` file under the project root,
`docs/` and `scripts/` against that file's last git commit date, and reports a
date more than `STALE_THRESHOLD_DAYS` (7) behind it as stale. A file with no
"Last Updated" line at all is a warning rather than an error. `--fix` rewrites
the stale ones.

The tolerance is the reason this validator can pass while `update_all_docs.py`
in preview mode still names a file: the updater flags any documented date older
than the git date at all, so up to seven days of drift is stale to the updater
and current to the validator.

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

### Unit state reads

```bash
python3 scripts/validate/validate_unit_state_reads.py
```

Holds every `systemctl is-enabled` call site to a written answer: does it judge
systemd's word, or systemd's exit status, and why is that right there.

The two are different questions. Measured on a live host: `static` and
`indirect` each print their own word and exit 0, while `disabled` and `masked`
exit 1, and `enabled-runtime` exits 0 although the next boot discards it. So
"the command succeeded" does not mean "this unit starts at the next boot".

A rule banning the exit status would be wrong, which is why this is a registry
rather than a ban. Firewall reads the word and keeps a three-way answer, because
it tells the operator which way the unit fails to start. Audit reads the word
and reduces it to a boolean, because it only decides whether to enable; it
judged the exit status until an `enabled-runtime` host read as compliant with
nothing to start auditd after a reboot. Services judges the exit status
deliberately, because a `static` unit reaches its unconditional mask only
because of it, and reading the word there would leave a unit another unit can
pull in unmasked.

What makes it more than a form is that the answer is cross-checked against the
code: a site answering `word` must not read `output.success()` in the function
holding it, and a site answering `exit-status` must. Flipping an implementation
without touching its entry fails here. The cross-check is deliberately crude, as
the script's docstring says at length, along with what it cannot see: a probe
built through `format!`, a variable or a shell; `is-active` and the other
subcommands, held out because their status and their word answer the same
question; anything below the first `#[cfg(test)]` in a file, production or not;
and whether the answer a site gives is the right one for its plugin.

Fix a report by adding an entry that names the file and enclosing function,
answers `word` or `exit-status`, and says why, then moving
`EXPECTED_SITE_COUNT`. The count is pinned as a literal for the same reason the
file-creation registry pins its own: a check that counts its own expected size
cannot fail when a site is added, and it is the guard against this script
quietly matching nothing at all.

### Doc sync targets

```bash
python3 scripts/validate/validate_doc_targets.py
```

Holds the updater's declared targets and the tree to agreeing in both
directions. Forward: every target it declares resolves, the file it names exists
and its pattern matches something in that file. Inverse: no markdown file
outside an archive carries a version line without being a declared target.

The updater walks two lists and skips, in silence, any target whose file is
missing or whose pattern matches nothing. A skipped target produces no update
and no complaint, so the run reports "no changes needed" for work it never
attempted. Five of the compliance framework files it named were deleted in
`4039ed1`, and for six weeks afterwards the control counts in
`architecture.md` described files that no longer existed while every run of the
updater said there was nothing to do.

The inverse direction is issue #54, and it exists because a list of files to
rewrite cannot notice a file that should be on it. `data-flow.md` carried a
version line for months without being declared, drifted to 1.4.0 while the
release was 1.5.1, and was corrected by hand. Adding it to the list fixed that
file and left the next one in exactly the same position, so the check now asks
the question the list cannot ask of itself.

The version-line pattern is deliberately loose about where the colon sits.
`architecture.md` writes `**Version:**` and `README.md` writes `**Version**:`,
and that one character is what hid the first of them from the updater for
months.

Anything under an `archive` directory is exempt. An archived audit is supposed
to name the version it was written for, and rewriting it would be the wrong kind
of correct.

Rewriting the updater to discover version lines rather than being told where
they are was the other option and was rejected. A script that silently rewrites
every version-shaped string it finds will eventually rewrite one meant to stay,
such as a minimum-supported-version statement, and a wrong rewrite is worse than
a stale line something complains about.

It imports the target lists rather than restating them, because a second copy of
a list is a second thing to drift. That import is also why the script sets
`sys.dont_write_bytecode`: Python invalidates a `.pyc` on source mtime and size
at one-second granularity, so a same-length edit landing within the same second
is served from cache and the check reports on a file that no longer exists.

### Test assertions

```bash
python3 scripts/validate/validate_test_assertions.py
```

Checks that every test reaches an assertion on every path through its body.

A test whose only assertions sit inside an `if` with no `else`, or inside a loop
over a collection that might be empty, does not assert when the condition does
not hold. It still exits 0 and it still counts towards the suite total, which is
the number everyone reads. Issue #46 is the family: seven plugin tests ran
against whatever machine the suite was on and wrapped their real assertions in a
conditional, so a host with no `sshd_config`, or no firewall, or nothing to
flag, made them assert one string equality and pass.

Constructs that cover all their own paths satisfy the check: a `match`, which
Rust makes exhaustive, provided every arm asserts or panics; an `if`/`else`
chain ending in a bare `else` with every branch asserting; and a `for` over an
array literal written at the site, which is the good form of the table-driven
test rather than the bad one.

Where the assertions genuinely live in a helper the test calls, write

```rust
// assertions-in-helper: <reason>
```

above the test attribute. It is a comment rather than a naming convention so
that the reason travels with the exemption, and so a single grep lists every
exemption in the tree with its justification attached.

### Badges

```bash
python3 scripts/validate/validate_badges.py
```

Checks that each SVG under `docs/assets/badges/` renders the label and message
that `scripts/badges/generate.js` declares for it.

The generator is the declared source and `docs/contributing/releasing.md`
documents regenerating from it as a release step, but nothing held the two
together and they drifted: the generator declared version 1.5.0 and tests 1100+
while the committed SVGs read 1.5.1 and 1191+. Somebody had edited the artefacts
without the source, which made the documented procedure destructive, and the
only warning would have been a reader noticing the front page had got worse.

Agreeing with the generator is not the same as being true, so a badge with a
single authority in the repo is compared against that authority as well. `aur`
is checked against `packaging/PKGBUILD`, and `version` and `rust` against
`Cargo.toml`'s `version` and `rust-version`. A trailing plus in a badge marks a
floor rather than an exact value, so the rust badge's `1.85+` is compared on the
number in front of it. That second kind of check is what catches the case the
first cannot: the AUR badge read 1.5.0
while the published package was 1.5.1, with generator and artefact in perfect
agreement about a release they were both behind. Where the authority itself
cannot be read, or its pattern matches nothing, that is reported rather than
passed, because a cross-check that could not run must not read as one that
agreed.

Two ceilings are deliberate. It compares rendered text rather than SVG bytes, so
it needs no node or `npm install` in the gate and a change to badge-maker's
colours or geometry is invisible to it; only the values a human edits are
pinned, which are the ones that have drifted. And the tests badge has no
authority: its `+` makes it a floor rather than a count, and pinning it to a
measured figure would make this gate depend on a full workspace test run.

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

Compares the workspace version in `Cargo.toml` against
`docs/architecture/architecture.md`, `packaging/assets/hardener.1` and
`src-tauri/tauri.conf.json`, and against nothing else: the packaging versions
(`PKGBUILD`, the RPM spec, `debian/changelog`) are outside its reach. Also
invoked by `validate_all.py`, as its first entry.

**Last Updated**: 2026-08-01

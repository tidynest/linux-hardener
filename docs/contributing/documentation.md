# Documentation Commands

Commands for validating and auto-updating project documentation.

`scripts/validate/` holds the master runner `validate_all.py`, the auto-updater
`update_all_docs.py`, the validators `validate_all.py` runs, and
`validate_naming.py`, which is standalone and is what a hand-installed
pre-commit hook runs, if there is one. The one check that is not Python lives
elsewhere: version consistency is `scripts/release/release.sh --verify`, which
`validate_all.py` shells out to, and it is why the run reports one more check
than there are Python validators.

**No count is written here on purpose.** The figures read "twenty-three Python
scripts, twenty validators, twenty-one checks" from 2026-08-08 until 2026-08-18,
and by then they were 27, 24 and 25. All four numbers were exactly four low and
internally consistent with each other, so the paragraph reconciled with itself
while disagreeing with the directory. Read them off the tree:

```bash
ls scripts/validate/*.py | wc -l                       # every script here
./scripts/validate/validate_all.py | tail -1           # checks the run reports
```

The count that outgrew this paragraph is the same event
`validate_test_counts.py` was written for: two validators landing on 2026-08-12
made the evidence ledger's own validator row false the moment they landed. That
check re-derives the number for the ledger and **cannot see this file**, because
its `CROSS_DOCUMENT_SITES` list holds `README.md` and `scripts/README.md` and
nothing else.

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

It also derives the test counts the descriptions claim. A row reading
"21 tests of the renderers" is checked against the `#[test]` and
`#[tokio::test]` declarations in the file it describes, so a number kept by
hand cannot drift away from the tests it counts. Both spellings are matched,
because a file that gained an async test would otherwise start undercounting
without saying so. A claim on a row whose file no longer exists is left to the
missing-file report above rather than counted twice.

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
python3 scripts/validate/validate_test_assertions.py --all
```

Checks that every test reaches an assertion on every path through its body.

`--all` is the whole tree, and it is what `validate_all.py` runs. Without it the
scope is the integration suites under `crates/*/tests/` and `src-tauri/tests/`
alone. The gate used that narrow scope until issue #130, and it meant the check
read 646 tests, reported them all clean, and never opened an inline
`#[cfg(test)]` module under `src/`, which is where most of this workspace's
tests live. A test that asserted nothing at all sat in that unread half. Run the
narrow form for a faster local pass if you like, but the gate reads everything.

A test whose only assertions sit inside an `if` with no `else`, or inside a loop
over a collection that might be empty, does not assert when the condition does
not hold. It still exits 0 and it still counts towards the suite total, which is
the number everyone reads. Issue #46 is the family: seven plugin tests ran
against whatever machine the suite was on and wrapped their real assertions in a
conditional, so a host with no `sshd_config`, or no firewall, or nothing to
flag, made them assert one string equality and pass.

Constructs that cover all their own paths satisfy the check: a `match`, which
Rust makes exhaustive, provided every arm asserts or panics; an `if`/`else`
chain ending in a bare `else` with every branch asserting; and a `for` over a
table written at the site, which is the good form of the table-driven test
rather than the bad one. The table counts as written at the site whether it sits
in the `for` header or is bound just above it by a non-`mut` `let` or `const`,
because the reader can count it either way. A `let mut` does not count: it can be
drained or filtered between its literal and the loop.

A loop over a table declared in another file is a different matter, and is
reported. This script cannot see whether such a table is empty, and an emptied
one is exactly the silent vacuity it exists to catch, so assert the table is not
empty before the loop.

`expect_err` and `unwrap_err` count as assertions, as `expect` and `unwrap` do.
They are the same family pointed the other way: they fail the test when the call
succeeded, which is the whole point of a test that proves a refusal.

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
floor rather than an exact value, so the rust badge's `1.88+` is compared on the
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

### Policy exception sites

```bash
python3 scripts/validate/validate_policy_exception_sites.py
```

Checks that every scan finding hardcoding `finding_exception:
ExceptionOutcome::NotConfigured` carries a comment above the field saying why.

`ReportGenerator::has_live_finding` fails a compliance control on any finding
whose exception did not apply, `NotConfigured` and a declined exception alike,
so a hardcoded `NotConfigured` is not a missing feature: it silently overrides
a deviation the operator wrote down and approved. Six of these shipped at once
across firewall, mac and audit and none was a decision anyone had taken, while
pam's module-absence finding is deliberate and says so at the site. Counting
the sites cannot tell an oversight from a decision, and neither can a test,
because a test asserting the field is `NotConfigured` passes just as happily
on either. A comment beside it can, and it travels with the exemption.

### Evidence ledger

```bash
python3 scripts/validate/validate_evidence_ledger.py
```

Checks that every path `docs/reference/evidence-ledger.md` cites still exists,
and that the ledger's own table is what the citations are counted against.

A ledger row states a claim and names the file that backs it. Rename or delete
that file and the row goes on asserting coverage that is gone, which makes the
ledger worse than no ledger: a promise nobody checks. Nothing else looks, because
the paths are prose to every other tool in the tree.

It reads the whole file rather than one table, matching backticked paths that
begin `crates/`, `scripts/`, `src-tauri/` or `gui-tests/`, which is the citation
form the ledger's own "Adding a row" section requires. The Evidence column is
therefore not the only column checked: a citation in a Command or a Ceiling cell,
or in the prose around the tables, is held to exactly the same rule, so no path
in the document is exempt because of where it sits.

Existence on its own would not be worth much, because any non-empty result passes
it. Measured on a modified copy: stripping the backticks out of the Evidence
column left eleven references and exit 0, and deleting every table row while
keeping the prose left seven and exit 0, a ledger promising nothing reporting
green. So the references are cross-checked against the ledger's structure. Every
row of a capability table, meaning every row under a
`| Claim | Evidence | Command | Ceiling |` header, must cite at least one path in
its Evidence cell, and a run with no such row at all is failed rather than passed
on whatever the prose still carries. Both of those gutting edits now die by name,
as does emptying one row's Evidence cell while its claim stays.

The floor is derived from the document rather than written into the validator, so
adding a row raises it with no edit here, and amending a citation as Phase 3 will
have to leaves it alone. What it cannot check is whether the named test exercises
the claim beside it; that judgement is made at review time, and this catches only
the mechanical half.

### Persisted finding fields

```bash
python3 scripts/validate/validate_persisted_finding_fields.py
```

Checks that every field in the `Finding` literal that
`ScanHistoryManager::get_result_findings` rebuilds from a database row, in
`crates/hardener-state/src/scan_manager.rs`, comes from that row rather than a
hardcoded default.

The rebuild is not shaped uniformly: most fields read `row.get(...)` directly,
two pass through a transform (`str_to_category`, `str_to_severity`), and three
are local variables already deserialised from JSON earlier in the loop. A
field given a hardcoded default such as `None` or `vec![]` instead compiles,
passes every test that does not happen to assert on it, and drops the
persisted value in silence. That is exactly how `finding_exception_key`
shipped as a hardcoded `None`: nothing failed, and every scan history record
silently lost its exception key.

A comment written immediately above a hardcoded field exempts it, for a field
that genuinely has no column, the same idiom Policy exception sites uses
above. The check deliberately stops there rather than trying to prove
provenance for every field: a rule demanding `row.get` appear in every
expression would itself be wrong about five of the thirteen fields, the ones
sitting behind a transform or already read out into a variable above the
literal. What that leaves unseen, a field that is not one of the literal
defaults this check recognises yet still fails to survive the round trip, is
covered instead by `every_finding_field_survives_the_scan_history`, a
whole-struct serde round-trip test in
`crates/hardener-state/tests/scan_manager_tests.rs`.

### GUI mock fixtures

```bash
python3 scripts/validate/validate_gui_mock_fixtures.py
```

Checks that every payload `gui-tests/tauri-mock.js` returns carries the fields
the Rust type requires, carries no field that type does not have, and gives
every enum-valued field a real variant name.

The mock is a hand-written mirror of the types the Leptos frontend
deserialises, and until this check existed nothing in the tree read it. Eight
separate drifts had accumulated: a removed `finding_policy_exception` still
being sent, missing `finding_exception`, `plugin_version` and `controls`, an
invented `plugin_dependencies`, `Logging` and `AccessControl` where
`FindingCategory` has neither, a framework key nothing could match, four
frameworks absent outright, and a `window.__TAURI__` claiming a runtime it
implemented half of.

Every one of them failed in the same misleading way. The frontend reports
"missing field `x`" into an alert box no Playwright test asserts on, the view
that consumes the payload renders empty, and the suite reports what reads as a
stale selector. A release cycle was spent believing an interface redesign had
invalidated 34 tests.

The payloads are obtained by **running** the mock against a stubbed `window`
and invoking each command, not by parsing the file, so what is compared is what
serde actually receives. A field serde can supply is not required: `Option<T>`
deserialises to `None` when absent and `#[serde(default)]` says so outright,
and an earlier draft that ignored this reported three working fields as
missing, which is the direction that would condemn a mock that works. An extra
field is reported as well as a missing one, because a rename arrives as both
and naming only the missing half describes half the problem.

A command the mock has no case for is a different failure, and it used to be an
illegible one. The harness catches the rejected `invoke`, writes
`{"error": ...}` to stdout and exits 3; the Python side reported stderr alone,
so the whole message was `could not run the mock:` and an empty line. Both
streams are now printed, whichever carried the reason. It matters because that
is the failure a new probe produces on purpose: `get_host_history` was probed
before the mock could answer it, and the point of writing the probe first is to
read what the check says when the thing it checks is absent.

### .SRCINFO

```bash
python3 scripts/validate/validate_srcinfo.py
```

Checks that `packaging/.SRCINFO` says what `packaging/PKGBUILD` declares.

`.SRCINFO` is generated rather than edited, and it is the only file the AUR
reads: the web interface, the search index and every helper resolve a package's
version, dependencies and sources from it and never from the PKGBUILD beside it.
It had fallen three releases behind, `pkgver` reading 1.2.2 against a PKGBUILD
of 1.5.1, with the `source` line derived from it pointing at the wrong tarball.

It asks twice on purpose. A full `makepkg --printsrcinfo` regeneration compared
byte for byte is the whole truth and catches a field this check has never
thought about, but it needs `makepkg` and so cannot run on the project's Ubuntu
CI. A pure-Python comparison of the scalars, plus the assertion that no line
carries a version string other than `pkgver`, needs nothing and still fails on
the exact drift that happened. Where `makepkg` is absent that is reported as a
reduced run rather than a pass, because a check that quietly skips itself
off-platform is a control that cannot fail.

### CHANGELOG headings

```bash
python3 scripts/validate/validate_changelog_headings.py
```

Checks that no release entry in `CHANGELOG.md` repeats a change-type heading.

A second `### Fixed` under one `## [version]` hides its own entries from anyone
who found the first, and a release whose notes are cut from the file publishes
the same heading twice with its entries split between them on no principle. It
had happened seven times across three releases and nothing had looked.

The comparison is on the exact heading text, which is deliberately narrow:
`[1.0.3]` writes `### Added (Testing Infrastructure)` beside `### Fixed (GUI
Tests)`, two different sections rather than a duplicate pair, so matching on a
normalised prefix would fail a file doing nothing wrong. Everything below the
last release entry is ignored, so the link-reference definitions and the
version-history summary are not read as part of the release above them.

### Markdown links

```bash
python3 scripts/validate/validate_doc_links.py
```

Checks that every markdown link in a tracked `.md` resolves for a reader who
has only the repository.

A link to a missing file is the obvious half. The half this exists for is
invisible to the maintainer by construction: a link whose target sits on their
disk but is gitignored. It opens in their editor, on every check they think to
run, and 404s for everyone who clones. It had happened twice, both times into
`docs/archive/`, which `.gitignore` lists file by file under the heading
"Internal development documents (not for public repositories)".

Relative targets are resolved against the linking file's own directory rather
than matched as text, which is the whole point: the hand audit that missed
`../archive/browser-automation.md` had grepped for `docs/archive/`, and those
are the same directory written from one level down. Anchors are not resolved,
because a hand audit of all 63 in the corpus found none broken.

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

### Cross-document facts

```bash
python3 scripts/validate/validate_cross_document_facts.py
```

Holds a fact stated in more than one document to the site that owns it. Each
registered fact names a canonical source, a callable taking the project root:
the tree, where the tree is the one that decides the fact, or one named
document, where a measurement does.

Its four failure arms are kept distinguishable rather than folded into one
generic mismatch: a number that drifted from its canonical source, a pattern
that matched nothing and so left the site unchecked rather than found clean,
a pattern that matched more than one place and so would depend on file order,
and a capture that was not an integer. Each is reported as its own error with
its own explanation.

A dated reading is never registered. A present-tense claim is expected to
still be true today, while a reading that names its own date or commit is
supposed to keep saying what it said, and registering one would fail the
check the moment the fact changed even though the reading would still be
correct history.

### Ignore rules

```bash
python3 scripts/validate/validate_gitignore.py
```

Checks that every path a document says is ignored still is, and that no file is
tracked and ignored at once without a registered reason.

Some of those claims are instructions rather than description. `docs/superpowers/`
and `.rust-sec-ci.toml` being ignored is the stated reason `git add -A` is safe
here, so a reader following that after a rule changed would put specifications
and a CI configuration into a release commit. The reverse state is quieter and
one file was already in it: git honours the index, so the rule does nothing while
every reader of `.gitignore` is told otherwise. Whether a rule is still *needed*
is not checked, because a stale rule matching nothing is harmless and nagging
about one gets a check turned off.

### Documented exception keys

```bash
python3 scripts/validate/validate_documented_exception_keys.py
```

Checks that every exception key `docs/reference/configuration.md` publishes
exists as a string literal in the plugins.

A key matching nothing is silence rather than an error: the exception never
fires and the host is hardened against a deviation its operator documented and
approved. The in-code tests pin the keys against themselves, so renaming a
constant and its test together leaves the reference promising a key that is
gone. It checks documentation against source only, so a key that exists and is
documented nowhere is not covered.

### Version locations

```bash
python3 scripts/validate/validate_version_locations.py
```

Checks that every file stating the **current** version agrees with `Cargo.toml`,
and fails any tracked file carrying a current-version marker that is not
registered.

`release.sh --verify` reads four such files; this reads thirteen. Historical
mentions, changelog headings and older debian stanzas are silent by design,
since they are supposed to keep saying what they say after a bump. It overlaps
Doc sync targets above and does not replace it: that check asks whether the
updater's target list is honest, this one asks whether the versions themselves
agree.

### Colour contrast

```bash
python3 scripts/validate/validate_contrast.py
```

Checks that every foreground and background pair `crates/hardener-ui/styles.css`
declares **together in one rule** clears WCAG AA, across all seven themes.

Translucent fills are composited rather than skipped. An `rgba()` background has
no one colour until it lands on an ancestor, so each is weighed over every
opaque `--bg-*` surface the theme declares and scored on the best of those
ratios, which keeps a failure a fact whatever the real ancestor turns out to be.
Worst-case compositing was measured too and reported 61 failures on pairings
that may never co-occur; best case reported 8, and all 8 were real. That took
the pairs checked from 182 to 322, the 140 new ones coming from 18 rules that
declare an alpha background, every severity badge among them.

Deliberately not every token against every surface: that pairing was tried,
reported five themes failing on combinations that may never render, and
contradicted the screenshots. The ceiling follows directly from the scope. A
pair the stylesheet never states in one rule is unchecked, and text whose
background comes from an ancestor is not reached by a static parse at all, which
is how a High Contrast `.btn-danger` sat at 1.9:1 through eight reviewers. See
[theming.md](../design/theming.md) for what a new theme owes it.

### Test counts

```bash
python3 scripts/validate/validate_test_counts.py
```

Checks the test-count figures in `docs/reference/evidence-ledger.md` against the
tree, without running cargo.

Counts a `grep` can reproduce are reproduced from the command the ledger states
beside each reading. The rest are pinned to each other by identities the ledger
asserts in prose, so a figure edited alone fails even though nothing about it was
measured: the gap between annotations and executions **is** the `#[ignore]`d
count, and the `cargo test` totals **are** the nextest totals plus the doctests.

Every other validator here reads structure, so a number in a sentence was
invisible to all of them: one count reached four values across six documents.

**Its cross-document scope is a hand-maintained list and is the thing to know
about it.** `CROSS_DOCUMENT_SITES` names `README.md` and `scripts/README.md`, so
a count stated as current in any other tracked document is read by nothing.
Dated readings are exempt on purpose, and that exemption is why the list cannot
simply be widened to the whole corpus: a reading naming its own commit is
supposed to keep saying what it says.

### Version consistency

```bash
./scripts/release/release.sh --verify
```

Compares the workspace version in `Cargo.toml` against
`docs/architecture/architecture.md`, `packaging/assets/hardener.1` and
`src-tauri/tauri.conf.json`, and against nothing else: the packaging versions
(`PKGBUILD`, the RPM spec, `debian/changelog`) are outside its reach. Also
invoked by `validate_all.py`, as its first entry.

**Last Updated**: 2026-08-20

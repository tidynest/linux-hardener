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

**Last Updated**: 2026-07-18

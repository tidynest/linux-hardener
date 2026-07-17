# Documentation Commands

Commands for validating and auto-updating project documentation.

All scripts are Python 3 and located in `scripts/`.

---

## Master Validator

### Full validation

```bash
./scripts/validate_all.py
```

Runs every individual validator listed below in sequence. Exits non-zero if any check fails. Includes slower checks (CLI doc verification, compliance control counts).

### Quick validation

```bash
./scripts/validate_all.py --quick
```

Skips the slower validators (`validate_cli_docs.py` and `validate_compliance_docs.py`). Suitable for pre-commit checks where speed matters.

### Auto-fix mode

```bash
./scripts/validate_all.py --fix
```

Where possible, automatically corrects issues (e.g. outdated "Last Updated" dates). Not all validators support auto-fix; those that don't will still report errors for manual resolution.

---

## Auto-Update Documentation

### Preview changes (dry run)

```bash
./scripts/update_all_docs.py
```

Scans all documentation and reports what would be updated, without modifying any files. Shows:
- "Last Updated" dates that are older than the file's last git commit
- Missing entries in `FILE_MAP.md` for new source files
- Compliance framework control counts that are out of sync
- Version references that don't match `Cargo.toml`

### Apply changes

```bash
./scripts/update_all_docs.py --apply
```

Same scan as above, but writes the fixes. This is what `release.sh` runs during the release process.

---

## Individual Validators

Each of these is called by `validate_all.py`, but can be run standalone for targeted checks.

### Naming conventions

```bash
./scripts/validate_naming.py
```

Checks that Rust identifiers follow the naming conventions in `docs/NAMING_CONVENTIONS.md`: PascalCase for types, snake_case for functions, SCREAMING_SNAKE_CASE for constants.

### File map completeness

```bash
./scripts/validate_file_map.py
```

Verifies that every source file in the workspace has an entry in `docs/FILE_MAP.md`. Reports missing entries.

### Plugin documentation

```bash
./scripts/validate_plugin_docs.py
```

Checks that each plugin in `crates/hardener-plugins/` has corresponding documentation and that plugin names, descriptions, and scan/apply operations are documented accurately.

### Tauri command documentation

```bash
./scripts/validate_tauri_docs.py
```

Verifies that every `#[tauri::command]` function in `src-tauri/src/commands.rs` is documented and that the IPC command names match between code and documentation.

### Last Updated dates

```bash
./scripts/validate_last_updated.py
```

Checks that "Last Updated" dates in documentation files match (or are close to) the file's last git modification date. Reports files with stale dates.

### CLI documentation (slower)

```bash
./scripts/validate_cli_docs.py
```

Parses the CLI argument definitions in `crates/hardener-cli/src/cli.rs` and cross-references them against CLI documentation. Reports undocumented flags and subcommands. Slower because it parses Rust source.

### Compliance documentation (slower)

```bash
./scripts/validate_compliance_docs.py
```

Counts the control mappings in each compliance framework implementation and compares them against the documented counts. Slower because it reads all framework source files.

### Version consistency

```bash
./scripts/release.sh --verify
```

Checks that the version in `Cargo.toml` matches `tauri.conf.json` and all documentation references. Also invoked by `validate_all.py`.

**Last Updated**: 2026-02-26

#!/usr/bin/env python3
"""Validate that every field of a rebuilt `Finding` comes from its database row.

`ScanHistoryManager::get_result_findings` rebuilds a `Finding` field by field
from a row. A field given a hardcoded default instead compiles, passes every
test that does not happen to assert on it, and drops the persisted value in
silence. That is not hypothetical: `finding_exception_key` shipped as a
hardcoded `None` here and nothing said so, which is what this check exists to
stop happening to the next field.

A comment written immediately above the field exempts it, for the case where a
field genuinely has no column and that is a decision rather than an oversight.

The opposite direction, a field that is not a literal but still does not
survive the trip, is invisible here and is covered by
`every_finding_field_survives_the_scan_history` in
`crates/hardener-state/tests/scan_manager_tests.rs`.

Usage:
    ./scripts/validate/validate_persisted_finding_fields.py
"""

import re
import sys
from pathlib import Path

RED = "\033[0;31m"
GREEN = "\033[0;32m"
NC = "\033[0m"

SOURCE = Path("crates") / "hardener-state" / "src" / "scan_manager.rs"
TYPES = Path("crates") / "hardener-types" / "src" / "lib.rs"

# The rebuild site. Everything between this line and its closing brace is the
# literal whose fields must each come from the row.
LITERAL_START = re.compile(r"^\s*findings\.push\(Finding\s*\{\s*$")
LITERAL_END = re.compile(r"^\s*\}\);\s*$")

# `\s*` rather than a single space because rustfmt owns the whitespace and this
# check must not.
FIELD = re.compile(r"^\s*(\w+):\s*(.+?),?\s*$")
COMMENT = re.compile(r"^\s*//")

STRUCT_START = re.compile(r"^pub struct Finding \{$")
PUB_FIELD = re.compile(r"^\s*pub (\w+):")

# Values meaning "this field was not read from the row": defaults a compiler
# accepts in place of a real value.
HARDCODED = {
    "None",
    "vec![]",
    "Vec::new()",
    "String::new()",
    '"".to_string()',
    '""',
    "false",
    "true",
    "0",
    "Default::default()",
}


def find_project_root() -> Path:
    """Find the project root by looking for Cargo.toml."""
    current = Path.cwd()
    while current != current.parent:
        if (current / "Cargo.toml").exists():
            return current
        current = current.parent
    print(f"{RED}Error: could not find project root (no Cargo.toml found){NC}")
    sys.exit(1)


def declared_fields(root: Path) -> set[str]:
    """Every field `Finding` declares, read from hardener-types."""
    fields: set[str] = set()
    inside = False
    for line in (root / TYPES).read_text(encoding="utf-8").splitlines():
        if STRUCT_START.match(line):
            inside = True
            continue
        if not inside:
            continue
        if line.startswith("}"):
            break
        match = PUB_FIELD.match(line)
        if match:
            fields.add(match.group(1))
    return fields


def literal_span(lines: list[str]) -> tuple[int, int] | None:
    """The half-open line range of the rebuild literal's body, or None."""
    for index, line in enumerate(lines):
        if not LITERAL_START.match(line):
            continue
        for end in range(index + 1, len(lines)):
            if LITERAL_END.match(lines[end]):
                return index + 1, end
        break
    return None


def reason_precedes(lines: list[str], index: int) -> bool:
    """Whether a comment sits immediately above the field at `index`."""
    cursor = index - 1
    while cursor >= 0 and not lines[cursor].strip():
        cursor -= 1
    return cursor >= 0 and bool(COMMENT.match(lines[cursor]))


def check_rebuild(root: Path) -> tuple[list[str], int, set[str]]:
    """Return the failures, the exempted count, and the field names seen."""
    failures: list[str] = []
    exempted = 0
    seen: set[str] = set()

    lines = (root / SOURCE).read_text(encoding="utf-8").splitlines()
    span = literal_span(lines)
    if span is None:
        failures.append(
            f"{SOURCE}: the `findings.push(Finding {{` rebuild site was not "
            f"found, so this check examined nothing while reporting success"
        )
        return failures, 0, seen

    start, end = span
    for index in range(start, end):
        line = lines[index]
        if not line.strip() or COMMENT.match(line):
            continue
        if line.strip().startswith(".."):
            failures.append(
                f"{SOURCE}:{index + 1}: the rebuild fills fields from a struct "
                f"update (`..`) without naming them, so a dropped field cannot "
                f"be seen here"
            )
            continue
        match = FIELD.match(line)
        if not match:
            continue
        name, value = match.group(1), match.group(2)
        seen.add(name)
        if value not in HARDCODED:
            continue
        if reason_precedes(lines, index):
            exempted += 1
            continue
        failures.append(
            f"{SOURCE}:{index + 1}: {name} is rebuilt as the hardcoded {value} "
            f"rather than from the row, so whatever was persisted is dropped "
            f"silently. Read it from the row, or write the reason above it"
        )

    return failures, exempted, seen


def main() -> int:
    root = find_project_root()
    print("Validating persisted finding fields...")

    failures, exempted, seen = check_rebuild(root)
    declared = declared_fields(root)

    # Positive control. A regex reaching nothing would report every field as
    # persisted, and zero fields examined reads exactly like zero problems.
    if not declared:
        print(
            f"  {RED}x{NC} no field of `Finding` was found in {TYPES}. Either "
            f"the struct was renamed or this check's pattern no longer reaches "
            f"it, and it compared nothing while reporting success"
        )
        return 1

    missing = sorted(declared - seen)
    if missing and not failures:
        print(
            f"  {RED}x{NC} {SOURCE}: the rebuild names {len(seen)} fields but "
            f"`Finding` declares {len(declared)}. Unmatched: "
            f"{', '.join(missing)}. This check reads one line at a time, so a "
            f"field rustfmt split across lines is invisible to it and must be "
            f"handled before the check means anything"
        )
        return 1

    if failures:
        print(f"  {RED}Fields not read from the row:{NC}")
        for failure in failures:
            print(f"    {RED}x{NC} {failure}")
        print(
            f"\n{RED}{len(failures)} unexplained field(s) against "
            f"{len(seen)} examined. A hardcoded default drops a persisted "
            f"value silently.{NC}"
        )
        return 1

    print(f"  {GREEN}v{NC} All {len(seen)} rebuilt Finding fields come from the row")
    if exempted:
        print(f"  {GREEN}v{NC} {exempted} carry a default and each says why")
    print(f"\n{GREEN}Persisted finding field validation passed{NC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Validate that every evidence reference in the ledger still exists.

A ledger row claims a capability is covered and names the file that covers it.
When that file is renamed or deleted the row goes on asserting coverage that is
gone, and the ledger becomes worse than no ledger: it is a promise nobody
checks. This fails on any referenced path that is absent.

Existence alone is too weak to be believed, because a check that reports nothing
looks identical whether it is clean or broken. Any non-empty result passes an
existence test: stripping the backticks out of the Evidence column left eleven
references and exit 0, and deleting every table row while keeping the prose left
seven and exit 0, a ledger promising nothing at all reported green. So the
collected references are cross-checked against the ledger's own structure. Every
row of a capability table must cite at least one path in its Evidence cell. That
number is derived from the document rather than pinned here, so a later phase
adding rows raises it without editing this file, while emptying one row's cell
fails even though every other row still cites plenty.

It cannot check that the named test actually exercises the claim. That is a
judgement, and it is made at review time; this only catches the mechanical half.

Usage:
    ./scripts/validate/validate_evidence_ledger.py

Exit codes:
    0: every capability row cites evidence, and every path cited anywhere exists
    1: the ledger is missing, cites nothing, holds no capability row, holds a row
       citing nothing, or cites a path that is gone
"""

import re
import sys
from pathlib import Path

RED = "\033[0;31m"
GREEN = "\033[0;32m"
NC = "\033[0m"

# The header every capability table carries. The rows beneath one are the
# ledger's claims; the tables above the capabilities section (the column key,
# the baseline readings, the mutation readings) are not, and counting those as
# coverage would be the same vacuity in a subtler form.
CLAIM_HEADER = "| Claim | Evidence | Command | Ceiling |"

# A citation: a repo-relative path in backticks, beginning with one of the four
# prefixes the ledger's own "Adding a row" section requires.
REFERENCE = re.compile(r"`((?:crates|scripts|src-tauri|gui-tests)/[A-Za-z0-9_./-]+)`")

# A cell boundary. A pipe written as `\|` belongs to its cell rather than
# separating two, so it must not split the row.
CELL = re.compile(r"(?<!\\)\|")

# The dashes, colons, pipes and spaces a table's separator row is made of.
SEPARATOR_CHARS = set("|-: ")


def find_project_root() -> Path:
    """The repository root, found by walking up from this file."""
    return Path(__file__).resolve().parent.parent.parent


def capability_rows(ledger: str) -> list[tuple[int, str, str]]:
    """(line number, claim cell, evidence cell) for every capability row.

    A row counts only while `CLAIM_HEADER` is the nearest table header above it,
    which is what keeps the baseline and mutation tables out. The separator row
    is skipped and the table ends at the first line that is not a row, so prose
    between two tables cannot join them into one.
    """
    rows: list[tuple[int, str, str]] = []
    in_table = False
    for number, line in enumerate(ledger.splitlines(), start=1):
        stripped = line.strip()
        if stripped == CLAIM_HEADER:
            in_table = True
        elif not in_table:
            continue
        elif not stripped.startswith("|"):
            in_table = False
        elif not set(stripped) <= SEPARATOR_CHARS:
            cells = [cell.strip() for cell in CELL.split(stripped.strip("|"))]
            rows.append((number, cells[0], cells[1] if len(cells) > 1 else ""))
    return rows


def summarise(claim: str, width: int = 60) -> str:
    """A claim cell shortened to one readable line for a failure listing."""
    return claim if len(claim) <= width else f"{claim[: width - 3]}..."


def main() -> int:
    root = find_project_root()
    ledger = root / "docs" / "reference" / "evidence-ledger.md"
    if not ledger.exists():
        print(f"{RED}The evidence ledger is missing: {ledger}{NC}")
        return 1

    text = ledger.read_text()
    refs = set(REFERENCE.findall(text))
    if not refs:
        print(f"{RED}No evidence references found in the ledger.{NC}")
        print("  An empty ledger passes vacuously, which is the failure mode")
        print("  this check exists to prevent.")
        return 1

    rows = capability_rows(text)
    if not rows:
        print(f"{RED}No capability rows found in the ledger.{NC}")
        print(f"  Expected at least one row under {CLAIM_HEADER!r}, found none.")
        print(f"  The {len(refs)} references collected elsewhere in the file are")
        print("  prose and commands: on their own they claim no coverage, so a")
        print("  ledger whose table is gone would otherwise report a healthy")
        print("  count while promising nothing.")
        return 1

    uncited = [(n, claim) for n, claim, evidence in rows if not REFERENCE.search(evidence)]
    if uncited:
        print(f"{RED}Capability rows citing no evidence ({len(uncited)} of {len(rows)}):{NC}")
        for number, claim in uncited:
            print(f"  - line {number}: {summarise(claim)}")
        print()
        print("  Each row's Evidence cell must name at least one repo-relative")
        print("  path in backticks, beginning crates/, scripts/, src-tauri/ or")
        print("  gui-tests/. A row without one claims coverage nothing can check,")
        print("  and the file-wide count stays healthy on other rows' citations.")
        return 1

    missing = sorted(r for r in refs if not (root / r).exists())
    if missing:
        print(f"{RED}Evidence referenced by the ledger that no longer exists ({len(missing)}):{NC}")
        for m in missing:
            print(f"  - {m}")
        print()
        print("  Each row claims a capability is covered and names this file as the")
        print("  cover. A missing file means the claim is now unbacked.")
        return 1

    print(f"{GREEN}All {len(refs)} evidence references in the ledger exist, "
          f"cited by {len(rows)} capability rows{NC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

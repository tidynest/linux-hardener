#!/usr/bin/env python3
"""Validate that every evidence reference in the ledger still exists.

A ledger row claims a capability is covered and names the file that covers it.
When that file is renamed or deleted the row goes on asserting coverage that is
gone, and the ledger becomes worse than no ledger: it is a promise nobody
checks. This fails on any referenced path that is absent.

It cannot check that the named test actually exercises the claim. That is a
judgement, and it is made at review time; this only catches the mechanical half.

Usage:
    ./scripts/validate/validate_evidence_ledger.py

Exit codes:
    0: every path the ledger cites as evidence exists
    1: the ledger is missing, cites nothing, or cites a path that is gone
"""

import re
import sys
from pathlib import Path

RED, GREEN, NC = "\033[0;31m", "\033[0;32m", "\033[0m"


def main() -> int:
    root = Path(__file__).resolve().parent.parent.parent
    ledger = root / "docs" / "reference" / "evidence-ledger.md"
    if not ledger.exists():
        print(f"{RED}The evidence ledger is missing: {ledger}{NC}")
        return 1

    refs = set(re.findall(r"`((?:crates|scripts|src-tauri|gui-tests)/[A-Za-z0-9_./-]+)`",
                          ledger.read_text()))
    if not refs:
        print(f"{RED}No evidence references found in the ledger.{NC}")
        print("  An empty ledger passes vacuously, which is the failure mode")
        print("  this check exists to prevent.")
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

    print(f"{GREEN}All {len(refs)} evidence references in the ledger exist{NC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

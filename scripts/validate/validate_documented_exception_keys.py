#!/usr/bin/env python3
"""Validate that every exception key the configuration reference publishes exists.

`docs/reference/configuration.md` names the literal strings an operator types
into `[<plugin>.exceptions."<key>"]`. That is a published contract, not a
description: an exception whose key matches nothing is not an error, it is
silence. `matching_exception` simply never fires, the plugin applies the change,
and the host is hardened against a deviation the operator wrote down and
approved. Nothing in the run says so.

The keys are pinned inside the code already, by tests such as
`every_audit_finding_names_the_exception_key_that_silences_it`. That guards the
code's agreement with itself and not its agreement with the documentation:
renaming a constant and updating the test beside it is one natural edit, and it
leaves the reference promising a key that no longer exists. Measured while
building this: mutating `AUDITD_PRESENT_EXCEPTION` to `auditd_present` failed
that test and left all eighteen validators passing.

Direction, stated because it bounds what this can catch. This checks
documentation against source: every key the reference names must appear as a
string literal in `crates/hardener-plugins/src`. It cannot catch the reverse, a
key that exists in source and is documented nowhere, because source is full of
string literals that are not exception keys and any rule separating them would
be guesswork. The undocumented-key direction is a real gap and is not covered
here.

Usage:
    ./scripts/validate/validate_documented_exception_keys.py

Exit codes:
    0: every documented key exists in the plugin sources
    1: at least one documented key exists nowhere
"""

import re
import sys
from pathlib import Path

RED = "\033[0;31m"
GREEN = "\033[0;32m"
NC = "\033[0m"

# The reference section that publishes the keys. Bounded at both ends so the
# scan cannot wander into unrelated backticked prose and start reporting
# ordinary words as missing keys.
SECTION_START = "The exception key is check-specific"
SECTION_END = "## Environment variables"


def find_project_root() -> Path:
    """The repository root, found by walking up from this file."""
    return Path(__file__).resolve().parent.parent.parent


def documented_keys(reference: str) -> set[str]:
    """Every exception key named in the reference's exception-key section.

    Backticked lowercase tokens only. That deliberately also picks up the
    per-plugin examples (`minlen`, `cups`, `/etc/shadow`'s neighbours), which is
    correct: they are published as keys that work, so a reader will type them,
    and they should exist for the same reason the rest should.
    """
    start = reference.find(SECTION_START)
    end = reference.find(SECTION_END, start)
    if start == -1 or end == -1:
        return set()
    return set(re.findall(r"`([a-z0-9][a-z0-9_-]*)`", reference[start:end]))


def main() -> int:
    root = find_project_root()
    reference = root / "docs" / "reference" / "configuration.md"
    plugins = root / "crates" / "hardener-plugins" / "src"

    if not reference.exists() or not plugins.exists():
        print(f"{RED}Cannot find the reference or the plugin sources{NC}")
        return 1

    keys = documented_keys(reference.read_text())
    if not keys:
        # An empty set would pass vacuously, and the section moving or being
        # renamed is exactly how that would happen.
        print(f"{RED}No exception keys found in {reference.name}.{NC}")
        print(f"  Expected a section starting {SECTION_START!r}.")
        print("  If that heading moved, update SECTION_START rather than")
        print("  leaving this validator passing on nothing.")
        return 1

    source = "\n".join(p.read_text() for p in plugins.rglob("*.rs"))
    missing = sorted(key for key in keys if f'"{key}"' not in source)

    if missing:
        print(f"{RED}Documented exception keys that exist nowhere ({len(missing)}):{NC}")
        for key in missing:
            print(f"  - {key}")
        print()
        print("  Each is published in docs/reference/configuration.md as a key an")
        print("  operator writes. A key matching nothing is silence rather than an")
        print("  error: the exception never fires and the host is hardened against")
        print("  a deviation its operator documented and approved.")
        print()
        print("  Either restore the key in the plugin, or correct the reference.")
        return 1

    print(f"{GREEN}All {len(keys)} documented exception keys exist in the plugins{NC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

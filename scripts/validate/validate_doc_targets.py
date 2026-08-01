#!/usr/bin/env python3
"""
Validates that every doc-sync target update_all_docs.py declares can be reached.

The updater walks two lists of targets and skips, silently, any whose file is
missing or whose pattern matches nothing. A skipped target produces no update
and no complaint, so the run reports "no changes needed" for work it never
attempted, and the documentation it exists to maintain rots with a green light
above it. That is the same failure the rest of this project refuses elsewhere:
doing nothing must never report success.

Five of the compliance framework files the updater names were deleted in
4039ed1 (2026-06-20). For six weeks afterwards the control counts in
architecture.md were the sizes of files that no longer existed, and every run of
the updater said there was nothing to do.

This check imports the target lists rather than restating them, because a second
copy of a list is a second thing to drift.

Usage:
    ./scripts/validate/validate_doc_targets.py

Exit codes:
    0: every declared target resolves
    1: at least one target names a missing file or matches nothing
"""

import re
import sys
from pathlib import Path

# Import the targets rather than caching bytecode for them. Python invalidates a
# .pyc on source mtime and size, both at one-second granularity, so an edit that
# preserves a file's length and lands in the same second as the last one is
# served from cache: this check then reports on a version of update_all_docs.py
# that no longer exists. That is not hypothetical, it happened while proving this
# check discriminates, and it is the same shape as any control anchored to a
# snapshot of a world that has since moved.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from update_all_docs import (  # noqa: E402
    COMPLIANCE_SOURCE_FILES,
    VERSION_REFERENCE_TARGETS,
)

RED = "\033[0;31m"
GREEN = "\033[0;32m"
BLUE = "\033[0;34m"
NC = "\033[0m"

FRAMEWORKS_DIR = Path("crates") / "hardener-compliance" / "src" / "frameworks"


def find_project_root() -> Path:
    """Find the project root by looking for Cargo.toml."""
    current = Path.cwd()
    while current != current.parent:
        if (current / "Cargo.toml").exists():
            return current
        current = current.parent
    print(f"{RED}Error: Could not find project root (no Cargo.toml found){NC}")
    sys.exit(1)


def check_compliance_sources(root: Path) -> list[str]:
    """Every framework file the updater counts controls in must exist."""
    failures = []
    for filename, framework in COMPLIANCE_SOURCE_FILES.items():
        if not (root / FRAMEWORKS_DIR / filename).exists():
            failures.append(
                f"COMPLIANCE_SOURCE_FILES names {FRAMEWORKS_DIR / filename} "
                f"for {framework}, which does not exist: its count can never "
                f"be updated and the updater will not say so"
            )
    return failures


def check_version_references(root: Path) -> list[str]:
    """Every version-reference target must exist and its pattern must match."""
    failures = []
    for rel_path, pattern in VERSION_REFERENCE_TARGETS:
        filepath = root / rel_path
        if not filepath.exists():
            failures.append(
                f"VERSION_REFERENCE_TARGETS names {rel_path}, which does not exist"
            )
            continue
        if not re.search(pattern, filepath.read_text(encoding="utf-8")):
            failures.append(
                f"VERSION_REFERENCE_TARGETS pattern for {rel_path} matches "
                f"nothing in it: {pattern}"
            )
    return failures


def main() -> int:
    print(f"{BLUE}Validating documentation sync targets...{NC}\n")
    root = find_project_root()

    failures = check_compliance_sources(root) + check_version_references(root)

    declared = len(COMPLIANCE_SOURCE_FILES) + len(VERSION_REFERENCE_TARGETS)
    if failures:
        print(f"  {RED}Unreachable targets:{NC}")
        for failure in failures:
            print(f"    {RED}x{NC} {failure}")
        print(
            f"\n{RED}{len(failures)} of {declared} declared targets cannot be "
            f"reached. update_all_docs.py reports success without them.{NC}"
        )
        return 1

    print(f"  {GREEN}v{NC} All {declared} declared doc-sync targets resolve")
    print(f"\n{GREEN}Documentation sync target validation passed{NC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

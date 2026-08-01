#!/usr/bin/env python3
"""
Validates that update_all_docs.py's declared targets and the tree agree, in
both directions.

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

The version references need the inverse check as well, and issue #54 is why. A
list of files to rewrite cannot notice a file that should be on it. data-flow.md
carried a version line for months, was not declared, and drifted to 1.4.0 while
the release was 1.5.1; adding it fixed that file and left the next one in exactly
the same position. So every markdown file carrying a version-line shape must be a
declared target, and one that is not fails this check by name.

Rewriting the updater to discover version lines instead was considered and
rejected. A script that silently rewrites every version-shaped string it finds
will eventually rewrite one meant to stay, such as a minimum-supported-version
statement or a historical note, and a wrong rewrite is worse than a stale line
that something complains about.

Usage:
    ./scripts/validate/validate_doc_targets.py

Exit codes:
    0: every declared target resolves, and nothing that should be declared is not
    1: a target names a missing file, matches nothing, or a file carries an
       undeclared version line
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


# The shape of a version line as this documentation writes it. Deliberately
# loose about where the colon sits, because that is exactly the difference that
# hid architecture.md from the updater for months: it writes `**Version:**` and
# README.md writes `**Version**:`.
VERSION_LINE = re.compile(r"^\s*\*\*Version:?\*\*:?\s*\d+\.\d+\.\d+", re.MULTILINE)

# Directories whose contents are not maintained against the current release.
# An archived audit or a shipped dependency is supposed to name the version it
# was written for, and rewriting it would be the wrong kind of correct.
UNMAINTAINED = ("archive", "node_modules", "target", ".git", "superpowers")


def check_undeclared_version_lines(root: Path) -> list[str]:
    """Every markdown file with a version line must be a declared target.

    The forward check asks whether each declared target can be reached. This
    asks the question a list cannot ask of itself: whether anything that should
    be on it is missing. A file in that position is silently never updated, and
    the updater reports success without it, which is how data-flow.md came to
    sit at 1.4.0 through two releases.
    """
    declared = {rel_path for rel_path, _ in VERSION_REFERENCE_TARGETS}
    failures = []
    for path in sorted(root.rglob("*.md")):
        relative = path.relative_to(root)
        if any(part in UNMAINTAINED for part in relative.parts):
            continue
        if str(relative) in declared:
            continue
        if VERSION_LINE.search(path.read_text(encoding="utf-8")):
            failures.append(
                f"{relative} carries a version line and is not in "
                f"VERSION_REFERENCE_TARGETS, so no release will ever update it "
                f"and update_all_docs.py will not say so"
            )
    return failures


def main() -> int:
    print(f"{BLUE}Validating documentation sync targets...{NC}\n")
    root = find_project_root()

    failures = (
        check_compliance_sources(root)
        + check_version_references(root)
        + check_undeclared_version_lines(root)
    )

    declared = len(COMPLIANCE_SOURCE_FILES) + len(VERSION_REFERENCE_TARGETS)
    if failures:
        print(f"  {RED}Unreachable targets:{NC}")
        for failure in failures:
            print(f"    {RED}x{NC} {failure}")
        print(
            f"\n{RED}{len(failures)} problem(s) against {declared} declared "
            f"targets. update_all_docs.py reports success without them.{NC}"
        )
        return 1

    print(f"  {GREEN}v{NC} All {declared} declared doc-sync targets resolve")
    print(f"  {GREEN}v{NC} No undeclared version line anywhere in the documentation")
    print(f"\n{GREEN}Documentation sync target validation passed{NC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

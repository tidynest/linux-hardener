#!/usr/bin/env python3
"""Validate that every finding which forgoes a policy exception says why.

A `Finding` carrying `finding_policy_exception: None` is a finding no operator
can excuse. `ReportGenerator::has_live_finding` fails a compliance control on
any finding whose exception is `None`, so a hardcoded `None` in a scan is not a
missing feature: it silently overrides a deviation the operator wrote down and
approved.

Six of these shipped at once, in firewall, mac and audit, and none of them was
a decision anyone had taken. The seventh, pam's module-absence finding, is
deliberate and says so at the site: an exception documents a value the operator
accepts, and that finding is not about a value.

That difference is the whole check. A `None` with a reason written beside it is
a decision; a `None` with nothing beside it is an oversight that reads exactly
like a decision. Counting the sites cannot tell them apart, and neither can a
test, because a test asserting a field is `None` passes just as happily on an
oversight as on a choice.

Usage:
    ./scripts/validate/validate_policy_exception_sites.py
"""

import re
import sys
from pathlib import Path

RED = "\033[0;31m"
GREEN = "\033[0;32m"
NC = "\033[0m"

PLUGIN_SOURCE_ROOT = Path("crates") / "hardener-plugins" / "src"

# The field as it is written at a struct literal. `\s*` rather than a single
# space because rustfmt owns the whitespace and this check must not.
FIELD = re.compile(r"^\s*finding_policy_exception:\s*(.+?),?\s*$")

# A line carrying the exemption: an ordinary comment, or a doc comment, written
# immediately above the field. Blank lines between the two are allowed, because
# rustfmt is entitled to insert one.
COMMENT = re.compile(r"^\s*//")


def find_project_root() -> Path:
    """Find the project root by looking for Cargo.toml."""
    current = Path.cwd()
    while current != current.parent:
        if (current / "Cargo.toml").exists():
            return current
        current = current.parent
    print(f"{RED}Error: could not find project root (no Cargo.toml found){NC}")
    sys.exit(1)


def reason_precedes(lines: list[str], index: int) -> bool:
    """Whether a comment sits immediately above the field at `index`."""
    cursor = index - 1
    while cursor >= 0 and not lines[cursor].strip():
        cursor -= 1
    return cursor >= 0 and bool(COMMENT.match(lines[cursor]))


def check_sites(root: Path) -> tuple[list[str], int, int]:
    """Return the unexplained sites, the exempted count, and the total seen."""
    failures: list[str] = []
    exempted = 0
    total = 0

    for source in sorted((root / PLUGIN_SOURCE_ROOT).rglob("*.rs")):
        lines = source.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            match = FIELD.match(line)
            if not match:
                continue
            total += 1
            if match.group(1) != "None":
                continue
            if reason_precedes(lines, index):
                exempted += 1
                continue
            failures.append(
                f"{source.relative_to(root)}:{index + 1}: "
                f"finding_policy_exception is None with no reason written above "
                f"it, so no operator can excuse this finding and report fails "
                f"its controls. Write the reason, or look the exception up"
            )

    return failures, exempted, total


def main() -> int:
    root = find_project_root()
    print("Validating policy exception sites...")

    failures, exempted, total = check_sites(root)

    # Positive control. A regex that matched nothing would report every site as
    # explained, which is this project's most repeated defect and is especially
    # quiet here: zero sites examined reads exactly like zero problems found.
    if total == 0:
        print(
            f"  {RED}x{NC} no finding_policy_exception site found anywhere under "
            f"{PLUGIN_SOURCE_ROOT}. Either the field was renamed or this check's "
            f"pattern no longer reaches it, and it compared nothing while "
            f"reporting success"
        )
        return 1

    if failures:
        print(f"  {RED}Unexplained sites:{NC}")
        for failure in failures:
            print(f"    {RED}x{NC} {failure}")
        print(
            f"\n{RED}{len(failures)} unexplained site(s) against {total} "
            f"examined. A hardcoded None overrides an approved deviation "
            f"silently.{NC}"
        )
        return 1

    print(f"  {GREEN}v{NC} All {total} policy exception sites examined")
    print(f"  {GREEN}v{NC} {exempted} forgo an exception and each says why")
    print(f"\n{GREEN}Policy exception site validation passed{NC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

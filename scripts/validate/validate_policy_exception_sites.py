#!/usr/bin/env python3
"""Validate that every finding which forgoes a policy exception says why.

A `Finding` carrying `finding_exception: ExceptionOutcome::NotConfigured` is a
finding no operator can excuse. `ReportGenerator::has_live_finding` fails a
compliance control on any finding whose exception is `NotConfigured`, so a
hardcoded `NotConfigured` in a scan is not a missing feature: it silently
overrides a deviation the operator wrote down and approved.

Six of these shipped at once, in firewall, mac and audit, and none of them was
a decision anyone had taken. The seventh, pam's module-absence finding, is
deliberate and says so at the site: an exception documents a value the operator
accepts, and that finding is not about a value.

That difference is the whole check. A `NotConfigured` with a reason written
beside it is a decision; a `NotConfigured` with nothing beside it is an
oversight that reads exactly like a decision. Counting the sites cannot tell
them apart, and neither can a test, because a test asserting a field is
`NotConfigured` passes just as happily on an oversight as on a choice.

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
FIELD = re.compile(r"^\s*finding_exception:\s*(.+?),?\s*$")

# A line carrying the exemption: an ordinary comment, or a doc comment, written
# immediately above the field. Blank lines between the two are allowed, because
# rustfmt is entitled to insert one.
COMMENT = re.compile(r"^\s*//")

# The key an operator writes the exception under, which sits at the same
# literal. `finding_id` cannot stand in for it: every plugin derives the id
# from the key by a transform that loses information.
KEY_FIELD = re.compile(r"^\s*finding_exception_key:\s*(.+?),?\s*$")


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


def key_beside(lines: list[str], index: int) -> str | None:
    """The `finding_exception_key` value at the same literal as `index`.

    Both fields belong to one `Finding`, so the search stops at the literal's
    closing brace rather than running on into the next one and reading its key.
    `finding_exception` is now often a multi-line `.map_or(NotConfigured, |e|
    { ... })` lookup, and that closure's own closing brace would otherwise be
    mistaken for the end of the `Finding` literal, so the search tracks brace
    depth rather than stopping at the first line that starts with `}`.
    """
    depth = lines[index].count("{") - lines[index].count("}")
    for cursor in range(index + 1, min(index + 8, len(lines))):
        line = lines[cursor]
        if depth == 0:
            match = KEY_FIELD.match(line)
            if match:
                return match.group(1)
            if line.strip().startswith("}"):
                break
        depth += line.count("{") - line.count("}")
        if depth < 0:
            break
    return None


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

            # The two fields answer the same question and must agree. A key
            # beside a hardcoded NotConfigured advertises a setting that
            # changes nothing; no key beside a live lookup hides a usable one.
            # Neither is visible to a test: one asserting the field is
            # NotConfigured passes just as happily on an oversight as on a
            # choice, which is why this check is here rather than in the
            # suite.
            key = key_beside(lines, index)
            consults_config = match.group(1) != "ExceptionOutcome::NotConfigured"
            if key is None:
                failures.append(
                    f"{source.relative_to(root)}:{index + 1}: "
                    f"this Finding carries no finding_exception_key at all, so "
                    f"nothing can tell an operator which key an exception takes"
                )
            elif consults_config and key == "None":
                failures.append(
                    f"{source.relative_to(root)}:{index + 1}: "
                    f"the exception is looked up here but finding_exception_key "
                    f"is None, so a usable setting is hidden from the operator"
                )
            elif not consults_config and key != "None":
                failures.append(
                    f"{source.relative_to(root)}:{index + 1}: "
                    f"finding_exception_key names {key} while the exception is "
                    f"hardcoded ExceptionOutcome::NotConfigured, so an operator "
                    f"is offered a setting that changes nothing"
                )

            if consults_config:
                continue
            if reason_precedes(lines, index):
                exempted += 1
                continue
            failures.append(
                f"{source.relative_to(root)}:{index + 1}: "
                f"finding_exception is ExceptionOutcome::NotConfigured with no "
                f"reason written above it, so no operator can excuse this "
                f"finding and report fails its controls. Write the reason, or "
                f"look the exception up"
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
            f"  {RED}x{NC} no finding_exception site found anywhere under "
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
            f"examined. A hardcoded ExceptionOutcome::NotConfigured overrides "
            f"an approved deviation silently.{NC}"
        )
        return 1

    print(f"  {GREEN}v{NC} All {total} policy exception sites examined")
    print(f"  {GREEN}v{NC} {exempted} forgo an exception and each says why")
    print(f"\n{GREEN}Policy exception site validation passed{NC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

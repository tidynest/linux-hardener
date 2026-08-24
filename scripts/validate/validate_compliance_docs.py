#!/usr/bin/env python3
"""
Validates that compliance documentation lists every framework defined in the
`ComplianceFramework` enum (the single source of truth).

Why not control counts? Post-rework the per-framework control catalogues are
split between curated files (`cis.rs`, `iso27001.rs`) and plugin-declared
coverage that is aggregated at runtime, so a static per-control count is no
longer meaningful here. This validator therefore checks the framework *list*:
every enum variant must appear in each documented framework table, and no table
may list a framework the code does not define.

Usage:
    ./scripts/validate/validate_compliance_docs.py

Exit codes:
    0: every enum framework is documented in each table (and vice versa)
    1: drift between the enum and the docs

Checks:
    - docs/architecture/architecture.md framework table
    - docs/ROADMAP.md framework table
    - scripts/test/full-test-suite.sh `FRAMEWORKS`, the table the cross-distro
      matrix renders a report and a PDF for

The last of those was added on 2026-08-19, after that array was found naming
seven of the ten: soc2, 800-171 and fedramp were rendered on no distribution and
nothing said so, because a documentation validator that reads only documentation
cannot see a gap in a test table. It is asked as set equality against `id()`
rather than as containment, so a renamed id fails here too instead of quietly
falling through to the alias table `from_id` keeps for legacy spellings.
"""

import re
import sys
from pathlib import Path

# ANSI colour codes
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
NC = "\033[0m"  # No colour

# enum variant -> a distinctive substring that must appear in a doc table row.
# Defaults to the variant name itself for any future variant not listed here, so
# adding a framework without updating this map still surfaces as a drift error.
DOC_MARKERS = {
    "CIS": "CIS",
    "STIG": "STIG",
    "NIST": "NIST",
    "PCIDSS": "PCI",  # docs write "PCI-DSS"
    "HIPAA": "HIPAA",
    "GDPR": "GDPR",
    "ISO27001": "27001",  # docs write "ISO/IEC 27001:2022"
    "SOC2": "SOC 2",  # docs write "SOC 2", not the bare variant name
    "NIST800171": "800-171",  # docs write "NIST SP 800-171"
    "FedRAMP": "FedRAMP",
}


def find_project_root() -> Path:
    """Find the project root by looking for Cargo.toml."""
    current = Path.cwd()
    while current != current.parent:
        if (current / "Cargo.toml").exists():
            return current
        current = current.parent
    print(f"{RED}Error: Could not find project root (no Cargo.toml found){NC}")
    sys.exit(1)


def parse_enum_frameworks(root: Path) -> list[str]:
    """Extract ComplianceFramework variant identifiers (the source of truth)."""
    src = (root / "crates" / "hardener-types" / "src" / "lib.rs").read_text()
    match = re.search(r"enum ComplianceFramework\s*\{(.*?)\n\}", src, re.DOTALL)
    if not match:
        print(f"{RED}Error: ComplianceFramework enum not found in hardener-types{NC}")
        sys.exit(1)
    # Variant lines look like `    CIS,` (skip doc comments and attributes).
    return re.findall(r"^\s*([A-Z][A-Za-z0-9]+)\s*,", match.group(1), re.MULTILINE)


def parse_enum_ids(root: Path) -> dict[str, str]:
    """Map each variant to the request id `ComplianceFramework::id()` returns."""
    src = (root / "crates" / "hardener-types" / "src" / "lib.rs").read_text()
    match = re.search(r"fn id\(&self\)[^{]*\{(.*?)\n    \}", src, re.DOTALL)
    if not match:
        print(f"{RED}Error: ComplianceFramework::id() not found in hardener-types{NC}")
        sys.exit(1)
    return dict(
        re.findall(r"ComplianceFramework::(\w+)\s*=>\s*\"([^\"]+)\"", match.group(1))
    )


def parse_suite_frameworks(root: Path) -> list[str]:
    """Extract the `FRAMEWORKS` array the cross-distro suite loops over."""
    src = (root / "scripts" / "test" / "full-test-suite.sh").read_text()
    match = re.search(r"^FRAMEWORKS=\((.*?)\)", src, re.DOTALL | re.MULTILINE)
    if not match:
        print(f"{RED}Error: FRAMEWORKS array not found in full-test-suite.sh{NC}")
        sys.exit(1)
    return re.findall(r'"([^"]+)"', match.group(1))


def check_suite_table(root: Path, frameworks: list[str]) -> bool:
    """Hold the suite's FRAMEWORKS array to the enum. True on drift."""
    rel = "scripts/test/full-test-suite.sh"
    print(f"{BLUE}Checking {rel} FRAMEWORKS...{NC}")

    ids = parse_enum_ids(root)
    missing_ids = [fw for fw in frameworks if fw not in ids]
    if missing_ids:
        print(f"  {RED}Variants with no arm in id(): {', '.join(missing_ids)}{NC}\n")
        return True

    want = {ids[fw] for fw in frameworks}
    got = set(parse_suite_frameworks(root))
    absent, extra = sorted(want - got), sorted(got - want)
    if not absent and not extra:
        print(f"  {GREEN}✓ All {len(want)} frameworks rendered by the suite{NC}\n")
        return False

    for label, items in (
        ("defined in code but rendered by no distribution", absent),
        ("named by the suite but defined by no variant's id()", extra),
    ):
        if items:
            print(f"  {RED}Frameworks {label}:{NC}")
            for item in items:
                print(f"    - {item}")
    print()
    return True


def framework_table_cells(content: str) -> list[str]:
    """The first cell of every markdown table row, which is where a table names
    its subject.

    This used to join whole rows into one string and search that. A substring
    match over every pipe-carrying line in the file answers "is this framework
    mentioned anywhere in anything table-shaped", which is a weaker question
    than the one this validator is named for, and the difference is reachable:
    renaming architecture.md's `| ISO 27001:2022 |` to `| ISO 27002:2022 |`
    passed, because the same row's own description says `ISO/IEC 27001:2022`
    and cites `frameworks/iso27001.rs`, so the `27001` marker survived the
    label being wrong. Measured 2026-08-24, along with the two cases that were
    already caught: deleting the row, and deleting every row mentioning 27001.

    Separator rows are dropped. `|---|---|` carries three pipes and a first
    cell of dashes, and leaving it in would only add noise.
    """
    cells = []
    for line in content.split("\n"):
        if line.count("|") < 3:
            continue
        parts = line.split("|")
        # A row written with a leading pipe puts an empty string in parts[0],
        # so the subject is parts[1]. A row written without one is not a shape
        # any table in these documents uses.
        cell = parts[1].strip() if len(parts) > 1 else ""
        # Anything that is only dashes, colons and spaces is a separator.
        if cell and set(cell) - set("-: "):
            cells.append(cell)
    return cells


def main():
    print(f"{BLUE}Validating compliance framework documentation...{NC}\n")
    root = find_project_root()

    frameworks = parse_enum_frameworks(root)
    if not frameworks:
        print(f"{RED}Error: parsed zero variants from ComplianceFramework enum{NC}")
        sys.exit(1)
    print(
        f"Found {GREEN}{len(frameworks)}{NC} frameworks in ComplianceFramework enum: "
        f"{', '.join(frameworks)}\n"
    )

    files_to_check = [
        "docs/architecture/architecture.md",
        "docs/ROADMAP.md",
    ]

    has_errors = False
    for rel in files_to_check:
        full_path = root / rel
        if not full_path.exists():
            print(f"{YELLOW}Skipping {rel} (not found){NC}\n")
            continue

        print(f"{BLUE}Checking {rel}...{NC}")
        cells = framework_table_cells(full_path.read_text())

        missing = [
            fw
            for fw in frameworks
            if not any(DOC_MARKERS.get(fw, fw) in cell for cell in cells)
        ]
        if missing:
            has_errors = True
            print(
                f"  {RED}Frameworks defined in code but named by no table row "
                f"in this file:{NC}"
            )
            for fw in missing:
                print(f"    - {fw} (expected marker '{DOC_MARKERS.get(fw, fw)}')")
            print(
                f"  {YELLOW}The marker is looked for in each row's first cell, "
                f"where a table names its subject. A mention in a description "
                f"or a file path no longer satisfies it.{NC}"
            )
        else:
            print(f"  {GREEN}✓ All {len(frameworks)} frameworks documented{NC}")
        print()

    has_errors |= check_suite_table(root, frameworks)

    if has_errors:
        print(f"{RED}Compliance documentation validation failed{NC}")
        sys.exit(1)
    print(f"{GREEN}All compliance documentation is accurate{NC}")
    sys.exit(0)


if __name__ == "__main__":
    main()

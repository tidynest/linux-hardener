#!/usr/bin/env python3
"""
Validates that docs/reference/file-map.md accurately reflects all Rust source files.

Usage:
    ./scripts/validate/validate_file_map.py [--fix]

Exit codes:
    0: All files documented correctly
    1: Discrepancies found

Options:
    --fix    Generate stub entries for missing files (prints to stdout)
"""

import re
import subprocess
import sys
from pathlib import Path

# Directories to scan for Rust files
SCAN_DIRS = [
    "crates",
    "src-tauri/src",
]

# Files/patterns to exclude from validation
EXCLUDE_PATTERNS = [
    r"/target/",           # Build artifacts
    r"/tests/common/",     # Test utilities (often not documented)
    r"\.#",                # Editor temp files
]

# Path to file-map.md relative to project root
FILE_MAP_PATH = "docs/reference/file-map.md"

# A test function, as declared. Both spellings, because a crate that gained an
# async test would otherwise start undercounting silently.
TEST_ATTRIBUTE = re.compile(r"^[ \t]*#\[(?:tokio::)?test\]", re.MULTILINE)

# A count claimed in a file-map description, as in "21 tests of the renderers".
# These have drifted twice in two sessions, which is what this derives away:
# the number in the prose is checked against the file it describes rather than
# maintained by hand.
CLAIMED_TEST_COUNT = re.compile(r"\b(\d+) tests\b")

# A row of the per-crate summary table near the foot of file-map.md, whose last
# column is that crate's whole test-annotation count:
#
#     | hardener-cli | `cli.rs`, ... | `batch_ssh_integration.rs` | 180 |
#
# Checked for the same reason as the per-file claims above and after the same
# history: this column drifted three times in two days, every time because a
# commit added tests somewhere else in the branch, and nothing looked at it. The
# per-file rule could not catch it, because these rows name a crate rather than
# a file and carry no "N tests" phrase for it to match.
CRATE_ANNOTATION_ROW = re.compile(
    r"^\|\s*(hardener-\w+|src-tauri)\s*\|.*\|\s*(\d+)\s*\|\s*$"
)

# The three numbers the prose above that table asserts, and the two the evidence
# ledger asserts about the same measurement:
#
#     The table covers the ten crates under `crates/` and sums to 1789. The
#     eleventh workspace member, `src-tauri`, carries 107 more, which is why the
#     tree total the evidence ledger records is 1896 and not this table's sum.
#
# The per-crate rule above cannot see any of these. It checks each row against
# its own crate, so a sum sentence stays green while being arithmetically wrong,
# and a cross-file total stays green while naming a number the other file does
# not carry. Both happened: the sum sentence read 1746 against rows totalling
# 1773, and correcting it in file-map alone left the ledger contradicting it in
# the same session.
#
# Every one of these matches across newlines, because the prose is hard-wrapped
# and a sentence gains a line break whenever a number's width changes. Written
# with literal spaces, this validator reported the sentence as deleted the first
# time a wrap moved, which is a false alarm that teaches the reader to ignore it.
CRATE_TABLE_SUM = re.compile(r"\bsums\s+to\s+(\d+)\b")
TAURI_EXTRA_COUNT = re.compile(r"`src-tauri`,\s+carries\s+(\d+)\s+more\b")
TREE_TOTAL = re.compile(r"the\s+evidence\s+ledger\s+records\s+is\s+(\d+)\b")
LEDGER_ANNOTATION_ROW = re.compile(r"Test\s+annotations\s+in\s+the\s+tree.*?\|\s*(\d+)\s*\|")
LEDGER_ASSERTION_ROW = re.compile(r"\b(\d+)\s+across\s+(\d+)\s+files?\b")

EVIDENCE_LEDGER_PATH = "docs/reference/evidence-ledger.md"
TEST_ASSERTION_VALIDATOR = "scripts/validate/validate_test_assertions.py"
TEST_ASSERTION_SUMMARY = re.compile(r"All (\d+) test\(s\) across (\d+) file\(s\)")

# ANSI colour codes
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
NC = "\033[0m"  # No colour


def find_project_root() -> Path:
    """Find the project root by looking for Cargo.toml."""
    current = Path.cwd()
    while current != current.parent:
        if (current / "Cargo.toml").exists():
            return current
        current = current.parent
    print(f"{RED}Error: Could not find project root (no Cargo.toml found){NC}")
    sys.exit(1)


def find_rust_files(root: Path) -> set[str]:
    """Find all .rs files in the scan directories."""
    rust_files = set()

    for scan_dir in SCAN_DIRS:
        dir_path = root / scan_dir
        if not dir_path.exists():
            continue

        for rs_file in dir_path.rglob("*.rs"):
            rel_path = rs_file.relative_to(root)
            path_str = str(rel_path)

            # Check exclusion patterns
            excluded = False
            for pattern in EXCLUDE_PATTERNS:
                if re.search(pattern, path_str):
                    excluded = True
                    break

            if not excluded:
                rust_files.add(path_str)

    return rust_files


def parse_file_map(root: Path) -> set[str]:
    """Parse file-map.md and extract documented file paths."""
    file_map_path = root / FILE_MAP_PATH

    if not file_map_path.exists():
        print(f"{RED}Error: {FILE_MAP_PATH} not found{NC}")
        sys.exit(1)

    documented_files = set()
    content = file_map_path.read_text()

    # Pattern to match file paths in Markdown tables
    # Matches: | `src/file.rs` | description |
    table_pattern = r'\|\s*`([^`]+\.rs)`\s*\|'

    matches = re.findall(table_pattern, content)
    for match in matches:
        # Normalise path - prepend crate path if it's a relative src/ path
        normalised = match.lstrip("./")
        documented_files.add(normalised)

    return documented_files


def extract_crate_from_path(file_path: str) -> str:
    """Extract the crate name from a file path."""
    parts = Path(file_path).parts
    if parts[0] == "crates" and len(parts) > 1:
        return parts[1]
    elif parts[0] == "src-tauri":
        return "src-tauri"
    return "unknown"


def count_test_attributes(source: Path) -> int:
    """Count the test functions one Rust file declares."""
    return len(TEST_ATTRIBUTE.findall(source.read_text(encoding="utf-8")))


def count_crate_test_attributes(crate_dir: Path) -> int:
    """Count the test functions a whole crate declares, tests directory included.

    The same expression the per-file rule uses, over every `.rs` file under the
    crate, because the table it checks says exactly that: annotations counted in
    the tree, not a run total.
    """
    return sum(count_test_attributes(source) for source in crate_dir.rglob("*.rs"))


def sole_claim(pattern: re.Pattern, text: str, what: str, where: str,
               errors: list[str]) -> tuple[str, ...] | None:
    """The one match `pattern` has in `text`, or None with an error recorded.

    A sentence that has been deleted or reworded past recognition is drift too,
    and the failure it causes is worse than a wrong number: nothing is checked
    and nothing says so. So a missing claim fails rather than passing quietly.
    """
    matches = pattern.findall(text)
    if len(matches) == 1:
        found = matches[0]
        return found if isinstance(found, tuple) else (found,)

    errors.append(
        f"{where}: expected exactly one {what}, found {len(matches)}. "
        f"Restore the sentence or update this validator to match its new wording"
    )
    return None


def measured_assertion_summary(root: Path, errors: list[str]) -> tuple[int, int] | None:
    """What `validate_test_assertions.py --all` measures: (tests, files).

    Asked of that script rather than recomputed here, because its file count is
    its own definition of which files it reads, and a second implementation of
    that rule would be one more thing to drift.
    """
    validator = root / TEST_ASSERTION_VALIDATOR
    if not validator.is_file():
        errors.append(f"{TEST_ASSERTION_VALIDATOR} not found, so its totals cannot be checked")
        return None

    result = subprocess.run(
        [sys.executable, str(validator), "--all"],
        capture_output=True, text=True, cwd=root,
    )
    summary = TEST_ASSERTION_SUMMARY.search(result.stdout)
    if not summary:
        errors.append(
            f"{TEST_ASSERTION_VALIDATOR} --all printed no 'All N test(s) across M file(s)' "
            f"line, so the ledger's figure cannot be checked (exit {result.returncode})"
        )
        return None

    return int(summary.group(1)), int(summary.group(2))


def check_declared_totals(root: Path, file_map_content: str) -> list[str]:
    """Check every total the two documents assert against the tree and each other.

    Three claims in file-map's prose (the table's sum, src-tauri's count, the
    tree total) and two in the evidence ledger (the annotation row, the
    assertion validator's figures). All five describe one measurement, so all
    five are derived here from the same count the per-crate rule uses.
    """
    errors: list[str] = []

    crates_total = sum(
        count_crate_test_attributes(crate_dir)
        for crate_dir in sorted((root / "crates").iterdir())
        if crate_dir.is_dir()
    )
    tauri_total = count_crate_test_attributes(root / "src-tauri")
    tree_total = crates_total + tauri_total

    claimed = sole_claim(CRATE_TABLE_SUM, file_map_content, "'sums to N' claim",
                         FILE_MAP_PATH, errors)
    if claimed and int(claimed[0]) != crates_total:
        errors.append(
            f"{FILE_MAP_PATH}: the table is said to sum to {claimed[0]}, "
            f"the crates declare {crates_total}"
        )

    claimed = sole_claim(TAURI_EXTRA_COUNT, file_map_content, "'src-tauri carries N more' claim",
                         FILE_MAP_PATH, errors)
    if claimed and int(claimed[0]) != tauri_total:
        errors.append(
            f"{FILE_MAP_PATH}: src-tauri is said to carry {claimed[0]} more, "
            f"it declares {tauri_total}"
        )

    claimed = sole_claim(TREE_TOTAL, file_map_content, "tree-total claim",
                         FILE_MAP_PATH, errors)
    if claimed and int(claimed[0]) != tree_total:
        errors.append(
            f"{FILE_MAP_PATH}: the tree total is said to be {claimed[0]}, "
            f"the tree declares {tree_total}"
        )

    ledger_path = root / EVIDENCE_LEDGER_PATH
    if not ledger_path.is_file():
        errors.append(f"{EVIDENCE_LEDGER_PATH} not found, so its totals cannot be checked")
        return errors

    ledger = ledger_path.read_text(encoding="utf-8")

    claimed = sole_claim(LEDGER_ANNOTATION_ROW, ledger, "'Test annotations in the tree' row",
                         EVIDENCE_LEDGER_PATH, errors)
    if claimed and int(claimed[0]) != tree_total:
        errors.append(
            f"{EVIDENCE_LEDGER_PATH}: the annotation row records {claimed[0]}, "
            f"the tree declares {tree_total}"
        )

    claimed = sole_claim(LEDGER_ASSERTION_ROW, ledger, "'N across M files' figure",
                         EVIDENCE_LEDGER_PATH, errors)
    measured = measured_assertion_summary(root, errors)
    if claimed and measured and (int(claimed[0]), int(claimed[1])) != measured:
        errors.append(
            f"{EVIDENCE_LEDGER_PATH}: the assertion check is recorded as "
            f"{claimed[0]} across {claimed[1]} files, it reports "
            f"{measured[0]} across {measured[1]} files"
        )

    return errors


def generate_stub_entry(file_path: str) -> str:
    """Generate a Markdown table row stub for a missing file."""
    filename = Path(file_path).name
    # Convert filename to a basic description
    name_parts = filename.replace(".rs", "").replace("_", " ").title()
    return f"| `{file_path}` | {name_parts} | TODO |"


def main():
    fix_mode = "--fix" in sys.argv

    print(f"{BLUE}Validating file-map.md completeness...{NC}\n")

    root = find_project_root()

    # Find actual files and documented files
    actual_files = find_rust_files(root)

    # Parse file-map.md with section context to build full paths
    # file-map.md uses paths like `src/lib.rs` within crate sections
    # We need to match these against full paths like `crates/hardener-core/src/lib.rs`

    # Build a mapping of short paths to full paths for documented files
    documented_full_paths = set()
    file_map_content = (root / FILE_MAP_PATH).read_text()

    # Parse sections to understand which crate each file belongs to
    # The same walk collects the test counts the descriptions claim, so the
    # crate context a row's path needs is resolved once rather than twice.
    current_crate = None
    claimed_test_counts: list[tuple[str, int]] = []
    claimed_crate_counts: list[tuple[str, int]] = []
    for line in file_map_content.split('\n'):
        # Detect crate section headers like "## hardener-core" or "## hardener-cli (CLI Binary)"
        section_match = re.match(r'^##\s+(hardener-\w+|src-tauri)', line)
        if section_match:
            current_crate = section_match.group(1)
            continue

        # The per-crate summary rows, which name a crate rather than a file
        # and so never reach the per-file branch below.
        crate_row = CRATE_ANNOTATION_ROW.match(line)
        if crate_row:
            claimed_crate_counts.append((crate_row.group(1), int(crate_row.group(2))))
            continue

        # Match file entries in tables
        file_match = re.search(r'\|\s*`(src/[^`]+\.rs)`\s*\|', line)
        if file_match and current_crate:
            rel_path = file_match.group(1)
            if current_crate == "src-tauri":
                full_path = f"src-tauri/{rel_path}"
            else:
                full_path = f"crates/{current_crate}/{rel_path}"
            documented_full_paths.add(full_path)
            claim = CLAIMED_TEST_COUNT.search(line)
            if claim:
                claimed_test_counts.append((full_path, int(claim.group(1))))

    # Find discrepancies
    missing_from_docs = actual_files - documented_full_paths
    extra_in_docs = documented_full_paths - actual_files

    # Filter out test files from "missing" (they're often intentionally undocumented)
    missing_from_docs = {f for f in missing_from_docs if "/tests/" not in f}

    has_errors = False

    # Report missing files
    if missing_from_docs:
        has_errors = True
        print(f"{YELLOW}Files missing from file-map.md ({len(missing_from_docs)}):{NC}\n")

        # Group by crate
        by_crate: dict[str, list[str]] = {}
        for f in sorted(missing_from_docs):
            crate = extract_crate_from_path(f)
            if crate not in by_crate:
                by_crate[crate] = []
            by_crate[crate].append(f)

        for crate in sorted(by_crate.keys()):
            print(f"  {BLUE}{crate}:{NC}")
            for f in by_crate[crate]:
                print(f"    - {f}")
            print()

        if fix_mode:
            print(f"\n{GREEN}Suggested stub entries:{NC}\n")
            for crate in sorted(by_crate.keys()):
                print(f"# Add to {crate} section:")
                for f in by_crate[crate]:
                    print(generate_stub_entry(f))
                print()

    # Report extra files (documented but deleted)
    if extra_in_docs:
        has_errors = True
        print(f"{RED}Files in file-map.md but not in codebase ({len(extra_in_docs)}):{NC}\n")
        for f in sorted(extra_in_docs):
            print(f"  - {f}")
        print()
        print(f"  {YELLOW}These entries should be removed from file-map.md{NC}\n")

    # Report test counts the prose claims and the source does not support.
    # A row whose file is missing is skipped: that is already reported above as
    # an entry documenting a file the codebase does not have, and counting the
    # tests in a file that is not there would report one defect as two.
    miscounted = []
    for full_path, claimed in claimed_test_counts:
        source = root / full_path
        if not source.exists():
            continue
        actual = count_test_attributes(source)
        if actual != claimed:
            miscounted.append((full_path, claimed, actual))

    # And the same question of the per-crate table. A crate the checkout does
    # not have is skipped rather than reported as a miscount: that is a row
    # naming a crate that does not exist, which is a different defect from a
    # number that has drifted.
    crate_miscounted = []
    for crate, claimed in claimed_crate_counts:
        crate_dir = root / ("src-tauri" if crate == "src-tauri" else f"crates/{crate}")
        if not crate_dir.is_dir():
            continue
        actual = count_crate_test_attributes(crate_dir)
        if actual != claimed:
            crate_miscounted.append((crate, claimed, actual))

    if crate_miscounted:
        has_errors = True
        print(f"{RED}Per-crate annotation counts in file-map.md that the tree does "
              f"not support ({len(crate_miscounted)}):{NC}\n")
        for crate, claimed, actual in sorted(crate_miscounted):
            print(f"  - {crate}: the table says {claimed}, the crate declares {actual}")
        print()
        print(f"  {YELLOW}Take the count after the last test in the branch, not before it{NC}\n")

    # And the totals both documents assert about the same measurement, which no
    # per-row rule can see.
    total_errors = check_declared_totals(root, file_map_content)
    if total_errors:
        has_errors = True
        print(f"{RED}Declared totals that the tree does not support "
              f"({len(total_errors)}):{NC}\n")
        for error in total_errors:
            print(f"  - {error}")
        print()
        print(f"  {YELLOW}Correct every document that names the measurement, not "
              f"only the one that failed{NC}\n")

    if miscounted:
        has_errors = True
        print(f"{RED}Test counts in file-map.md that the source does not support "
              f"({len(miscounted)}):{NC}\n")
        for full_path, claimed, actual in sorted(miscounted):
            print(f"  - {full_path}: the description says {claimed}, the file declares {actual}")
        print()
        print(f"  {YELLOW}Correct the number in the description, or the tests it counts{NC}\n")

    # Summary
    if has_errors:
        print(f"{RED}file-map.md validation failed{NC}")
        print(f"\nRun with --fix to generate stub entries for missing files.")
        sys.exit(1)
    else:
        print(f"{GREEN}file-map.md is complete and accurate{NC}")
        print(f"  Documented: {len(documented_full_paths)} files")
        print(f"  Actual: {len(actual_files)} source files (excluding tests)")
        sys.exit(0)


if __name__ == "__main__":
    main()

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
    current_crate = None
    for line in file_map_content.split('\n'):
        # Detect crate section headers like "## hardener-core" or "## hardener-cli (CLI Binary)"
        section_match = re.match(r'^##\s+(hardener-\w+|src-tauri)', line)
        if section_match:
            current_crate = section_match.group(1)
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

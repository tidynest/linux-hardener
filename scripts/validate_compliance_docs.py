#!/usr/bin/env python3
"""
Validates that compliance framework documentation matches actual control counts.

Usage:
    ./scripts/validate_compliance_docs.py

Exit codes:
    0: All compliance framework counts are accurate
    1: Discrepancies found

Checks:
    - docs/architecture/ARCHITECTURE.md framework table
    - ROADMAP.md framework table
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


def find_project_root() -> Path:
    """Find the project root by looking for Cargo.toml."""
    current = Path.cwd()
    while current != current.parent:
        if (current / "Cargo.toml").exists():
            return current
        current = current.parent
    print(f"{RED}Error: Could not find project root (no Cargo.toml found){NC}")
    sys.exit(1)


def count_controls_in_source(root: Path) -> dict[str, int]:
    """Count ComplianceMapping definitions in each framework file."""
    frameworks_dir = root / "crates" / "hardener-compliance" / "src" / "frameworks"

    counts = {}

    # Map file names to framework display names
    file_to_name = {
        "cis.rs": "CIS",
        "stig.rs": "STIG",
        "nist.rs": "NIST 800-53",
        "pci.rs": "PCI-DSS",
        "hipaa.rs": "HIPAA",
        "gdpr.rs": "GDPR",
    }

    for filename, display_name in file_to_name.items():
        filepath = frameworks_dir / filename
        if filepath.exists():
            content = filepath.read_text()
            # Count ComplianceMapping struct instantiations
            # Each control is defined as: ComplianceMapping { ... }
            count = len(re.findall(r'ComplianceMapping\s*\{', content))
            counts[display_name] = count

    return counts


def parse_framework_table(content: str) -> dict[str, str]:
    """Parse framework control counts from a markdown table."""
    counts = {}

    # Match table rows: | Framework | Count | Description |
    # Count can be "35+" or "35" etc.
    pattern = r'\|\s*([^|]+)\s*\|\s*(\d+\+?)\s*\|'

    for line in content.split('\n'):
        match = re.match(pattern, line)
        if match:
            framework = match.group(1).strip()
            count_str = match.group(2).strip()
            # Skip header row
            if framework.lower() not in ['framework', '---', '-']:
                counts[framework] = count_str

    return counts


def parse_documented_counts(root: Path) -> dict[str, dict[str, str]]:
    """Parse framework counts from documentation files."""
    docs = {}

    files_to_check = [
        ("docs/architecture/ARCHITECTURE.md", "ARCHITECTURE.md"),
        ("ROADMAP.md", "ROADMAP.md"),
    ]

    for filepath, name in files_to_check:
        full_path = root / filepath
        if full_path.exists():
            content = full_path.read_text()
            counts = parse_framework_table(content)
            if counts:
                docs[name] = counts

    return docs


def main():
    print(f"{BLUE}Validating compliance framework documentation...{NC}\n")

    root = find_project_root()

    # Get actual counts from source
    source_counts = count_controls_in_source(root)

    print(f"Found {GREEN}{len(source_counts)}{NC} frameworks in source code:")
    for framework, count in sorted(source_counts.items()):
        print(f"  - {framework}: {count} controls")
    print()

    # Get documented counts
    documented = parse_documented_counts(root)

    has_errors = False

    # Check each documentation file
    for doc_name, doc_counts in documented.items():
        print(f"{BLUE}Checking {doc_name}...{NC}")

        mismatches = []
        missing = []

        for framework, actual_count in source_counts.items():
            if framework in doc_counts:
                doc_count_str = doc_counts[framework]
                # Parse documented count (handle "35+" format)
                doc_count = int(doc_count_str.rstrip('+'))
                is_approximate = doc_count_str.endswith('+')

                # Check if counts match (with tolerance for approximate)
                if is_approximate:
                    # For "35+", actual should be >= 35
                    if actual_count < doc_count:
                        mismatches.append(
                            f"{framework}: documented {doc_count_str}, actual {actual_count}"
                        )
                else:
                    if actual_count != doc_count:
                        mismatches.append(
                            f"{framework}: documented {doc_count}, actual {actual_count}"
                        )
            else:
                missing.append(framework)

        if mismatches:
            has_errors = True
            print(f"  {RED}Count mismatches:{NC}")
            for msg in mismatches:
                print(f"    - {msg}")

        if missing:
            has_errors = True
            print(f"  {RED}Frameworks missing from documentation:{NC}")
            for framework in missing:
                print(f"    - {framework}")

        if not mismatches and not missing:
            print(f"  {GREEN}✓ All {len(source_counts)} frameworks documented correctly{NC}")
        print()

    # Summary
    if has_errors:
        print(f"{RED}Compliance documentation validation failed{NC}")
        print(f"\nSuggested updates based on actual counts:")
        print("```")
        print("| Framework | Controls | Description |")
        print("|-----------|----------|-------------|")
        descriptions = {
            "CIS": "Center for Internet Security Benchmarks",
            "STIG": "DISA Security Technical Implementation Guides",
            "NIST 800-53": "US Federal security controls",
            "PCI-DSS": "Payment Card Industry standards",
            "HIPAA": "Healthcare security requirements",
            "GDPR": "EU data protection (Article 32)",
        }
        for framework, count in sorted(source_counts.items()):
            desc = descriptions.get(framework, "")
            print(f"| {framework} | {count} | {desc} |")
        print("```")
        sys.exit(1)
    else:
        print(f"{GREEN}All compliance documentation is accurate{NC}")
        sys.exit(0)


if __name__ == "__main__":
    main()

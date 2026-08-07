#!/usr/bin/env python3
"""
Master validation script that runs all documentation validators.

Usage:
    ./scripts/validate/validate_all.py           # Run all checks
    ./scripts/validate/validate_all.py --fix     # Run all checks and auto-fix where possible
    ./scripts/validate/validate_all.py --quick   # Skip slow checks (compliance, cli)

Exit codes:
    0: All validations passed
    1: One or more validations failed
"""

import subprocess
import sys
from pathlib import Path

# ANSI colour codes
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
BOLD = "\033[1m"
NC = "\033[0m"  # No colour


def find_project_root() -> Path:
    """Find the project root by looking for Cargo.toml."""
    current = Path.cwd()
    while current != current.parent:
        if (current / "Cargo.toml").exists():
            return current
        current = current.parent
    print(f"{RED}Error: Could not find project root{NC}")
    sys.exit(1)


def run_validator(name: str, script: str, args: list[str] = None) -> bool:
    """Run a validation script and return success status."""
    args = args or []
    print(f"\n{BOLD}{'='*60}{NC}")
    print(f"{BLUE}Running: {name}{NC}")
    print(f"{BOLD}{'='*60}{NC}\n")

    result = subprocess.run(
        ["python3", script] + args,
        cwd=find_project_root(),
    )

    return result.returncode == 0


def main():
    fix_mode = "--fix" in sys.argv
    quick_mode = "--quick" in sys.argv

    print(f"{BOLD}{'#'*60}{NC}")
    print(f"{BOLD}#  Linux Hardener - Documentation Validator{' '*8}#{NC}")
    print(f"{BOLD}{'#'*60}{NC}")

    if fix_mode:
        print(f"\n{YELLOW}Running in --fix mode (will auto-correct where possible){NC}")
    if quick_mode:
        print(f"\n{YELLOW}Running in --quick mode (skipping slow checks){NC}")

    root = find_project_root()
    scripts_dir = Path(__file__).resolve().parent

    # Define all validators (paths relative to scripts_dir; the sibling
    # validators live next to this file, release.sh in scripts/release/)
    validators = [
        ("Version Synchronisation", "../release/release.sh", ["--verify"]),
        ("file-map.md Completeness", "validate_file_map.py", []),
        ("Plugin Documentation", "validate_plugin_docs.py", []),
        ("Tauri Command Documentation", "validate_tauri_docs.py", []),
        ("Last Updated Dates", "validate_last_updated.py", ["--fix"] if fix_mode else []),
        ("Doc Comment Attachment", "validate_doc_attachment.py", []),
        ("File Creation Sites", "validate_write_sites.py", []),
        ("Unit State Reads", "validate_unit_state_reads.py", []),
        ("Doc Sync Targets", "validate_doc_targets.py", []),
        ("Badges", "validate_badges.py", []),
        # `--all` is the whole tree. Without it the check globbed the
        # integration suites alone and exempted every inline `#[cfg(test)]`
        # module under `src/`, which is where most of this workspace's tests
        # live: it read 646 of them and reported a clean tree (issue #130).
        ("Test Assertions", "validate_test_assertions.py", ["--all"]),
        ("Policy Exception Sites", "validate_policy_exception_sites.py", []),
        ("Documented Exception Keys", "validate_documented_exception_keys.py", []),
        ("Evidence Ledger", "validate_evidence_ledger.py", []),
        ("Persisted Finding Fields", "validate_persisted_finding_fields.py", []),
        # The neighbouring check above covers the Rust side of a finding. This
        # one covers the JavaScript fixture the GUI suite deserialises, which
        # nothing read until eight drifts had accumulated in it.
        ("GUI Mock Fixtures", "validate_gui_mock_fixtures.py", []),
        (".SRCINFO", "validate_srcinfo.py", []),
        ("CHANGELOG Headings", "validate_changelog_headings.py", []),
        ("Markdown Links", "validate_doc_links.py", []),
    ]

    # Add slower validators unless in quick mode
    if not quick_mode:
        validators.extend([
            ("CLI Documentation", "validate_cli_docs.py", []),
            ("Compliance Framework List", "validate_compliance_docs.py", []),
        ])

    results = {}

    for name, script, args in validators:
        script_path = scripts_dir / script
        if not script_path.exists():
            print(f"\n{YELLOW}Skipping {name}: {script} not found{NC}")
            results[name] = None
            continue

        # Use bash for .sh scripts
        if script.endswith(".sh"):
            print(f"\n{BOLD}{'='*60}{NC}")
            print(f"{BLUE}Running: {name}{NC}")
            print(f"{BOLD}{'='*60}{NC}\n")
            result = subprocess.run(
                ["bash", str(script_path)] + args,
                cwd=root,
            )
            results[name] = result.returncode == 0
        else:
            results[name] = run_validator(name, str(script_path), args)

    # Summary
    print(f"\n{BOLD}{'#'*60}{NC}")
    print(f"{BOLD}#  Summary{' '*49}#{NC}")
    print(f"{BOLD}{'#'*60}{NC}\n")

    passed = 0
    failed = 0
    skipped = 0

    for name, success in results.items():
        if success is None:
            print(f"  {YELLOW}⊘{NC} {name}: skipped")
            skipped += 1
        elif success:
            print(f"  {GREEN}✓{NC} {name}: passed")
            passed += 1
        else:
            print(f"  {RED}✗{NC} {name}: failed")
            failed += 1

    print()
    total = passed + failed
    if failed == 0:
        print(f"{GREEN}All {total} validations passed!{NC}")
        if skipped:
            print(f"{YELLOW}({skipped} skipped){NC}")
        sys.exit(0)
    else:
        print(f"{RED}{failed}/{total} validations failed{NC}")
        if skipped:
            print(f"{YELLOW}({skipped} skipped){NC}")
        sys.exit(1)


if __name__ == "__main__":
    main()

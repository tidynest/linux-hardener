#!/usr/bin/env python3
"""
Validates that "Last Updated" dates in markdown files match git history.

Usage:
    ./scripts/validate_last_updated.py
    ./scripts/validate_last_updated.py --fix  # Update stale dates

Exit codes:
    0: All dates are accurate (within tolerance)
    1: Stale dates found
"""

import re
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

# ANSI colour codes
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
NC = "\033[0m"  # No colour

# Tolerance: dates within this many days are considered current
STALE_THRESHOLD_DAYS = 7


def find_project_root() -> Path:
    """Find the project root by looking for Cargo.toml."""
    current = Path.cwd()
    while current != current.parent:
        if (current / "Cargo.toml").exists():
            return current
        current = current.parent
    print(f"{RED}Error: Could not find project root (no Cargo.toml found){NC}")
    sys.exit(1)


def get_git_last_modified(filepath: Path) -> datetime | None:
    """Get the last git commit date for a file."""
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%cs", "--", str(filepath)],
            capture_output=True,
            text=True,
            check=True,
            env={**subprocess.os.environ, "GIT_PAGER": "", "NO_COLOR": "1"},
        )
        date_str = result.stdout.strip()
        # Validate format before parsing
        if date_str and re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
            return datetime.strptime(date_str, "%Y-%m-%d")
    except subprocess.CalledProcessError:
        pass
    return None


def parse_last_updated(content: str) -> tuple[str | None, datetime | None]:
    """Parse 'Last Updated' date from markdown content."""
    # Match patterns like:
    # **Last Updated**: 2025-12-06
    # *Last Updated*: 2025-12-06
    # Last Updated: 2025-12-06
    patterns = [
        r'\*\*Last Updated\*\*:\s*(\d{4}-\d{2}-\d{2})',
        r'\*Last Updated\*:\s*(\d{4}-\d{2}-\d{2})',
        r'Last Updated:\s*(\d{4}-\d{2}-\d{2})',
    ]

    for pattern in patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            date_str = match.group(1)
            try:
                date = datetime.strptime(date_str, "%Y-%m-%d")
                return date_str, date
            except ValueError:
                pass

    return None, None


def find_markdown_files(root: Path) -> list[Path]:
    """Find all markdown files that should have Last Updated dates."""
    files = []

    # Root markdown files
    for md in root.glob("*.md"):
        files.append(md)

    # docs/ directory
    docs_dir = root / "docs"
    if docs_dir.exists():
        for md in docs_dir.glob("*.md"):
            files.append(md)

    # scripts/README.md
    scripts_readme = root / "scripts" / "README.md"
    if scripts_readme.exists():
        files.append(scripts_readme)

    return sorted(files)


def update_last_updated(filepath: Path, new_date: str) -> bool:
    """Update the Last Updated date in a file."""
    content = filepath.read_text()

    patterns = [
        (r'(\*\*Last Updated\*\*:\s*)\d{4}-\d{2}-\d{2}', rf'\g<1>{new_date}'),
        (r'(\*Last Updated\*:\s*)\d{4}-\d{2}-\d{2}', rf'\g<1>{new_date}'),
        (r'(Last Updated:\s*)\d{4}-\d{2}-\d{2}', rf'\g<1>{new_date}'),
    ]

    for pattern, replacement in patterns:
        new_content, count = re.subn(pattern, replacement, content, flags=re.IGNORECASE)
        if count > 0:
            filepath.write_text(new_content)
            return True

    return False


def main():
    fix_mode = "--fix" in sys.argv

    print(f"{BLUE}Validating 'Last Updated' dates in markdown files...{NC}\n")

    root = find_project_root()
    markdown_files = find_markdown_files(root)

    print(f"Found {GREEN}{len(markdown_files)}{NC} markdown files to check\n")

    today = datetime.now()
    threshold = timedelta(days=STALE_THRESHOLD_DAYS)

    stale_files = []
    missing_dates = []
    current_files = []

    for filepath in markdown_files:
        rel_path = filepath.relative_to(root)
        content = filepath.read_text()

        date_str, doc_date = parse_last_updated(content)
        git_date = get_git_last_modified(filepath)

        if doc_date is None:
            missing_dates.append(rel_path)
            continue

        if git_date is None:
            # File not in git yet, can't validate
            current_files.append((rel_path, date_str, "untracked"))
            continue

        # Check if documented date is stale compared to git
        if git_date > doc_date + threshold:
            stale_files.append({
                "path": rel_path,
                "documented": date_str,
                "git_date": git_date.strftime("%Y-%m-%d"),
                "days_stale": (git_date - doc_date).days,
            })
        else:
            current_files.append((rel_path, date_str, "current"))

    # Report results
    if current_files:
        print(f"{GREEN}Current files ({len(current_files)}):{NC}")
        for path, date, status in current_files:
            print(f"  ✓ {path}: {date}")
        print()

    if missing_dates:
        print(f"{YELLOW}Files without 'Last Updated' date ({len(missing_dates)}):{NC}")
        for path in missing_dates:
            print(f"  - {path}")
        print()

    if stale_files:
        print(f"{RED}Stale dates found ({len(stale_files)}):{NC}")
        for info in stale_files:
            print(f"  ✗ {info['path']}")
            print(f"      Documented: {info['documented']}")
            print(f"      Git shows:  {info['git_date']} ({info['days_stale']} days newer)")

        if fix_mode:
            print(f"\n{BLUE}Updating stale dates...{NC}")
            for info in stale_files:
                filepath = root / info['path']
                if update_last_updated(filepath, info['git_date']):
                    print(f"  ✓ Updated {info['path']} to {info['git_date']}")
                else:
                    print(f"  ✗ Failed to update {info['path']}")
            print()
        else:
            print(f"\n{YELLOW}Run with --fix to update stale dates automatically{NC}\n")

    # Summary
    total_checked = len(markdown_files)
    issues = len(stale_files) + len(missing_dates)

    if stale_files and not fix_mode:
        print(f"{RED}Last Updated validation failed: {len(stale_files)} stale date(s){NC}")
        sys.exit(1)
    elif missing_dates:
        print(f"{YELLOW}Warning: {len(missing_dates)} file(s) missing 'Last Updated' date{NC}")
        sys.exit(0)
    else:
        print(f"{GREEN}All {total_checked} markdown files have current dates{NC}")
        sys.exit(0)


if __name__ == "__main__":
    main()

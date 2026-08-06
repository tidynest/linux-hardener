#!/usr/bin/env python3
"""
Automatically updates documentation files with data from source code.

Usage:
    ./scripts/validate/update_all_docs.py           # Preview changes (dry-run)
    ./scripts/validate/update_all_docs.py --apply   # Apply changes

Exit codes:
    0: All updates successful (or no updates needed)
    1: Some updates failed or need manual attention

Safe auto-fixes:
    - Last Updated dates (from git history)
    - file-map.md stub entries for new files
    - Compliance framework counts
    - Tauri command signatures in file-map.md
    - Version references across documentation

Cannot auto-fix (requires human attention):
    - Plugin descriptions and names
    - CLI command examples
    - Architecture explanations
    - Removing stale entries
"""

import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ANSI colour codes
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
BOLD = "\033[1m"
NC = "\033[0m"

# Doc-sync targets, declared here rather than inside the methods that consume
# them so that scripts/validate/validate_doc_targets.py can hold every one to
# actually resolving. Both loops below skip a target silently: a named file that
# no longer exists, or a pattern that matches nothing, produces no update and no
# complaint, so the updater reports success for work it never attempted. Five of
# the framework files named here were deleted in 4039ed1 and nothing noticed for
# six weeks.
# Only CIS. The other five named here until 2026-08-01 (stig, nist, pci, hipaa,
# gdpr) were deleted in 4039ed1 when catalogues became coverage-derived, so their
# control counts are computed at report time and cannot be read off a file at
# all. iso27001.rs survives but is deliberately absent: it builds its 93 Annex A
# controls without writing 93 `ComplianceMapping {` literals, so counting them
# yields 2 and adding it here would rewrite a correct 93 to a wrong 2.
COMPLIANCE_SOURCE_FILES = {
    "cis.rs": "CIS",
}

# The pattern differs per file because the emphasis does: architecture.md and
# data-flow.md write `**Version:**` and README.md writes `**Version**:`. The
# mismatch is why architecture.md sat in this list for months while being
# unreachable by it.
VERSION_REFERENCE_TARGETS = [
    ("docs/architecture/architecture.md", r'(\*\*Version:\*\*\s*)\d+\.\d+\.\d+'),
    ("docs/reference/data-flow.md", r'(\*\*Version:\*\*\s*)\d+\.\d+\.\d+'),
    ("README.md", r'(\*\*Version\*\*:\s*)\d+\.\d+\.\d+'),
    # SECURITY.md names the current release in prose rather than as a marker,
    # and it is the one file where a stale number is a false statement about
    # which versions receive security fixes rather than a cosmetic lag.
    ("SECURITY.md", r'(The current release is \*\*)\d+\.\d+\.\d+'),
]


def find_project_root() -> Path:
    """Find the project root by looking for Cargo.toml."""
    current = Path.cwd()
    while current != current.parent:
        if (current / "Cargo.toml").exists():
            return current
        current = current.parent
    print(f"{RED}Error: Could not find project root{NC}")
    sys.exit(1)


class DocumentationUpdater:
    def __init__(self, root: Path, apply: bool = False):
        self.root = root
        self.apply = apply
        self.updates = []
        self.manual_fixes = []

    def log_update(self, category: str, description: str):
        """Log a pending or applied update."""
        self.updates.append((category, description))
        action = "Applied" if self.apply else "Would update"
        print(f"  {GREEN}✓{NC} {action}: {description}")

    def log_manual(self, category: str, description: str):
        """Log something that needs manual attention."""
        self.manual_fixes.append((category, description))
        print(f"  {YELLOW}!{NC} Manual fix needed: {description}")

    # -------------------------------------------------------------------------
    # 1. Last Updated Dates
    # -------------------------------------------------------------------------
    def update_last_updated_dates(self):
        """Update Last Updated dates to match git history."""
        print(f"\n{BLUE}Updating Last Updated dates...{NC}")

        # Recurse docs/, but never rewrite dates on archived records or
        # gitignored local notes.
        markdown_files = list(self.root.glob("*.md"))
        markdown_files += [
            md for md in (self.root / "docs").rglob("*.md")
            if "superpowers" not in md.parts and "archive" not in md.parts
        ]
        markdown_files += [self.root / "scripts" / "README.md"]

        for filepath in markdown_files:
            if not filepath.exists():
                continue

            content = filepath.read_text()
            rel_path = filepath.relative_to(self.root)

            # Get git date
            git_date = self._get_git_date(filepath)
            if not git_date:
                continue

            # Find current documented date
            match = re.search(r'\*\*Last Updated\*\*:\s*(\d{4}-\d{2}-\d{2})', content)
            if match:
                doc_date = match.group(1)
                # Only update if git date is newer (don't go backwards)
                if doc_date < git_date:
                    if self.apply:
                        new_content = re.sub(
                            r'(\*\*Last Updated\*\*:\s*)\d{4}-\d{2}-\d{2}',
                            rf'\g<1>{git_date}',
                            content
                        )
                        filepath.write_text(new_content)
                    self.log_update("dates", f"{rel_path}: {doc_date} → {git_date}")

    def _get_git_date(self, filepath: Path) -> str | None:
        """Get last git commit date for a file."""
        try:
            result = subprocess.run(
                ["git", "log", "-1", "--format=%cs", "--", str(filepath)],
                capture_output=True, text=True, check=True,
                cwd=self.root
            )
            date_str = result.stdout.strip()
            if re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
                return date_str
        except subprocess.CalledProcessError:
            pass
        return None

    # -------------------------------------------------------------------------
    # 2. file-map.md Stub Entries
    # -------------------------------------------------------------------------
    def update_file_map_stubs(self):
        """Add stub entries for missing files in file-map.md."""
        print(f"\n{BLUE}Checking file-map.md for missing files...{NC}")

        file_map = self.root / "docs" / "reference" / "file-map.md"
        if not file_map.exists():
            return

        content = file_map.read_text()

        # Find all source files
        source_files = set()
        for pattern in ["crates/*/src/**/*.rs", "src-tauri/src/**/*.rs"]:
            for f in self.root.glob(pattern):
                if "/tests/" not in str(f) and "/target/" not in str(f):
                    source_files.add(str(f.relative_to(self.root)))

        # Find documented files - check for various path formats
        # Match: `crates/...` or `src/...` (with or without full path)
        documented = set()

        # Full paths with backticks: `crates/hardener-core/src/lib.rs`
        documented.update(re.findall(r'`(crates/[^`]+\.rs)`', content))
        documented.update(re.findall(r'`(src-tauri/[^`]+\.rs)`', content))

        # Short paths: `src/lib.rs` within a crate section
        # We need to expand these based on context
        for crate_match in re.finditer(r'## (hardener-\w+|src-tauri)[^\n]*\n(.*?)(?=\n## |\Z)', content, re.DOTALL):
            crate_name = crate_match.group(1)
            section = crate_match.group(2)

            # Find short paths like `src/lib.rs`
            short_paths = re.findall(r'`(src/[^`]+\.rs)`', section)
            for short_path in short_paths:
                if crate_name == "src-tauri":
                    full_path = f"src-tauri/{short_path}"
                else:
                    full_path = f"crates/{crate_name}/{short_path}"
                documented.add(full_path)

        missing = source_files - documented

        if missing:
            # Group by crate
            by_crate: dict[str, list[str]] = {}
            for path in sorted(missing):
                parts = path.split("/")
                crate = parts[1] if parts[0] == "crates" else "src-tauri"
                by_crate.setdefault(crate, []).append(path)

            stubs = []
            for crate, files in sorted(by_crate.items()):
                for f in files:
                    name = Path(f).stem.replace("_", " ").title()
                    stubs.append(f"| `{f}` | {name} | TODO |")
                    self.log_update("file_map", f"Added stub for {f}")

            if self.apply and stubs:
                # Check if "New Files (TODO)" section already exists
                if "## New Files (TODO: Categorise)" in content:
                    # Append to existing section
                    pattern = r'(## New Files \(TODO: Categorise\)\n\n\| File \| Purpose \| Key Items \|\n\|[^\n]+\|\n)(.*?)(\n## |\Z)'
                    match = re.search(pattern, content, re.DOTALL)
                    if match:
                        existing = match.group(2).strip()
                        existing_files = set(re.findall(r'`([^`]+)`', existing))
                        # Only add files not already in the section
                        new_stubs = [s for s in stubs if not any(f in s for f in existing_files)]
                        if new_stubs:
                            new_content = match.group(1) + existing + "\n" + "\n".join(new_stubs) + "\n" + match.group(3)
                            content = content[:match.start()] + new_content + content[match.end():]
                            file_map.write_text(content)
                else:
                    # Create new section before Configuration Files
                    insert_marker = "\n## Configuration Files"
                    if insert_marker in content:
                        stub_text = "\n## New Files (TODO: Categorise)\n\n| File | Purpose | Key Items |\n|------|---------|----------|\n"
                        stub_text += "\n".join(stubs) + "\n"
                        content = content.replace(insert_marker, stub_text + insert_marker)
                        file_map.write_text(content)

    # -------------------------------------------------------------------------
    # 3. Compliance Framework Counts
    # -------------------------------------------------------------------------
    def update_compliance_counts(self):
        """Update compliance framework control counts."""
        print(f"\n{BLUE}Updating compliance framework counts...{NC}")

        frameworks_dir = self.root / "crates" / "hardener-compliance" / "src" / "frameworks"
        if not frameworks_dir.exists():
            return

        counts = {}
        for filename, name in COMPLIANCE_SOURCE_FILES.items():
            filepath = frameworks_dir / filename
            if filepath.exists():
                content = filepath.read_text()
                count = len(re.findall(r'ComplianceMapping\s*\{', content))
                counts[name] = count

        # Update in architecture.md
        arch_file = self.root / "docs" / "architecture" / "architecture.md"
        if arch_file.exists():
            content = arch_file.read_text()
            updated = False

            for framework, count in counts.items():
                # Match: | Framework | XX | or | Framework | XX+ |
                pattern = rf'(\|\s*{re.escape(framework)}\s*\|\s*)\d+\+?(\s*\|)'
                if re.search(pattern, content):
                    new_content = re.sub(pattern, rf'\g<1>{count}\2', content)
                    if new_content != content:
                        content = new_content
                        updated = True
                        self.log_update("compliance", f"architecture.md: {framework} → {count}")

            if updated and self.apply:
                arch_file.write_text(content)

    # -------------------------------------------------------------------------
    # 4. Tauri Command Signatures
    # -------------------------------------------------------------------------
    def update_tauri_signatures(self):
        """Update Tauri command signatures in file-map.md."""
        print(f"\n{BLUE}Updating Tauri command signatures...{NC}")

        commands_file = self.root / "src-tauri" / "src" / "commands.rs"
        file_map = self.root / "docs" / "reference" / "file-map.md"

        if not commands_file.exists() or not file_map.exists():
            return

        # Parse commands from source
        content = commands_file.read_text()
        pattern = r'#\[tauri::command\]\s*pub\s+async\s+fn\s+(\w+)\s*\(([^)]*)\)\s*->\s*Result<([^,]+),\s*String>'

        commands = []
        for match in re.finditer(pattern, content):
            name = match.group(1)
            args = match.group(2).strip()
            ret = match.group(3).strip()
            commands.append(f"pub async fn {name}({args}) -> Result<{ret}, String>")

        if not commands:
            return

        # Generate new Tauri Commands section
        new_section = "### Tauri Commands\n```rust\n"
        new_section += "\n".join(sorted(commands))
        new_section += "\n```"

        # Replace in file-map.md
        file_map_content = file_map.read_text()
        old_section = re.search(
            r'### Tauri Commands\s*```rust\s*.*?```',
            file_map_content,
            re.DOTALL
        )

        if old_section:
            old_text = old_section.group(0)
            if old_text != new_section:
                if self.apply:
                    file_map_content = file_map_content.replace(old_text, new_section)
                    file_map.write_text(file_map_content)
                self.log_update("tauri", f"Updated {len(commands)} command signatures in file-map.md")

    # -------------------------------------------------------------------------
    # 5. Version References
    # -------------------------------------------------------------------------
    def update_version_references(self):
        """Update version references to match Cargo.toml."""
        print(f"\n{BLUE}Updating version references...{NC}")

        # Get version from Cargo.toml
        cargo_toml = self.root / "Cargo.toml"
        content = cargo_toml.read_text()
        match = re.search(r'^\s*version\s*=\s*"([^"]+)"', content, re.MULTILINE)
        if not match:
            return

        version = match.group(1)

        for rel_path, pattern in VERSION_REFERENCE_TARGETS:
            filepath = self.root / rel_path
            if not filepath.exists():
                continue

            content = filepath.read_text()
            match = re.search(pattern, content)
            if match:
                old_version = re.search(r'\d+\.\d+\.\d+', match.group(0))
                if old_version and old_version.group(0) != version:
                    if self.apply:
                        new_content = re.sub(pattern, rf'\g<1>{version}', content)
                        filepath.write_text(new_content)
                    self.log_update("version", f"{rel_path}: {old_version.group(0)} → {version}")

    # -------------------------------------------------------------------------
    # 6. Check for Manual Fixes
    # -------------------------------------------------------------------------
    def check_manual_fixes(self):
        """Identify issues that need manual attention."""
        print(f"\n{BLUE}Checking for issues requiring manual attention...{NC}")

        # Check plugin name mismatches
        self._check_plugin_names()

        # Check CLI documentation
        self._check_cli_docs()

    def _check_plugin_names(self):
        """Check if plugin names in docs match source."""
        plugins_dir = self.root / "crates" / "hardener-plugins" / "src"
        if not plugins_dir.exists():
            return

        source_names = set()
        for mod_dir in plugins_dir.iterdir():
            if not mod_dir.is_dir():
                continue
            mod_file = mod_dir / "mod.rs"
            if mod_file.exists():
                content = mod_file.read_text()
                match = re.search(r'plugin_name:\s*"([^"]+)"', content)
                if match:
                    source_names.add(match.group(1))

        # Check README.md
        readme = self.root / "README.md"
        if readme.exists():
            content = readme.read_text()
            readme_names = set(re.findall(r'\|\s*\*\*([^*]+)\*\*\s*\|', content))

            missing = source_names - readme_names
            extra = readme_names - source_names

            for name in missing:
                self.log_manual("plugins", f"Plugin '{name}' missing from README.md")
            for name in extra:
                if name not in ["Plugin", "Status"]:  # Skip header
                    self.log_manual("plugins", f"Plugin '{name}' in README.md not found in source")

    def _check_cli_docs(self):
        """Check if CLI commands are documented."""
        cli_file = self.root / "crates" / "hardener-cli" / "src" / "cli.rs"
        readme = self.root / "README.md"

        if not cli_file.exists() or not readme.exists():
            return

        # Simple check: count commands in source vs documented
        cli_content = cli_file.read_text()
        readme_content = readme.read_text()

        # Top-level commands only, taken from the body of `enum Command`.
        #
        # This used to scan the whole file, so it matched every doc-commented
        # variant of every enum in it: the `*Action` subcommand enums, and the
        # `GlobalFormat`/`SeverityFilter`/`ScanMode` value enums too. That
        # reported 17 "missing" commands including `json` and `text`, which are
        # output formats rather than commands at all, on every single run.
        #
        # README documents the top-level commands; the subcommands are
        # `docs/reference/cli.md`'s job and `validate_cli_docs.py` already
        # checks that file against the same source. A permanent notice is one
        # nobody reads, and it buries the real ones beside it.
        command_enum = re.search(
            r'\benum\s+Command\s*\{(.*?)\n\}', cli_content, re.DOTALL
        )
        if not command_enum:
            self.log_manual("cli", "Could not find `enum Command` in cli.rs to check")
            return
        cmd_matches = re.findall(
            r'///\s*[^\n]+\n\s+(\w+)\s*(?:\{|\,)', command_enum.group(1)
        )
        source_cmds = {m.lower() for m in cmd_matches if m[0].isupper()}

        # Count hardener commands in README
        doc_cmds = set(re.findall(r'hardener\s+(\w+)', readme_content.lower()))

        missing = source_cmds - doc_cmds
        for cmd in missing:
            self.log_manual("cli", f"Command '{cmd}' may need documentation in README.md")

    # -------------------------------------------------------------------------
    # Main Runner
    # -------------------------------------------------------------------------
    def run(self):
        """Run all documentation updates."""
        print(f"{BOLD}{'#'*60}{NC}")
        print(f"{BOLD}#  Documentation Auto-Updater{' '*30}#{NC}")
        print(f"{BOLD}{'#'*60}{NC}")

        if self.apply:
            print(f"\n{GREEN}Running in --apply mode (changes will be written){NC}")
        else:
            print(f"\n{YELLOW}Running in preview mode (use --apply to write changes){NC}")

        self.update_last_updated_dates()
        self.update_file_map_stubs()
        self.update_compliance_counts()
        self.update_tauri_signatures()
        self.update_version_references()
        self.check_manual_fixes()

        # Summary
        print(f"\n{BOLD}{'#'*60}{NC}")
        print(f"{BOLD}#  Summary{' '*49}#{NC}")
        print(f"{BOLD}{'#'*60}{NC}")

        if self.updates:
            action = "Applied" if self.apply else "Pending"
            print(f"\n{GREEN}{action} updates: {len(self.updates)}{NC}")

        if self.manual_fixes:
            print(f"\n{YELLOW}Manual fixes needed: {len(self.manual_fixes)}{NC}")
            for category, desc in self.manual_fixes:
                print(f"  - [{category}] {desc}")

        if not self.updates and not self.manual_fixes:
            print(f"\n{GREEN}All documentation is up to date!{NC}")
            return 0

        if self.manual_fixes:
            print(f"\n{YELLOW}Some issues require manual attention.{NC}")
            return 1

        if not self.apply and self.updates:
            print(f"\n{YELLOW}Run with --apply to write changes.{NC}")

        return 0


def main():
    apply_mode = "--apply" in sys.argv
    root = find_project_root()

    updater = DocumentationUpdater(root, apply=apply_mode)
    sys.exit(updater.run())


if __name__ == "__main__":
    main()

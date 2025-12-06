#!/usr/bin/env python3
"""
Validates that CLI documentation in README.md matches actual CLI implementation.

Usage:
    ./scripts/validate_cli_docs.py

Exit codes:
    0: All CLI commands are documented
    1: Discrepancies found

Checks:
    - All main commands are documented with examples
    - All subcommands are documented
    - Global flags are mentioned
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


def parse_commands_from_source(root: Path) -> tuple[dict[str, dict], list[str]]:
    """Parse CLI commands from cli.rs."""
    cli_file = root / "crates" / "hardener-cli" / "src" / "cli.rs"
    content = cli_file.read_text()

    commands = {}

    # Find the Command enum block - need to handle nested braces
    # Look for: pub enum Command { ... }
    start_match = re.search(r'pub enum Command \{', content)
    if start_match:
        start_pos = start_match.end()
        brace_count = 1
        pos = start_pos
        while brace_count > 0 and pos < len(content):
            if content[pos] == '{':
                brace_count += 1
            elif content[pos] == '}':
                brace_count -= 1
            pos += 1
        enum_content = content[start_pos:pos-1]

        # Parse each command variant - look for doc comment followed by variant name
        # Pattern: /// description \n    VariantName { or /// description \n    VariantName,
        for match in re.finditer(r'///\s*([^\n]+)\n\s+(\w+)\s*(?:\{|\,)', enum_content):
            description = match.group(1).strip()
            name = match.group(2).strip()
            commands[name.lower()] = {
                "name": name,
                "description": description,
                "subcommands": [],
            }

    # Parse subcommand enums
    subcommand_enums = [
        ("CheckpointAction", "checkpoint"),
        ("DaemonAction", "daemon"),
        ("SystemdAction", "systemd"),
        ("HistoryAction", "history"),
    ]

    for enum_name, parent_cmd in subcommand_enums:
        # Find the enum block with proper brace matching
        start_match = re.search(rf'pub enum {enum_name} \{{', content)
        if start_match:
            start_pos = start_match.end()
            brace_count = 1
            pos = start_pos
            while brace_count > 0 and pos < len(content):
                if content[pos] == '{':
                    brace_count += 1
                elif content[pos] == '}':
                    brace_count -= 1
                pos += 1
            enum_content = content[start_pos:pos-1]

            subcommands = []
            # Match variant names (the subcommand), not their parameters
            for match in re.finditer(r'///\s*([^\n]+)\n\s+(\w+)\s*(?:\{|\,)', enum_content):
                subcmd_name = match.group(2).strip().lower()
                # Convert CamelCase to kebab-case for CLI
                subcmd_cli = re.sub(r'([a-z])([A-Z])', r'\1-\2', match.group(2)).lower()
                subcommands.append(subcmd_cli)
            if parent_cmd in commands:
                commands[parent_cmd]["subcommands"] = subcommands

    # Parse global flags
    global_flags = []
    # Match: /// Description\n    #[arg(global = true, ...
    flag_pattern = r'///\s*([^\n]+)\n\s+#\[arg\([^)]*global\s*=\s*true[^)]*\)\]\s*pub\s+(\w+)'
    for match in re.finditer(flag_pattern, content):
        flag_name = match.group(2).strip()
        # Convert snake_case to kebab-case for CLI
        flag_cli = flag_name.replace('_', '-')
        global_flags.append(flag_cli)

    return commands, global_flags


def parse_cli_examples_from_readme(root: Path) -> dict[str, list[str]]:
    """Parse CLI examples from README.md."""
    readme = root / "README.md"
    content = readme.read_text()

    # Find all hardener command examples
    # Match lines starting with: hardener or sudo hardener
    pattern = r'^(?:sudo\s+)?hardener\s+(\S+)'

    documented_commands: dict[str, list[str]] = {}
    for line in content.split('\n'):
        match = re.match(pattern, line.strip())
        if match:
            cmd = match.group(1).lower()
            # Handle flags like --ssh as special case
            if cmd.startswith('-'):
                continue
            if cmd not in documented_commands:
                documented_commands[cmd] = []
            documented_commands[cmd].append(line.strip())

    return documented_commands


def parse_global_flags_from_readme(root: Path) -> set[str]:
    """Parse mentioned global flags from README.md."""
    readme = root / "README.md"
    content = readme.read_text()

    # Find mentions of --flag anywhere in hardener command lines
    # Match any --flag on a line containing 'hardener'
    flags = set()
    for line in content.split('\n'):
        if 'hardener' in line.lower():
            # Find all --flag patterns on this line
            for match in re.finditer(r'--(\w[\w-]*)', line):
                flags.add(match.group(1))

    return flags


def main():
    print(f"{BLUE}Validating CLI documentation...{NC}\n")

    root = find_project_root()

    # Get commands from source
    source_commands, source_global_flags = parse_commands_from_source(root)

    print(f"Found {GREEN}{len(source_commands)}{NC} commands in cli.rs:")
    for cmd_name, cmd_info in sorted(source_commands.items()):
        subcmds = cmd_info.get("subcommands", [])
        if subcmds:
            print(f"  - {cmd_name} ({', '.join(subcmds)})")
        else:
            print(f"  - {cmd_name}")
    print()

    print(f"Found {GREEN}{len(source_global_flags)}{NC} global flags:")
    for flag in sorted(source_global_flags):
        print(f"  --{flag}")
    print()

    # Get documented commands from README
    readme_commands = parse_cli_examples_from_readme(root)
    readme_flags = parse_global_flags_from_readme(root)

    has_errors = False
    has_warnings = False

    # Check 1: All source commands have examples in README
    print(f"{BLUE}Checking command documentation...{NC}")
    source_cmd_names = set(source_commands.keys())
    readme_cmd_names = set(readme_commands.keys())

    missing_commands = source_cmd_names - readme_cmd_names
    extra_commands = readme_cmd_names - source_cmd_names

    if missing_commands:
        has_errors = True
        print(f"  {RED}Commands missing from README.md:{NC}")
        for cmd in sorted(missing_commands):
            print(f"    - {cmd}")

    if extra_commands:
        # Filter out likely subcommands that appear as separate commands
        known_subcommands = {'list', 'create', 'delete', 'show', 'start', 'status',
                            'generate', 'install', 'uninstall', 'export', 'run-once'}
        real_extra = {c for c in extra_commands if c not in known_subcommands}
        if real_extra:
            has_warnings = True
            print(f"  {YELLOW}Possible unknown commands in README.md:{NC}")
            for cmd in sorted(real_extra):
                print(f"    - {cmd}")

    documented_count = len(source_cmd_names & readme_cmd_names)
    if documented_count == len(source_cmd_names):
        print(f"  {GREEN}✓ All {documented_count} main commands documented{NC}")
    else:
        print(f"  Documented: {documented_count}/{len(source_cmd_names)}")
    print()

    # Check 2: Subcommands are documented
    print(f"{BLUE}Checking subcommand documentation...{NC}")
    missing_subcommands = []

    for cmd_name, cmd_info in source_commands.items():
        subcmds = cmd_info.get("subcommands", [])
        if not subcmds:
            continue

        # Check if subcommand examples exist
        for subcmd in subcmds:
            # Look for "hardener cmd subcmd" pattern in README
            found = False
            for doc_cmd, examples in readme_commands.items():
                if doc_cmd == cmd_name:
                    for example in examples:
                        if subcmd in example.lower() or subcmd.replace('_', '-') in example.lower():
                            found = True
                            break
                if found:
                    break

            if not found:
                # Also check if subcmd appears as its own entry
                if subcmd in readme_cmd_names or subcmd.replace('_', '-') in readme_cmd_names:
                    found = True

            if not found:
                missing_subcommands.append(f"{cmd_name} {subcmd}")

    if missing_subcommands:
        has_warnings = True
        print(f"  {YELLOW}Subcommands without clear examples:{NC}")
        for subcmd in sorted(missing_subcommands):
            print(f"    - hardener {subcmd}")
    else:
        print(f"  {GREEN}✓ All subcommands have examples{NC}")
    print()

    # Check 3: Global flags mentioned
    print(f"{BLUE}Checking global flag documentation...{NC}")
    # Key global flags that should be documented
    key_flags = {'ssh', 'ssh-key', 'config', 'format', 'quiet'}
    documented_key_flags = key_flags & readme_flags
    missing_key_flags = key_flags - readme_flags

    if missing_key_flags:
        has_warnings = True
        print(f"  {YELLOW}Key global flags not demonstrated:{NC}")
        for flag in sorted(missing_key_flags):
            print(f"    --{flag}")
    else:
        print(f"  {GREEN}✓ All key global flags documented{NC}")
    print()

    # Summary
    if has_errors:
        print(f"{RED}CLI documentation validation failed{NC}")
        sys.exit(1)
    elif has_warnings:
        print(f"{YELLOW}CLI documentation has warnings (non-critical){NC}")
        sys.exit(0)
    else:
        print(f"{GREEN}All CLI documentation is complete{NC}")
        sys.exit(0)


if __name__ == "__main__":
    main()

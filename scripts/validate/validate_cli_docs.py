#!/usr/bin/env python3
"""
Validates that the CLI documentation matches the CLI implementation.

Usage:
    ./scripts/validate/validate_cli_docs.py

Exit codes:
    0: All CLI commands are documented
    1: Discrepancies found

Checks:
    - All main commands are documented with examples in README.md
    - All subcommands are documented
    - Global flags are mentioned
    - Every reference surface carries every command and subcommand

Surfaces
--------
This check was named "CLI Documentation" and read `README.md` alone. It never
opened `docs/reference/cli.md` or the man page, and its name gave no hint of
that. An audit on 2026-08-12 read both by hand: `cli.md` was clean across 1135
lines, and the man page carried ten defects, two of which an operator would act
on. The narrowness was the whole story, since nothing had ever looked.

README.md documents by example and is held to a weaker standard: a command
absent from it is a warning, because the file is a tour rather than a
reference. `cli.md` and the man page are references, are complete today, and a
gap in either is an error.

Reading the man page needs its markup taken seriously. Subcommands appear in an
`.RI [ a | b | c ]` alternation under the `.B` line rather than beside the
command, and roff escapes mean `run-once` is written `run\\-once`. A parser
that misses either reports documented subcommands as missing, which is a false
defect in a check whose purpose is trust.
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


def parse_commands_from_man(root: Path) -> tuple[set[str], set[tuple[str, str]]]:
    """Parse commands and subcommands from the man page synopsis.

    Two shapes carry them, and reading only the first is how this file went
    unchecked. `.B hardener scan` names a command; the `.RI [ a | b | c ]` that
    may follow names its subcommands, so a command whose subcommands live in
    the alternation list looks bare to a parser that reads `.B` lines alone.

    Roff escapes are undone first. `run-once` is written `run\\-once`, and a
    literal comparison reports a documented subcommand as missing.
    """
    text = (root / "packaging" / "assets" / "hardener.1").read_text()
    text = text.replace("\\-", "-")

    top: set[str] = set()
    pairs: set[tuple[str, str]] = set()
    lines = text.splitlines()

    for i, line in enumerate(lines):
        match = re.match(r"^\.B(?:R)? +hardener +([\w-]+)(?: +([\w-]+))?", line)
        if not match:
            continue
        command, direct = match.group(1), match.group(2)
        top.add(command)
        if direct:
            pairs.add((command, direct))
        # Subcommands offered as an alternation on the following line.
        if i + 1 < len(lines):
            alternation = re.match(r"^\.RI +\[ *(.+?) *\]", lines[i + 1])
            if alternation:
                for option in alternation.group(1).split("|"):
                    option = option.strip()
                    if re.fullmatch(r"[\w-]+", option):
                        pairs.add((command, option))

    return top, pairs


def parse_commands_from_cli_md(root: Path) -> tuple[set[str], set[tuple[str, str]]]:
    """Parse commands and subcommands from the cli.md headings."""
    text = (root / "docs" / "reference" / "cli.md").read_text()
    top = set(re.findall(r"^## ([a-z][\w-]*)$", text, re.M))
    pairs = {
        (match.group(1), match.group(2))
        for match in re.finditer(r"^### ([a-z][\w-]+) ([\w-]+)$", text, re.M)
    }
    return top, pairs


# The reference surfaces, each read in full. README.md is checked separately
# below because it documents by example rather than by heading, so absence
# there is a weaker signal and stays a warning.
REFERENCE_SURFACES = [
    ("docs/reference/cli.md", parse_commands_from_cli_md),
    ("packaging/assets/hardener.1", parse_commands_from_man),
]


def check_reference_surfaces(root: Path, source_commands: dict[str, dict]) -> bool:
    """Hold every reference surface to the full command set from cli.rs.

    Returns True on a defect. Missing entries are errors rather than warnings:
    both surfaces are complete as of 2026-08-12, so this locks that in. The man
    page had never been opened by any check, and an audit found ten defects in
    it including two an operator would act on, while `cli.md` came back clean
    across 1135 lines.
    """
    expected_pairs = {
        (name, subcommand)
        for name, info in source_commands.items()
        for subcommand in info.get("subcommands") or []
    }
    failed = False

    for path, parse in REFERENCE_SURFACES:
        top, pairs = parse(root)
        missing_top = set(source_commands) - top
        missing_subs = expected_pairs - pairs

        if not missing_top and not missing_subs:
            print(
                f"  {GREEN}✓{NC} {path}: all {len(source_commands)} commands and "
                f"{len(expected_pairs)} subcommands present"
            )
            continue

        failed = True
        print(f"  {RED}✗ {path}:{NC}")
        for command in sorted(missing_top):
            print(f"    - command not documented: {command}")
        for command, subcommand in sorted(missing_subs):
            print(f"    - subcommand not documented: {command} {subcommand}")

    return failed


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

    # Check 4: the reference surfaces carry every command and subcommand
    print(f"{BLUE}Checking reference documentation surfaces...{NC}")
    if check_reference_surfaces(root, source_commands):
        has_errors = True
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

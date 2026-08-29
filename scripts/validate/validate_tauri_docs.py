#!/usr/bin/env python3
"""
Validates that Tauri command documentation matches actual implementations.

Usage:
    ./scripts/validate/validate_tauri_docs.py

Exit codes:
    0: All Tauri commands are documented correctly
    1: Discrepancies found

Checks:
    - commands.rs Tauri commands match file-map.md documentation
    - tauri_bindings.rs invoke calls match actual command names
    - every command is registered in all three places that must know about it

Why the third check exists
--------------------------
Adding a Tauri command means editing four files, and this check read one of
them. `commands.rs` defines the handler, `main.rs` lists it in
`generate_handler!`, `build.rs` names it in COMMANDS, and
`capabilities/default.json` grants `allow-<command>`. The last is the
per-command ACL from SAM-039; without it Tauri denies the call.

A command defined, bound and documented but absent from the capabilities file
therefore passed every check here and failed only when a user clicked the
thing. Nothing compared the four lists. They agree today, at 32 commands
each, which is what makes this the right moment to pin them: a check added
while the tree is clean states a property, where one added during an outage
only reproduces a bug.
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


def parse_tauri_commands(root: Path) -> dict[str, dict]:
    """Parse #[tauri::command] functions from the commands tree.

    The tree is `src-tauri/src/commands/`: `mod.rs` plus one file per
    domain, split along the seams the test files named. The `*_tests.rs`
    siblings are excluded because they define no commands - reading them
    would only risk mistaking a test's shape for a command's.
    """
    commands_dir = root / "src-tauri" / "src" / "commands"
    contents = [
        path.read_text()
        for path in sorted(commands_dir.glob("*.rs"))
        if not path.stem.endswith("_tests")
    ]
    content = "\n".join(contents)

    commands = {}

    # Find all #[tauri::command] annotated functions
    # Pattern: #[tauri::command]\npub async fn name(args) -> Result<ReturnType, String>
    pattern = r'#\[tauri::command\]\s*pub\s+async\s+fn\s+(\w+)\s*\(([^)]*)\)\s*->\s*Result<([^,]+),\s*String>'

    for match in re.finditer(pattern, content):
        name = match.group(1)
        args_str = match.group(2).strip()
        return_type = match.group(3).strip()

        # Parse arguments
        args = []
        if args_str:
            # Split by comma, handling generic types
            depth = 0
            current_arg = ""
            for char in args_str:
                if char in '<(':
                    depth += 1
                elif char in '>)':
                    depth -= 1
                elif char == ',' and depth == 0:
                    if current_arg.strip():
                        args.append(current_arg.strip())
                    current_arg = ""
                    continue
                current_arg += char
            if current_arg.strip():
                args.append(current_arg.strip())

        # Extract argument names and types
        parsed_args = []
        for arg in args:
            # Pattern: name: Type
            arg_match = re.match(r'(\w+)\s*:\s*(.+)', arg)
            if arg_match:
                parsed_args.append({
                    "name": arg_match.group(1),
                    "type": arg_match.group(2).strip(),
                })

        commands[name] = {
            "args": parsed_args,
            "return_type": return_type,
        }

    return commands


def parse_tauri_bindings(root: Path) -> dict[str, str]:
    """Parse invoke_command calls from tauri_bindings.rs."""
    bindings_file = root / "crates" / "hardener-ui" / "src" / "tauri_bindings.rs"
    content = bindings_file.read_text()

    bindings = {}

    # Find all invoke_command("command_name", ...) calls
    pattern = r'invoke_command\("(\w+)"'

    for match in re.finditer(pattern, content):
        command_name = match.group(1)
        # Find the function this is in (look backwards for pub async fn)
        pos = match.start()
        preceding = content[:pos]
        fn_match = re.search(r'pub\s+async\s+fn\s+(\w+)[^{]*\{[^}]*$', preceding, re.DOTALL)
        if fn_match:
            fn_name = fn_match.group(1)
            bindings[fn_name] = command_name

    return bindings


def parse_documented_commands(root: Path) -> dict[str, dict]:
    """Parse Tauri command signatures from file-map.md."""
    file_map = root / "docs" / "reference" / "file-map.md"
    content = file_map.read_text()

    commands = {}

    # Find the Tauri Commands section
    section_match = re.search(r'### Tauri Commands\s*```rust\s*(.*?)```', content, re.DOTALL)
    if not section_match:
        return commands

    section = section_match.group(1)

    # Parse each command signature
    pattern = r'pub\s+async\s+fn\s+(\w+)\s*\(([^)]*)\)\s*->\s*Result<([^,]+),\s*String>'

    for match in re.finditer(pattern, section):
        name = match.group(1)
        args_str = match.group(2).strip()
        return_type = match.group(3).strip()

        # Parse arguments (simplified)
        args = []
        if args_str:
            for arg in args_str.split(','):
                arg = arg.strip()
                if ':' in arg:
                    arg_name, arg_type = arg.split(':', 1)
                    args.append({
                        "name": arg_name.strip(),
                        "type": arg_type.strip(),
                    })

        commands[name] = {
            "args": args,
            "return_type": return_type,
        }

    return commands


def parse_registrations(root: Path) -> dict[str, tuple[set[str], str]]:
    """Every command name each registration site names, keyed by site.

    Returned as a set per site rather than a merged verdict so a disagreement
    can say which file is missing which name. The value carries the remedy,
    because knowing `foo` is absent from `build.rs` is not the same as knowing
    what to type.

    A site whose pattern matches nothing yields an empty set, and main() treats
    that as a failure rather than as a site that agreed: three empty sets and
    an empty command list would otherwise be perfect agreement about nothing.
    """
    tauri = root / "src-tauri"

    handler = re.search(
        r"generate_handler!\[(.*?)\]", (tauri / "src" / "main.rs").read_text(), re.S
    )
    registered = set(re.findall(r"\b(\w+)\b", handler.group(1))) if handler else set()

    commands = re.search(
        r"COMMANDS[^=]*=\s*&?\[(.*?)\]", (tauri / "build.rs").read_text(), re.S
    )
    declared = set(re.findall(r'"([\w-]+)"', commands.group(1))) if commands else set()

    # The ACL spells commands with hyphens: `allow-run-scan` for `run_scan`.
    granted = {
        permission.removeprefix("allow-").replace("-", "_")
        for permission in re.findall(
            r'"(allow-[\w-]+)"', (tauri / "capabilities" / "default.json").read_text()
        )
    }

    return {
        "src-tauri/src/main.rs": (registered, "add it to generate_handler!"),
        "src-tauri/build.rs": (
            {name.replace("-", "_") for name in declared},
            "add it to COMMANDS",
        ),
        "src-tauri/capabilities/default.json": (
            granted,
            "grant allow-<command>, or Tauri denies the call at runtime",
        ),
    }


def main():
    print(f"{BLUE}Validating Tauri command documentation...{NC}\n")

    root = find_project_root()

    # Get commands from source
    source_commands = parse_tauri_commands(root)
    bindings = parse_tauri_bindings(root)
    documented_commands = parse_documented_commands(root)

    print(f"Found {GREEN}{len(source_commands)}{NC} Tauri commands in commands.rs:")
    for name, info in sorted(source_commands.items()):
        args = ", ".join(f"{a['name']}: {a['type']}" for a in info['args'])
        print(f"  - {name}({args}) -> {info['return_type']}")
    print()

    has_errors = False

    # Check 1: All source commands are documented
    print(f"{BLUE}Checking file-map.md documentation...{NC}")
    source_names = set(source_commands.keys())
    doc_names = set(documented_commands.keys())

    missing_docs = source_names - doc_names
    extra_docs = doc_names - source_names

    if missing_docs:
        has_errors = True
        print(f"  {RED}Commands missing from file-map.md:{NC}")
        for name in sorted(missing_docs):
            print(f"    - {name}")

    if extra_docs:
        has_errors = True
        print(f"  {RED}Commands in file-map.md but not in source:{NC}")
        for name in sorted(extra_docs):
            print(f"    - {name}")

    # Check signatures match
    signature_mismatches = []
    for name in source_names & doc_names:
        src = source_commands[name]
        doc = documented_commands[name]

        # Compare return types (normalise whitespace)
        src_ret = re.sub(r'\s+', '', src['return_type'])
        doc_ret = re.sub(r'\s+', '', doc['return_type'])

        if src_ret != doc_ret:
            signature_mismatches.append(
                f"{name}: return type differs (source: {src['return_type']}, doc: {doc['return_type']})"
            )

        # Compare argument counts
        if len(src['args']) != len(doc['args']):
            signature_mismatches.append(
                f"{name}: argument count differs (source: {len(src['args'])}, doc: {len(doc['args'])})"
            )

    if signature_mismatches:
        has_errors = True
        print(f"  {RED}Signature mismatches:{NC}")
        for msg in signature_mismatches:
            print(f"    - {msg}")

    if not missing_docs and not extra_docs and not signature_mismatches:
        print(f"  {GREEN}✓ All {len(source_names)} commands documented correctly{NC}")
    print()

    # Check 2: Bindings call correct command names
    print(f"{BLUE}Checking tauri_bindings.rs invoke calls...{NC}")
    binding_errors = []

    for fn_name, invoked_cmd in bindings.items():
        if invoked_cmd not in source_commands:
            binding_errors.append(
                f"{fn_name}() calls '{invoked_cmd}' which doesn't exist in commands.rs"
            )

    if binding_errors:
        has_errors = True
        print(f"  {RED}Invalid command invocations:{NC}")
        for msg in binding_errors:
            print(f"    - {msg}")
    else:
        print(f"  {GREEN}✓ All {len(bindings)} bindings call valid commands{NC}")
    print()

    # Check 3: Every command is registered everywhere it has to be
    print(f"{BLUE}Checking the three registration sites...{NC}")
    registration_errors = []
    for site, (names, remedy) in sorted(parse_registrations(root).items()):
        if not names:
            registration_errors.append(
                f"{site}: nothing matched. The list moved or changed shape, so "
                f"this site was compared against nothing"
            )
            continue
        for missing in sorted(source_names - names):
            registration_errors.append(f"{site}: '{missing}' is not registered, {remedy}")
        for extra in sorted(names - source_names):
            registration_errors.append(
                f"{site}: registers '{extra}', which no #[tauri::command] defines"
            )

    if registration_errors:
        has_errors = True
        print(f"  {RED}Registration sites that disagree with commands.rs:{NC}")
        for msg in registration_errors:
            print(f"    - {msg}")
    else:
        print(f"  {GREEN}✓ All {len(source_names)} commands registered in all 3 sites{NC}")
    print()

    # Summary
    if has_errors:
        print(f"{RED}Tauri command validation failed{NC}")
        sys.exit(1)
    else:
        print(f"{GREEN}All Tauri command documentation is accurate{NC}")
        sys.exit(0)


if __name__ == "__main__":
    main()

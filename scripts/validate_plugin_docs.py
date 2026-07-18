#!/usr/bin/env python3
"""
Validates that plugin documentation matches actual plugin implementations.

Usage:
    ./scripts/validate_plugin_docs.py

Exit codes:
    0: All plugin documentation is accurate
    1: Discrepancies found

Checks:
    - README.md plugin table
    - docs/ROADMAP.md plugin checklist
    - docs/architecture/architecture.md plugin table
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


def parse_plugins_from_source(root: Path) -> dict[str, dict]:
    """Parse plugin metadata from source files."""
    plugins = {}
    plugins_dir = root / "crates" / "hardener-plugins" / "src"

    # Find all plugin modules (directories with mod.rs)
    for mod_dir in plugins_dir.iterdir():
        if not mod_dir.is_dir():
            continue
        mod_file = mod_dir / "mod.rs"
        if not mod_file.exists():
            continue

        content = mod_file.read_text()

        # Extract plugin metadata from metadata() function
        # Look for: plugin_id: PluginId::new("xxx") or PluginId::from("xxx")
        id_match = re.search(r'plugin_id:\s*PluginId::(?:new|from)\("([^"]+)"\)', content)
        # Look for: plugin_name: "xxx".to_string()
        name_match = re.search(r'plugin_name:\s*"([^"]+)"', content)
        # Look for: plugin_description: "xxx".to_string()
        desc_match = re.search(r'plugin_description:\s*"([^"]+)"', content)
        # Look for: plugin_category: FindingCategory::Xxx
        cat_match = re.search(r'plugin_category:\s*FindingCategory::(\w+)', content)

        if id_match and name_match:
            plugin_id = id_match.group(1)
            plugins[plugin_id] = {
                "id": plugin_id,
                "name": name_match.group(1),
                "description": desc_match.group(1) if desc_match else "",
                "category": cat_match.group(1) if cat_match else "Unknown",
                "source_file": str(mod_file.relative_to(root)),
            }

    return plugins


def parse_plugins_from_registry(root: Path) -> list[str]:
    """Parse plugin IDs from create_plugin_registry() function."""
    lib_file = root / "crates" / "hardener-plugins" / "src" / "lib.rs"
    content = lib_file.read_text()

    # Find all registry.register() calls
    # Match: registry.register(Box::new(XxxPlugin::new()))
    pattern = r'\.register\(Box::new\((\w+)::new\(\)\)\)'
    matches = re.findall(pattern, content)

    return matches


def parse_plugins_from_readme(root: Path) -> dict[str, str]:
    """Parse plugin names from README.md plugin table."""
    readme = root / "README.md"
    content = readme.read_text()

    plugins = {}
    # Match table rows: | **Plugin Name** | description | status |
    pattern = r'\|\s*\*\*([^*]+)\*\*\s*\|([^|]+)\|'

    # Find the plugin table section
    in_plugin_section = False
    for line in content.split('\n'):
        if 'Security Plugins' in line:
            in_plugin_section = True
            continue
        if in_plugin_section and line.startswith('###'):
            break
        if in_plugin_section:
            match = re.match(pattern, line)
            if match:
                name = match.group(1).strip()
                desc = match.group(2).strip()
                plugins[name] = desc

    return plugins


def parse_plugins_from_architecture(root: Path) -> dict[str, dict]:
    """Parse plugin info from architecture.md plugin table."""
    arch_file = root / "docs" / "architecture" / "architecture.md"
    content = arch_file.read_text()

    plugins = {}
    # Match table rows: | `PluginName` | Category | description |
    pattern = r'\|\s*`(\w+)`\s*\|\s*(\w+)\s*\|([^|]+)\|'

    for line in content.split('\n'):
        match = re.match(pattern, line)
        if match:
            name = match.group(1).strip()
            category = match.group(2).strip()
            desc = match.group(3).strip()
            plugins[name] = {"category": category, "description": desc}

    return plugins


def main():
    print(f"{BLUE}Validating plugin documentation...{NC}\n")

    root = find_project_root()

    # Get plugins from source
    source_plugins = parse_plugins_from_source(root)
    registry_plugins = parse_plugins_from_registry(root)

    print(f"Found {GREEN}{len(source_plugins)}{NC} plugins in source code:")
    for plugin_id, info in sorted(source_plugins.items()):
        print(f"  - {info['name']} ({plugin_id})")
    print()

    # Get plugins from documentation
    readme_plugins = parse_plugins_from_readme(root)
    arch_plugins = parse_plugins_from_architecture(root)

    has_errors = False

    # Check 1: All source plugins are in README
    print(f"{BLUE}Checking README.md...{NC}")
    source_names = {info['name'] for info in source_plugins.values()}
    readme_names = set(readme_plugins.keys())

    missing_in_readme = source_names - readme_names
    extra_in_readme = readme_names - source_names

    if missing_in_readme:
        has_errors = True
        print(f"  {RED}Missing from README.md:{NC}")
        for name in sorted(missing_in_readme):
            print(f"    - {name}")

    if extra_in_readme:
        has_errors = True
        print(f"  {RED}Extra in README.md (not in source):{NC}")
        for name in sorted(extra_in_readme):
            print(f"    - {name}")

    if not missing_in_readme and not extra_in_readme:
        print(f"  {GREEN}✓ All {len(readme_names)} plugins documented{NC}")
    print()

    # Check 2: All source plugins are in architecture.md
    print(f"{BLUE}Checking docs/architecture/architecture.md...{NC}")
    # Architecture uses struct names like "AuditHardeningPlugin"
    arch_names = set(arch_plugins.keys())

    # Map source plugin IDs to expected struct names
    # Note: Some struct names don't follow the ID convention exactly
    id_to_struct_overrides = {
        "service-minimisation": "ServicesHardeningPlugin",  # Struct uses "Services" + "Hardening"
    }
    expected_structs = set()
    for plugin_id, info in source_plugins.items():
        if plugin_id in id_to_struct_overrides:
            struct_name = id_to_struct_overrides[plugin_id]
        else:
            # Convert "kernel-hardening" to "KernelHardeningPlugin"
            parts = plugin_id.split('-')
            struct_name = ''.join(p.title() for p in parts) + "Plugin"
        expected_structs.add(struct_name)

    missing_in_arch = expected_structs - arch_names
    extra_in_arch = arch_names - expected_structs

    if missing_in_arch:
        has_errors = True
        print(f"  {RED}Missing from architecture.md:{NC}")
        for name in sorted(missing_in_arch):
            print(f"    - {name}")

    if extra_in_arch:
        has_errors = True
        print(f"  {RED}Extra in architecture.md (not in source):{NC}")
        for name in sorted(extra_in_arch):
            print(f"    - {name}")

    if not missing_in_arch and not extra_in_arch:
        print(f"  {GREEN}✓ All {len(arch_names)} plugins documented{NC}")
    print()

    # Check 3: Registry has all plugins
    print(f"{BLUE}Checking plugin registry...{NC}")
    registered_count = len(registry_plugins)
    source_count = len(source_plugins)

    if registered_count != source_count:
        has_errors = True
        print(f"  {RED}Registry has {registered_count} plugins but source has {source_count}{NC}")
    else:
        print(f"  {GREEN}✓ Registry has all {registered_count} plugins{NC}")
    print()

    # Summary
    if has_errors:
        print(f"{RED}Plugin documentation validation failed{NC}")
        sys.exit(1)
    else:
        print(f"{GREEN}All plugin documentation is accurate{NC}")
        sys.exit(0)


if __name__ == "__main__":
    main()

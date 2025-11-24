#!/usr/bin/env python3
"""
Naming Convention Validator for Linux Hardening Tool

This script scans the Rust codebase and validates that identifiers follow
the naming conventions defined in .claude/NAMING_CONVENTIONS.md

Author: Eric Jingryd
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple, Dict
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    """Validation issue severity levels"""
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass
class ValidationIssue:
    """Represents a naming convention violation"""
    file_path: Path
    line_number: int
    severity: Severity
    category: str
    issue: str
    suggestion: str = ""


class NamingValidator:
    """Validates Rust code against project naming conventions"""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.issues: List[ValidationIssue] = []

        # Patterns for different naming conventions
        self.patterns = {
            'snake_case': re.compile(r'^[a-z][a-z0-9_]*$'),
            'PascalCase': re.compile(r'^[A-Z][a-zA-Z0-9]*$'),
            'SCREAMING_SNAKE_CASE': re.compile(r'^[A-Z][A-Z0-9_]*$'),
            'kebab-case': re.compile(r'^[a-z][a-z0-9-]*$'),
        }

        # Common abbreviations to avoid
        self.forbidden_abbreviations = {
            'mgr': 'manager',
            'ctx': 'context',
            'cfg': 'config',
            'cmd': 'command',
            'msg': 'message',
            'dist': 'distribution',
            'distro': 'distribution',  # Except in 'distro_' prefix
            'param': 'parameter',
            'res': 'result',
            'val': 'value',
            'pkg': 'package',
            'auth': 'authentication',
            'perms': 'permissions',
        }

        # Required prefixes for struct fields
        self.field_prefixes = {
            'Distribution': 'distro_',
            'Plugin': 'plugin_',
            'Checkpoint': 'checkpoint_',
            'Package': 'package_',
            'AuditEntry': 'entry_',
            'FileState': 'file_',
        }

    def validate_project(self) -> int:
        """
        Validate entire project and return exit code

        Returns:
            0 if no errors, 1 if errors found
        """
        print("🔍 Validating naming conventions...\n")

        # Find all Rust source files
        rust_files = list(self.project_root.glob('crates/**/*.rs'))

        for rust_file in rust_files:
            # Skip generated files and build artifacts
            if 'target' in str(rust_file) or 'build.rs' in str(rust_file):
                continue

            self.validate_file(rust_file)

        # Print results
        self.print_results()

        # Return exit code
        error_count = sum(1 for issue in self.issues if issue.severity == Severity.ERROR)
        return 1 if error_count > 0 else 0

    def validate_file(self, file_path: Path):
        """Validate a single Rust source file"""
        try:
            content = file_path.read_text(encoding='utf-8')
            lines = content.split('\n')

            # Track if next function is a Leptos component
            next_is_component = False

            for line_num, line in enumerate(lines, start=1):
                stripped = line.strip()

                # Check if this line is a #[component] attribute
                if stripped == '#[component]':
                    next_is_component = True
                    continue

                # Validate the line, passing component flag
                self.validate_line(file_path, line_num, stripped, next_is_component)

                # Reset component flag after processing function definition
                if stripped.startswith('fn ') or stripped.startswith('pub fn '):
                    next_is_component = False

        except Exception as e:
            print(f"⚠️  Error reading {file_path}: {e}")

    def validate_line(self, file_path: Path, line_num: int, line: str, is_component: bool = False):
        """Validate naming conventions in a single line"""
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith('//') or line.startswith('/*'):
            return

        # Check struct definitions
        if match := re.match(r'pub struct (\w+)', line):
            struct_name = match.group(1)
            self.validate_struct_name(file_path, line_num, struct_name)

        # Check enum definitions
        if match := re.match(r'pub enum (\w+)', line):
            enum_name = match.group(1)
            self.validate_enum_name(file_path, line_num, enum_name)

        # Check trait definitions
        if match := re.match(r'pub trait (\w+)', line):
            trait_name = match.group(1)
            self.validate_trait_name(file_path, line_num, trait_name)

        # Check function definitions
        if match := re.match(r'(?:pub )?(?:async )?fn (\w+)', line):
            fn_name = match.group(1)
            self.validate_function_name(file_path, line_num, fn_name, is_component)

        # Check const definitions
        if match := re.match(r'const (\w+):', line):
            const_name = match.group(1)
            self.validate_const_name(file_path, line_num, const_name)

        # Check for common abbreviations
        self.check_abbreviations(file_path, line_num, line)

        # Check for American spellings
        self.check_british_english(file_path, line_num, line)

    def validate_struct_name(self, file_path: Path, line_num: int, name: str):
        """Validate struct name follows PascalCase"""
        if not self.patterns['PascalCase'].match(name):
            self.issues.append(ValidationIssue(
                file_path=file_path,
                line_number=line_num,
                severity=Severity.ERROR,
                category="Struct Name",
                issue=f"Struct '{name}' should use PascalCase",
                suggestion=self.to_pascal_case(name)
            ))

    def validate_enum_name(self, file_path: Path, line_num: int, name: str):
        """Validate enum name follows PascalCase"""
        if not self.patterns['PascalCase'].match(name):
            self.issues.append(ValidationIssue(
                file_path=file_path,
                line_number=line_num,
                severity=Severity.ERROR,
                category="Enum Name",
                issue=f"Enum '{name}' should use PascalCase",
                suggestion=self.to_pascal_case(name)
            ))

    def validate_trait_name(self, file_path: Path, line_num: int, name: str):
        """Validate trait name follows PascalCase"""
        if not self.patterns['PascalCase'].match(name):
            self.issues.append(ValidationIssue(
                file_path=file_path,
                line_number=line_num,
                severity=Severity.ERROR,
                category="Trait Name",
                issue=f"Trait '{name}' should use PascalCase",
                suggestion=self.to_pascal_case(name)
            ))

        # Warn if trait name ends with 'Trait'
        if name.endswith('Trait'):
            self.issues.append(ValidationIssue(
                file_path=file_path,
                line_number=line_num,
                severity=Severity.WARNING,
                category="Trait Name",
                issue=f"Trait '{name}' should not end with 'Trait' suffix",
                suggestion=name[:-5]  # Remove 'Trait' suffix
            ))

    def validate_function_name(self, file_path: Path, line_num: int, name: str, is_component: bool = False):
        """Validate function name follows snake_case (or PascalCase for Leptos components)"""
        # Leptos components must use PascalCase
        if is_component:
            if not self.patterns['PascalCase'].match(name):
                self.issues.append(ValidationIssue(
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.ERROR,
                    category="Leptos Component Name",
                    issue=f"Leptos component '{name}' should use PascalCase",
                    suggestion=self.to_pascal_case(name)
                ))
        # Regular functions use snake_case
        elif not self.patterns['snake_case'].match(name):
            self.issues.append(ValidationIssue(
                file_path=file_path,
                line_number=line_num,
                severity=Severity.ERROR,
                category="Function Name",
                issue=f"Function '{name}' should use snake_case",
                suggestion=self.to_snake_case(name)
            ))

    def validate_const_name(self, file_path: Path, line_num: int, name: str):
        """Validate constant name follows SCREAMING_SNAKE_CASE"""
        if not self.patterns['SCREAMING_SNAKE_CASE'].match(name):
            self.issues.append(ValidationIssue(
                file_path=file_path,
                line_number=line_num,
                severity=Severity.ERROR,
                category="Constant Name",
                issue=f"Constant '{name}' should use SCREAMING_SNAKE_CASE",
                suggestion=self.to_screaming_snake_case(name)
            ))

    def check_abbreviations(self, file_path: Path, line_num: int, line: str):
        """Check for forbidden abbreviations"""
        for abbrev, full_word in self.forbidden_abbreviations.items():
            # Look for abbreviation as a whole word (not part of another word)
            pattern = r'\b' + abbrev + r'\b'
            if re.search(pattern, line, re.IGNORECASE):
                # Allow 'distro_' prefix
                if abbrev == 'distro' and 'distro_' in line:
                    continue

                self.issues.append(ValidationIssue(
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.WARNING,
                    category="Abbreviation",
                    issue=f"Avoid abbreviation '{abbrev}'",
                    suggestion=f"Use '{full_word}' instead"
                ))

    def check_british_english(self, file_path: Path, line_num: int, line: str):
        """Check for American English spellings"""
        american_to_british = {
            'authorize': 'authorise',
            'color': 'colour',
            'organization': 'organisation',
            'initialize': 'initialise',
            'serialize': 'serialise',
            'finalize': 'finalise',
        }

        for american, british in american_to_british.items():
            if re.search(r'\b' + american + r'\b', line, re.IGNORECASE):
                self.issues.append(ValidationIssue(
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.WARNING,
                    category="British English",
                    issue=f"Use British spelling '{british}' instead of '{american}'"
                ))

    def print_results(self):
        """Print validation results to console"""
        if not self.issues:
            print("✅ All naming conventions validated successfully!\n")
            return

        # Group issues by severity
        errors = [i for i in self.issues if i.severity == Severity.ERROR]
        warnings = [i for i in self.issues if i.severity == Severity.WARNING]

        # Print errors
        if errors:
            print(f"❌ Found {len(errors)} naming convention error(s):\n")
            for issue in errors:
                print(f"  {issue.file_path}:{issue.line_number}")
                print(f"    [{issue.category}] {issue.issue}")
                if issue.suggestion:
                    print(f"    Suggestion: {issue.suggestion}")
                print()

        # Print warnings
        if warnings:
            print(f"⚠️  Found {len(warnings)} naming convention warning(s):\n")
            for issue in warnings:
                print(f"  {issue.file_path}:{issue.line_number}")
                print(f"    [{issue.category}] {issue.issue}")
                if issue.suggestion:
                    print(f"    Suggestion: {issue.suggestion}")
                print()

        # Summary
        print(f"Summary: {len(errors)} errors, {len(warnings)} warnings")
        print(f"\nRefer to .claude/NAMING_CONVENTIONS.md for complete naming standards.\n")

    @staticmethod
    def to_snake_case(name: str) -> str:
        """Convert name to snake_case"""
        # Insert underscore before capitals
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

    @staticmethod
    def to_pascal_case(name: str) -> str:
        """Convert name to PascalCase"""
        return ''.join(word.capitalize() for word in name.split('_'))

    @staticmethod
    def to_screaming_snake_case(name: str) -> str:
        """Convert name to SCREAMING_SNAKE_CASE"""
        return NamingValidator.to_snake_case(name).upper()


def main():
    """Main entry point"""
    # Find project root (where Cargo.toml is)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent

    if not (project_root / 'Cargo.toml').exists():
        print("❌ Error: Could not find project root (Cargo.toml)")
        sys.exit(1)

    validator = NamingValidator(project_root)
    exit_code = validator.validate_project()
    sys.exit(exit_code)


if __name__ == '__main__':
    main()

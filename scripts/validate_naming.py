#!/usr/bin/env python3
"""
Naming Convention Validator for Linux Hardening Tool

This script scans the Rust codebase and validates that identifiers follow
the naming conventions defined in docs/reference/naming-conventions.md

Author: Eric Jingryd
"""

import re
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


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
    in_test: bool = False


@dataclass
class WarningSummary:
    """Summarises warnings of the same type"""
    category: str
    issue: str
    suggestion: str
    locations: List[str] = field(default_factory=list)
    test_count: int = 0
    non_test_count: int = 0


class NamingValidator:
    """Validates Rust code against project naming conventions"""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.issues: List[ValidationIssue] = []

        # Em-dash and en-dash are forbidden project-wide (they read as an AI
        # tell). The scan covers tracked prose and source; use comma, colon,
        # parentheses, or a plain hyphen instead. See docs/reference/naming-conventions.md.
        # Pattern uses unicode escapes (not literal glyphs) so this file does
        # not flag itself. Matches em-dash, en-dash, and their Rust \u escapes.
        _em, _en = chr(0x2014), chr(0x2013)
        self.dash_pattern = re.compile('[' + _em + _en + ']|' + r'\\u\{201[34]\}')
        self.dash_scan_suffixes = {
            '.md', '.rs', '.toml', '.py', '.sh', '.txt', '.yml', '.yaml', '.json',
        }

        # Patterns for different naming conventions
        self.patterns = {
            'snake_case': re.compile(r'^[a-z][a-z0-9_]*$'),
            'PascalCase': re.compile(r'^[A-Z][a-zA-Z0-9]*$'),
            'SCREAMING_SNAKE_CASE': re.compile(r'^[A-Z][A-Z0-9_]*$'),
            'kebab-case': re.compile(r'^[a-z][a-z0-9-]*$'),
        }

        # Abbreviations to check (key: abbrev, value: (full_word, is_allowed_in_context))
        # Some abbreviations are domain-specific and acceptable
        self.forbidden_abbreviations = {
            'mgr': ('manager', False),
            'ctx': ('context', True),  # Allowed - standard parameter name for Context
            'cfg': ('config', True),   # Allowed - Rust keyword in #[cfg(...)]
            'cmd': ('command', True),  # Allowed - common in CLI/executor contexts
            'msg': ('message', False),
            'dist': ('distribution', False),
            'distro': ('distribution', True),  # Allowed - domain term
            'param': ('parameter', False),
            'res': ('result', False),
            'val': ('value', False),
            'pkg': ('package', False),
            'auth': ('authentication', False),
            'perms': ('permissions', False),
        }

        # Allowed in specific contexts (don't warn)
        self.context_allowlist = {
            'cfg': [r'#\[cfg\(', r'cfg!'],  # Rust cfg attribute/macro
            'ctx': [r'ctx:', r'&ctx', r'ctx\.', r'ctx,', r'\(ctx\)', r'mut ctx', r'ctx\)', r'let ctx'],  # Context param
            'distro': [r'distro_', r'DistroFamily', r'hardener-distro'],
            'cmd': [r'execute_command', r'CommandOutput', r'firewall_cmd', r'cmd:', r'&cmd', r'cmd\.', r'let cmd'],
        }

        # External crate terms that use American English (can't be changed)
        self.external_american_terms = {
            'serialize', 'deserialize', 'serializer', 'deserializer',
            'color',  # From PDF/graphics libraries (printpdf crate)
        }

        # Lines containing these patterns skip British English checks entirely
        self.external_crate_patterns = [
            r'printpdf::',  # PDF library uses American English
            r'Rgb::',       # Colour type from printpdf
            r'Color::',     # External colour types
        ]

        # Official control titles from US standards (NIST/CIS/STIG) keep their
        # canonical American spelling -- they are proper nouns quoted verbatim
        # from the published catalogue, not our own prose.
        self.standards_american_patterns = [
            r'Authorize Access to Security Functions',  # NIST SP 800-53 AC-6(1)
        ]

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

        # Repo-wide em/en dash scan across tracked prose and source
        self.check_dashes()

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

            # Track if we're inside a test module or function
            in_test_context = False
            brace_depth = 0
            test_brace_start = -1

            # Track if next function is a Leptos component
            next_is_component = False

            for line_num, line in enumerate(lines, start=1):
                stripped = line.strip()

                # Track brace depth for test context
                brace_depth += line.count('{') - line.count('}')

                # Detect test module or test function start
                if '#[cfg(test)]' in stripped or '#[test]' in stripped or '#[tokio::test]' in stripped:
                    in_test_context = True
                    test_brace_start = brace_depth

                # Exit test context when we close the test block
                if in_test_context and brace_depth < test_brace_start:
                    in_test_context = False
                    test_brace_start = -1

                # Also detect test modules by name
                if 'mod tests' in stripped or 'mod test' in stripped:
                    in_test_context = True
                    test_brace_start = brace_depth

                # Check if this line is a #[component] attribute
                if stripped == '#[component]':
                    next_is_component = True
                    continue

                # Validate the line, passing context flags
                self.validate_line(file_path, line_num, stripped, next_is_component, in_test_context)

                # Reset component flag after processing function definition
                if stripped.startswith('fn ') or stripped.startswith('pub fn '):
                    next_is_component = False

        except Exception as e:
            print(f"⚠️  Error reading {file_path}: {e}")

    def check_dashes(self):
        """Flag em-dashes and en-dashes in tracked prose and source files."""
        try:
            tracked = subprocess.run(
                ['git', 'ls-files', '-z'],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.split('\0')
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"⚠️  Dash scan skipped (git unavailable): {e}")
            return

        for rel in tracked:
            if not rel or Path(rel).suffix not in self.dash_scan_suffixes:
                continue
            path = self.project_root / rel
            try:
                lines = path.read_text(encoding='utf-8').split('\n')
            except (OSError, UnicodeDecodeError):
                continue
            for line_num, line in enumerate(lines, start=1):
                if self.dash_pattern.search(line):
                    self.issues.append(ValidationIssue(
                        file_path=path,
                        line_number=line_num,
                        severity=Severity.ERROR,
                        category="Forbidden Dash",
                        issue="Em-dash or en-dash is forbidden project-wide",
                        suggestion="Use a comma, colon, parentheses, or plain hyphen",
                    ))

    def validate_line(self, file_path: Path, line_num: int, line: str,
                      is_component: bool = False, in_test: bool = False):
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

        # Check for common abbreviations (pass test context)
        self.check_abbreviations(file_path, line_num, line, in_test)

        # Check for American spellings (pass test context)
        self.check_british_english(file_path, line_num, line, in_test)

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

    def check_abbreviations(self, file_path: Path, line_num: int, line: str, in_test: bool = False):
        """Check for forbidden abbreviations"""
        for abbrev, (full_word, is_contextual) in self.forbidden_abbreviations.items():
            # Look for abbreviation as a whole word (not part of another word)
            pattern = r'\b' + abbrev + r'\b'
            if re.search(pattern, line, re.IGNORECASE):
                # Check if this abbreviation is allowed in this context
                if is_contextual and abbrev in self.context_allowlist:
                    # Check if any allowlist pattern matches
                    if any(re.search(p, line) for p in self.context_allowlist[abbrev]):
                        continue

                self.issues.append(ValidationIssue(
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.WARNING,
                    category="Abbreviation",
                    issue=f"Avoid abbreviation '{abbrev}'",
                    suggestion=f"Use '{full_word}' instead",
                    in_test=in_test
                ))

    def check_british_english(self, file_path: Path, line_num: int, line: str, in_test: bool = False):
        """Check for American English spellings"""
        # Skip lines that are clearly from external crates
        if any(re.search(p, line) for p in self.external_crate_patterns):
            return
        # Skip official US-standard control titles (proper nouns, American spelling)
        if any(re.search(p, line) for p in self.standards_american_patterns):
            return

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
                # Skip if this is from an external crate (serde, etc.)
                if american in self.external_american_terms:
                    # Check if it's in a derive attribute or similar
                    if re.search(r'#\[derive\(.*' + american, line, re.IGNORECASE):
                        continue
                    if re.search(r'serde\(', line, re.IGNORECASE):
                        continue
                    # Skip 'Serialize' and 'Deserialize' trait names entirely
                    if american in ('serialize', 'deserialize') and american.capitalize() in line:
                        continue
                    # Skip 'color' when used with external types
                    if american == 'color':
                        continue

                self.issues.append(ValidationIssue(
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.WARNING,
                    category="British English",
                    issue=f"Use British spelling '{british}' instead of '{american}'",
                    in_test=in_test
                ))

    def print_results(self):
        """Print validation results to console"""
        if not self.issues:
            print("✅ All naming conventions validated successfully!\n")
            return

        # Group issues by severity
        errors = [i for i in self.issues if i.severity == Severity.ERROR]
        warnings = [i for i in self.issues if i.severity == Severity.WARNING]

        # Separate warnings into test and non-test
        test_warnings = [w for w in warnings if w.in_test]
        non_test_warnings = [w for w in warnings if not w.in_test]

        # Print errors (always show all)
        if errors:
            print(f"❌ Found {len(errors)} naming convention error(s):\n")
            for issue in errors:
                print(f"  {issue.file_path}:{issue.line_number}")
                print(f"    [{issue.category}] {issue.issue}")
                if issue.suggestion:
                    print(f"    Suggestion: {issue.suggestion}")
                print()

        # Print non-test warnings (show all)
        if non_test_warnings:
            print(f"⚠️  Found {len(non_test_warnings)} naming convention warning(s) in production code:\n")

            # Group by issue type for cleaner output
            grouped = self._group_warnings(non_test_warnings)
            for key, summary in grouped.items():
                print(f"  [{summary.category}] {summary.issue}")
                if summary.suggestion:
                    print(f"    Suggestion: {summary.suggestion}")
                if len(summary.locations) <= 3:
                    for loc in summary.locations:
                        print(f"    - {loc}")
                else:
                    for loc in summary.locations[:3]:
                        print(f"    - {loc}")
                    print(f"    ... and {len(summary.locations) - 3} more")
                print()

        # Summarise test warnings (don't show individual locations)
        if test_warnings:
            test_grouped = self._group_warnings(test_warnings)
            print(f"📋 Found {len(test_warnings)} warning(s) in test code (summarised):\n")
            for key, summary in test_grouped.items():
                print(f"  [{summary.category}] {summary.issue} ({len(summary.locations)} occurrences)")
            print()

        # Summary
        print(f"Summary: {len(errors)} errors, {len(non_test_warnings)} production warnings, {len(test_warnings)} test warnings")
        print(f"\nRefer to docs/reference/naming-conventions.md for complete naming standards.\n")

    def _group_warnings(self, warnings: List[ValidationIssue]) -> Dict[str, WarningSummary]:
        """Group warnings by type for cleaner output"""
        grouped: Dict[str, WarningSummary] = {}

        for w in warnings:
            key = f"{w.category}:{w.issue}"
            if key not in grouped:
                grouped[key] = WarningSummary(
                    category=w.category,
                    issue=w.issue,
                    suggestion=w.suggestion
                )
            grouped[key].locations.append(f"{w.file_path}:{w.line_number}")

        return grouped

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

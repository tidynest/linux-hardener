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
from typing import List, Dict, Optional, Set
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
class NameExemption:
    """A tracked path where the project's pre-#51 name is still correct.

    `reason` says why, so the list documents itself rather than reading as a
    list of files somebody could not be bothered to fix. `line_pattern`
    narrows the exemption to the lines it matches, leaving the rest of that
    file checked; an empty pattern exempts the whole file, which also blinds
    this check to every other line in it. `temporary` marks an exemption that
    a named future event deletes rather than one that must never be removed.
    """
    reason: str
    line_pattern: str = ''
    temporary: bool = False


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
            # `#!?\[` so the inner form matches too: a test module split out of
            # its source file carries `#![cfg(test)]`, and the outer-only pattern
            # flagged that attribute as a badly named identifier once per file.
            'cfg': [r'#!?\[cfg\(', r'cfg!'],  # Rust cfg attribute/macro
            'ctx': [r'ctx:', r'&ctx', r'ctx\.', r'ctx,', r'\(ctx\)', r'mut ctx', r'ctx\)', r'let ctx'],  # Context param
            'distro': [r'distro_', r'DistroFamily', r'hardener-distro'],
            'cmd': [r'execute_command', r'CommandOutput', r'firewall_cmd', r'cmd:', r'&cmd', r'cmd\.', r'let cmd'],
        }

        # External crate terms that use American English (can't be changed)
        self.external_american_terms = {
            'serialize', 'deserialize', 'serializer', 'deserializer',
            'color',  # see external_color_patterns for what this actually means
        }

        # Where `color` is not ours to spell. The exemption used to be
        # unconditional and was justified as "from PDF/graphics libraries
        # (printpdf crate)", which described one of the 38 lines carrying the
        # word: 35 are CSS, 2 are a webhook payload field, 1 is a crate path.
        # So `color` could never raise a warning anywhere, and a Rust field of
        # our own named `color` would have been exempted by a rule written for
        # a PDF crate. Measured 2026-08-19: with these patterns the tree still
        # warns nowhere, and a probe declaring `pub color: String` does warn,
        # which together say they cover the real reasons rather than replacing
        # a blanket skip with a narrower blanket skip.
        #
        # The CSS pattern matches on the VALUE and not on `color:` alone. A
        # Rust field is written `color: String,` and matched the first version
        # of this list, so the probe above stayed silent and the narrowing
        # bought nothing. A CSS value is a hex literal, a function or a bare
        # keyword ending the declaration; a Rust type is neither. The second
        # CSS pattern is there because `html.rs:249` wraps a declaration across
        # two lines, so the value is not on the line the word is on and a
        # line-based check sees `color:` with nothing after it.
        self.external_color_patterns = [
            r'--color-',        # CSS custom property names; renaming breaks the sheet
            r'\bcolor\s*:\s*(#|var\(|rgba?\(|hsla?\(|[a-z-]+\s*;)',  # a CSS declaration
            r'\bcolor\s*:\s*$',  # ... and one whose value wrapped to the next line
            r'"color"',         # the field name Slack and Discord payloads require
            r'\bcolor::',       # an external crate's module path
            r'^\s*use\b',       # ... and the import that brings it in
        ]

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

        # Rule 6, "One Name for the Project". The project unified on
        # `linux-hardener` in issue #51 (641360cb, 2026-08-07) and the old
        # name survives only where it is correct. That rule says in as many
        # words that it "exists so it cannot accumulate again", and until this
        # check nothing enforced it: of the scripts in scripts/validate/, only
        # validate_srcinfo.py reads the name at all, and it compares PKGBUILD
        # against .SRCINFO, so it agrees with itself on whichever name both
        # files happen to carry. The rule was prose with no instrument behind
        # it, which is the state a name accumulates in.
        #
        # Assembled from two halves rather than written out, for the same
        # reason the dash pattern above uses unicode escapes: a check that
        # spells the string it forbids reports its own source.
        self.old_project_name = 'linux-system' + '-hardener'

        # Permanent: packaging migration metadata. Renaming or deleting any of
        # these strands an existing Arch, deb or rpm install on upgrade, so
        # the old name here is load bearing rather than left over. Each
        # pattern admits the migration directives and the comments explaining
        # them, and nothing else, so a `pkgname=`, `Package:` or `Name:` line
        # that regressed to the old name is still an error in these files.
        self.old_name_allowlist: Dict[str, NameExemption] = {
            'packaging/PKGBUILD': NameExemption(
                'provides/conflicts/replaces carry an existing Arch install '
                'across the rename',
                r'^\s*(#|(provides|conflicts|replaces)=)',
            ),
            'packaging/.SRCINFO': NameExemption(
                'generated from PKGBUILD by makepkg --printsrcinfo; the same '
                'three directives',
                r'^\s*(provides|conflicts|replaces)\s*=',
            ),
            'packaging/debian/control': NameExemption(
                'Provides/Replaces/Breaks carry an existing deb install '
                'across the rename',
                r'^\s*(#|(Provides|Replaces|Breaks):)',
            ),
            'packaging/linux-hardener.spec': NameExemption(
                'Obsoletes/Provides carry an existing rpm install across the '
                'rename',
                r'^\s*(#|(Obsoletes|Provides):)',
            ),

            # Permanent: records that are correct about their own moment.
            # Rewriting them would make them wrong, and Rule 6 names this
            # exception itself. Whole-file, because the old name appears in
            # running prose rather than on a shape a pattern could pin.
            'CHANGELOG.md': NameExemption(
                'past entries describe the tree as it was when they were '
                'written',
            ),
            'docs/plans/2026-07-18-docs-and-repo-reorg.md': NameExemption(
                'a superseded plan, kept as the record of what was proposed '
                'and what #51 did instead',
            ),
            'docs/reference/naming-conventions.md': NameExemption(
                'Rule 6 itself, which has to be able to name the old name in '
                'order to forbid it',
            ),

            # Temporary: prose that is accurate only until the AUR
            # resubmission lands, at which point the old package stops being
            # the one to install and every entry below becomes false. The
            # cleanup step in docs/contributing/releasing.md names each of
            # them, because a deferral nothing points at goes stale in
            # silence.
            'README.md': NameExemption(
                'TEMPORARY: names the AUR package to install until the '
                'resubmission lands',
                temporary=True,
            ),
            'docs/guide/installation.md': NameExemption(
                'TEMPORARY: install, upgrade and removal commands against '
                'the old AUR package',
                temporary=True,
            ),
            'docs/guide/upgrading.md': NameExemption(
                'TEMPORARY: explains the rename to an operator upgrading '
                'across it',
                temporary=True,
            ),
            'docs/contributing/releasing.md': NameExemption(
                'TEMPORARY: the one-time AUR resubmission note, including the '
                'not-yet-existing linux-hardener.git remote it will be '
                'pushed to',
                temporary=True,
            ),
            'scripts/test/polkit/test-polkit-matrix.sh': NameExemption(
                'TEMPORARY: operator-facing remedy strings naming the package '
                'that currently ships the policy and the binary',
                temporary=True,
            ),
        }

        # `field_prefixes` used to sit here, mapping six type names to a
        # required struct-field prefix. No method ever read it, so it enforced
        # nothing while reading as a rule this validator applied. Deleted
        # 2026-08-19 rather than implemented. The rule itself is real and is
        # written down in `docs/reference/naming-conventions.md` under Field
        # Names; the tree already follows it, and the one field that does not,
        # `Checkpoint::host_key`, is documented there as an exception. So
        # implementing it would need a struct parser and an exception list to
        # find nothing, and its absence is not what lets a bad field name in.

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

        # Repo-wide scan for the project's pre-#51 name (Rule 6)
        self.check_project_name()

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

                # A file gated in its entirety, rather than a module at the end
                # of one. Note this is checked before the inline forms below:
                # `#![cfg(test)]` does not contain `#[cfg(test)]`, so the inline
                # test would miss it and judge a whole split-out test file as
                # production code, starting with the attribute's own `cfg`.
                if stripped == '#![cfg(test)]':
                    in_test_context = True
                    test_brace_start = brace_depth

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

    def tracked_files(self, scan_name: str) -> List[str]:
        """List every git-tracked path, or an empty list if git is unavailable.

        `git ls-files` and not a filesystem walk, because the tree carries
        ignored build output and vendored dependencies that are not ours to
        judge. Note this is also the only reading that cannot be skewed by a
        shell alias: the interactive `grep` on this machine injects
        `--ignore-files`, so a raw sweep silently answers a different
        question than the one asked.
        """
        try:
            return subprocess.run(
                ['git', 'ls-files', '-z'],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.split('\0')
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"⚠️  {scan_name} skipped (git unavailable): {e}")
            return []

    def check_dashes(self):
        """Flag em-dashes and en-dashes in tracked prose and source files."""
        for rel in self.tracked_files("Dash scan"):
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

    def name_exemption(self, rel: str) -> Optional[NameExemption]:
        """Return the exemption covering a tracked path, or None."""
        if rel in self.old_name_allowlist:
            return self.old_name_allowlist[rel]

        # Archived documents keep the name they were written with. Matched by
        # shape rather than by path, because the archives grow: a new
        # docs/*/archive/ directory would otherwise need a list entry before
        # the document could be filed, and the check would then be refusing a
        # document for being accurate.
        parts = Path(rel).parts
        if parts and parts[0] == 'docs' and 'archive' in parts[1:]:
            return NameExemption(
                'an archived document, accurate about the moment it was '
                'written'
            )
        return None

    def check_project_name(self):
        """Flag the project's pre-#51 name outside the paths where it is correct.

        Rule 6 of docs/reference/naming-conventions.md. Reported as an ERROR
        and not a warning: the rule's stated purpose is that a second name
        "cannot accumulate again", and the warning counts this validator
        prints are non-blocking and drift, so a reappearance raised as a
        warning would be counted, shipped and then normalised. An error is
        also what the exemption list needs to stay honest, since an entry
        nobody is forced to justify is an entry nobody removes.

        Every tracked file is read, not only the suffixes the dash scan
        covers. The name reaches unit files, polkit actions, desktop entries
        and shell scripts, and a suffix list is how a check ends up green
        over the half of the tree it never opened.
        """
        for rel in self.tracked_files("Project name scan"):
            if not rel:
                continue
            exemption = self.name_exemption(rel)
            if exemption and not exemption.line_pattern:
                continue
            path = self.project_root / rel
            try:
                lines = path.read_text(encoding='utf-8').split('\n')
            except (OSError, UnicodeDecodeError):
                continue  # binary or unreadable; no name to read out of it
            for line_num, line in enumerate(lines, start=1):
                if self.old_project_name not in line:
                    continue
                if exemption and re.search(exemption.line_pattern, line):
                    continue
                self.issues.append(ValidationIssue(
                    file_path=path,
                    line_number=line_num,
                    severity=Severity.ERROR,
                    category="Project Name",
                    issue=(
                        f"'{self.old_project_name}' is the pre-#51 project "
                        f"name and this path is not exempt from Rule 6"
                    ),
                    suggestion=(
                        f"Use 'linux-hardener'. This path is exempt only on "
                        f"the lines its pattern admits ({exemption.reason}), "
                        f"and this is not one of them"
                        if exemption else
                        "Use 'linux-hardener'. If the old name is correct "
                        "here, add the path to old_name_allowlist with the "
                        "reason it is"
                    ),
                ))

        # The temporary exemptions announce themselves on every run. A
        # deferral consulted only from inside a failure branch reports nothing
        # while it is being honoured, which is the whole window in which it
        # goes stale; this list is read while the check is passing, which is
        # when somebody can still act on it.
        temporary = sorted(
            rel for rel, exemption in self.old_name_allowlist.items()
            if exemption.temporary
        )
        if temporary:
            print(
                f"ℹ️  {len(temporary)} path(s) carry the old project name "
                f"under a TEMPORARY exemption, cleared by the AUR "
                f"resubmission (see docs/contributing/releasing.md):"
            )
            for rel in temporary:
                print(f"    - {rel}")
            print()

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
                    # Skip 'color' only where the spelling is not ours to choose
                    if american == 'color' and any(
                        re.search(p, line) for p in self.external_color_patterns
                    ):
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
    # Find project root (where Cargo.toml is); this file lives in
    # scripts/validate/, two levels below the root
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent.parent

    if not (project_root / 'Cargo.toml').exists():
        print("❌ Error: Could not find project root (Cargo.toml)")
        sys.exit(1)

    validator = NamingValidator(project_root)
    exit_code = validator.validate_project()
    sys.exit(exit_code)


if __name__ == '__main__':
    main()

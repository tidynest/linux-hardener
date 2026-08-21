# Naming Conventions Reference

**Author**: Eric Jingryd
**Last Updated**: 2026-08-19
**Purpose**: Complete and authoritative naming standards for all identifiers in the project

---

## Table of Contents

1. [Core Principles](#core-principles)
2. [Validator Behaviour](#validator-behaviour)
3. [File and Directory Names](#file-and-directory-names)
4. [Crate Names](#crate-names)
5. [Module Names](#module-names)
6. [Struct Names](#struct-names)
7. [Enum Names](#enum-names)
8. [Trait Names](#trait-names)
9. [Function and Method Names](#function-and-method-names)
10. [Variable Names](#variable-names)
11. [Constant Names](#constant-names)
12. [Type Alias Names](#type-alias-names)
13. [Generic Parameter Names](#generic-parameter-names)
14. [Lifetime Names](#lifetime-names)
15. [Field Names](#field-names)
16. [Test Function Names](#test-function-names)
17. [Documentation File Names](#documentation-file-names)
18. [Examples by Domain](#examples-by-domain)

---

## Core Principles

### 1. Clarity Over Brevity

**ALWAYS prefer descriptive, explicit names over short, ambiguous ones.**

```rust
// ✅ GOOD: Clear and unambiguous
distro_name: String
plugin_id: PluginId
checkpoint_timestamp: u64

// ❌ BAD: Ambiguous, context-dependent
name: String
id: PluginId
timestamp: u64
```

### 2. Descriptive Prefixes

**Use domain prefixes to disambiguate related concepts.**

```rust
// ✅ GOOD: Prefixed for clarity
pub struct Distribution {
    pub distro_family: DistroFamily,
    pub distro_name: String,
    pub distro_version: String,
    pub distro_codename: Option<String>,
}

// ❌ BAD: Ambiguous without context
pub struct Distribution {
    pub family: DistroFamily,
    pub name: String,
    pub version: String,
    pub codename: Option<String>,
}
```

### 3. Alphabetical Ordering

**Use alphabetical ordering where it doesn't interfere with functionality.**

**Always alphabetise:**
- Import statements (`use` declarations)
- Derive trait lists (e.g., `#[derive(Clone, Debug, Deserialize, Serialize)]`)
- Struct fields when order doesn't affect layout/performance
- Module declarations in `lib.rs`

**Never alphabetise when:**
- Order has semantic meaning (e.g., `Severity` enum: `Info < Low < Medium < High < Critical`)
- Derive order matters for functionality (e.g., `Error` before `Debug` in thiserror)
- Performance/memory layout is affected

### 4. British English Only

**All names, comments, documentation, and user-facing text MUST use British English.**

```rust
// ✅ GOOD: British spelling
pub fn authorise_user() -> Result<()> { }
pub struct ColourScheme { }

// ❌ BAD: American spelling
pub fn authorize_user() -> Result<()> { }
pub struct ColorScheme { }
```

**Exception: verbatim external wording.** Text quoted directly from an external
source keeps that source's spelling, even when American. This covers official
compliance control titles (e.g. NIST SP 800-53 AC-6(1) *"Authorize Access to
Security Functions"*) and external crate APIs (`printpdf`, `Color::`). These are
proper nouns, not our own prose, so `scripts/validate/validate_naming.py` allowlists them.

### 5. No Em-Dashes or En-Dashes

**Em-dashes and en-dashes are forbidden project-wide** (they read as an AI tell).
Use a comma, colon, parentheses, or a plain hyphen instead. This applies to all
tracked prose and source; `scripts/validate/validate_naming.py` scans every
tracked file (`.md`, `.rs`, `.toml`, `.py`, `.sh`, `.txt`, `.yml`, `.yaml`,
`.json`) and reports any em-dash or en-dash as an error.

### 6. One Name for the Project

**The project is `linux-hardener`, written "Linux Hardener".** One slug and one
display name, in the repository, the AUR/deb/rpm package, the runtime paths
(`/etc/linux-hardener`, `/var/lib/linux-hardener`, `/var/log/linux-hardener`,
`~/.config/linux-hardener`), the systemd units, the polkit actions, the desktop
entry and every document.

It was two names until #51: the product, repository and package were
`linux-system-hardener` while everything an operator's host actually held was
`linux-hardener`. Nobody chose that split, it accumulated, and this rule exists
so it cannot accumulate again.

Two deliberate exceptions, both narrower than the project name rather than a
second name for it:

- **`hardener` is the CLI binary**, installed to `/usr/bin/hardener`, and
  `hardener-` is the crate prefix. Shortening the command an operator types is
  a separate breaking change with its own deprecation window, and it is not
  taken. The same shortening appears in file names this tool writes into other
  packages' directories, `00-hardener.conf` and `99-hardener.conf`, where the
  full name would only add length.
- **Archived documents keep the name they were written with.** `docs/*/archive/`
  and past `CHANGELOG.md` entries are accurate about their own moment, and
  rewriting them would make them wrong.

---

## Validator Behaviour

`scripts/validate/validate_naming.py` is the executable half of this document.
It reads every `.rs` file under `crates/` (skipping `build.rs` and any path
containing `target`), and for the dash scan it reads every git-tracked file with
a `.md`, `.rs`, `.toml`, `.py`, `.sh`, `.txt`, `.yml`, `.yaml` or `.json`
suffix. The Rule 6 project-name scan reads every git-tracked file whatever its
suffix, because the name reaches `.desktop`, `.policy` and `.service` files that
carry no extension the other scans list. Only the declaration checks are
confined to `crates/`.

### Errors, which fail the run

Only these return a non-zero exit code:

- A `pub struct`, `pub enum` or `pub trait` whose name is not `PascalCase`
- A function whose name is not `snake_case`, or a function directly under
  `#[component]` whose name is not `PascalCase`
- A `const` whose name is not `SCREAMING_SNAKE_CASE`
- An em-dash or en-dash in a tracked file, including the two written as Rust
  unicode escapes rather than as the glyph
- The pre-#51 project name in a tracked file that no entry of
  `old_name_allowlist` exempts, which is the check behind Rule 6. Four packaging
  files are exempt only on the lines carrying `provides`, `conflicts`,
  `replaces` and their rpm and deb equivalents, so a `pkgname=` or `Name:`
  regression in those same files is still an error. Five further paths are
  exempt only until the AUR resubmission lands, and the validator names them on
  every run, passing or failing, so the list cannot go stale unobserved.

The declaration checks are line based and anchored to the start of the declaring
line, so a name is judged where it is written and never where it is used, and
the exact spelling of the declaration decides whether it is judged at all. A
private `struct`, `enum` or `trait` is not checked, because the pattern requires
the leading `pub`; a `pub const` is not checked, because that pattern requires
`const` first. Functions are checked as `fn`, `pub fn`, `async fn` and
`pub async fn`. Widening any of those patterns will surface names that have
never been checked, so treat a sudden crop of errors as new coverage rather than
as new code.

### Warnings, which never fail the run

- **Abbreviations.** Always flagged: `mgr`, `msg`, `dist`, `param`, `res`,
  `val`, `pkg`, `auth`, `perms`. Flagged only outside an allowlisted context:
  `ctx`, `cfg`, `cmd`, `distro` (the contexts are listed under
  [Crate Names](#crate-names)). The match is a whole word and case insensitive,
  so `param_name` passes while `param:` does not, and `/etc/pam.d/password-auth`
  reads as the word `auth`.
- **American spellings**: `authorize`, `organization`, `initialize`,
  `serialize`, `finalize`, less the verbatim-external exceptions in Core
  Principle 4. **`color` is in the validator's list but can never warn**: the
  external-crate branch returns before the issue is recorded, unconditionally
  (`validate_naming.py`, `check_british_english`), not only on a `printpdf::`,
  `Rgb::` or `Color::` line. Nothing else on this list is exempt that way:
  `serialize` is waived only inside a `derive`, a `serde(` line or beside the
  capitalised trait name.

Both word checks match whole words, so Core Principle 4's own bad example,
`pub struct ColorScheme`, is out of reach twice over: `\bcolor\b` does not match
inside `ColorScheme` at all, and the unconditional exemption above would drop it
even if it did. The same boundary rule is why `authorize_user` passes while a
bare `authorize` warns. Compound identifiers built on an American stem are
enforced by review alone.
- **A trait name ending in `Trait`.**

Both word checks read the whole line, not just the identifier, so a trailing
comment on a code line is scanned. A line that opens with `//` or `/*` is
skipped entirely.

### How test context is decided

The scanner walks each file line by line, keeps a running brace depth, and
enters test context at `#![cfg(test)]`, `#[cfg(test)]`, `#[test]`,
`#[tokio::test]` or a line containing `mod test` (which is a substring of
`mod tests`, so both forms trigger), recording the brace depth at that point.
The inner `#![cfg(test)]` is checked first and on purpose: it is how a test
module split out into its own file is gated, and it does not contain the string
`#[cfg(test)]`, so testing only for the outer form would read such a file as
production code from its first line. It leaves test
context when the depth falls back below that mark. Each warning is then counted
as production or test.

Two consequences are worth knowing before reading a count:

- An inline `#[cfg(test)] mod tests { ... }` behaves as expected: the mark is
  taken inside the module, and the module's closing brace ends the context.
- A file under `tests/` is not test context by virtue of its path. Context
  starts at the first test attribute in the file, so a fixture helper written
  above it counts as production. That is why several production warnings point
  into `crates/hardener-plugins/tests/`. Because that mark is taken at file
  scope, where the depth is zero, it can never be fallen below, so everything
  after the first test attribute in such a file is counted as test.

### The warning count is known noise

Measured 2026-08-16 on a clean tree: **0 errors, 122 production warnings, 212
test warnings.** Every one of them is an abbreviation; there were no British
English warnings at that measurement. The previous reading here, 108 and 192 on
2026-08-02, is what a fortnight of drift looks like, which is the point of the
next paragraph: the totals move, so a stale one read as current invents a
regression that is not there.

They are pre-existing names, plus, in the `auth` group, the PAM configuration
filenames `system-auth`, `password-auth` and `common-auth`. Those are filenames
the distributions ship rather than names anyone here chose, and renaming them
would break the tool. **Never "fix" a warning by renaming.**

Read the count as a delta and never as a total: what a change has to show is
that it added none. A decrease needs no justification.

---

## File and Directory Names

### Rust Source Files

**Format**: `snake_case.rs`

**Rules**:
- All lowercase
- Words separated by underscores
- Descriptive of module contents
- Singular for single-concept modules
- Plural for collection modules

**Examples**:
```
✅ GOOD:
mod.rs              # Module root
lib.rs              # Crate root
plugin.rs           # Single concept (the Plugin trait)
plugin_manager.rs   # Single manager type
checkpoint.rs       # Checkpoint types
hash_chain.rs       # Hash chain implementation
common_types.rs     # Collection of related types

❌ BAD:
Plugin.rs           # Wrong case (CamelCase)
pluginManager.rs    # Wrong case (camelCase)
checkpoint-impl.rs  # Wrong separator (hyphen)
hashchain.rs        # Missing underscore
```

### Directory Names

**Format**: `snake_case` or `kebab-case`

**Rules for crates**: `kebab-case` (Cargo convention)
**Rules for modules**: `snake_case` (Rust convention)

**Examples**:
```
✅ GOOD:
crates/hardener-core/       # Crate (kebab-case)
crates/hardener-plugins/    # Crate (kebab-case)
src/package/               # Module directory (snake_case)
tests/common/              # Test utilities (snake_case)
docs/                      # Documentation directory

❌ BAD:
crates/hardener_core/      # Should be kebab-case for crate
src/packageManager/        # Should be snake_case
tests/testUtils/           # Wrong case
```

### Test Files

**Format**: `<module_name>_tests.rs` or `test_<feature>.rs`

**Examples**:
```
✅ GOOD:
tests/kernel_tests.rs
tests/ssh_tests.rs
tests/plugin_manager_tests.rs
tests/checkpoint_system.rs

❌ BAD:
tests/kernel.rs            # Ambiguous (test file or regular module?)
tests/testKernel.rs        # Wrong case
tests/kernel-tests.rs      # Wrong separator
```

---

## Crate Names

**Format**: `kebab-case`

**Rules**:
- All lowercase
- Words separated by hyphens
- Descriptive of crate purpose
- Prefix with project name for workspace crates

**Project Crates**:
```
hardener-types          # WASM-compatible shared type definitions
hardener-core           # Core engine and traits
hardener-common         # Shared utilities and error types
hardener-distro         # Distribution detection and adaptation
hardener-plugins        # Security plugin implementations
hardener-state          # State management (checkpoints, audit)
hardener-compliance     # Compliance framework mapping (pdf feature)
hardener-scheduler      # Scheduled scanning daemon
hardener-cli            # Command-line interface
hardener-ui             # Leptos WASM frontend
linux-hardener-desktop  # Tauri v2 desktop application (src-tauri)
```

**Permitted Abbreviations**: The following short names are exceptions to the
"no abbreviations" rule because they are idiomatic in Rust and used consistently
throughout the codebase:

- `ctx` -- Standard name for the `Context` parameter passed to all plugin trait methods
- `cfg` -- Used in `#[cfg()]` attributes (Rust built-in conditional compilation)
- `cmd` -- Common in CLI and executor contexts (e.g. `execute_command`, `firewall_cmd`)
- `distro` -- Domain term for a Linux distribution (e.g. `distro_name`, `DistroFamily`, `hardener-distro`)

The exemption is per line and per context, not per word. `scripts/validate/validate_naming.py`
waives one of these four only where the line also matches its allowlist: `#[cfg(`,
`#![cfg(` or `cfg!` for `cfg`; a `ctx` parameter, binding or field access for `ctx`;
`execute_command`, `CommandOutput`, `firewall_cmd` or a `cmd` binding for `cmd`;
`distro_`, `DistroFamily` or `hardener-distro` for `distro`. The same word
elsewhere still warns, which is most of the noise described under
[Validator Behaviour](#validator-behaviour). Every other abbreviation, including
`dist`, `param`, `mgr` and `auth`, warns wherever it appears.

---

## Module Names

**Format**: `snake_case`

**Rules**:
- All lowercase
- Words separated by underscores
- Descriptive of module contents
- Singular for single-concept modules

**Examples**:
```rust
// ✅ GOOD:
pub mod plugin;
pub mod plugin_manager;
pub mod checkpoint;
pub mod hash_chain;
pub mod audit;

// ❌ BAD:
pub mod Plugin;           // Wrong case
pub mod pluginManager;    // Wrong case (camelCase)
pub mod checkpoint_mgr;   // Abbreviation (use full words)
```

---

## Struct Names

**Format**: `PascalCase`

**Rules**:
- Each word capitalised
- No underscores or hyphens
- Descriptive, explicit nouns
- Avoid abbreviations

**General Structs**:
```rust
// ✅ GOOD:
pub struct Distribution { }
pub struct PluginMetadata { }
pub struct CheckpointManager { }
pub struct AuditLogger { }
pub struct ScanResult { }

// ❌ BAD:
pub struct dist { }           // Wrong case, abbreviation
pub struct PluginMD { }       // Abbreviation
pub struct checkpoint_mgr { } // Wrong case
pub struct AuditLog { }       // Ambiguous (logger or entry?)
```

**Plugin Structs**:
```rust
// Pattern: <Domain>HardeningPlugin (standardised as of 2025-11-24)

// ✅ GOOD (All 8 implemented plugins follow this pattern):
pub struct KernelHardeningPlugin { }
pub struct SshHardeningPlugin { }
pub struct FirewallHardeningPlugin { }
pub struct PamHardeningPlugin { }
pub struct ServicesHardeningPlugin { }
pub struct AuditHardeningPlugin { }
pub struct PermissionsHardeningPlugin { }
pub struct MacHardeningPlugin { }

// ❌ BAD:
pub struct KernelPlugin { }      // Missing "Hardening" suffix
pub struct SSH_Plugin { }        // Wrong case
pub struct FirewallHardener { }  // Wrong suffix (use "HardeningPlugin")
pub struct ServicesPlugin { }    // Missing "Hardening" (inconsistent)
```

**Plugin IDs** (Corresponding to Plugin Structs):
```rust
// Pattern: "<domain>-hardening" or "<domain>-<function>" (kebab-case)

// ✅ GOOD (All 8 implemented plugin IDs):
PluginId::new("kernel-hardening")
PluginId::new("ssh-hardening")
PluginId::new("firewall-hardening")
PluginId::new("pam-hardening")
PluginId::new("service-minimisation")  // British spelling, descriptive function
PluginId::new("audit-hardening")
PluginId::new("permissions-hardening")
PluginId::new("mac-hardening")

// ❌ BAD:
PluginId::new("kernel")           // Too generic, missing suffix
PluginId::new("ssh")              // Too generic, could mean many things
PluginId::new("audit")            // Ambiguous: audit logging or audit hardening?
PluginId::new("mac")              // Ambiguous: MAC addresses or Mandatory Access Control?
PluginId::new("service_hardening") // Wrong case (use kebab-case, not snake_case)
```

**Rationale for Plugin ID Suffixes**:
- Descriptive suffixes prevent ambiguity and make plugin purpose immediately clear
- `"audit"` alone could mean audit logging or audit rule hardening
- `"mac"` alone could refer to MAC addresses (network) or Mandatory Access Control (security)
- Hyphenated suffixes follow kebab-case convention for identifiers
- All 8 plugin IDs use the `-hardening` suffix except `service-minimisation`, which is the sole exception: it uses British spelling and describes the specific function rather than appending `-hardening`

**Backend/Adapter Structs**:
```rust
// Pattern: <Technology><Type>

// ✅ GOOD (Firewall Backends):
pub struct FirewalldBackend { }
pub struct UfwBackend { }
pub struct NftablesBackend { }

// ❌ BAD:
pub struct AptManager { }        // Ambiguous (what does it manage?)
pub struct Ufw { }               // Too short, unclear purpose
pub struct NftablesFirewall { }  // Redundant (backend implies firewall context)
pub struct Firewalld { }         // Missing Backend suffix (inconsistent)
```

The firewall backends are the only implementations of this pattern in the tree.
A matching set of package managers (`AptPackageManager`, `DnfPackageManager`,
`PacmanPackageManager`, `ZypperPackageManager`) was listed here until it was
found to be unreferenced and deleted in `3e22d29e` on 2026-08-07. The pattern
still governs any `<Technology><Type>` adapter added later; there simply is no
second family of them today.

**Result/Data Structs**:
```rust
// Pattern: Descriptive noun

// ✅ GOOD:
pub struct ScanResult { }
pub struct ApplyResult { }
pub struct ValidationReport { }
pub struct Finding { }
pub struct Change { }
pub struct Rule { }              // Firewall rule (domain-specific)

// ❌ BAD:
pub struct ScanRes { }           // Abbreviation
pub struct ApplyOutput { }       // Inconsistent with Result pattern
pub struct ValidationResults { } // Plural (struct represents single report)
pub struct FirewallRule { }      // Redundant prefix (context clear from module)
```

---

## Enum Names

**Format**: `PascalCase` for enum name, `PascalCase` for variants

**Rules**:
- Enum name: Descriptive noun
- Variants: Clear, unambiguous identifiers
- Avoid redundant prefixes (enum name already provides context)

**Examples**:
```rust
// ✅ GOOD:
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

pub enum FindingCategory {
    Audit,
    Authentication,
    Cryptography,
    FileSystem,
    Kernel,
    MandatoryAccessControl,
    Network,
    Services,
}

pub enum DistroFamily {
    Debian,
    RedHat,
    Arch,
    Suse,
}

pub enum ActionType {
    Scan,
    Apply,
    Rollback,
    ConfigChange,
    CheckpointCreate,
    CheckpointDelete,
    ScopeExclusion,
}

// ❌ BAD:
pub enum Severity {
    severity_info,    // Wrong case, redundant prefix
    SeverityLow,      // Redundant prefix
    MEDIUM,           // Wrong case
}

pub enum FindingCat {     // Abbreviation
    Kern,                 // Abbreviation
    Net,                  // Abbreviation
}
```

**Error Enums**:
```rust
// Pattern: <Domain>Error

// ✅ GOOD:
#[derive(Error, Debug)]
pub enum HardeningError {
    #[error("Insufficient privileges: {0}")]
    Privilege(String),

    #[error("Distribution not supported: {0}")]
    UnsupportedDistro(String),

    #[error("Plugin error: {0}")]
    Plugin(String),
}

// ❌ BAD:
pub enum Error {              // Too generic
    Priv(String),             // Abbreviation
    UnsupportedDist(String),  // Abbreviation
    NoPlugin(String),         // Inconsistent naming
}
```

---

## Trait Names

**Format**: `PascalCase`

**Rules**:
- Descriptive noun or adjective
- Should indicate capability or behaviour
- Avoid redundant suffixes like "Trait"

**Core Traits**:
```rust
// ✅ GOOD (every trait the workspace declares):
pub trait HardeningPlugin { }
pub trait FirewallBackend { }       // Firewall backend abstraction
pub trait SystemExecutor { }        // Local or SSH command execution
pub trait ReportFormatter { }       // One compliance output format
pub trait Notifier { }              // One scheduler notification channel

// ❌ BAD:
pub trait HardeningPluginTrait { }  // Redundant "Trait" suffix
pub trait PkgMgr { }                // Abbreviation
pub trait Firewall { }              // Too generic (is it a backend? a manager?)
pub trait FirewallManager { }       // Inconsistent (use Backend for implementation abstraction)
```

---

## Function and Method Names

**Format**: `snake_case`

**Rules**:
- All lowercase
- Words separated by underscores
- Verb-first for actions
- Descriptive, clear purpose
- No abbreviations

**Constructor Methods**:
```rust
// Pattern: new() returns explicit type

// ✅ GOOD:
impl KernelHardeningPlugin {
    pub fn new() -> KernelHardeningPlugin {
        Self
    }
}

impl CheckpointManager {
    pub fn new(db_pool: SqlitePool) -> Result<CheckpointManager> {
        // Explicit in the return position, not Result<Self>
    }
}

// ❌ ACCEPTABLE BUT LESS PREFERRED:
impl KernelHardeningPlugin {
    pub fn new() -> Self {  // Using Self is acceptable but less searchable
        Self
    }
}
```

**Query/Getter Methods**:
```rust
// Pattern: get_<noun> or is_<adjective> or has_<noun>

// ✅ GOOD:
pub fn get_plugin_config(&self, plugin_id: &str) -> &PluginConfig { }
pub fn is_plugin_enabled(&self, plugin_id: &str) -> bool { }
pub fn has_valid_exception(&self, key: &str) -> Option<&PolicyException> { }
pub fn system_info(&self) -> &SystemInfo { }

// ❌ BAD:
pub fn dist() -> Result<Distribution> { }      // Abbreviation
pub fn enabled() -> bool { }                    // Ambiguous (getter or setter?)
pub fn check_dep(&self, id: &PluginId) -> bool { }  // Abbreviation
```

**Setter/Modifier Methods**:
```rust
// Pattern: set_<noun> or update_<noun> or apply_<noun>

// ✅ GOOD:
pub fn set_checkpoint_manager(&mut self, checkpoint_manager: CheckpointManager) { }
pub fn update_file_atomically(path: &Path, content: &str) -> Result<()> { }
async fn apply_rules(&self, ctx: &Context, rules: &[Rule]) -> Result<Vec<Change>> { }

// ❌ BAD:
pub fn severity(&mut self, s: Severity) { }        // Ambiguous (getter or setter?)
pub fn checkpoint(&mut self, cp: &Checkpoint) { }  // Unclear action
pub fn sysctl(&self, p: &str, v: &str) { }        // Unclear action, abbreviations
```

**Action Methods (from Plugin Trait)**:
```rust
// Pattern: verb describing action

// ✅ GOOD (Plugin trait methods):
async fn scan(&self, ctx: &Context, config: &PluginConfig) -> Result<ScanResult> { }
async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> { }
async fn reload_after_rollback(&self, ctx: &Context) -> Result<Option<String>> { }
async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> { }

// ✅ GOOD (Supporting methods):
pub async fn validate_sshd_config(executor: &dyn SystemExecutor, candidate: &str) -> Result<()> { }
pub fn select_algorithms(desired: &[&str], supported: &[String]) -> Vec<String> { }
pub async fn create_checkpoint(&self, executor: &dyn SystemExecutor, checkpoint_name: &str,
                               file_paths: &[&Path]) -> Result<CheckpointId> { }

// ❌ BAD:
fn do_scan(&self) { }              // Redundant "do_"
fn apply_changes(&self) { }        // Too generic (apply what?)
fn read_param(p: &str) { }         // Abbreviation, unclear domain
fn parse_directive(c: &str) { }    // Missing context (parse what kind of directive?)
```

**Helper/Internal Methods**:
```rust
// Pattern: descriptive verb_noun combination

// ✅ GOOD:
pub fn execute_command(command: &str, args: &[&str]) -> Result<String> { }
pub fn from_os_release(content: &str) -> Result<Distribution> { }
fn generate_checkpoint_id() -> CheckpointId { }
pub async fn verify_checkpoint(&self, checkpoint_id: &CheckpointId) -> Result<()> { }

// ✅ GOOD (Domain-specific helpers):
async fn execute_firewall_cmd(&self, ctx: &Context, args: &[&str]) -> Result<String> { }
fn build_nft_rule_args(&self, rule: &Rule) -> Vec<String> { }
fn parse_input_chain_rules(chain_output: &str) -> Vec<Vec<String>> { }
async fn get_default_zone(&self, ctx: &Context) -> Result<String> { }
pub fn get_baseline_rules() -> Vec<Rule> { }

// ❌ BAD:
fn exec_cmd(cmd: &str) { }         // Abbreviation
fn parse_content(c: &str) { }      // Too generic
fn gen_id() { }                    // Abbreviation
fn verify(d: &[u8], s: &[u8]) { }  // Abbreviation, unclear
fn parse_rule(l: &str) { }         // Missing context (what kind of rule?)
fn get_rules() { }                 // Too generic (which rules? where from?)
```

---

## Variable Names

**Format**: `snake_case`

**Rules**:
- All lowercase
- Words separated by underscores
- Descriptive, context-aware
- Use domain prefixes when helpful
- Avoid single-letter names except in very short scopes (loops, closures)

**Local Variables**:
```rust
// ✅ GOOD:
let plugin_id = PluginId::new("kernel");
let checkpoint_manager = CheckpointManager::new(pool);
let scan_result = plugin.scan(&context)?;
let distro_name = distribution.distro_name.clone();

// ❌ BAD:
let id = PluginId::new("kernel");           // Too generic
let mgr = CheckpointManager::new(pool);     // Abbreviation
let result = plugin.scan(&context)?;        // Too generic
let name = distribution.distro_name.clone(); // Ambiguous
```

**Loop Variables**:
```rust
// ✅ GOOD (descriptive even in short scope):
for plugin in plugins {
    println!("{}", plugin.metadata().name);
}

for (param_name, param_value) in sysctl_params {
    apply_sysctl(param_name, param_value)?;
}

// ✅ ACCEPTABLE (very short scope):
for i in 0..10 {
    println!("{}", i);
}

// ❌ BAD:
for p in plugins {              // Too short, unclear
    println!("{}", p.metadata().name);
}
```

**Function Parameters**:
```rust
// ✅ GOOD:
pub fn set_config_directive(content: &str, directive_name: &str, value: &str,
                            format: ConfigFormat, case_sensitive: bool,
                            duplicates: Duplicates) -> String { }
pub async fn validate_sshd_config(executor: &dyn SystemExecutor, candidate: &str) -> Result<()> { }
pub fn select_algorithms(desired: &[&str], supported: &[String]) -> Vec<String> { }

// ❌ BAD:
pub fn set_config_directive(c: &str, d: &str, v: &str, f: ConfigFormat) -> String { }  // Abbreviations
pub async fn validate_sshd_config(executor: &dyn SystemExecutor, config: &str) -> Result<()> { }
                                  // Ambiguous: the running config, or the one being proposed?
pub fn select_algorithms(a: &[&str], b: &[String]) -> Vec<String> { }                  // Meaningless
```

---

## Constant Names

**Format**: `SCREAMING_SNAKE_CASE`

**Rules**:
- All uppercase
- Words separated by underscores
- Descriptive, explicit
- Use domain prefixes for clarity

**Examples**:
```rust
// ✅ GOOD:
const KERNEL_PARAMS: &[KernelParameter] = &[
    KernelParameter {
        kernel_parameter_name: "kernel.randomize_va_space",
        kernel_secure_value: "2",
        kernel_description: "Enable full address space layout randomisation (ASLR)",
        kernel_severity: Severity::High,
        kernel_compare: Strictness::AtLeast,
    },
];

const SSH_DIRECTIVES: &[SshConfigDirective] = &[
    SshConfigDirective {
        ssh_directive_name: "PermitRootLogin",
        ssh_secure_value: "no",
        ssh_description: "Disable direct root login via SSH",
        ssh_severity: Severity::Critical,
        ssh_compare: Strictness::Ranked(PERMIT_ROOT_LOGIN_ORDER),
    },
];

const SSHD_ADMIN_CONFIG_PATH: &str = "/etc/ssh/sshd_config";
const SSHD_DROPIN_DIR: &str = "/etc/ssh/sshd_config.d";

const SYSCTL_DROPIN_DIR: &str = "/etc/sysctl.d";
const SYSCTL_HARDENER_CONF: &str = "/etc/sysctl.d/99-hardener.conf";

const ADMIN_UNIT_DIR: &str = "/etc/systemd/system";
const MAX_INCLUDE_DEPTH: usize = 16;

// ❌ BAD:
const PARAMS: &[KernelParameter] = &[];        // Too generic
const DIRECTIVES: &[SshConfigDirective] = &[];  // Missing domain prefix
const DB_PATH: &str = "/var/lib/...";          // Abbreviation
const MAX_AGE: u64 = 90;                       // Too generic
const CFG_PATH: &str = "/etc/ssh/sshd_config"; // Abbreviation
```

---

## Type Alias Names

**Format**: `PascalCase`

**Rules**:
- Same as struct names
- Descriptive of the aliased type
- Avoid redundant "Type" suffix

**Examples**:
```rust
// ✅ GOOD:
pub type Result<T> = std::result::Result<T, HardeningError>;
pub type SeverityTuple = (i64, i64, i64, i64, i64);  // Per-severity counts, scheduler db

// ❌ BAD:
pub type Res<T> = std::result::Result<T, HardeningError>;  // Abbreviation
pub type ResultType<T> = std::result::Result<T, HardeningError>;  // Redundant suffix
```

---

## Generic Parameter Names

**Format**: Single uppercase letter or descriptive `PascalCase`

**Rules**:
- Use `T` for single generic type
- Use descriptive names for multiple or domain-specific generics
- Common conventions: `T`, `E`, `K`, `V`

**Examples**:
```rust
// ✅ GOOD (single generic):
pub struct Container<T> {
    value: T,
}

// ✅ GOOD (multiple generics):
pub struct Mapping<K, V> {
    key: K,
    value: V,
}

// ✅ GOOD (descriptive generics for clarity):
pub trait Adapter<Distribution, Backend> {
    fn adapt(&self, distro: Distribution) -> Backend;
}

// ❌ BAD:
pub struct Container<TYPE> {    // All caps (use T or Type)
    value: TYPE,
}
```

---

## Lifetime Names

**Format**: `'lowercase` (single lowercase letter or descriptive word)

**Rules**:
- Use `'a` for single lifetime
- Use descriptive names for multiple lifetimes
- Common conventions: `'a`, `'b`, `'c`

**Examples**:
```rust
// ✅ GOOD (single lifetime):
pub struct Context<'a> {
    config: &'a PluginConfig,
}

// ✅ GOOD (multiple lifetimes):
pub fn compare<'a, 'b>(first: &'a str, second: &'b str) -> bool {
    first == second
}

// ✅ GOOD (descriptive lifetime):
pub struct Parser<'input> {
    source: &'input str,
}

// ❌ BAD:
pub struct Context<'A> {        // Should be lowercase
    config: &'A PluginConfig,
}
```

---

## Field Names

**Format**: `snake_case`

**Rules**:
- All lowercase
- Words separated by underscores
- **ALWAYS use descriptive prefixes** for clarity
- Avoid ambiguous short names

**Struct Fields with Prefixes**:
```rust
// ✅ GOOD: Clear, prefixed field names
pub struct Distribution {
    pub distro_family: DistroFamily,
    pub distro_name: String,
    pub distro_version: String,
    pub distro_codename: Option<String>,
}

pub struct PluginMetadata {
    pub plugin_id: PluginId,
    pub plugin_name: String,
    pub plugin_version: String,
    pub plugin_description: String,
    pub plugin_category: FindingCategory,
}

pub struct Checkpoint {
    pub checkpoint_id: CheckpointId,
    pub checkpoint_name: String,
    pub checkpoint_timestamp: i64,
    pub checkpoint_username: String,
    pub checkpoint_signature: Vec<u8>,
    pub host_key: String,
}

pub struct ScanResult {
    pub scan_plugin_id: PluginId,
    pub scan_success: bool,
    pub scan_findings: Vec<Finding>,
    pub scan_unchecked: Vec<UncheckedCheck>,
    pub scan_duration_us: u64,
    pub scan_error: Option<String>,
}

// ❌ BAD: Ambiguous field names without prefixes
pub struct Distribution {
    pub family: DistroFamily,     // Ambiguous: family of what?
    pub name: String,              // Ambiguous: name of what?
    pub version: String,           // Ambiguous: version of what?
    pub codename: Option<String>,  // Less clear
}
```

`Checkpoint::host_key` is the one unprefixed field in that group. It records
which host the checkpoint was captured from ("local", or an SSH target). Under
the prefix rule it would be `checkpoint_host_key`; it is listed here as the code
spells it, not as the rule would have it.

**This rule is convention, not gate.** `validate_naming.py` checks case,
abbreviations and British spelling; it has never checked field prefixes. It
carried a `field_prefixes` table naming six of these types until 2026-08-19,
which no method read, so the table enforced nothing while reading like
enforcement. It was deleted rather than implemented: the tree already follows
the rule, with the one exception above, so a struct parser and an exception
list would find nothing today. A new field that breaks it is caught in review
or not at all.

**Result/Data Struct Fields**:
```rust
// ✅ GOOD:
pub struct Finding {
    pub finding_id: String,
    pub finding_severity: Severity,
    pub finding_category: FindingCategory,
    pub finding_title: String,
    pub finding_description: String,
    pub finding_current_value: String,
    pub finding_recommended_value: String,
    pub finding_explanation: String,
    pub finding_impact: String,
    pub finding_remediation_steps: Vec<String>,
    pub finding_compliance: Vec<ComplianceMapping>,
    pub finding_exception: ExceptionOutcome,
    pub finding_exception_key: Option<String>,
}

pub struct ApplyResult {
    pub apply_plugin_id: PluginId,
    pub apply_success: bool,
    pub apply_changes: Vec<Change>,
    pub apply_checkpoint_id: Option<String>,
    pub apply_error: Option<String>,
}

pub struct Rule {
    pub rule_description: String,
    pub rule_protocol: String,
    pub rule_port: String,
    pub rule_source: String,
    pub rule_action: String,
}

struct SshConfigDirective {
    ssh_description: &'static str,
    ssh_directive_name: &'static str,
    ssh_secure_value: &'static str,
    ssh_severity: Severity,
    ssh_compare: Strictness,
}

// ❌ BAD:
pub struct Finding {
    pub id: String,                // Too generic
    pub cat: FindingCategory,      // Abbreviation
    pub cur_val: String,           // Abbreviation
    pub rec_val: String,           // Abbreviation
}

pub struct Rule {
    pub description: String,       // Too generic (what kind of finding_description?)
    pub protocol: String,          // Missing rule_ prefix
    pub port: String,              // Missing rule_ prefix
}
```

---

## Test Function Names

**Format**: `test_<what_is_being_tested>`

**Rules**:
- Always prefix with `test_`
- Descriptive of what is being tested
- Use underscores to separate logical parts
- Should read like a sentence when the `test_` prefix is removed

**Unit Tests**:
```rust
// ✅ GOOD:
#[test]
fn test_distribution_detection() { }

#[test]
fn test_kernel_key_accepts_valid_sysctl_names() { }

#[test]
fn test_hash_chain_verification() { }

#[test]
fn test_change_type_display() { }

// ❌ BAD:
#[test]
fn test_distro() { }                           // Too vague
fn distribution_detection() { }                 // Missing test_ prefix
#[test]
fn test_DistributionDetection() { }             // Wrong case
#[test]
fn test_det_dist() { }                          // Abbreviations
```

**Integration Tests**:
```rust
// ✅ GOOD:
#[tokio::test]
async fn test_rollback_restores_files() { }

#[tokio::test]
async fn test_checkpoint_captures_and_restores_directory_permissions() { }

#[test]
fn test_dependency_resolution_valid_chain() { }

#[test]
fn test_kernel_plugin_metadata() { }

#[tokio::test]
async fn test_ssh_scan_reads_configuration() { }

// ❌ BAD:
#[tokio::test]
async fn test_workflow() { }                    // Too vague
#[test]
fn test_metadata() { }                          // Missing context
#[test]
fn kernel_test() { }                            // Wrong format
```

**Tests Requiring Root/Special Conditions**:
```rust
// Pattern: Mark with #[ignore] and descriptive name

// ✅ GOOD:
#[test]
#[ignore]  // Requires root privileges
fn test_kernel_apply_requires_root() { }

#[test]
#[ignore]  // Requires root privileges
fn test_ssh_apply_requires_root() { }

// ❌ BAD:
#[test]
#[ignore]
fn test_apply() { }                             // Too generic
```

---

## Documentation File Names

**Format**: `SCREAMING_SNAKE_CASE.md` at the repository root and at the top of
`docs/`, `kebab-case.md` inside the `docs/` subdirectories

**Project Documentation**:
```
✅ GOOD:
README.md                              # Repository root, uppercase
LICENSE
CONTRIBUTING.md
CHANGELOG.md
SECURITY.md
docs/README.md                         # Top of docs/, uppercase
docs/ROADMAP.md
docs/reference/naming-conventions.md   # Inside docs/, kebab-case
docs/guide/getting-started.md
docs/architecture/architecture.md

❌ BAD:
docs/reference/NamingConventions.md    # Wrong case (PascalCase)
docs/reference/naming_conventions.md   # Wrong separator (use a hyphen)
docs/guide/GettingStarted.md           # Wrong case
readme.md                              # Root documents are uppercase
```

---

## Examples by Domain

### Distribution Detection Domain

```rust
// Struct:
pub struct Distribution {
    pub distro_family: DistroFamily,
    pub distro_name: String,
    pub distro_version: String,
    pub distro_codename: Option<String>,
}

// Enum:
pub enum DistroFamily {
    Debian,
    RedHat,
    Arch,
    Suse,
}

// Methods (hardener-distro::Distribution):
pub fn detect() -> Result<Distribution> { }
pub fn from_os_release(content: &str) -> Result<Distribution> { }
pub fn version_major(&self) -> Option<u32> { }
fn extract_field(data: &HashMap<String, String>, field_name: &str) -> Result<String> { }
fn map_to_family(distro_id: &str) -> Result<DistroFamily> { }

// Methods (hardener-core::SystemInfo, which reads the same file for itself):
fn read_os_release() -> Result<HashMap<String, String>> { }
fn detect_distribution() -> Result<String> { }
```

Neither reader holds its path in a constant: `/etc/os-release` is written at the
two call sites.

### Plugin Domain

```rust
// Trait:
pub trait HardeningPlugin { }

// Structs (All 8 follow standardised pattern):
pub struct KernelHardeningPlugin { }
pub struct SshHardeningPlugin { }
pub struct FirewallHardeningPlugin { }
pub struct PamHardeningPlugin { }
pub struct ServicesHardeningPlugin { }
pub struct AuditHardeningPlugin { }
pub struct PermissionsHardeningPlugin { }
pub struct MacHardeningPlugin { }

pub struct PluginMetadata {
    pub plugin_id: PluginId,
    pub plugin_name: String,
    pub plugin_version: String,
    pub plugin_description: String,
    pub plugin_category: FindingCategory,
}

pub struct ScanResult {
    pub scan_plugin_id: PluginId,
    pub scan_success: bool,
    pub scan_findings: Vec<Finding>,
    pub scan_unchecked: Vec<UncheckedCheck>,
    pub scan_duration_us: u64,
    pub scan_error: Option<String>,
}

// Methods:
impl HardeningPlugin for KernelHardeningPlugin {
    fn metadata(&self) -> PluginMetadata { }
    fn dependencies(&self) -> Vec<PluginId> { }
    async fn scan(&self, ctx: &Context, config: &PluginConfig) -> Result<ScanResult> { }
    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> { }
    fn reloads_for_path(&self, path: &Path) -> bool { }
    async fn reload_after_rollback(&self, ctx: &Context) -> Result<Option<String>> { }
    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> { }
}

// Helper functions (kernel):
async fn read_sysctl(&self, param: &str, ctx: &Context) -> Result<String> { }
fn resolved_target(parameter: &KernelParameter, config: &PluginConfig) -> String { }
fn parse_sysctl(content: &str) -> SysctlAssignments { }

// Constants:
const KERNEL_PARAMS: &[KernelParameter] = &[...];
const SSH_DIRECTIVES: &[SshConfigDirective] = &[...];
```

### Checkpoint/State Management Domain

```rust
// Structs:
pub struct CheckpointManager { }
pub struct Checkpoint {
    pub checkpoint_id: CheckpointId,
    pub checkpoint_name: String,
    pub checkpoint_timestamp: i64,
    pub checkpoint_username: String,
    pub checkpoint_signature: Vec<u8>,
    pub host_key: String,
}

pub struct FileState {
    pub file_path: String,
    pub file_content: Option<Vec<u8>>,
    pub file_permissions: u32,
    pub file_owner_uid: u32,
    pub file_owner_gid: u32,
    pub file_link_target: Option<String>,
    pub file_content_absence: Option<ContentAbsence>,
}

pub enum ContentAbsence {
    ByDesign,   // no bytes stored on purpose: a directory, or an account
                // database captured metadata-only
    ReadFailed, // bytes were wanted and could not be read
}

// Methods:
impl CheckpointManager {
    pub fn new(db_pool: SqlitePool) -> Result<CheckpointManager> { }
    pub fn new_with_signer(...) -> Result<CheckpointManager> { }
    pub fn new_with_allowlist(...) -> Result<CheckpointManager> { }
    pub async fn create_checkpoint(&self, executor: &dyn SystemExecutor,
                                   checkpoint_name: &str, file_paths: &[&Path])
        -> Result<CheckpointId> { }
    pub async fn create_checkpoint_metadata_only(...) -> Result<CheckpointId> { }
    pub async fn rollback(&self, executor: &dyn SystemExecutor,
                          checkpoint_id: &CheckpointId) -> Result<RollbackResult> { }
    pub async fn get_checkpoint(...) -> Result<(Checkpoint, Vec<FileState>)> { }
    pub async fn list_checkpoints(&self) -> Result<Vec<Checkpoint>> { }
    pub async fn latest_named_for_host(...) -> Result<Option<Checkpoint>> { }
    pub async fn delete_checkpoint(&self, checkpoint_id: &CheckpointId) -> Result<()> { }
    pub async fn verify_checkpoint(&self, checkpoint_id: &CheckpointId) -> Result<()> { }

    fn generate_checkpoint_id() -> CheckpointId { }
    async fn capture_file_state(&self, executor: &dyn SystemExecutor,
                                file_path: &Path) -> Result<Vec<FileState>> { }
    async fn restore_file_state_tracked(&self, executor: &dyn SystemExecutor,
                                        file_state: &FileState)
        -> (FileRestoreAction, Result<()>) { }
}

// Constants:
const DEFAULT_DB_PATH: &str = "/var/lib/linux-hardener/checkpoints.db";  // hardener-state::db
```

### Audit Logging Domain

```rust
// Structs:
pub struct AuditLogger { }
pub struct AuditEntry {
    pub entry_timestamp: DateTime<Utc>,
    pub entry_action_type: ActionType,
    pub entry_user: String,
    pub entry_target: String,
    pub entry_result: ActionResult,
    pub entry_details: HashMap<String, String>,
    pub entry_hash: Vec<u8>,
}

pub struct HashChain {
    previous_hash: Vec<u8>,
}

// Enums:
pub enum ActionType {
    Scan,
    Apply,
    Rollback,
    ConfigChange,
    CheckpointCreate,
    CheckpointDelete,
    ScopeExclusion,
}

pub enum ActionResult {
    Success,
    Failure,
}

// Methods:
impl AuditLogger {
    pub async fn new(log_path: &str) -> Result<AuditLogger> { }
    pub async fn log_action(&self, action_type: ActionType, user: &str, target: &str) -> Result<()> { }
    pub async fn log_failure(&self, action_type: ActionType, user: &str, target: &str, error: &str) -> Result<()> { }
    pub async fn verify_integrity(log_path: &str) -> Result<bool> { }
    pub async fn query(log_path: &str, filter: QueryFilter) -> Result<Vec<AuditEntry>> { }
}

impl HashChain {
    pub fn new() -> HashChain { }
    pub fn next_hash(&self, data: &[u8]) -> Vec<u8> { }
    pub fn update(&mut self, new_hash: Vec<u8>) { }
    pub fn current_hash(&self) -> &[u8] { }
    pub fn verify_entry(previous_hash: &[u8], data: &[u8], claimed_hash: &[u8]) -> bool { }
}
```

### Firewall Management Domain

```rust
// Trait:
pub trait FirewallBackend: Send + Sync { }

// Structs:
pub struct FirewallHardeningPlugin { }
pub struct FirewalldBackend { }
pub struct UfwBackend { }
pub struct NftablesBackend { }

pub struct Rule {
    pub rule_description: String,
    pub rule_protocol: String,
    pub rule_port: String,
    pub rule_source: String,
    pub rule_action: String,
}

// Methods:
impl FirewallBackend for FirewalldBackend {
    fn backend_name(&self) -> &str { }
    fn systemd_unit(&self) -> &'static str { }
    async fn detect(&self, ctx: &Context) -> Result<bool> { }
    async fn is_enabled(&self, ctx: &Context) -> Result<()> { }
    async fn enable(&self, ctx: &Context) -> Result<()> { }
    async fn apply_rules(&self, ctx: &Context, rules: &[Rule]) -> Result<Vec<Change>> { }
    fn get_default_rules(&self) -> Vec<Rule> { }
}

// Helper functions:
pub fn get_baseline_rules() -> Vec<Rule> { }               // Module level
pub fn validate_zone_name(name: &str) -> Result<()> { }    // firewalld
async fn execute_firewall_cmd(&self, ctx: &Context, args: &[&str]) -> Result<String> { }
async fn get_default_zone(&self, ctx: &Context) -> Result<String> { }
fn build_nft_rule_args(&self, rule: &Rule) -> Vec<String> { }   // nftables
fn build_ufw_rule_args(&self, rule: &Rule) -> Vec<String> { }   // ufw
```

### SSH Hardening Domain

```rust
// Struct:
pub struct SshHardeningPlugin { }

struct SshConfigDirective {
    ssh_description: &'static str,
    ssh_directive_name: &'static str,
    ssh_secure_value: &'static str,
    ssh_severity: Severity,
    ssh_compare: Strictness,
}

// Constants:
const SSH_DIRECTIVES: &[SshConfigDirective] = &[...];
const SSH_CRYPTO_DIRECTIVES: &[SshCryptoDirective] = &[...];
const SSHD_ADMIN_CONFIG_PATH: &str = "/etc/ssh/sshd_config";
const SSHD_DROPIN_DIR: &str = "/etc/ssh/sshd_config.d";
const SSH_DESIRED_KEX: &[&str] = &[...];
const SSH_DESIRED_CIPHERS: &[&str] = &[...];
const SSH_DESIRED_MACS: &[&str] = &[...];

// Helper functions:
pub async fn supported_algorithms(executor: &dyn SystemExecutor, query_arg: &str) -> Vec<String> { }
pub fn select_algorithms(desired: &[&str], supported: &[String]) -> Vec<String> { }
pub async fn validate_sshd_config(executor: &dyn SystemExecutor, candidate: &str) -> Result<()> { }
pub fn sshd_validate_scratch_path() -> PathBuf { }
fn resolved_target(directive: &SshConfigDirective, config: &PluginConfig) -> String { }
async fn restart_ssh_service(ctx: &Context) -> Result<()> { }
```

### Service Minimisation Domain

```rust
// Struct:
pub struct ServicesHardeningPlugin { }

struct ServiceDirective {
    service_description: &'static str,
    service_name: &'static str,
    service_severity: Severity,
}

// Constants:
const UNNECESSARY_SERVICES: &[ServiceDirective] = &[
    ServiceDirective {
        service_description: "Bluetooth service - rarely needed on servers",
        service_name: "bluetooth",
        service_severity: Severity::High,
    },
    // ... more services
];

const ADMIN_UNIT_DIR: &str = "/etc/systemd/system";
const ENABLED_STATES: &[&str] = &[...];

// Helper functions:
async fn is_service_exists(ctx: &Context, service_name: &str) -> Result<bool> { }
async fn is_service_enabled(ctx: &Context, service_name: &str) -> Result<bool> { }
async fn is_service_active(ctx: &Context, service_name: &str) -> Result<bool> { }
async fn stop_service(ctx: &Context, service_name: &str) -> Result<()> { }
async fn disable_service(ctx: &Context, service_name: &str) -> Result<()> { }
async fn mask_service(ctx: &Context, service_name: &str) -> Result<()> { }
fn unit_name(service_name: &str) -> String { }
fn mask_link_paths(directives: &[&ServiceDirective]) -> Vec<PathBuf> { }
```

### Configuration Domain

```rust
// Root Config Struct:
pub struct HardenerConfig {
    pub global: GlobalConfig,
    pub ssh: PluginConfig,
    pub kernel: PluginConfig,
    pub firewall: PluginConfig,
    pub pam: PluginConfig,
    pub audit: PluginConfig,
    pub mac: PluginConfig,
    pub permissions: PluginConfig,
    pub services: PluginConfig,
}

// Global Config (non-plugin settings):
pub struct GlobalConfig {
    pub enabled_plugins: Vec<String>,
    pub disabled_plugins: Vec<String>,
}

// Per-Plugin Config (uniform for all plugins):
pub struct PluginConfig {
    /// `None` means the source did not mention the key, which is not the same
    /// as mentioning it as `true`. Read it through `is_enabled()`.
    pub enabled: Option<bool>,
    pub directives: HashMap<String, String>,
    pub exceptions: HashMap<String, PolicyException>,
}

// Methods:
impl PluginConfig {
    pub fn has_valid_exception(&self, key: &str) -> Option<&PolicyException> { }
}

impl HardenerConfig {
    pub fn is_plugin_enabled(&self, plugin_id: &str) -> bool { }
    pub fn get_plugin_config(&self, plugin_id: &str) -> &PluginConfig { }
}

// Policy Exception Struct:
pub struct PolicyException {
    pub value: String,
    pub allowed: bool,
    pub reason: String,
    pub approved_by: Option<String>,
    pub approved_date: Option<String>,
    pub ticket: Option<String>,
    pub expires: Option<String>,
}

// Methods:
impl PolicyException {
    pub fn is_expired(&self) -> bool { }
    pub fn is_valid(&self) -> bool { }
}

// Finding Policy Exception (attached to Finding, in hardener-types):
pub struct FindingPolicyException {
    pub exception_allowed_value: String,
    pub exception_reason: String,
    pub exception_approved_by: Option<String>,
    pub exception_approved_date: Option<String>,
    pub exception_ticket: Option<String>,
    pub exception_expires: Option<String>,
    pub exception_is_expired: bool,
}

// Config Loader:
pub struct ConfigLoader {
    cli_config_path: Option<PathBuf>,
    skip_defaults: bool,
}

// Methods and associated constants:
impl ConfigLoader {
    const SYSTEM_CONFIG_PATH: &'static str = "/etc/linux-hardener/config.toml";
    const ENV_DISABLED_PLUGINS: &'static str = "HARDENER_DISABLED_PLUGINS";
    const ENV_ENABLED_PLUGINS: &'static str = "HARDENER_ENABLED_PLUGINS";
    const MAX_CONFIG_SIZE: u64 = 1_048_576;
    const MAX_DIRECTIVES_PER_PLUGIN: usize = 500;
    const MAX_EXCEPTIONS_PER_PLUGIN: usize = 200;

    pub fn new() -> ConfigLoader { }
    pub fn with_cli_config(mut self, path: PathBuf) -> ConfigLoader { }
    pub fn skip_defaults(mut self) -> ConfigLoader { }
    pub fn load(&self) -> Result<HardenerConfig> { }
    pub fn system_config_path() -> Option<PathBuf> { }
    pub fn user_config_path() -> Option<PathBuf> { }
    fn merge_configs(base: HardenerConfig, overlay: HardenerConfig) -> Result<HardenerConfig> { }
    fn apply_env_overrides(config: HardenerConfig) -> Result<HardenerConfig> { }
}
```

The loader keeps its paths as associated constants on `ConfigLoader`, not as
module-level ones, and the user path is built inline from `dirs::config_dir()`.

### Scheduler/Daemon Domain

```rust
// Main Daemon Struct:
pub struct Daemon {
    daemon_config: SchedulerConfig,
    daemon_runner: Arc<ScanRunner>,
    daemon_scheduler: Option<JobScheduler>,
    daemon_shutdown_tx: Option<broadcast::Sender<()>>,
    daemon_scan_in_progress: Arc<AtomicBool>,
}

// Scan Runner Struct (private fields, no runner_ prefix in the code today):
pub struct ScanRunner {
    db: Arc<ScanHistoryManager>,
    json_store: Arc<JsonStore>,
    min_severity: Severity,
    plugins: Vec<String>,
    host: String,
    dispatcher: Option<NotificationDispatcher>,
}

// Scan Summary (for notifications):
pub struct ScanSummary {
    pub session_id: String,
    pub host: String,
    pub plugins_scanned: Vec<String>,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub json_path: Option<String>,
    pub json_hash: Option<String>,
    pub had_errors: bool,
    pub regression: Option<RegressionInfo>,
}

// Trigger Type Enum:
pub enum TriggerType {
    Scheduled,  // Cron scheduler daemon
    Manual,     // CLI command
    Systemd,    // Systemd timer
}

// Scheduler Config Structs:
pub struct SchedulerConfig {
    pub enabled: bool,
    pub schedule: String,               // Cron expression
    pub plugins: Vec<String>,
    pub min_severity: String,
    pub storage: StorageConfig,
    pub notifications: NotificationConfig,
}

pub struct StorageConfig {
    pub database_path: PathBuf,
    pub json_output_dir: PathBuf,
    pub retention_count: u32,
    pub retention_days: u32,
}

// Methods:
impl Daemon {
    pub fn new(config: SchedulerConfig, db: Arc<ScanHistoryManager>, json_store: Arc<JsonStore>) -> Daemon { }
    pub async fn start(&mut self, plugin_manager: Arc<PluginManager>, ctx: Arc<Context>) -> Result<()> { }
    pub async fn run_once(&self, plugin_manager: &PluginManager, ctx: &Context,
                          trigger: TriggerType) -> Result<ScanSummary> { }
    pub async fn stop(&mut self) -> Result<()> { }

    async fn signal_handler(shutdown_tx: broadcast::Sender<()>) { }
    async fn execute_scan(runner: Arc<ScanRunner>, plugin_manager: Arc<PluginManager>,
                          ctx: Arc<Context>, scan_in_progress: Arc<AtomicBool>) { }
    async fn shutdown_scheduler(&mut self) -> Result<()> { }
}

impl ScanRunner {
    pub fn new(config: &SchedulerConfig, db: Arc<ScanHistoryManager>,
               json_store: Arc<JsonStore>) -> ScanRunner { }
    pub async fn run(&self, plugin_manager: &PluginManager, ctx: &Context,
                     trigger: TriggerType) -> Result<ScanSummary> { }
}

// Notification System:
#[async_trait]
pub trait Notifier: Send + Sync {
    async fn send(&self, summary: &ScanSummary) -> NotificationResult;
    fn channel(&self) -> &str;
}

pub struct NotificationResult {
    pub channel: String,
    pub success: bool,
    pub error: Option<String>,
}

pub struct EmailNotifier {
    config: EmailConfig,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

pub struct WebhookNotifier {
    endpoint: WebhookEndpoint,
    client: Client,
}

pub struct NotificationDispatcher {
    notifiers: Vec<Box<dyn Notifier>>,
    min_severity: Severity,
    db: Arc<ScanHistoryManager>,
    mode: NotifyMode,
}

impl NotificationDispatcher {
    pub fn new(config: &NotificationConfig, db: Arc<ScanHistoryManager>) -> Self { }
    pub async fn dispatch(&self, summary: &ScanSummary) -> Vec<NotificationResult> { }
}

// Helper functions:
pub fn parse_severity(s: &str) -> Severity { }
pub fn meets_severity_threshold(summary: &ScanSummary, min_severity: Severity) -> bool { }
```

### User Interface (Leptos) Domain

```rust
// Page Components (Route handlers):
// Pattern: <Name>Page, one per file in src/pages/, all of them functions
// carrying #[component], never structs.

// ✅ GOOD (the seven routed pages):
#[component] pub fn DashboardPage() -> impl IntoView { }
#[component] pub fn AnalysisPage() -> impl IntoView { }
#[component] pub fn HardeningPage() -> impl IntoView { }
#[component] pub fn HostsPage() -> impl IntoView { }
#[component] pub fn FleetApplyPage() -> impl IntoView { }
#[component] pub fn SchedulerPage() -> impl IntoView { }
#[component] pub fn SettingsPage() -> impl IntoView { }

// ❌ BAD:
#[component] pub fn Dashboard() { }      // Missing Page suffix (page or component?)
#[component] pub fn ConfigPage() { }     // Abbreviation (spell Configuration out)

// Reusable Components:
// Pattern: <Name> without suffix, in src/components/

// ✅ GOOD:
#[component] pub fn SecurityScore() -> impl IntoView { }
#[component] pub fn FindingsTab(...) -> impl IntoView { }
#[component] pub fn ComplianceTab(...) -> impl IntoView { }
#[component] pub fn Card(...) -> impl IntoView { }
#[component] pub fn Modal(...) -> impl IntoView { }
#[component] pub fn Sidebar(...) -> impl IntoView { }
#[component] pub fn ThemePicker(...) -> impl IntoView { }
#[component] pub fn SegmentedControl(...) -> impl IntoView { }

// ❌ BAD:
#[component] pub fn SecurityScoreComponent() { }  // Redundant suffix
#[component] pub fn ComplTab() { }                // Abbreviation
#[component] pub fn Score() { }                   // Too generic

// Component Props (function parameters):
// Pattern: Descriptive names, no special prefix needed

// ✅ GOOD:
#[component]
pub fn Card(
    #[prop(into, optional)] title: Option<String>,
    #[prop(into, optional)] class: Option<String>,
    #[prop(optional)] title_level: Option<HeadingLevel>,
) -> impl IntoView { }

// ❌ BAD:
#[component]
pub fn Card(#[prop(optional)] cfg: Option<HeadingLevel>) -> impl IntoView { }  // Abbreviation

// UI State Signals:
// Pattern: Descriptive names describing what they hold

// ✅ GOOD:
pub struct AppState {
    pub scan_results: RwSignal<Vec<ScanResult>>,
    pub selected_finding: RwSignal<Option<Finding>>,
    pub is_scanning: RwSignal<bool>,
    pub is_applying: RwSignal<bool>,
}

// ❌ BAD:
pub struct AppState {
    pub results: RwSignal<Vec<ScanResult>>,     // Too generic
    pub finding: RwSignal<Option<Finding>>,     // Ambiguous (selected? current? any?)
    pub scanning: RwSignal<bool>,               // Prefer is_scanning for boolean
}

// CSS Class Names:
// Pattern: kebab-case matching component/purpose

// ✅ GOOD:
<div class="dashboard-page">
<div class="analysis-page">
<div class="security-score score-good">
<div class="activity-item">
<button class="btn btn-primary">

// ❌ BAD:
<div class="DashboardPage">     // Wrong case
<div class="findingsGrid">      // Wrong case (camelCase)
<span class="sev-badge">        // Abbreviation
```

---

## Summary Checklist

When naming any identifier in this project, verify:

- [ ] **Clarity**: Is the name immediately clear and unambiguous?
- [ ] **Prefix**: Does it use a descriptive prefix where helpful? (distro_, plugin_, checkpoint_, etc.)
- [ ] **Case**: Does it use the correct case convention for its type?
- [ ] **British English**: Does it use British spellings?
- [ ] **Alphabetical**: If part of a list/group, is it alphabetised (where appropriate)?
- [ ] **No Abbreviations**: Are all words spelled out fully?
- [ ] **Explicit Return Types**: (Constructors only) Does it return an explicit type rather than `Self`?
- [ ] **Consistency**: Does it match existing patterns in the codebase?

---

## Recent Additions

### 2025-12-05 (GUI Styling)

**CSS Styling**:
- Added `styles.css` with dark terminal theme (~500 lines)
- CSS Variables for colours, typography, spacing (e.g., `--bg-primary`, `--accent-green`, `--font-mono`)
- Component class naming: `kebab-case` (e.g., `.security-score`, `.nav-links`, `.severity-badge`)
- State class naming: `<component>-<state>` (e.g., `.score-good`, `.score-warning`, `.score-critical`, `.score-pending`)

### 2025-12-05 (WASM Fix)

**hardener-types Crate**:
- New crate for WASM-compatible shared type definitions
- Contains all types previously in hardener-common/src/types.rs, hardener-core/src/plugin.rs, hardener-compliance/src/report.rs
- Dependencies: serde, chrono only (no system dependencies)
- Key exports: `PluginId`, `Severity`, `FindingCategory`, `ComplianceFramework`, `Finding`, `ScanResult`, `ApplyResult`, `ComplianceReport`, `ControlResult`, `ComplianceSummary`

**Type Re-exports**:
- `hardener-common/src/types.rs` now uses `pub use hardener_types::*;`
- `hardener-core/src/plugin.rs` now re-exports from hardener-types
- `hardener-compliance/src/report.rs` now re-exports from hardener-types
- `hardener-ui/src/types.rs` now uses `pub use hardener_types::*;`

**hardener-compliance Feature Gate**:
- krilla PDF library now behind `pdf` feature (default enabled)
- Allows WASM builds to exclude native PDF dependencies

### 2025-12-05 (History/Systemd)

**History CLI Domain**:
- Added `HistoryAction` enum with variants: `List`, `Show`, `Export`
- CLI commands: `history list`, `history show`, `history export`
- Helper functions: `list()`, `show()`, `export()`, `open_database()`, `format_timestamp()`, `print_session_detail()`, `truncate_string()`
- Internal struct: `SessionDetail` for JSON serialisation

**Systemd Integration Domain**:
- Added `SystemdGenerator` struct for unit file generation
- Added module-level helper functions: `service_name()`, `timer_name()`, `system_unit_path()`, `user_unit_path()`
- Added `cron_to_calendar()` function for cron-to-systemd conversion
- CLI commands: `systemd generate`, `systemd install`, `systemd uninstall`, `systemd status`
- Added `SystemdAction` enum to CLI

### 2025-12-04

**Scheduler/Daemon Domain**:
- Added `Daemon` struct for cron-scheduled scanning
- Fields use `daemon_*` prefix: `daemon_config`, `daemon_runner`, `daemon_scheduler`, `daemon_shutdown_tx`, `daemon_scan_in_progress`
- Added `ScanRunner` struct for scan orchestration
- Added `ScanSummary` struct for notification payloads
- Added `TriggerType` enum: `Scheduled`, `Manual`, `Systemd`
- Added `JsonStore` struct for timestamped JSON output
- Added `ScanHistoryManager` for SQLite scan history
- Added `SchedulerConfig`, `StorageConfig`, `NotificationConfig` structs
- Config fields use domain prefixes: `scheduler_*`, `storage_*`

### 2025-11-24

**Plugin Naming Standardisation**:
- Standardised ALL plugin struct names to `*HardeningPlugin` pattern
- Standardised ALL plugin IDs to use descriptive suffixes (e.g., `-hardening`)
- Updated kernel plugin ID from `"kernel"` to `"kernel-hardening"` for consistency
- Confirmed struct names: All 8 plugins now follow `<Domain>HardeningPlugin` pattern
- Added comprehensive plugin ID naming convention documentation
- Added rationale for descriptive suffixes (prevents ambiguity)
- Special case documented: `"service-minimisation"` uses British spelling and descriptive function name

**Plugin ID and Struct Name Reference**:
- `KernelHardeningPlugin` → `"kernel-hardening"`
- `SshHardeningPlugin` → `"ssh-hardening"`
- `FirewallHardeningPlugin` → `"firewall-hardening"` (struct previously was `FirewallPlugin`)
- `PamHardeningPlugin` → `"pam-hardening"`
- `ServicesHardeningPlugin` → `"service-minimisation"` (struct previously was `ServicesPlugin`)
- `AuditHardeningPlugin` → `"audit-hardening"`
- `PermissionsHardeningPlugin` → `"permissions-hardening"`
- `MacHardeningPlugin` → `"mac-hardening"` (struct previously was `MacPlugin`)

**Bug Fix**:
- Fixed critical frontend bug where configuration page was sending incorrect plugin IDs to backend
- Only kernel plugin was working due to ID mismatch; now all 8 plugins work correctly

**Verification**:
- All 53 tests passing (36 plugin + 17 core)
- Tauri application builds successfully
- Backend plugin registration and ID resolution verified working
- Known issue: Wayland/GBM graphics errors on some Linux configurations (workaround: use `GDK_BACKEND=x11`)

### 2025-11-23

**User Interface (Leptos) Domain**:
- Added page component naming pattern: `<Name>Page` suffix for route handlers
- Added reusable component naming: `<Name>` without suffix
- Added component props patterns: descriptive names, no special prefixes
- Added UI state signal patterns: descriptive names (e.g., `is_scanning`, `selected_finding`)
- Added CSS class naming: kebab-case matching component/purpose
- Comprehensive examples for all UI naming patterns

### 2025-11-22

**Firewall Management Domain**:
- Added `FirewallBackend` trait
- Added backend structs: `FirewalldBackend`, `UfwBackend`, `NftablesBackend`
- Added `FirewallPlugin` struct
- Added `Rule` struct with `rule_*` field prefixes
- Added helper functions: `execute_firewall_cmd`, `get_default_zone`, `parse_nft_rule_line`, `build_nft_rule_args`, `get_baseline_rules`

**SSH Hardening Domain**:
- Added `SshHardeningPlugin` struct
- Added `SshConfigDirective` struct with `ssh_*` field prefixes
- Added constants: `SSH_DIRECTIVES`, `SSH_CONFIG_PATH`, `SSH_BACKUP_DIR`
- Added helper functions: `parse_ssh_directive`, `apply_ssh_directive`, `create_ssh_config_backup`, `restart_ssh_service`

**Service Minimisation Domain**:
- Added `ServicesPlugin` struct
- Added `ServiceDirective` struct with `service_*` field prefixes
- Added constant: `UNNECESSARY_SERVICES`
- Added helper functions: `is_service_exists`, `is_service_enabled`, `is_service_active`, `stop_service`, `disable_service`, `mask_service`

**MAC (Mandatory Access Control) System Domain**:
- Added `MacPlugin` struct
- Added `MacSystem` enum (SELinux, AppArmor)
- Added helper functions: `detect_mac_system`, `get_selinux_mode`, `set_selinux_enforcing`, `get_apparmor_status`, `count_apparmor_profiles`
- Filesystem-based detection patterns: `/sys/fs/selinux`, `/sys/kernel/security/apparmor`
- Command execution patterns: `getenforce`, `setenforce`, `aa-status`

**Updated Patterns**:
- Backend struct naming: `<Technology>Backend` (e.g., FirewalldBackend, NftablesBackend)
- Rule field naming: All fields prefixed with `rule_` for clarity
- SSH directive fields: All fields prefixed with `ssh_` for clarity
- Service directive fields: All fields prefixed with `service_` for clarity
- MAC system enum naming: Direct technology names (SELinux, AppArmor) without prefixes
- Comprehensive examples added for all new domains

---

**Last Updated**: 2026-08-19

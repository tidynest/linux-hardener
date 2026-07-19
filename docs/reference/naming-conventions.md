# Naming Conventions Reference

**Author**: Eric Jingryd
**Last Updated**: 2026-07-19
**Purpose**: Complete and authoritative naming standards for all identifiers in the project

---

## Table of Contents

1. [Core Principles](#core-principles)
2. [File and Directory Names](#file-and-directory-names)
3. [Crate Names](#crate-names)
4. [Module Names](#module-names)
5. [Struct Names](#struct-names)
6. [Enum Names](#enum-names)
7. [Trait Names](#trait-names)
8. [Function and Method Names](#function-and-method-names)
9. [Variable Names](#variable-names)
10. [Constant Names](#constant-names)
11. [Type Alias Names](#type-alias-names)
12. [Generic Parameter Names](#generic-parameter-names)
13. [Lifetime Names](#lifetime-names)
14. [Field Names](#field-names)
15. [Test Function Names](#test-function-names)
16. [Documentation File Names](#documentation-file-names)
17. [Examples by Domain](#examples-by-domain)

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

// ✅ GOOD (Package Managers):
pub struct AptPackageManager { }
pub struct DnfPackageManager { }
pub struct PacmanPackageManager { }
pub struct ZypperPackageManager { }

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
pub struct Package { }           // Package information

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
    Kernel,
    Network,
    Authentication,
    FileSystem,
    Services,
    Audit,
    Permissions,
    Compliance,
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

    #[error("Plugin not found: {0}")]
    PluginNotFound(String),
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
// ✅ GOOD:
pub trait HardeningPlugin { }
pub trait PackageManager { }
pub trait FirewallBackend { }       // Firewall backend abstraction
pub trait DistributionAdapter { }
pub trait ComplianceFramework { }

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
    pub fn new(pool: SqlitePool) -> CheckpointManager {
        Self { pool }
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
pub fn get_distribution() -> Result<Distribution> { }
pub fn is_enabled() -> bool { }
pub fn has_dependency(&self, id: &PluginId) -> bool { }
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
pub fn set_severity(&mut self, severity: Severity) { }
pub fn update_checkpoint(&mut self, checkpoint: &Checkpoint) -> Result<()> { }
pub fn apply_sysctl_param(&self, param: &str, value: &str) -> Result<()> { }

// ❌ BAD:
pub fn severity(&mut self, s: Severity) { }        // Ambiguous (getter or setter?)
pub fn checkpoint(&mut self, cp: &Checkpoint) { }  // Unclear action
pub fn sysctl(&self, p: &str, v: &str) { }        // Unclear action, abbreviations
```

**Action Methods (from Plugin Trait)**:
```rust
// Pattern: verb describing action

// ✅ GOOD (Plugin trait methods):
fn scan(&self, ctx: &Context) -> Result<ScanResult> { }
fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> { }
fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()> { }
fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> { }

// ✅ GOOD (Supporting methods):
fn read_sysctl_param(param: &str) -> Result<String> { }
fn write_sysctl_param(param: &str, value: &str) -> Result<()> { }
fn parse_ssh_directive(content: &str, directive: &str) -> Option<String> { }
fn create_checkpoint(name: &str) -> Result<CheckpointId> { }

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
fn execute_command(cmd: &str, args: &[&str]) -> Result<String> { }
fn parse_os_release_content(content: &str) -> Result<OsRelease> { }
fn generate_checkpoint_id() -> String { }
fn verify_signature(data: &[u8], signature: &[u8]) -> bool { }

// ✅ GOOD (Domain-specific helpers):
fn execute_firewall_cmd(args: &[&str]) -> Result<String> { }
fn execute_apt_command(args: &[&str]) -> Result<String> { }
fn parse_nft_rule_line(line: &str) -> Option<Rule> { }
fn build_nft_rule_args(rule: &Rule) -> Vec<String> { }
fn parse_ssh_directive(content: &str, directive_name: &str) -> Option<String> { }
fn get_default_zone() -> Result<String> { }
fn get_baseline_rules() -> Vec<Rule> { }

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
fn apply_sysctl_param(param_name: &str, param_value: &str) -> Result<()> { }
fn create_checkpoint(checkpoint_name: &str) -> Result<CheckpointId> { }
fn parse_ssh_directive(config_content: &str, directive_name: &str) -> Option<String> { }

// ❌ BAD:
fn apply_sysctl_param(p: &str, v: &str) -> Result<()> { }      // Abbreviations
fn create_checkpoint(name: &str) -> Result<CheckpointId> { }    // Ambiguous
fn parse_ssh_directive(c: &str, d: &str) -> Option<String> { } // Abbreviations
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
const KERNEL_PARAMS: &[(&str, &str, &str)] = &[
    ("kernel.randomize_va_space", "2", "Enable full ASLR"),
];

const SSH_DIRECTIVES: &[SshConfigDirective] = &[
    SshConfigDirective {
        ssh_directive_name: "PermitRootLogin",
        ssh_secure_value: "no",
        ssh_description: "Disable direct root SSH access",
        ssh_severity: Severity::Critical,
    },
];

const SSH_CONFIG_PATH: &str = "/etc/ssh/sshd_config";
const SSH_BACKUP_DIR: &str = "/var/backups/ssh";

const DEFAULT_CHECKPOINT_PATH: &str = "/var/lib/linux-hardener/checkpoints.db";
const MAX_CHECKPOINT_AGE_DAYS: u64 = 90;

const OS_RELEASE_PATH: &str = "/etc/os-release";
const FALLBACK_OS_RELEASE_PATH: &str = "/usr/lib/os-release";

// ❌ BAD:
const PARAMS: &[(&str, &str, &str)] = &[];     // Too generic
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
pub type PluginRegistry = Arc<RwLock<HashMap<PluginId, Arc<Box<dyn HardeningPlugin>>>>>;

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
    pub checkpoint_timestamp: u64,
    pub checkpoint_username: String,
    pub checkpoint_signature: Vec<u8>,
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
    pub finding_policy_exception: Option<FindingPolicyException>,
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

pub struct SshConfigDirective {
    pub ssh_directive_name: &'static str,
    pub ssh_secure_value: &'static str,
    pub ssh_description: &'static str,
    pub ssh_severity: Severity,
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
fn test_sysctl_param_verification() { }

#[test]
fn test_ssh_directive_parsing() { }

#[test]
fn test_checkpoint_creation_with_signature() { }

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
async fn test_full_checkpoint_and_rollback_workflow() { }

#[tokio::test]
async fn test_plugin_dependency_resolution() { }

#[tokio::test]
async fn test_scan_apply_verify_rollback_workflow() { }

#[test]
fn test_kernel_plugin_metadata() { }

#[test]
fn test_ssh_scan_reads_configuration() { }

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

**Format**: `SCREAMING_SNAKE_CASE.md` for important docs, `lowercase.md` for others

**Project Documentation**:
```
✅ GOOD:
README.md
LICENSE
CONTRIBUTING.md
CHANGELOG.md
SECURITY.md
docs/reference/naming-conventions.md
docs/architecture/architecture.md

❌ BAD:
docs/architecture.md         # Should be uppercase for important docs
docs/progress-tracking.md    # Should use underscore, not hyphen
docs/code_patterns.md        # Should be uppercase
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

// Functions:
pub fn detect_distribution() -> Result<Distribution> { }
fn read_os_release() -> Result<String> { }
fn parse_os_release_content(content: &str) -> Result<OsRelease> { }
fn map_to_family(distro_name: &str) -> DistroFamily { }

// Constants:
const OS_RELEASE_PATH: &str = "/etc/os-release";
const FALLBACK_OS_RELEASE_PATH: &str = "/usr/lib/os-release";
```

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
    fn scan(&self, ctx: &Context) -> Result<ScanResult> { }
    fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> { }
    fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()> { }
    fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> { }
}

// Helper functions:
fn read_sysctl_param(param_name: &str) -> Result<String> { }
fn write_sysctl_param(param_name: &str, param_value: &str) -> Result<()> { }
fn parse_ssh_directive(config_content: &str, directive_name: &str) -> Option<String> { }

// Constants:
const KERNEL_PARAMS: &[(&str, &str, &str)] = &[...];
const SSH_DIRECTIVES: &[SshConfigDirective] = &[...];
```

### Checkpoint/State Management Domain

```rust
// Structs:
pub struct CheckpointManager { }
pub struct Checkpoint {
    pub checkpoint_id: CheckpointId,
    pub checkpoint_name: String,
    pub checkpoint_timestamp: u64,
    pub checkpoint_username: String,
    pub checkpoint_signature: Vec<u8>,
}

pub struct FileState {
    pub file_path: PathBuf,
    pub file_content: Option<Vec<u8>>,
    pub file_permissions: u32,
    pub file_owner_uid: u32,
    pub file_owner_gid: u32,
}

// Methods:
impl CheckpointManager {
    pub fn new(pool: SqlitePool) -> CheckpointManager { }
    pub async fn create_checkpoint(&self, checkpoint_name: &str) -> Result<CheckpointId> { }
    pub async fn rollback(&self, checkpoint_id: &CheckpointId) -> Result<()> { }
    pub async fn list_checkpoints(&self) -> Result<Vec<Checkpoint>> { }
    pub async fn delete_checkpoint(&self, checkpoint_id: &CheckpointId) -> Result<()> { }

    fn generate_checkpoint_id() -> String { }
    fn capture_file_state(&self, file_path: &Path) -> Result<FileState> { }
    fn restore_file_state(&self, file_state: &FileState) -> Result<()> { }
}

// Constants:
const DEFAULT_CHECKPOINT_PATH: &str = "/var/lib/linux-hardener/checkpoints.db";
const MAX_CHECKPOINT_AGE_DAYS: u64 = 90;
```

### Audit Logging Domain

```rust
// Structs:
pub struct AuditLogger { }
pub struct AuditEntry {
    pub entry_timestamp: u64,
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
}

pub enum ActionResult {
    Success,
    Failure,
}

// Methods:
impl AuditLogger {
    pub async fn new(log_path: &Path) -> Result<AuditLogger> { }
    pub async fn log_action(&self, action_type: ActionType, user: &str, target: &str) -> Result<()> { }
    pub async fn log_failure(&self, action_type: ActionType, user: &str, target: &str, error: &str) -> Result<()> { }
    pub async fn verify_integrity(log_path: &Path) -> Result<bool> { }
    pub async fn query(log_path: &Path, filter: &QueryFilter) -> Result<Vec<AuditEntry>> { }
}

impl HashChain {
    pub fn new() -> HashChain { }
    pub fn next_hash(&mut self, data: &[u8]) -> Vec<u8> { }
    pub fn verify_entry(previous_hash: &[u8], data: &[u8], claimed_hash: &[u8]) -> bool { }
}
```

### Package Management Domain

```rust
// Trait:
pub trait PackageManager { }

// Structs:
pub struct AptPackageManager { }
pub struct DnfPackageManager { }
pub struct PacmanPackageManager { }
pub struct ZypperPackageManager { }

pub struct Package {
    pub package_name: String,
    pub package_version: String,
    pub package_architecture: String,
    pub package_is_security_update: bool,
}

// Methods:
impl PackageManager for AptPackageManager {
    fn update(&self) -> Result<()> { }
    fn install(&self, package_name: &str) -> Result<()> { }
    fn remove(&self, package_name: &str) -> Result<()> { }
    fn list_installed(&self) -> Result<Vec<Package>> { }
    fn is_installed(&self, package_name: &str) -> Result<bool> { }
    fn security_updates(&self) -> Result<Vec<Package>> { }
}

// Helper functions:
fn execute_apt_command(args: &[&str]) -> Result<String> { }
fn parse_dpkg_output(output: &str) -> Vec<Package> { }
fn validate_package_name(package_name: &str) -> Result<()> { }
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
    fn detect(&self) -> Result<bool> { }
    fn is_enabled(&self) -> Result<()> { }
    fn enable(&self) -> Result<()> { }
    fn list_rules(&self) -> Result<Vec<Rule>> { }
    fn apply_rules(&self, rules: &[Rule]) -> Result<Vec<Change>> { }
    fn get_default_rules(&self) -> Vec<Rule> { }
}

// Helper functions:
fn execute_firewall_cmd(args: &[&str]) -> Result<String> { }
fn get_default_zone() -> Result<String> { }
fn parse_nft_rule_line(line: &str) -> Option<Rule> { }
fn build_nft_rule_args(rule: &Rule) -> Vec<String> { }
fn get_baseline_rules() -> Vec<Rule> { }
```

### SSH Hardening Domain

```rust
// Struct:
pub struct SshHardeningPlugin { }

pub struct SshConfigDirective {
    pub ssh_directive_name: &'static str,
    pub ssh_secure_value: &'static str,
    pub ssh_description: &'static str,
    pub ssh_severity: Severity,
}

// Constants:
const SSH_DIRECTIVES: &[SshConfigDirective] = &[...];
const SSH_CONFIG_PATH: &str = "/etc/ssh/sshd_config";
const SSH_BACKUP_DIR: &str = "/var/backups/ssh";

// Helper functions:
fn read_ssh_config() -> Result<String> { }
fn parse_ssh_directive(content: &str, directive_name: &str) -> Option<String> { }
fn apply_ssh_directive(content: &mut String, directive_name: &str, value: &str) -> bool { }
fn create_ssh_config_backup() -> Result<PathBuf> { }
fn restart_ssh_service() -> Result<()> { }
```

### Service Minimisation Domain

```rust
// Struct:
pub struct ServicesHardeningPlugin { }

pub struct ServiceDirective {
    service_description: &'static str,
    service_name:        &'static str,
    service_severity:    Severity,
}

// Constants:
const UNNECESSARY_SERVICES: &[ServiceDirective] = &[
    ServiceDirective {
        service_description: "Bluetooth service - rarely needed on servers",
        service_name:        "bluetooth",
        service_severity:    Severity::High,
    },
    // ... more services
];

// Helper functions:
fn is_service_exists(service_name: &str) -> Result<bool> { }
fn is_service_enabled(service_name: &str) -> Result<bool> { }
fn is_service_active(service_name: &str) -> Result<bool> { }
fn stop_service(service_name: &str) -> Result<()> { }
fn disable_service(service_name: &str) -> Result<()> { }
fn mask_service(service_name: &str) -> Result<()> { }
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
    pub enabled: bool,
    pub directives: HashMap<String, String>,
    pub custom_directives: HashMap<String, String>,
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

// Finding Policy Exception (attached to Finding):
pub struct FindingPolicyException {
    pub allowed_value: String,
    pub reason: String,
    pub approved_by: Option<String>,
    pub approved_date: Option<String>,
    pub ticket: Option<String>,
    pub expires: Option<String>,
    pub is_expired: bool,
}

// Config Loader:
pub struct ConfigLoader {
    cli_config_path: Option<PathBuf>,
}

// Methods:
impl ConfigLoader {
    pub fn new() -> ConfigLoader { }
    pub fn with_cli_config(self, path: PathBuf) -> ConfigLoader { }
    pub fn load(&self) -> Result<HardenerConfig, ConfigError> { }
}

// Helper functions:
fn user_config_path() -> Option<PathBuf> { }

// Constants:
const SYSTEM_CONFIG_PATH: &str = "/etc/linux-hardener/config.toml";
const USER_CONFIG_DIR: &str = "linux-hardener";
const CONFIG_FILE_NAME: &str = "config.toml";
```

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

// Scan Runner Struct:
pub struct ScanRunner {
    runner_db: Arc<ScanHistoryManager>,
    runner_json_store: Arc<JsonStore>,
    runner_min_severity: Severity,
    runner_plugins: Vec<String>,
    runner_host: String,
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
    pub async fn start(&mut self, pm: Arc<PluginManager>, ctx: Arc<Context>) -> Result<()> { }
    pub async fn run_once(&self, pm: &PluginManager, ctx: &Context, trigger: TriggerType) -> Result<ScanSummary> { }
    pub async fn stop(&mut self) -> Result<()> { }
}

impl ScanRunner {
    pub fn new(db: Arc<ScanHistoryManager>, json_store: Arc<JsonStore>, config: &SchedulerConfig, host: String) -> ScanRunner { }
    pub async fn run(&self, pm: &PluginManager, ctx: &Context, trigger: TriggerType) -> Result<ScanSummary> { }
}

// Helper functions:
fn spawn_signal_handler(shutdown_tx: broadcast::Sender<()>) { }
async fn execute_scan(runner: Arc<ScanRunner>, pm: Arc<PluginManager>, ctx: Arc<Context>, scan_in_progress: Arc<AtomicBool>) { }

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
// Pattern: <Name>Page

// ✅ GOOD:
pub struct DashboardPage;
pub struct ScannerPage;
pub struct ConfigurationPage;

// ❌ BAD:
pub struct Dashboard;        // Missing Page suffix (ambiguous - is it a page or a component?)
pub struct ScanPage;          // Inconsistent (use ScannerPage)
pub struct ConfigPage;        // Abbreviation (use ConfigurationPage)

// Reusable Components:
// Pattern: <Name> without suffix

// ✅ GOOD:
pub struct FindingsGrid;
pub struct SeverityBadge;
pub struct SecurityScore;
pub struct QuickActions;
pub struct FindingDetail;

// ❌ BAD:
pub struct FindingsGridComponent;  // Redundant suffix
pub struct SevBadge;                // Abbreviation
pub struct Score;                   // Too generic

// Component Props (function parameters):
// Pattern: Descriptive names, no special prefix needed

// ✅ GOOD:
#[component]
pub fn SeverityBadge(severity: Severity) -> impl IntoView { }

#[component]
pub fn FindingsGrid(findings: Vec<Finding>) -> impl IntoView { }

// ❌ BAD:
#[component]
pub fn SeverityBadge(sev: Severity) -> impl IntoView { }  // Abbreviation

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
<div class="findings-grid">
<span class="severity-badge severity-critical">
<div class="security-score score-high">

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

**Last Updated**: 2026-07-19

### 2025-12-05 (GUI Styling)

**CSS Styling**:
- Added `styles.css` with dark terminal theme (~500 lines)
- CSS Variables for colours, typography, spacing (e.g., `--bg-primary`, `--accent-green`, `--font-mono`)
- Component class naming: `kebab-case` (e.g., `.security-score`, `.nav-links`, `.severity-badge`)
- State class naming: `<component>-<state>` (e.g., `.score-good`, `.score-warning`, `.score-critical`, `.score-pending`)

## Recent Additions

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

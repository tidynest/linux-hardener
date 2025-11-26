# Compliance Report Generation Plan

## Overview

Add compliance framework mapping and report generation to the Linux System Hardener. This allows users to see how their security posture aligns with industry standards.

---

## Implementation Progress

### Phase 1: Foundation (Restore compilation with new field)
| Step | Task | Status |
|------|------|--------|
| 1 | Add `ComplianceMapping` struct to `hardener-common/types.rs` | ✅ Complete |
| 2 | Add `finding_compliance` field to `Finding` in `hardener-core` | ✅ Complete |
| 3 | Update all 8 plugins with empty `finding_compliance: vec![]` | ✅ Complete |

### Phase 2: Core Compliance Logic
| Step | Task | Status |
|------|------|--------|
| 4 | Build `hardener-compliance` crate structure (config, report types) | ✅ Complete |
| 5 | Implement CIS framework control definitions | ✅ Complete |
| 6 | Implement `ReportGenerator` (shared logic) | ✅ Complete |
| 7 | Implement Text formatter | ✅ Complete |
| 8 | Implement JSON formatter | ✅ Complete |

### Phase 3: CLI Integration
| Step | Task | Status |
|------|------|--------|
| 9 | Add CLI `report` command (interactive + direct modes) | ✅ Complete |

### Phase 4: Plugin Compliance Mappings
| Step | Task | Status |
|------|------|--------|
| 10 | Add compliance mappings to Kernel Hardening plugin | ✅ Complete |
| 11 | Add compliance mappings to SSH Hardening plugin | ✅ Complete |
| 12 | Add compliance mappings to remaining 6 plugins | ✅ Complete |

### Phase 5: Framework Expansion
| Step | Task | Status |
|------|------|--------|
| 13 | Implement STIG framework controls | ✅ Complete |
| 14 | Implement CSV formatter | ✅ Complete |
| 15 | Implement HTML formatter | ✅ Complete |
| 16 | Implement remaining frameworks (NIST, PCI-DSS, HIPAA, GDPR) | ✅ Complete |

### Phase 6: Polish
| Step | Task | Status |
|------|------|--------|
| 17 | Final testing and documentation updates | ✅ Complete |

**Legend**: ⬜ Pending | 🔄 In Progress | ✅ Complete

---

## Design

### Two-Part Implementation

**Part 1: Enhanced Findings** - Each finding includes compliance control IDs
```
! Kernel Hardening - 3 finding(s)
  • [HIGH] Insecure value for kernel.randomize_va_space
    Compliance: CIS 1.5.1, STIG V-230223, NIST SC-30
```

**Part 2: Framework Reports** - Dedicated compliance reports grouped by framework
```
CIS Benchmark v8.0 Compliance Report
=====================================

Section 1: Initial Setup
  1.5.1 Ensure ASLR enabled                    [FAIL]
  1.5.2 Ensure ptrace restricted               [FAIL]
  1.5.3 Ensure core dumps restricted           [PASS]

Section 5: Access Control
  5.2.1 Ensure SSH root login disabled         [PASS]
  5.2.2 Ensure SSH PermitEmptyPasswords disabled [PASS]

Summary: 42/60 controls passing (70%)
```

---

## CLI Commands

### Interactive Mode (Default - User Friendly)

```bash
hardener report
```

This launches an interactive wizard:
```
═══ Compliance Report Generator ═══

What is your use case?
  [1] Server (production systems)
  [2] Workstation (desktop/laptop)
  [3] Government (STIG/NIST compliance)
  [4] Healthcare (HIPAA)
  [5] Financial (PCI-DSS)
  [6] GDPR (EU data protection)
  [7] All frameworks (comprehensive check)
  [8] Custom (select specific frameworks)

Select scenario [1-8]: 1

Selected frameworks: CIS Server Benchmark, STIG

Would you like to save the report to a file? [Y/n]: y

Select output format(s):
  [1] Text (.txt)
  [2] JSON (.json)
  [3] CSV (.csv)
  [4] HTML (.html)
  [5] PDF (.pdf)
  [a] All formats

Select format(s) [1-5/a]: 1,4

Enter output directory [./reports]:

Generating report...
✓ Report saved to ./reports/compliance-report-2025-11-25.txt
✓ Report saved to ./reports/compliance-report-2025-11-25.html
```

### Direct Mode (Power Users / Scripting)

```bash
# Skip interactive prompts with flags
hardener report --scenario server --format html --output report.html

# Multiple formats at once
hardener report --scenario government --format json,csv,html --output-dir ./reports

# Specific framework
hardener report --framework cis --format text
```

### Configuration File (Persistent Settings)

```toml
# ~/.config/linux-hardener/config.toml
[report]
default_scenario = "server"
default_formats = ["text", "html"]
output_directory = "~/security-reports"
auto_open_html = true
```

---

## Compliance Frameworks

| Framework | Description | Use Case |
|-----------|-------------|----------|
| CIS Benchmarks | Center for Internet Security | General best practices |
| STIG | Security Technical Implementation Guides | Government/Military |
| NIST 800-53 | National Institute of Standards | US Federal systems |
| PCI-DSS | Payment Card Industry | Credit card handling |
| HIPAA | Health Insurance Portability | Healthcare systems |
| GDPR Art. 32 | General Data Protection Regulation | EU data protection |

---

## User Scenarios

| Scenario | Description | Frameworks Included |
|----------|-------------|---------------------|
| `server` | Production server hardening | CIS Server, STIG |
| `workstation` | Desktop/laptop security | CIS Workstation |
| `government` | Government compliance | STIG, NIST 800-53 |
| `healthcare` | Medical systems | HIPAA, NIST |
| `financial` | Payment processing | PCI-DSS, CIS |
| `gdpr` | EU data protection | GDPR Art. 32 |
| `all` | Comprehensive check | All frameworks |
| `custom` | User-selected | User picks from list |

---

## Output Formats

| Format | Extension | Use Case |
|--------|-----------|----------|
| Text | `.txt` | Terminal viewing |
| JSON | `.json` | API/automation integration |
| CSV | `.csv` | Spreadsheet analysis, auditors |
| HTML | `.html` | Web viewing, sharing |
| PDF | `.pdf` | Formal documentation |

---

## Data Structure

### Compliance Mapping (per finding)

```rust
pub struct ComplianceMapping {
    pub framework: ComplianceFramework,
    pub control_id: String,        // e.g., "1.5.1"
    pub control_title: String,     // e.g., "Ensure ASLR enabled"
    pub section: Option<String>,   // e.g., "Initial Setup"
}
```

### Finding Enhancement

```rust
// Add to existing Finding struct
pub finding_compliance: Vec<ComplianceMapping>,
```

### Report Structure

```rust
pub struct ComplianceReport {
    pub framework: ComplianceFramework,
    pub generated_at: DateTime<Utc>,
    pub system_info: SystemInfo,
    pub controls: Vec<ControlResult>,
    pub summary: ComplianceSummary,
}

pub struct ControlResult {
    pub control_id: String,
    pub control_title: String,
    pub section: String,
    pub status: ControlStatus,  // Pass, Fail, NotApplicable, Manual
    pub findings: Vec<Finding>,
}

pub struct ComplianceSummary {
    pub total_controls: usize,
    pub passing: usize,
    pub failing: usize,
    pub not_applicable: usize,
    pub manual_review: usize,
    pub score_percentage: f64,
}
```

---

## Files to Create/Modify

### New Files
- `crates/hardener-compliance/src/frameworks/mod.rs` - Framework definitions
- `crates/hardener-compliance/src/frameworks/cis.rs` - CIS mappings
- `crates/hardener-compliance/src/frameworks/stig.rs` - STIG mappings
- `crates/hardener-compliance/src/report.rs` - Report generation
- `crates/hardener-compliance/src/output/mod.rs` - Output formatters
- `crates/hardener-compliance/src/output/text.rs`
- `crates/hardener-compliance/src/output/json.rs`
- `crates/hardener-compliance/src/output/csv.rs`
- `crates/hardener-compliance/src/output/html.rs`
- `crates/hardener-compliance/src/output/pdf.rs`
- `crates/hardener-cli/src/commands/report.rs` - CLI command

### Modified Files
- `crates/hardener-common/src/types.rs` - Add ComplianceMapping
- `crates/hardener-core/src/plugin.rs` - Add compliance field to Finding
- `crates/hardener-plugins/src/*/mod.rs` - Add mappings to each plugin
- `crates/hardener-cli/src/cli.rs` - Add report subcommand
- `crates/hardener-cli/src/main.rs` - Wire up report command

---

## Architecture: CLI/GUI Code Sharing

### Principle: Separation of Concerns

```
┌─────────────────────────────────────────────────────────────┐
│                    User Interfaces                          │
├─────────────────────────┬───────────────────────────────────┤
│   hardener-cli          │   hardener-ui (Tauri/Leptos)      │
│   - Interactive prompts │   - GUI dialogs                   │
│   - Terminal output     │   - Visual components             │
│   - Argument parsing    │   - Event handling                │
└───────────┬─────────────┴───────────────┬───────────────────┘
            │                             │
            ▼                             ▼
┌─────────────────────────────────────────────────────────────┐
│              hardener-compliance (Shared Logic)             │
│                                                             │
│   ReportGenerator::new(scenario, frameworks)                │
│       .generate() -> ComplianceReport                       │
│                                                             │
│   ReportFormatter::format(report, OutputFormat) -> String   │
│                                                             │
│   InteractiveConfig::build() -> ReportConfig                │
│       (provides options/choices, UI renders them)           │
└─────────────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│              hardener-core / hardener-plugins               │
│              (Scan results, findings, mappings)             │
└─────────────────────────────────────────────────────────────┘
```

### Shared Components in hardener-compliance

| Component | Purpose | Used By |
|-----------|---------|---------|
| `ReportConfig` | Scenario, frameworks, formats, output path | CLI + GUI |
| `ReportGenerator` | Runs scan, maps to frameworks, builds report | CLI + GUI |
| `ReportFormatter` | Converts report to text/json/csv/html/pdf | CLI + GUI |
| `ScenarioDefinition` | What frameworks/controls each scenario includes | CLI + GUI |
| `FrameworkDefinition` | Control IDs, titles, sections for each framework | CLI + GUI |
| `InteractiveOptions` | Available choices for user selection | CLI + GUI |

### CLI-Specific (hardener-cli)

| Component | Purpose |
|-----------|---------|
| `commands/report.rs` | Argument parsing, interactive terminal prompts |
| Terminal rendering | Colored output, progress bars |

### GUI-Specific (hardener-ui)

| Component | Purpose |
|-----------|---------|
| `pages/report_page.rs` | Visual wizard, dropdowns, checkboxes |
| `components/report_*` | Report preview, export buttons |

### Example: How It Works

**CLI calls:**
```rust
// CLI gets user input via terminal prompts or flags
let config = ReportConfig {
    scenario: Scenario::Server,
    formats: vec![OutputFormat::Html, OutputFormat::Csv],
    output_dir: PathBuf::from("./reports"),
};

// Shared logic does the work
let generator = ReportGenerator::new(&config);
let report = generator.generate(&scan_results)?;

// Shared formatter produces output
for format in &config.formats {
    let content = ReportFormatter::format(&report, format)?;
    // CLI saves to file
}
```

**GUI calls the exact same code:**
```rust
// GUI gets user input via dropdowns/checkboxes
let config = ReportConfig { /* same struct */ };

// Same shared logic
let generator = ReportGenerator::new(&config);
let report = generator.generate(&scan_results)?;

// Same formatter, GUI displays or saves
let html = ReportFormatter::format(&report, &OutputFormat::Html)?;
// GUI shows preview or triggers download
```

---

## Implementation Order

1. Define compliance data structures in hardener-common
2. Add compliance field to Finding struct
3. Create framework mapping files in hardener-compliance (start with CIS)
4. **Build ReportGenerator in hardener-compliance (shared logic)**
5. **Build ReportFormatter in hardener-compliance (shared logic)**
6. Update plugins to include compliance mappings
7. Add CLI report command (thin wrapper around shared logic)
8. Add remaining frameworks (STIG, NIST, etc.)
9. *(Future)* GUI report page uses same ReportGenerator/Formatter

---

## Detailed Implementation Steps

### Step 1: Add Types to hardener-common

**File: `crates/hardener-common/src/types.rs`**

Add these types:

```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ComplianceFramework {
    Cis,
    Stig,
    Nist80053,
    PciDss,
    Hipaa,
    Gdpr,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceMapping {
    pub framework: ComplianceFramework,
    pub control_id: String,
    pub control_title: String,
    pub section: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub enum ControlStatus {
    Pass,
    Fail,
    #[default]
    NotApplicable,
    ManualReview,
}
```

### Step 2: Update Finding Struct

**File: `crates/hardener-core/src/plugin.rs`**

Add to the `Finding` struct:

```rust
pub struct Finding {
    // ... existing fields ...
    pub finding_compliance: Vec<ComplianceMapping>,  // NEW
}
```

Update the `Default` impl and any constructors.

### Step 3: Create hardener-compliance Crate Structure

```
crates/hardener-compliance/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── config.rs          # ReportConfig, Scenario enum
│   ├── generator.rs       # ReportGenerator
│   ├── report.rs          # ComplianceReport, ControlResult, ComplianceSummary
│   ├── frameworks/
│   │   ├── mod.rs
│   │   ├── cis.rs         # CIS control definitions and mappings
│   │   ├── stig.rs        # STIG control definitions
│   │   ├── nist.rs        # NIST 800-53 controls
│   │   ├── pci.rs         # PCI-DSS controls
│   │   ├── hipaa.rs       # HIPAA controls
│   │   └── gdpr.rs        # GDPR Art. 32 controls
│   └── output/
│       ├── mod.rs         # ReportFormatter trait
│       ├── text.rs
│       ├── json.rs
│       ├── csv.rs
│       ├── html.rs
│       └── pdf.rs
```

**Cargo.toml:**
```toml
[package]
name = "hardener-compliance"
version.workspace = true
edition.workspace = true

[dependencies]
hardener-common = { path = "../hardener-common" }
hardener-core = { path = "../hardener-core" }
serde = { workspace = true }
serde_json = { workspace = true }
chrono = "0.4"
```

### Step 4: Implement ReportConfig

**File: `crates/hardener-compliance/src/config.rs`**

```rust
use hardener_common::types::ComplianceFramework;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub enum Scenario {
    Server,
    Workstation,
    Government,
    Healthcare,
    Financial,
    Gdpr,
    All,
    Custom(Vec<ComplianceFramework>),
}

impl Scenario {
    pub fn frameworks(&self) -> Vec<ComplianceFramework> {
        match self {
            Scenario::Server => vec![ComplianceFramework::Cis, ComplianceFramework::Stig],
            Scenario::Workstation => vec![ComplianceFramework::Cis],
            Scenario::Government => vec![ComplianceFramework::Stig, ComplianceFramework::Nist80053],
            Scenario::Healthcare => vec![ComplianceFramework::Hipaa, ComplianceFramework::Nist80053],
            Scenario::Financial => vec![ComplianceFramework::PciDss, ComplianceFramework::Cis],
            Scenario::Gdpr => vec![ComplianceFramework::Gdpr],
            Scenario::All => vec![
                ComplianceFramework::Cis,
                ComplianceFramework::Stig,
                ComplianceFramework::Nist80053,
                ComplianceFramework::PciDss,
                ComplianceFramework::Hipaa,
                ComplianceFramework::Gdpr,
            ],
            Scenario::Custom(frameworks) => frameworks.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum OutputFormat {
    Text,
    Json,
    Csv,
    Html,
    Pdf,
}

#[derive(Clone, Debug)]
pub struct ReportConfig {
    pub scenario: Scenario,
    pub formats: Vec<OutputFormat>,
    pub output_dir: Option<PathBuf>,
}
```

### Step 5: Implement ReportGenerator

**File: `crates/hardener-compliance/src/generator.rs`**

```rust
use crate::config::{ReportConfig, Scenario};
use crate::report::{ComplianceReport, ComplianceSummary, ControlResult};
use hardener_common::types::{ComplianceFramework, ControlStatus};
use hardener_core::Finding;

pub struct ReportGenerator {
    config: ReportConfig,
}

impl ReportGenerator {
    pub fn new(config: ReportConfig) -> Self {
        Self { config }
    }

    pub fn generate(&self, findings: &[Finding]) -> Vec<ComplianceReport> {
        let frameworks = self.config.scenario.frameworks();

        frameworks.iter().map(|framework| {
            self.generate_for_framework(framework, findings)
        }).collect()
    }

    fn generate_for_framework(&self, framework: &ComplianceFramework, findings: &[Finding]) -> ComplianceReport {
        // Get all controls for this framework
        let all_controls = crate::frameworks::get_controls(framework);

        // Map findings to controls
        let controls: Vec<ControlResult> = all_controls.iter().map(|control| {
            let related_findings: Vec<Finding> = findings.iter()
                .filter(|f| f.finding_compliance.iter().any(|c|
                    c.framework == *framework && c.control_id == control.control_id
                ))
                .cloned()
                .collect();

            let status = if related_findings.is_empty() {
                ControlStatus::Pass
            } else {
                ControlStatus::Fail
            };

            ControlResult {
                control_id: control.control_id.clone(),
                control_title: control.control_title.clone(),
                section: control.section.clone().unwrap_or_default(),
                status,
                findings: related_findings,
            }
        }).collect();

        // Calculate summary
        let summary = ComplianceSummary {
            total_controls: controls.len(),
            passing: controls.iter().filter(|c| c.status == ControlStatus::Pass).count(),
            failing: controls.iter().filter(|c| c.status == ControlStatus::Fail).count(),
            not_applicable: controls.iter().filter(|c| c.status == ControlStatus::NotApplicable).count(),
            manual_review: controls.iter().filter(|c| c.status == ControlStatus::ManualReview).count(),
            score_percentage: 0.0, // Calculate below
        };

        let summary = ComplianceSummary {
            score_percentage: (summary.passing as f64 / summary.total_controls as f64) * 100.0,
            ..summary
        };

        ComplianceReport {
            framework: framework.clone(),
            generated_at: chrono::Utc::now(),
            controls,
            summary,
        }
    }
}
```

### Step 6: Add CLI Report Command

**File: `crates/hardener-cli/src/commands/report.rs`**

```rust
use anyhow::Result;
use hardener_compliance::{ReportConfig, ReportGenerator, ReportFormatter, Scenario, OutputFormat};
use std::io::{self, Write};

pub async fn run_interactive() -> Result<()> {
    println!("═══ Compliance Report Generator ═══\n");

    // Scenario selection
    println!("What is your use case?");
    println!("  [1] Server (production systems)");
    println!("  [2] Workstation (desktop/laptop)");
    println!("  [3] Government (STIG/NIST compliance)");
    println!("  [4] Healthcare (HIPAA)");
    println!("  [5] Financial (PCI-DSS)");
    println!("  [6] GDPR (EU data protection)");
    println!("  [7] All frameworks (comprehensive check)");
    println!("  [8] Custom (select specific frameworks)");
    print!("\nSelect scenario [1-8]: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let scenario = match input.trim() {
        "1" => Scenario::Server,
        "2" => Scenario::Workstation,
        "3" => Scenario::Government,
        "4" => Scenario::Healthcare,
        "5" => Scenario::Financial,
        "6" => Scenario::Gdpr,
        "7" => Scenario::All,
        "8" => select_custom_frameworks()?,
        _ => Scenario::Server,
    };

    // Format selection, output path, etc.
    // ... similar interactive prompts ...

    let config = ReportConfig {
        scenario,
        formats: vec![OutputFormat::Text],
        output_dir: None,
    };

    // Generate report using shared logic
    let generator = ReportGenerator::new(config);
    // ... run scan, generate reports, format output ...

    Ok(())
}

pub async fn run_direct(scenario: &str, format: &str, output: Option<&str>) -> Result<()> {
    // Non-interactive mode for scripting
    // ... parse args, build config, generate report ...
    Ok(())
}
```

### Step 7: Update CLI Main

**File: `crates/hardener-cli/src/cli.rs`**

Add to Commands enum:
```rust
#[derive(Subcommand)]
pub enum Commands {
    // ... existing commands ...

    /// Generate compliance reports
    Report {
        /// Use case scenario (server, workstation, government, healthcare, financial, gdpr, all)
        #[arg(short, long)]
        scenario: Option<String>,

        /// Output format(s): text, json, csv, html, pdf (comma-separated)
        #[arg(short, long)]
        format: Option<String>,

        /// Output file or directory
        #[arg(short, long)]
        output: Option<String>,
    },
}
```

### Step 8: Example CIS Framework Mapping

**File: `crates/hardener-compliance/src/frameworks/cis.rs`**

```rust
use hardener_common::types::ComplianceMapping;

pub fn get_controls() -> Vec<ComplianceMapping> {
    vec![
        // Section 1: Initial Setup
        ComplianceMapping {
            framework: ComplianceFramework::Cis,
            control_id: "1.5.1".to_string(),
            control_title: "Ensure ASLR is enabled".to_string(),
            section: Some("Initial Setup".to_string()),
        },
        ComplianceMapping {
            framework: ComplianceFramework::Cis,
            control_id: "1.5.2".to_string(),
            control_title: "Ensure ptrace scope is restricted".to_string(),
            section: Some("Initial Setup".to_string()),
        },
        // ... more controls ...

        // Section 5: Access Control
        ComplianceMapping {
            framework: ComplianceFramework::Cis,
            control_id: "5.2.1".to_string(),
            control_title: "Ensure SSH root login is disabled".to_string(),
            section: Some("Access Control".to_string()),
        },
        // ... etc ...
    ]
}
```

### Step 9: Update Plugins with Compliance Mappings

Example for kernel plugin:

**File: `crates/hardener-plugins/src/kernel/mod.rs`**

When creating findings, add compliance mappings:

```rust
Finding {
    finding_id: "kernel_aslr".to_string(),
    finding_title: "ASLR not fully enabled".to_string(),
    // ... other fields ...
    finding_compliance: vec![
        ComplianceMapping {
            framework: ComplianceFramework::Cis,
            control_id: "1.5.1".to_string(),
            control_title: "Ensure ASLR is enabled".to_string(),
            section: Some("Initial Setup".to_string()),
        },
        ComplianceMapping {
            framework: ComplianceFramework::Stig,
            control_id: "V-230223".to_string(),
            control_title: "RHEL 8 must implement ASLR".to_string(),
            section: None,
        },
    ],
}
```

---

## Dependencies to Add

**Workspace Cargo.toml:**
```toml
[workspace.dependencies]
# For PDF generation (optional, can be added later)
printpdf = "0.7"
```

**hardener-compliance Cargo.toml:**
```toml
[dependencies]
hardener-common = { path = "../hardener-common" }
hardener-core = { path = "../hardener-core" }
serde = { workspace = true }
serde_json = { workspace = true }
chrono = "0.4"
csv = "1.3"  # For CSV output

# Optional for HTML/PDF
askama = "0.12"  # HTML templating
printpdf = { workspace = true, optional = true }

[features]
default = []
pdf = ["printpdf"]
```

---

## Testing Strategy

1. Unit tests for each formatter (text, json, csv, html)
2. Integration tests that run a scan and generate reports
3. Test each scenario produces correct frameworks
4. Test custom framework selection
5. Test output file creation

---

## Notes for Implementation

- The `hardener-compliance` crate already exists but may need restructuring
- Start with CIS framework (most common), then add others
- PDF generation is complex - consider making it optional or using an external tool
- HTML output can use embedded CSS for styling
- CSV should include: control_id, control_title, status, finding_count, section

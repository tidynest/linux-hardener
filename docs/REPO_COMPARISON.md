# Repository Comparison Report: Local vs GitHub

**Generated:** 2026-01-29
**Local Repository:** `/home/bakri/RustroverProjects/linux-system-hardener/`
**GitHub Repository:** `tidynest/linux-system-hardener`

---

## Executive Summary

**Critical Issues Found:** 5
**Warnings:** 3
**Sync Status:** OUT OF SYNC - Multiple divergences detected

The local repository has significant uncommitted work, is 2 commits ahead of the last known remote state, and the remote has 2 commits (Dependabot PR merge) that are not in the local repository. Additionally, the local `main` branch diverged from `master` significantly in the past.

---

## 1. Version Discrepancies

| Location | Version | Notes |
|----------|---------|-------|
| **GitHub Cargo.toml** | 0.3.2 | Last pushed version |
| **Local Cargo.toml (master)** | 0.3.2 | Current working version |
| **Local Cargo.toml (main)** | 0.1.0 | **CRITICAL**: Old divergent branch |
| **README.md (GitHub)** | 0.3.2 | Matches Cargo.toml |
| **README.md (Local master)** | 0.3.2 | Matches |
| **README.md (Local main)** | 0.3.0 | Outdated |

**Action Required:** The local `main` branch is severely outdated and should NOT be used for development.

---

## 2. Branch State Analysis

### Local Branches
| Branch | Commit | Tracks | Status |
|--------|--------|--------|--------|
| `master` (HEAD) | `a1dbdc6` | `gitlab/master` | Ahead by 2 commits |
| `main` | `4bb37ea` | None | Diverged, 31+ commits behind master |

### Remote Tracking
| Remote | URL | Status |
|--------|-----|--------|
| `origin` | `git@github.com:tidynest/linux-system-hardener.git` | SSH auth failing |
| `gitlab` | `git@gitlab.com:tidynest/linux-system-hardener.git` | SSH auth failing |

### GitHub State
| Branch | Commit SHA | Notes |
|--------|------------|-------|
| `main` | `8418669` | Has Dependabot merge |
| `master` | Unknown | Not verified |

---

## 3. Commit Comparison

### Commits on Local (master) NOT on GitHub
```
a1dbdc6 docs: add GUI/CLI feature parity improvement plan
300d454 refactor(core): fix field naming conventions and add report descriptions
```
**Status:** These 2 commits exist locally but have not been pushed to GitHub.

### Commits on GitHub NOT in Local
```
ddcf180 chore(deps): bump rsa from 0.9.9 to 0.9.10
8418669 Merge pull request #2 from tidynest/dependabot/cargo/rsa-0.9.10
```
**Status:** Dependabot security update merged on GitHub but not pulled locally.

### Common Ancestor
```
bb124a5 chore: add RHEL container script and update dependencies
```
This is the last commit both local and GitHub share.

---

## 4. Uncommitted Local Changes

### Modified Files (12 files)
| File | Change Type | Impact |
|------|-------------|--------|
| `CHANGELOG.md` | Modified | +21 lines (GUI/CLI Parity Phase 1) |
| `NEXT.md` | Modified | Development notes updated |
| `crates/hardener-cli/src/commands/apply.rs` | Modified | Short plugin name expansion added |
| `crates/hardener-cli/src/output.rs` | Modified | **CRITICAL FIX**: JSON/text output format inverted |
| `crates/hardener-ui/dist/.../inline0.js` | Deleted | Build artifact |
| `crates/hardener-ui/src/components/configure_section.rs` | Modified | Preview & Apply flow added |
| `crates/hardener-ui/src/state/mod.rs` | Modified | Preview state signals added |
| `crates/hardener-ui/src/tauri_bindings.rs` | Modified | `invoke_apply_dry_run` binding |
| `crates/hardener-ui/styles.css` | Modified | Preview panel styles |
| `docs/GUI_CLI_PARITY_PLAN.md` | Modified | Phase 1 marked complete |
| `src-tauri/src/commands.rs` | Modified | `run_apply_dry_run` command added |
| `src-tauri/src/main.rs` | Modified | Command registration |

### Diff Statistics
```
12 files changed, 405 insertions(+), 108 deletions(-)
```

### Untracked Files (2 files)
| File | Purpose |
|------|---------|
| `NEXT2.md` | Development notes (32KB) |
| `PLAN2.md` | Development plans (29KB) |

---

## 5. Critical File Differences

### CHANGELOG.md
**Local has additional section:**
```markdown
### Added (GUI/CLI Feature Parity - Phase 1)
- Preview & Apply Flow: Users can now preview changes before applying
- `run_apply_dry_run` Tauri Command: Backend support for dry-run preview
- Preview State Signals: Leptos reactive state for preview workflow
- Short Plugin Name Support for Apply: `apply --plugin kernel` now works

### Fixed (GUI/CLI Feature Parity - Phase 1)
- CLI Output Format Inverted: Fixed 7 functions in output.rs
- Dry-run JSON Not Array: Changed to single array output
```
**GitHub version missing this section entirely.**

### output.rs (CRITICAL BUG FIX)
The local version contains a critical fix where the `--format json` flag was outputting text and vice versa. This affects 7 functions:
- `scan_results`
- `apply_results`
- `plugin_list`
- `checkpoint_list`
- `checkpoint_created`
- `checkpoint_details`
- `validation_reports`

**GitHub version has this bug unfixed.**

### src-tauri/src/commands.rs
Local adds new Tauri command:
```rust
#[tauri::command]
pub async fn run_apply_dry_run(plugin_ids: Vec<String>) -> Result<Vec<ValidationReport>, String>
```
**GitHub version missing this command.**

---

## 6. Documentation Differences

### Files Only in Local (Not on GitHub)
| File | Size | Purpose |
|------|------|---------|
| `docs/GUI_CLI_PARITY_PLAN.md` | 10KB | GUI feature parity planning |
| `docs/browser-automation.md` | 17KB | Development docs |
| `docs/claude-code-configuration.md` | - | AI assistant config |
| `docs/css-architecture.md` | - | CSS design docs |
| `docs/DOCUMENTATION_AUDIT.md` | - | Audit results |
| `docs/FRONTEND_LAYOUT_PLAN.md` | - | UI layout planning |
| `docs/GUI_V031_TEST_PLAN.md` | - | GUI test plan |
| `docs/tauri-plus-leptos-development-on-arch-linux-with-hyprland.md` | - | Development guide |

**8 documentation files exist locally but not on GitHub.**

### Files on Both (May Differ)
- All files in `docs/` may have content differences not compared in detail.

---

## 7. Crate Structure Comparison

### Workspace Members (Identical)
Both local and GitHub have identical crate structure:
```
crates/
  hardener-cli
  hardener-common
  hardener-compliance
  hardener-core
  hardener-distro
  hardener-plugins
  hardener-scheduler
  hardener-state
  hardener-types
  hardener-ui
src-tauri/
```

**No structural differences in crate organisation.**

---

## 8. CI/CD Status

### Last GitHub Actions Runs
| Status | Workflow | Branch | Date |
|--------|----------|--------|------|
| success | CI | main | 2026-01-20 |
| success | CI | dependabot/cargo/rsa-0.9.10 | 2026-01-06 |
| success | CI | main | 2025-12-11 |
| success | CI | master | 2025-12-11 |

**CI is passing on GitHub** with the Dependabot merge. Local uncommitted changes are untested by CI.

---

## 9. SSH Authentication Issue

Both `origin` (GitHub) and `gitlab` remotes are failing SSH authentication:
```
Permission denied (publickey).
```
**This prevents:** `git fetch`, `git pull`, `git push`

**Resolution Required:** Configure SSH keys or use HTTPS URLs.

---

## 10. Risk Assessment

### High Risk
1. **Uncommitted Bug Fix**: The `output.rs` format fix is critical but not pushed
2. **Branch Divergence**: Local `main` is severely outdated (version 0.1.0)
3. **Missing Remote Updates**: Dependabot security update not pulled

### Medium Risk
4. **Uncommitted Features**: GUI/CLI Parity Phase 1 work not backed up
5. **Untracked Files**: `NEXT2.md` and `PLAN2.md` contain development context

### Low Risk
6. **Documentation Gap**: 8 docs files only exist locally
7. **SSH Auth Failure**: Blocks normal git operations

---

## 11. Action Items

### Immediate (Priority 1)
- [ ] **Fix SSH authentication** or switch to HTTPS remotes
- [ ] **Pull Dependabot update**: `git pull origin main` (after auth fix)
- [ ] **Commit local changes**: Uncommitted work at risk of loss

### Short-term (Priority 2)
- [ ] **Push to GitHub**: 2 local commits + uncommitted work
- [ ] **Sync branches**: Ensure `main` and `master` are aligned
- [ ] **Track untracked files**: Commit or `.gitignore` NEXT2.md/PLAN2.md

### Cleanup (Priority 3)
- [ ] **Delete local `main` branch**: It's severely diverged and unused
- [ ] **Verify CI passes**: After pushing local changes
- [ ] **Update remote tracking**: Set `master` to track `origin/master`

---

## 12. Recommended Sync Procedure

```bash
# 1. Fix authentication (HTTPS approach)
git remote set-url origin https://github.com/tidynest/linux-system-hardener.git

# 2. Fetch latest from GitHub
git fetch origin

# 3. Check if rebase or merge needed
git log origin/main..HEAD --oneline  # Local commits not on remote
git log HEAD..origin/main --oneline  # Remote commits not local

# 4. Commit local changes (after review)
git add CHANGELOG.md NEXT.md docs/GUI_CLI_PARITY_PLAN.md
git add crates/hardener-cli/src/commands/apply.rs
git add crates/hardener-cli/src/output.rs
git add crates/hardener-ui/src/components/configure_section.rs
git add crates/hardener-ui/src/state/mod.rs
git add crates/hardener-ui/src/tauri_bindings.rs
git add crates/hardener-ui/styles.css
git add src-tauri/src/commands.rs src-tauri/src/main.rs
git commit -m "feat(ui): add Preview & Apply flow for GUI/CLI parity Phase 1"

# 5. Rebase onto latest remote (preserves local commits)
git rebase origin/main

# 6. Push to GitHub
git push origin master:main  # or appropriate branch

# 7. Clean up diverged local main branch
git branch -D main  # Delete severely outdated local main
git checkout -b main origin/main  # Create fresh tracking branch
```

---

## 13. Summary

| Metric | Value |
|--------|-------|
| **Local commits not on GitHub** | 2 |
| **GitHub commits not in local** | 2 |
| **Uncommitted file changes** | 12 |
| **Untracked files** | 2 |
| **Local documentation files not on GitHub** | 8 |
| **Version alignment** | PARTIAL (master matches, main diverged) |
| **CI status** | Passing (GitHub) |
| **SSH authentication** | FAILING |

**Overall Status:** The repositories are OUT OF SYNC with both local-only and remote-only changes. Immediate action required to avoid losing uncommitted work and to incorporate the Dependabot security update.

---

*Report generated by repository comparison analysis*

# linux-system-hardener - Pending Tasks

> Generated: 2026-01-29
> Status: Awaiting user presence for implementation

---

## Repository Synchronization Issues

### SSH Authentication (Blocking)
- Both `origin` (GitHub) and `gitlab` remotes failing SSH auth
- **Options:**
  1. Fix SSH key configuration
  2. Switch remotes to HTTPS URLs

### Uncommitted Local Work (12 files, +405/-108 lines)

GUI/CLI Parity Phase 1 work at risk:

| File | Changes |
|------|---------|
| `crates/hardener-cli/src/output.rs` | Critical bug fix (JSON/text format inverted) |
| `crates/hardener-core/src/apply/mod.rs` | Apply functionality |
| `crates/hardener-ui/src/lib.rs` | UI integration |
| `crates/hardener-ui/src/pages/apply.rs` | Preview & Apply flow |
| `crates/hardener-ui/src/tauri_commands.rs` | New `run_apply_dry_run` command |
| Plus 7 more files | Short plugin name support, etc. |

### Commits Not on GitHub

Local `master` has 2 unpushed commits:
1. `a1dbdc6` - docs: add GUI/CLI feature parity improvement plan
2. `300d454` - refactor(core): fix field naming conventions and add report descriptions

### Commits Missing Locally

Remote has 2 commits not in local:
1. `ddcf180` - chore(deps): bump rsa from 0.9.9 to 0.9.10 (Dependabot)
2. `8418669` - Merge pull request #2 (security update)

### Branch Issue

Local `main` branch is at v0.1.0 (commit `4bb37ea`) - severely diverged from `master` (v0.3.2).

**Action:** Delete local `main`, recreate from remote after sync.

---

## Documentation Not on GitHub

These 8 files exist locally but not pushed:

1. `GUI_CLI_PARITY_PLAN.md`
2. `browser-automation.md`
3. `claude-code-configuration.md`
4. `css-architecture.md`
5. `DOCUMENTATION_AUDIT.md`
6. `FRONTEND_LAYOUT_PLAN.md`
7. `GUI_V031_TEST_PLAN.md`
8. `tauri-plus-leptos-development-on-arch-linux-with-hyprland.md`

---

## Sync Procedure (When Ready)

```bash
# 1. Check current state
cd ~/RustroverProjects/linux-system-hardener
git status
git stash  # if needed to save uncommitted work temporarily

# 2. Fix remote (option A: HTTPS)
git remote set-url origin https://github.com/tidynest/linux-system-hardener.git

# 3. Fetch and check divergence
git fetch origin
git log --oneline origin/master..HEAD  # local ahead
git log --oneline HEAD..origin/master  # remote ahead

# 4. Rebase or merge
git rebase origin/master  # or git merge origin/master

# 5. Apply stashed changes
git stash pop

# 6. Commit and push
git add -A
git commit -m "feat(ui): GUI/CLI parity phase 1 - preview and apply flow"
git push origin master

# 7. Fix main branch
git branch -D main
git checkout -b main origin/main
```

---

## Version Status

| Location | Version | Notes |
|----------|---------|-------|
| GitHub master | 0.3.2 | + Dependabot RSA update |
| Local master | 0.3.2 | - Dependabot, + uncommitted work |
| Local main | 0.1.0 | BROKEN - do not use |

---

*See also: `REPO_COMPARISON.md` in this directory for full analysis*

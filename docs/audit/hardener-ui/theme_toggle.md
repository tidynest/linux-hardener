# hardener-ui::components::theme_toggle
**File:** `crates/hardener-ui/src/components/theme_toggle.rs` | **Lines:** 89

## Purpose
Theme switcher with 6 themes and localStorage persistence. Sets `data-theme` attribute
on the `<html>` element to drive CSS custom properties.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ThemeToggle` | component | Dropdown theme selector with 6 options and persistence |

## Internal Details
| Item | Description |
|------|-------------|
| Themes | Midnight Teal, Fortress, Sentinel, Command, Guardian, Daywatch |
| Persistence | Reads/writes `localStorage("hardener-theme")` |
| DOM update | Sets `document.documentElement.dataset.theme` on selection |
| Safe chaining | Uses `.and_then()` chains for DOM/storage access — no panics on missing APIs |

## Flags
None.

# hardener-ui::components::form_helpers
**File:** `crates/hardener-ui/src/components/form_helpers.rs` | **Lines:** 30

## Purpose
Shared utility module for JsCast event target extraction. Eliminates duplicated
`event.target().dyn_into::<HtmlInputElement>()` boilerplate across form components.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `input_value(event)` | fn | Extracts `String` value from `web_sys::Event` targeting `HtmlInputElement` |
| `checkbox_checked(event)` | fn | Extracts `bool` checked state from `web_sys::Event` targeting `HtmlInputElement` |
| `select_value(event)` | fn | Extracts `String` value from `web_sys::Event` targeting `HtmlSelectElement` |

## Design Notes
- Not re-exported from `components/mod.rs` — used internally by component modules
- Extracted in `e8742a0` to reduce code duplication across form-heavy components (HostForm, ScheduleSection, NotificationSection, ConfigFileCard)

## Flags
None.

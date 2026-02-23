# hardener-ui::utils::mock_data
**File:** `crates/hardener-ui/src/utils/mock_data.rs` | **Lines:** 106

## Purpose
Mock scan results for UI development and testing. Provides three pre-built `ScanResult`
objects (kernel, SSH, firewall) with realistic finding data.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `create_mock_scan_results` | fn | Returns `Vec<ScanResult>` with 3 mock plugin results |

## Internal Details
| Item | Description |
|------|-------------|
| Kernel mock | Sample findings for kernel parameter hardening |
| SSH mock | Sample findings for SSH configuration |
| Firewall mock | Sample findings for firewall rules |
| Dead-code gate | Module gated with `#[allow(dead_code)]` in `utils/mod.rs` — used in dev builds only |

## Flags
None.

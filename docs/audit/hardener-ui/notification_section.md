# hardener-ui::components::notification_section
**File:** `crates/hardener-ui/src/components/notification_section.rs` | **Lines:** 255

## Purpose
Email and webhook notification configuration. Part of the scheduler settings page.
Allows configuring email recipients, from address, webhook URL/format, and testing
notification delivery.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `NotificationSection` | component | Email + webhook notification settings with test button |

## Internal Details
| Item | Description |
|------|-------------|
| Email config | Enable/disable, recipients list, from address |
| Webhook config | Enable/disable, URL, format (JSON/text) |
| Min severity | Notification threshold separate from scan threshold |
| Test button | Calls `invoke_test_notification()` and displays `TestNotificationResult` |
| Validation | Client-side validation for email format, URL format |

## Flags
None.

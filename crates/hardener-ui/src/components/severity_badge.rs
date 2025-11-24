use hardener_common::types::Severity;
use leptos::prelude::*;

/// Displays a severity level with colour-coded badge.
///
/// CSS classes used:
/// - `severity-badge`      - Base badge styling
/// - `severity-critical`   - Red styling for Critical severity
/// - `severity-high` - Orange styling for High severity
/// - `severity-medium` - Yellow styling for Medium severity
/// - `severity-low` - Blue styling for Low severity
/// - `severity-info` - Grey styling for Info severity
#[component]
pub fn SeverityBadge(
    /// The severity level to display.
    severity: Severity,
) -> impl IntoView {
    let severity_class = match severity {
        Severity::Critical => "severity_critical",
        Severity::High     => "severity_high",
        Severity::Medium   => "severity_medium",
        Severity::Low      => "severity_low",
        Severity::Info     => "severity_info",
    };
    
    let severity_text = match severity {
        Severity::Critical => "Critical",
        Severity::High     => "High",
        Severity::Medium   => "Medium",
        Severity::Low      => "Low",
        Severity::Info     => "Info",
    };
    
    view! {
        <span class={format!("severity_badge {}", severity_class)}> 
            {severity_text}
        </span>
    }
}

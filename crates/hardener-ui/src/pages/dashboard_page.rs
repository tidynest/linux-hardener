use leptos::prelude::*;

use crate::components::{QuickActions, SecurityScore};

/// Dashboard page showing system security overview.
///
/// This is the main landing page displaying:
/// - Security score calculated from all findings
/// - Quick action buttons for common tasks
/// - Overall system security status
#[component]
pub fn DashboardPage() -> impl IntoView {
    view! {
        <article class="dashboard-page">
            <h1>"System Security Dashboard"</h1>
            <p class="dashboard-intro">
                "Monitor your system's security posture and take quick actions to improve it."
            </p>

            <section class="dashboard-grid">
                <section class="dashboard-section">
                    <SecurityScore/>
                </section>

                <section class="dashboard-section">
                    <QuickActions/>
                </section>
            </section>

            <footer class="dashboard-footer">
                <p class="help-text">
                    "Click 'Run Scan' to analyse your system security. Results will appear in the Scanner page."
                </p>
            </footer>
        </article>
    }
}

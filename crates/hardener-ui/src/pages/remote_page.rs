//! Remote scanning page — manage SSH hosts and scan remote systems.

use crate::components::Card;
use crate::state::AppState;
use leptos::prelude::*;

/// Remote scanning page with two-panel layout:
/// left panel for saved hosts, right panel for connection status and scan results.
#[component]
pub fn RemotePage() -> impl IntoView {
    let _app_state = expect_context::<AppState>();

    view! {
        <div class="remote-page">
            <Card title="Remote Scanning".to_string()>
                <div class="remote-layout">
                    <aside class="remote-sidebar">
                        <p class="help-text">"Host list will go here."</p>
                    </aside>
                    <section class="remote-main">
                        <p class="help-text">"Select a host or add a new one to get started."</p>
                    </section>
                </div>
            </Card>
        </div>
    }
}

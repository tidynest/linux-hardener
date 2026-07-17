//! Scheduler configuration page: manage scan schedules and notifications.

use crate::components::{Card, NotificationSection, ScheduleSection};
use crate::state::AppState;
use crate::tauri_bindings;
use leptos::prelude::*;

/// Scheduler page with two sections: schedule and notifications.
///
/// Loads the scheduler configuration from the backend on mount and stores
/// it in `AppState.scheduler_config`. Each child section reads from and
/// writes back to that shared signal, ensuring both halves of the config
/// stay in sync.
#[component]
pub fn SchedulerPage() -> impl IntoView {
    let app_state = expect_context::<AppState>();

    // Load scheduler config on mount
    leptos::task::spawn_local(async move {
        match tauri_bindings::invoke_get_scheduler_config().await {
            Ok(config) => app_state.scheduler_config.set(Some(config)),
            Err(e) => {
                web_sys::console::warn_1(&format!("Failed to load scheduler config: {e}").into());
            }
        }
    });

    view! {
        <div class="scheduler-page">
            <Card title="Schedule".to_string()>
                <ScheduleSection />
            </Card>
            <Card title="Notifications".to_string()>
                <NotificationSection />
            </Card>
        </div>
    }
}

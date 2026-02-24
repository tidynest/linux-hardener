//! Remote scanning page — manage SSH hosts and scan remote systems.

use crate::components::{Card, HostForm, HostList, RemoteStatus};
use hardener_types::remote::RemoteHostProfile;
use leptos::prelude::*;

/// Remote scanning page with two-panel layout:
/// left sidebar toggles between host list and add/edit form,
/// right panel always shows connection status and scan results.
#[component]
pub fn RemotePage() -> impl IntoView {
    let show_form = RwSignal::new(false);
    let editing_host = RwSignal::new(None::<RemoteHostProfile>);

    // HostList requests to add (None) or edit (Some) a host.
    let on_edit = move |host: Option<RemoteHostProfile>| {
        editing_host.set(host);
        show_form.set(true);
    };

    // HostForm signals that it has finished (saved or cancelled).
    let on_form_close = move |_: ()| {
        show_form.set(false);
        editing_host.set(None);
    };

    view! {
        <div class="remote-page">
            <Card title="Remote Scanning".to_string()>
                <div class="remote-layout">
                    <aside class="remote-sidebar">
                        <Show
                            when=move || show_form.get()
                            fallback=move || view! {
                                <HostList on_edit=on_edit />
                            }
                        >
                            <HostForm
                                existing=editing_host.get()
                                on_close=on_form_close
                            />
                        </Show>
                    </aside>
                    <section class="remote-main">
                        <RemoteStatus />
                    </section>
                </div>
            </Card>
        </div>
    }
}

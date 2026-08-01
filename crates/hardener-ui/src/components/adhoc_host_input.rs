//! Ad-hoc host input: add `user@host[:port]` targets not saved in the
//! inventory. Shared by the Fleet and Fleet Apply pages.

use crate::components::form_helpers::input_value;
use hardener_types::remote::RemoteHostProfile;
use leptos::prelude::*;

/// Client-side validation for one ad-hoc target; mirrors the backend guard
/// (`adhoc_profile` in src-tauri) so bad input fails before the IPC call.
fn target_error(target: &str, existing: &[String]) -> Option<String> {
    if target.is_empty() {
        return Some("Enter user@host[:port]".to_string());
    }
    let profile = RemoteHostProfile::from_target(target, 22, None, true);
    if !RemoteHostProfile::is_valid_hostname(&profile.hostname) {
        return Some(format!("Invalid target '{target}': invalid hostname"));
    }
    if existing.iter().any(|e| e == target) {
        return Some(format!("'{target}' already added"));
    }
    None
}

/// Text input + removable chips for ad-hoc SSH targets. `on_change` fires on
/// every add/remove so callers can invalidate stale state (e.g. the Fleet
/// Apply dry-run gate).
#[component]
pub fn AdhocHostInput(
    adhoc: RwSignal<Vec<String>>,
    #[prop(optional)] on_change: Option<Callback<()>>,
) -> impl IntoView {
    let draft = RwSignal::new(String::new());
    let input_error = RwSignal::new(None::<String>);

    let notify = move || {
        if let Some(cb) = on_change {
            cb.run(());
        }
    };

    let add = move || {
        let raw = draft.get().trim().to_string();
        match target_error(&raw, &adhoc.get()) {
            Some(e) => input_error.set(Some(e)),
            None => {
                // Store the canonical user@host:port form: it is the batch
                // history key, so display name and persisted key agree.
                let canonical = RemoteHostProfile::from_target(&raw, 22, None, true).target();
                if adhoc.with(|v| v.contains(&canonical)) {
                    input_error.set(Some(format!("'{canonical}' already added")));
                    return;
                }
                adhoc.update(|v| v.push(canonical));
                draft.set(String::new());
                input_error.set(None);
                notify();
            }
        }
    };
    let remove = move |target: String| {
        adhoc.update(|v| v.retain(|t| t != &target));
        notify();
    };

    view! {
        <fieldset class="fleet-host-select">
            <legend>"Ad-hoc hosts (not saved)"</legend>
            <div class="fleet-adhoc-row">
                <input
                    type="text"
                    placeholder="user@host[:port]"
                    aria-label="Ad-hoc SSH target"
                    prop:value=draft
                    on:input=move |ev| draft.set(input_value(&ev))
                    on:keydown=move |ev| {
                        if ev.key() == "Enter" {
                            ev.prevent_default();
                            add();
                        }
                    }
                />
                <button
                    type="button"
                    class="btn btn-secondary"
                    on:click=move |_| add()
                    disabled=move || draft.get().trim().is_empty()
                >
                    "Add"
                </button>
            </div>
            <Show when=move || input_error.get().is_some()>
                <p class="error-banner" role="alert">{move || input_error.get().unwrap_or_default()}</p>
            </Show>
            {move || {
                adhoc
                    .get()
                    .into_iter()
                    .map(|target| {
                        let label = target.clone();
                        let on_remove = move |_| remove(target.clone());
                        view! {
                            <span class="fleet-host-option">
                                {label.clone()}
                                <button
                                    type="button"
                                    class="btn btn-secondary"
                                    aria-label=format!("Remove {label}")
                                    on:click=on_remove
                                >
                                    "\u{00d7}"
                                </button>
                            </span>
                        }
                    })
                    .collect_view()
            }}
        </fieldset>
    }
}

#[cfg(test)]
mod tests;

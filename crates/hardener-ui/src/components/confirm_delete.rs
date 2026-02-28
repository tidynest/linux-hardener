//! Inline delete confirmation button to prevent accidental destructive actions.

use leptos::prelude::*;

/// A "Delete" button that expands to an inline "Delete? [Confirm] [Cancel]" prompt.
///
/// Uses a shared `pending` signal so only one item in a list shows confirmation at a time.
#[component]
pub fn ConfirmDeleteButton(
    /// Unique key for this item (compared against `pending` to show/hide confirmation).
    #[prop(into)]
    item_key: String,
    /// Shared signal tracking which item (if any) is awaiting confirmation.
    pending: RwSignal<Option<String>>,
    /// Called with the item key when the user confirms deletion.
    #[prop(into)]
    on_confirm: Callback<String>,
) -> impl IntoView {
    let key_for_check = item_key.clone();
    let key_for_arm = item_key.clone();
    let key_for_fire = item_key.clone();

    let is_confirming = move || pending.get().as_deref() == Some(key_for_check.as_str());

    view! {
        <Show
            when=is_confirming
            fallback=move || {
                let k = key_for_arm.clone();
                view! {
                    <button
                        class="btn btn-danger btn-small"
                        on:click=move |_| pending.set(Some(k.clone()))
                    >
                        "Delete"
                    </button>
                }
            }
        >
            <span class="confirm-delete-inline">
                <span class="confirm-delete-label">"Delete?"</span>
                <button
                    class="btn btn-danger btn-small"
                    on:click={
                        let k = key_for_fire.clone();
                        move |_| {
                            pending.set(None);
                            on_confirm.run(k.clone());
                        }
                    }
                >
                    "Confirm"
                </button>
                <button
                    class="btn btn-secondary btn-small"
                    on:click=move |_| pending.set(None)
                >
                    "Cancel"
                </button>
            </span>
        </Show>
    }
}

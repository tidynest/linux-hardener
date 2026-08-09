//! The form that accepts one finding as a documented deviation.
//!
//! Reason is required and the other three are optional and start empty. A
//! prefilled expiry would mean the next apply re-disables the thing the operator
//! asked to keep, on a date they never chose; a required one would make this
//! form stricter than the configuration file, which permits a permanent
//! exception.

use super::modal::Modal;
use crate::utils::is_expiry_in_the_past;
use leptos::prelude::*;

/// Today, as the `YYYY-MM-DD` an `<input type="date">` and
/// [`is_expiry_in_the_past`] both use.
///
/// `apply_written_exception` hardcodes `exception_is_expired: false` on a
/// fresh write rather than recomputing `PolicyException::is_expired`, so this
/// modal is the only place left that can refuse an expiry the operator typed
/// as already lapsed.
fn today_iso() -> String {
    let now = js_sys::Date::new_0();
    format!(
        "{:04}-{:02}-{:02}",
        now.get_full_year(),
        now.get_month() + 1,
        now.get_date()
    )
}

/// What the operator typed. The value is deliberately absent: the host is
/// re-read at write time and supplies its own.
#[derive(Clone, Debug, Default)]
pub struct ExceptionDraft {
    pub reason: String,
    pub approved_by: Option<String>,
    pub ticket: Option<String>,
    pub expires: Option<String>,
}

#[component]
pub fn ExceptionModal(
    finding_title: String,
    #[prop(into)] on_submit: Callback<ExceptionDraft>,
    #[prop(into)] on_dismiss: Callback<()>,
    /// A write failure, rendered inside this dialog rather than the global
    /// banner. The banner sits in normal document flow behind the modal
    /// backdrop's `z-index: 50`, so an error placed there is half-dimmed, its
    /// dismiss button unreachable, and a click meant for it lands on the
    /// backdrop instead and discards the reason the operator just typed.
    #[prop(into)]
    error: Signal<Option<String>>,
) -> impl IntoView {
    let reason = RwSignal::new(String::new());
    let approved_by = RwSignal::new(String::new());
    let ticket = RwSignal::new(String::new());
    let expires = RwSignal::new(String::new());
    let today = today_iso();
    let expiry_in_past = {
        let today = today.clone();
        Signal::derive(move || is_expiry_in_the_past(&expires.get(), &today))
    };
    let can_submit =
        Signal::derive(move || !reason.get().trim().is_empty() && !expiry_in_past.get());

    let optional = |s: String| {
        let trimmed = s.trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    };

    view! {
        <Modal on_dismiss=on_dismiss aria_label="Accept this finding" class="exception-modal">
            <h2 class="modal-title">"Accept This Finding"</h2>
            <p class="modal-subtitle">{finding_title}</p>
            <label class="field-label" for="exception-reason">"Reason"</label>
            <input
                id="exception-reason"
                class="field-input"
                type="text"
                required
                prop:value=move || reason.get()
                on:input=move |ev| reason.set(event_target_value(&ev))
            />
            <label class="field-label" for="exception-approved-by">"Approved By (optional)"</label>
            <input id="exception-approved-by" class="field-input" type="text"
                prop:value=move || approved_by.get()
                on:input=move |ev| approved_by.set(event_target_value(&ev)) />
            <label class="field-label" for="exception-ticket">"Ticket (optional)"</label>
            <input id="exception-ticket" class="field-input" type="text"
                prop:value=move || ticket.get()
                on:input=move |ev| ticket.set(event_target_value(&ev)) />
            <label class="field-label" for="exception-expires">"Expires (optional)"</label>
            <input id="exception-expires" class="field-input" type="date" min=today
                prop:value=move || expires.get()
                on:input=move |ev| expires.set(event_target_value(&ev)) />
            <Show when=move || expiry_in_past.get()>
                <p class="field-error" role="alert">"Expiry date is in the past."</p>
            </Show>
            {move || error.get().map(|msg| view! {
                <p class="modal-error" role="alert">{msg}</p>
            })}
            <div class="modal-actions">
                <button class="btn btn-secondary" on:click=move |_| on_dismiss.run(())>"Cancel"</button>
                <button
                    class="btn btn-primary"
                    disabled=move || !can_submit.get()
                    on:click=move |_| on_submit.run(ExceptionDraft {
                        reason: reason.get().trim().to_string(),
                        approved_by: optional(approved_by.get()),
                        ticket: optional(ticket.get()),
                        expires: optional(expires.get()),
                    })
                >"Accept Finding"</button>
            </div>
        </Modal>
    }
}

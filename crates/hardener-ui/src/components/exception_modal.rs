//! The form that accepts one finding as a documented deviation.
//!
//! Reason is required and the other three are optional and start empty. A
//! prefilled expiry would mean the next apply re-disables the thing the operator
//! asked to keep, on a date they never chose; a required one would make this
//! form stricter than the configuration file, which permits a permanent
//! exception.

use super::modal::Modal;
use leptos::prelude::*;

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
) -> impl IntoView {
    let reason = RwSignal::new(String::new());
    let approved_by = RwSignal::new(String::new());
    let ticket = RwSignal::new(String::new());
    let expires = RwSignal::new(String::new());
    let can_submit = Signal::derive(move || !reason.get().trim().is_empty());

    let optional = |s: String| {
        let trimmed = s.trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    };

    view! {
        <Modal on_dismiss=on_dismiss aria_label="Accept this finding" class="exception-modal">
            <h2 class="modal-title">"Accept This Finding"</h2>
            <p class="modal-subtitle">{finding_title}</p>
            <label class="field-label" for="exception-reason">"Reason"</label>
            <textarea
                id="exception-reason"
                class="field-input"
                required
                prop:value=move || reason.get()
                on:input=move |ev| reason.set(event_target_value(&ev))
            ></textarea>
            <label class="field-label" for="exception-approved-by">"Approved By (optional)"</label>
            <input id="exception-approved-by" class="field-input" type="text"
                prop:value=move || approved_by.get()
                on:input=move |ev| approved_by.set(event_target_value(&ev)) />
            <label class="field-label" for="exception-ticket">"Ticket (optional)"</label>
            <input id="exception-ticket" class="field-input" type="text"
                prop:value=move || ticket.get()
                on:input=move |ev| ticket.set(event_target_value(&ev)) />
            <label class="field-label" for="exception-expires">"Expires (optional)"</label>
            <input id="exception-expires" class="field-input" type="date"
                prop:value=move || expires.get()
                on:input=move |ev| expires.set(event_target_value(&ev)) />
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

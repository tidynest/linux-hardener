//! Shared modal shell: backdrop, dismissal, focus, and dialog ARIA.
//!
//! Every modal in the application renders through this component so that
//! Escape and a backdrop click always dismiss, and so the focus handling
//! below is solved once rather than rediscovered per modal.
//!
//! Focus matters more than it looks: a `keydown` listener bound inside the
//! dialog subtree only fires when something inside that subtree holds focus,
//! because key events bubble from the focused element. Without focusing the
//! dialog on mount, Escape silently does nothing. The dialog therefore
//! carries `tabindex="-1"` (focusable programmatically, not in tab order)
//! and is focused as soon as it mounts.
//!
//! A caller whose dialog swaps its own contents between stages must also
//! pull focus back after each swap, since removing the focused node drops
//! focus to `<body>` and out of the subtree. Such a caller passes its own
//! `dialog_ref` and runs that effect itself; see `rollback_modal.rs`.
//!
//! Escape is swallowed here rather than left to bubble. `keyboard.rs` binds a
//! keydown listener on `document` whose Escape branch is a priority chain over
//! global `AppState` (error banner, selected finding, preview panel). Without
//! `stop_propagation` a single press would both close this dialog and advance
//! that chain, so dismissing a host or fleet dialog would silently discard a
//! pending apply review. The event is swallowed even when `dismissible` reads
//! false: a modal that refuses to close during an in-flight operation must not
//! let the press reach the global chain either.

use leptos::html;
use leptos::prelude::*;

/// Renders `children` inside a dismissible modal dialog.
///
/// `on_dismiss` fires for both Escape and a backdrop click. `dismissible`
/// defaults to true; while it reads false, both dismissal paths are inert,
/// which is how a modal stays put during an in-flight operation.
#[component]
pub fn Modal(
    #[prop(into)] on_dismiss: Callback<()>,
    #[prop(default = Signal::derive(|| true), into)] dismissible: Signal<bool>,
    #[prop(optional, into)] class: Option<String>,
    #[prop(optional, into)] aria_label: Option<String>,
    #[prop(optional, into)] aria_labelledby: Option<String>,
    #[prop(optional)] dialog_ref: Option<NodeRef<html::Div>>,
    children: Children,
) -> impl IntoView {
    let node = dialog_ref.unwrap_or_default();
    let class = format!(
        "modal{}",
        class.map(|c| format!(" {c}")).unwrap_or_default()
    );

    // Focus the dialog on mount so its keydown handler can see Escape.
    Effect::new(move |_| {
        if let Some(el) = node.get() {
            let _ = el.focus();
        }
    });

    let dismiss = move || {
        if dismissible.get_untracked() {
            on_dismiss.run(());
        }
    };

    // A click event retargets to the nearest common ancestor when its mousedown
    // and mouseup land on different elements, so selecting text inside the
    // dialog and releasing over the backdrop would otherwise dismiss and throw
    // away whatever the user had typed. Only a press that began on the backdrop
    // itself counts as a dismissal.
    let pressed_on_backdrop = StoredValue::new(false);

    view! {
        <div
            class="modal-backdrop"
            on:mousedown=move |ev: web_sys::MouseEvent| {
                pressed_on_backdrop.set_value(ev.target() == ev.current_target());
            }
            on:click=move |_| {
                if pressed_on_backdrop.get_value() {
                    dismiss();
                }
            }
        >
            <div
                class=class
                role="dialog"
                aria-modal="true"
                aria-label=aria_label
                aria-labelledby=aria_labelledby
                tabindex="-1"
                node_ref=node
                on:click=move |ev| ev.stop_propagation()
                on:keydown=move |ev: web_sys::KeyboardEvent| {
                    if ev.key() == "Escape" {
                        ev.stop_propagation();
                        dismiss();
                    }
                }
            >
                {children()}
            </div>
        </div>
    }
}

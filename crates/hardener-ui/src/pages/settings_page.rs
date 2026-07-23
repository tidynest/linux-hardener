//! Settings page: Appearance (theme swatch grid) + About. Presentational over
//! the shared `AppState.theme` signal (via `ThemePicker`); the About block is
//! static compile-time build info. No Save - theme applies live on selection.

use crate::components::ThemePicker;
use leptos::prelude::*;

#[component]
pub fn SettingsPage() -> impl IntoView {
    view! {
        <div class="settings-page">
            <div class="settings-header">
                <h1 class="settings-title">"Settings"</h1>
                <p class="settings-subtitle">
                    "Choose how Hardener looks and see what you are running."
                </p>
            </div>

            <section class="settings-block">
                <h2 class="settings-block-title">"Appearance"</h2>
                <p class="settings-block-hint">
                    "Pick a colour theme. It applies instantly and is remembered on this device."
                </p>
                <ThemePicker/>
            </section>

            <section class="settings-block">
                <h2 class="settings-block-title">"About"</h2>
                <dl class="settings-about">
                    <div class="settings-about-row">
                        <dt>"Application"</dt>
                        <dd>"Linux System Hardener"</dd>
                    </div>
                    <div class="settings-about-row">
                        <dt>"Description"</dt>
                        <dd>
                            "Audit and harden a Linux system against a curated security baseline."
                        </dd>
                    </div>
                    <div class="settings-about-row">
                        <dt>"Version"</dt>
                        <dd>{env!("CARGO_PKG_VERSION")}</dd>
                    </div>
                    <div class="settings-about-row">
                        <dt>"Build"</dt>
                        <dd>{env!("HARDENER_BUILD_IDENTITY")}</dd>
                    </div>
                </dl>
            </section>
        </div>
    }
}

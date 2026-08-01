//! Shared theme metadata plus the single apply/persist side effects. One
//! source for the sidebar quick-switch (`ThemeToggle`) and the Settings page
//! grid (`ThemePicker`); the helpers here are the only writers of the
//! `<html data-theme>` attribute and the `theme` localStorage key.

/// Every selectable theme as `(id, display name)`. The `id` is the
/// `data-theme` attribute value, except `"default"` which is the bare `:root`
/// palette and carries no attribute. The name is the label shown in the
/// quick-switch and the swatch grid.
pub const THEMES: &[(&str, &str)] = &[
    ("default", "Midnight Teal"),
    ("fortress", "Fortress"),
    ("sentinel", "Sentinel"),
    ("command", "Command"),
    ("guardian", "Guardian"),
    ("daywatch", "Daywatch"),
    ("high-contrast", "High Contrast"),
];

/// Applies a theme by setting `data-theme` on `<html>`. The `"default"` theme
/// uses the base `:root` styles, so its attribute is removed rather than set.
pub fn apply_theme(theme: &str) {
    if let Some(document) = web_sys::window().and_then(|w| w.document())
        && let Some(root) = document.document_element()
    {
        if theme == "default" {
            let _ = root.remove_attribute("data-theme");
        } else {
            let _ = root.set_attribute("data-theme", theme);
        }
    }
}

/// Reads the stored theme from localStorage, validated against [`THEMES`].
/// An unknown or absent value yields `None`, so the caller falls back to the
/// default.
pub fn get_stored_theme() -> Option<String> {
    web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|storage| storage.get_item("theme").ok().flatten())
        .filter(|t| THEMES.iter().any(|(id, _)| *id == t.as_str()))
}

/// Persists the selected theme to localStorage.
pub fn store_theme(theme: &str) {
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.set_item("theme", theme);
    }
}

#[cfg(test)]
mod tests;

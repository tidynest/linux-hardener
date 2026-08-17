use leptos::prelude::*;

/// Heading level for card titles.
/// Note: All levels defined for semantic HTML flexibility.
#[derive(Default, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum HeadingLevel {
    H2,
    #[default]
    H3,
    H4,
}

/// Reusable card container component.
///
/// CSS classes used:
/// - `card`            - Base styling (bg-secondary, border, `--border-radius`
///   8px, `--space-lg` 16px padding, plus a hover border-colour transition)
/// - `card-title`      - Title text styling (`--font-size-head` 18px, 600 weight)
///
/// A `CardVariant` enum used to sit here, emitting `card--compact` and
/// `card--empty` for a nested and an empty-state look. Neither class has ever
/// had a rule in `styles.css`, the only stylesheet, and no caller ever passed
/// the prop, so both variants rendered exactly as the default. Deleted rather
/// than styled: the look nobody asked for is cheaper to add back than to carry.
#[component]
pub fn Card(
    /// Optional title displayed in card header.
    #[prop(into, optional)]
    title: Option<String>,
    /// Additional CSS classes to apply.
    #[prop(into, optional)]
    class: Option<String>,
    /// Heading level for the title: H2, H3 (default), or H4.
    #[prop(optional)]
    title_level: Option<HeadingLevel>,
    /// Card content.
    children: Children,
) -> impl IntoView {
    let title_level = title_level.unwrap_or_default();

    let combined_class = match class {
        Some(c) => format!("card {c}"),
        None => "card".to_string(),
    };

    let title_view = title.map(|t| match title_level {
        HeadingLevel::H2 => view! { <h2 class="card-title">{t}</h2>}.into_any(),
        HeadingLevel::H3 => view! { <h3 class="card-title">{t}</h3>}.into_any(),
        HeadingLevel::H4 => view! { <h4 class="card-title">{t}</h4>}.into_any(),
    });

    view! {
        <section class=combined_class>
            {title_view}
            {children()}
        </section>
    }
}

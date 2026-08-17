use leptos::prelude::*;

/// Card container variants for different visual contexts.
/// Note: Some variants are defined for future use and API consistency.
#[derive(Default, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum CardVariant {
    /// Standard card with full padding (sections, panels).
    #[default]
    Default,
    /// Smaller padding and radius for nested cards.
    Compact,
    /// Dashed border for empty state.
    Empty,
}

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
/// - `card--compact`   - Emitted by `CardVariant::Compact`
/// - `card--empty`     - Emitted by `CardVariant::Empty`
///
/// The last two have **no rule in `styles.css`**, the only stylesheet, so both
/// variants currently render identically to `Default`. Neither is constructed
/// anywhere, which is why nothing has noticed; see `CardVariant` above.
#[component]
pub fn Card(
    /// Optional title displayed in card header.
    #[prop(into, optional)]
    title: Option<String>,
    /// Additional CSS classes to apply.
    #[prop(into, optional)]
    class: Option<String>,
    /// Card variant: Default, Compact, or Empty
    #[prop(optional)]
    variant: Option<CardVariant>,
    /// Heading level for the title: H2, H3 (default), or H4.
    #[prop(optional)]
    title_level: Option<HeadingLevel>,
    /// Card content.
    children: Children,
) -> impl IntoView {
    let variant = variant.unwrap_or_default();
    let title_level = title_level.unwrap_or_default();

    let variant_class = match variant {
        CardVariant::Default => "",
        CardVariant::Compact => "card--compact",
        CardVariant::Empty => "card--empty",
    };

    let combined_class = match class {
        Some(c) => format!("card {} {}", variant_class, c),
        None if variant_class.is_empty() => "card".to_string(),
        None => format!("card {}", variant_class),
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

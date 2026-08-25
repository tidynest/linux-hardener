//! Text shaping shared by every renderer that writes into a fixed-width slot.

/// Shortens `text` to at most `max_chars` characters, marking any cut with an
/// ellipsis that counts against the budget.
///
/// Every caller is filling a column of known width: a PDF table cell at a
/// fixed x offset, or a `{:<24}` field in a terminal table. So the budget is
/// the whole returned string and not merely its content, and a result longer
/// than `max_chars` is the one thing this must never produce.
///
/// This lived twice, once in `hardener-compliance`'s PDF renderer and once in
/// `hardener-cli`'s history tables, and the two copies disagreed about exactly
/// that. The PDF one took `max_chars` characters and *then* appended the
/// ellipsis, so a parameter named `max_chars` returned `max_chars + 3`.
///
/// Below four characters there is no room for a marker that leaves anything
/// behind, so the text is cut with no ellipsis rather than returning three
/// dots that overflow a two-character column.
///
/// Trailing space before the marker is dropped, because a cut landing mid-gap
/// otherwise reads as `this is a ...`. Trimming only ever shortens, so the
/// budget still holds.
pub fn truncate_string(text: &str, max_chars: usize) -> String {
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(max_chars).collect();

    // `chars` is now positioned past the budget: anything left means a cut.
    if chars.next().is_none() {
        return text.to_string();
    }
    if max_chars <= 3 {
        return head;
    }

    let kept: String = head.chars().take(max_chars - 3).collect();
    format!("{}...", kept.trim_end())
}

#[cfg(test)]
mod tests;

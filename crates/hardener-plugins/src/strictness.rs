//! How a configuration value is judged against a secure baseline, in the one
//! direction that makes the judgement mean anything.
//!
//! Three plugins ask the same two questions of their own directive tables. Is
//! the host's current value weaker than the target? And when a second candidate
//! is offered, by an operator's `config.toml` override or by the host itself,
//! which of the two is stricter? Asking the first with `!=` has no direction, so
//! a host stricter than the baseline reads as violating and the apply writes the
//! baseline over it. That shipped: nine PAM directives relaxed a 30-day password
//! expiry to 90 days and reported success.
//!
//! This module is the one definition those plugins share, so the rule cannot be
//! applied to part of a table and quietly left off the rest, which is how it
//! survived in nine of eleven PAM directives after being applied by name to the
//! other two.

/// The direction in which one value is stricter than another.
///
/// **Every variant carries a direction, and that is the point.** PAM used to
/// have an `Exact`, and nine directives used it, which made any value other
/// than the baseline a violation including a stricter one. Removing the
/// variant rather than reassigning its members is what makes the no-loosen rule
/// structural: a directive added later cannot be given a comparison that has no
/// direction, because there is none to give it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Strictness {
    /// Smaller is stricter, and every value the setting accepts is meaningful
    /// (faillock `deny`, sshd `MaxAuthTries`).
    AtMost,
    /// Larger is stricter (pwquality `minlen`, pwhistory `remember`).
    AtLeast,
    /// Smaller is stricter **except zero**, which switches the setting off
    /// rather than tightening it.
    ///
    /// `maxrepeat = 0` disables the consecutive-character check outright, so
    /// zero is the loosest value the setting has while being the smallest
    /// number it can hold. A plain [`Self::AtMost`] scores it compliant, which
    /// is a check switched off reading as a check satisfied.
    NonZeroAtMost,
}

impl Strictness {
    /// The stricter of `baseline` and `candidate`, spelled the way this tool
    /// writes it.
    ///
    /// Callers ask this one question twice. An operator's directive override is
    /// clamped against the plugin's baseline so a per-host setting can only
    /// tighten; apply then clamps that result against the value the host
    /// already holds, so a write can only tighten too. Those two together are
    /// the whole of the no-loosen rule, and asking them through one definition
    /// is why they cannot drift apart.
    ///
    /// A candidate this comparison cannot place loses, so an override that is
    /// a typo leaves the plugin's own secure value standing rather than
    /// relaxing the target.
    pub fn clamp_target(self, baseline: &str, candidate: Option<&str>) -> String {
        let (baseline_score, baseline_spelling) = self
            .place(baseline)
            .expect("a plugin's own baseline must be a value its own comparison can place");
        match candidate.and_then(|value| self.place(value)) {
            Some((score, spelling)) if score > baseline_score => spelling,
            _ => baseline_spelling,
        }
    }

    /// True when `current` is weaker than `target`, which is the resolved and
    /// already-clamped target rather than the raw baseline.
    ///
    /// Unset counts as violating, and so does a value this comparison cannot
    /// place: an unrecognised value is not evidence of compliance, and scoring
    /// it compliant is how a check that could not run comes to look like a
    /// check that passed.
    pub fn violated_by(self, target: &str, current: Option<&str>) -> bool {
        let target_score = self
            .place(target)
            .expect("a clamped target is always a value its own comparison can place")
            .0;
        current
            .and_then(|value| self.place(value))
            .is_none_or(|(score, _)| score < target_score)
    }

    /// Where `value` sits on this comparison's strictness scale, **higher being
    /// stricter**, together with the spelling this tool writes for it.
    ///
    /// Collapsing the directions onto one scale is what lets the two public
    /// questions above have a single body each, so neither can implement one
    /// direction and forget another. The spelling travels with the score
    /// because a clamp returns a value the caller writes to a file: `03` and
    /// `3` place identically and must both be written `3`.
    ///
    /// `None` means this comparison cannot place that value at all, which is a
    /// deliberately different answer from "placed, and weak".
    fn place(self, value: &str) -> Option<(i64, String)> {
        let n = value.parse::<i64>().ok()?;
        let score = match self {
            Self::AtLeast => n,
            // Negated so that a smaller number sorts stricter on the shared
            // scale. Saturating because negating `i64::MIN` overflows, and a
            // configuration file is free to contain it.
            Self::AtMost => n.saturating_neg(),
            // Zero is the weakest value the scale has, however small a number
            // it is, so it can never win a clamp and is never compliant.
            Self::NonZeroAtMost if n == 0 => i64::MIN,
            Self::NonZeroAtMost => n.saturating_neg(),
        };
        Some((score, n.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::Strictness;

    #[test]
    fn a_direction_judges_by_direction_rather_than_by_equality() {
        // AtMost: a smaller number is stricter, so it is compliant, and this
        // is the whole of the defect the shared module exists to prevent.
        assert!(Strictness::AtMost.violated_by("3", Some("5")));
        assert!(!Strictness::AtMost.violated_by("3", Some("2")));
        assert!(!Strictness::AtMost.violated_by("3", Some("3")));

        // AtLeast: the other way round.
        assert!(Strictness::AtLeast.violated_by("14", Some("8")));
        assert!(!Strictness::AtLeast.violated_by("14", Some("20")));

        // Unset is a violation under every direction: nothing is enforcing it.
        assert!(Strictness::AtMost.violated_by("3", None));
        assert!(Strictness::AtLeast.violated_by("14", None));
        assert!(Strictness::NonZeroAtMost.violated_by("3", None));
    }

    #[test]
    fn zero_is_the_loosest_value_a_non_zero_at_most_setting_has() {
        // Smaller is stricter right up until the value that switches the
        // setting off, which a plain AtMost would have scored best of all.
        assert!(!Strictness::NonZeroAtMost.violated_by("3", Some("2")));
        assert!(Strictness::NonZeroAtMost.violated_by("3", Some("0")));
        assert_eq!(Strictness::NonZeroAtMost.clamp_target("3", Some("0")), "3");
        assert_eq!(Strictness::NonZeroAtMost.clamp_target("3", Some("2")), "2");
    }

    #[test]
    fn a_clamp_keeps_the_stricter_of_the_two_in_each_direction() {
        assert_eq!(Strictness::AtMost.clamp_target("5", Some("3")), "3");
        assert_eq!(Strictness::AtMost.clamp_target("5", Some("9")), "5");
        assert_eq!(Strictness::AtLeast.clamp_target("14", Some("20")), "20");
        assert_eq!(Strictness::AtLeast.clamp_target("14", Some("8")), "14");
    }

    #[test]
    fn a_value_the_comparison_cannot_place_is_never_compliant_and_never_wins() {
        // An unrecognised value is not evidence of anything, so it violates.
        assert!(Strictness::AtMost.violated_by("3", Some("banana")));

        // And as a candidate it loses, so a typo in an override cannot relax
        // the target the plugin would otherwise have used.
        assert_eq!(Strictness::AtMost.clamp_target("3", Some("banana")), "3");
        assert_eq!(Strictness::AtMost.clamp_target("3", None), "3");
    }

    #[test]
    fn a_clamp_returns_the_spelling_this_tool_writes() {
        // Two spellings of one number place identically, and the file gets the
        // canonical one either way.
        assert_eq!(Strictness::AtMost.clamp_target("5", Some("03")), "3");
        assert_eq!(Strictness::AtMost.clamp_target("5", Some("05")), "5");
        assert_eq!(Strictness::AtLeast.clamp_target("14", Some("+20")), "20");
    }

    #[test]
    fn an_extreme_value_does_not_overflow_the_shared_scale() {
        // AtMost negates to put smaller first, and negating i64::MIN overflows.
        // A configuration file is free to contain it.
        let min = i64::MIN.to_string();
        assert!(!Strictness::AtMost.violated_by("3", Some(&min)));
        assert_eq!(Strictness::AtMost.clamp_target("3", Some(&min)), min);
    }
}

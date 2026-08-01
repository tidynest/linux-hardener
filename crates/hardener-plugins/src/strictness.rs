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

use hardener_core::PluginConfig;

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
    /// `maxrepeat = 0` disables the consecutive-character check outright and
    /// `ClientAliveInterval 0` stops sshd probing an idle client at all, so
    /// zero is the loosest value either setting has while being the smallest
    /// number it can hold. A plain [`Self::AtMost`] scores it compliant, which
    /// is a check switched off reading as a check satisfied.
    NonZeroAtMost,
    /// The value space is a closed set whose strictness neither the number nor
    /// the alphabet carries, so it is listed here explicitly, **weakest first**.
    ///
    /// `net.ipv4.conf.all.rp_filter` is the clearest case: `0` is off, `1` is
    /// strict mode and `2` is loose mode, so strictness runs 1, then 2, then 0.
    /// [`Self::AtLeast`] scores loose-mode `2` compliant against a target of
    /// `1`, and [`Self::AtMost`] scores off compliant. Both are wrong, and
    /// neither is wrong in a way the integer could reveal. `PermitRootLogin` is
    /// the same shape in words.
    ///
    /// Each entry is a group of spellings of **one** strictness, so a legacy
    /// synonym does not read as a weaker setting than the name that replaced
    /// it. The first spelling in a group is the one this tool writes. Matching
    /// is case-insensitive, because sshd compares directive values with
    /// `strcasecmp` and a host spelling it `No` means `no`.
    Ranked(&'static [&'static [&'static str]]),
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

    /// The plugin's own `baseline` for `key`, tightened by the operator's
    /// directive override where the config sets one that tightens it.
    ///
    /// Every plugin resolves its target through here, in scan, in apply and in
    /// validate, so a preview cannot judge a host by a rule the apply it
    /// previews does not apply, and an override cannot mean "tighten only" in
    /// one plugin and "set to whatever I said" in another. Deviating from the
    /// baseline in the loosening direction is what the exceptions mechanism is
    /// for, and an exception is labelled in the report where an override is
    /// silent.
    pub fn resolved_target(self, config: &PluginConfig, key: &str, baseline: &str) -> String {
        // With no override this resolves to the baseline itself, which ties
        // with the baseline and leaves it standing, so the absent case needs no
        // separate spelling.
        self.clamp_target(baseline, Some(config.resolve_str(key, baseline)))
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
        match self {
            Self::Ranked(order) => order
                .iter()
                .position(|group| {
                    group
                        .iter()
                        .any(|spelling| spelling.eq_ignore_ascii_case(value))
                })
                .map(|index| (index as i64, order[index][0].to_string())),
            Self::AtLeast => value.parse::<i64>().ok().map(|n| (n, n.to_string())),
            // Negated so that a smaller number sorts stricter on the shared
            // scale. Saturating because negating `i64::MIN` overflows, and a
            // configuration file is free to contain it.
            Self::AtMost => value
                .parse::<i64>()
                .ok()
                .map(|n| (n.saturating_neg(), n.to_string())),
            // Zero is the weakest value the scale has, however small a number
            // it is, so it can never win a clamp and is never compliant.
            Self::NonZeroAtMost => value.parse::<i64>().ok().map(|n| match n {
                0 => (i64::MIN, n.to_string()),
                n => (n.saturating_neg(), n.to_string()),
            }),
        }
    }
}

#[cfg(test)]
mod tests;

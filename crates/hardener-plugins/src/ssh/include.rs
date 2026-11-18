//! Resolving `Include` directives in sshd_config.
//!
//! sshd uses the first value it obtains for a keyword, and distributions ship
//! an `sshd_config` whose second line is
//! `Include /etc/ssh/sshd_config.d/*.conf`. Everything this tool writes lands
//! below that line, so a drop-in setting the same keyword always wins. Reading
//! only the main file therefore reports the value this tool wrote while sshd
//! enforces the drop-in's: a false pass, and `sshd -t` does not object to it.
//!
//! This module reconstructs the order sshd reads in, so a caller can ask what
//! the daemon will actually use and which file supplies it.
//!
//! One boundary is deliberately not modelled: an `Include` that sits *inside* a
//! `Match` block is conditional, and the files it names are treated here as
//! global. Every shipped layout puts the Include at the top of the file, above
//! any `Match`, so this does not arise in practice; a configuration that does
//! it would need checking by hand with `sshd -T`.

use hardener_common::error::{HardeningError, Result};
use hardener_common::file_utils::{global_scope, split_directive};
use hardener_core::context::Context;
use std::path::{Path, PathBuf};

/// sshd stops following nested includes at this depth. The real limit is 16;
/// anything approaching it is a loop rather than a configuration.
const MAX_INCLUDE_DEPTH: usize = 16;

/// Relative include paths are resolved against this directory, per
/// sshd_config(5): "Files without absolute paths are assumed to be in
/// /etc/ssh".
const SSH_CONFIG_DIR: &str = "/etc/ssh";

/// The names sshd accepts for one option, the current name first.
///
/// `servconf.c` maps every name in a group to the same option, and sshd keeps
/// the first value it reads under any of them. Rocky 10 ships only
/// `ChallengeResponseAuthentication no`, so a lookup by the current name reads
/// that host as unset, and one lookup per name cannot order two hits inside
/// one file. Measured with `sshd -G` on OpenSSH 10.6p1, 2026-11-10: All three
/// names set `kbdinteractiveauthentication`, and the earlier line wins
/// whichever name it uses.
const KEYWORD_SPELLINGS: &[&[&str]] = &[&[
    "KbdInteractiveAuthentication",
    "ChallengeResponseAuthentication",
    "SkeyAuthentication",
]];

/// Every name sshd reads `keyword` under: Its group in
/// [`KEYWORD_SPELLINGS`], or the keyword alone where it has no other name.
fn spellings<'a>(keyword: &'a &'a str) -> &'a [&'a str] {
    KEYWORD_SPELLINGS
        .iter()
        .copied()
        .find(|group| group.iter().any(|name| name.eq_ignore_ascii_case(keyword)))
        .unwrap_or(std::slice::from_ref(keyword))
}

/// Where one directive's effective value comes from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveValue {
    /// The value sshd will use.
    pub value: String,
    /// The file supplying it.
    pub source: String,
    /// The keyword as that file spells it, which is not always the name the
    /// caller asked for: See [`KEYWORD_SPELLINGS`]. A caller editing the line
    /// in place has to address it by this name, because a second line under
    /// the current name would sit below it and lose.
    pub keyword: String,
}

/// sshd_config as sshd processes it: the main file with each `Include`
/// replaced, in place, by the files it names.
pub struct ResolvedConfig {
    /// `(path, content)` in sshd's processing order. The main file
    /// contributes several entries once it is split at its Include lines.
    segments: Vec<(String, String)>,
}

impl ResolvedConfig {
    /// The effective global value for a directive, and the file it comes from.
    ///
    /// Only the global scope of each segment is consulted: a value inside a
    /// `Match` block applies to particular connections, not to the host.
    pub fn effective(&self, directive_name: &str) -> Option<EffectiveValue> {
        self.first_value(directive_name, |_| true)
    }

    /// The effective global value a directive would have if one file were not
    /// there.
    ///
    /// Apply needs this to decide where a directive belongs. Once this tool has
    /// written its own fragment, that fragment supplies the value, so asking
    /// only "does anything other than us win" answers "no" on a host where a
    /// vendor fragment is still waiting underneath it. The question that
    /// decides whether the main file is a usable target is what would win
    /// without the fragment, which is this.
    pub fn effective_without(
        &self,
        directive_name: &str,
        ignored_path: &str,
    ) -> Option<EffectiveValue> {
        self.first_value(directive_name, |path| path != ignored_path)
    }

    /// Every argument of the directive's effective global line, for a keyword
    /// whose value is a list.
    ///
    /// [`Self::effective`] keeps the first argument, which is the whole value
    /// of a switch or a number and only the first of the lists in
    /// `AuthenticationMethods publickey,password publickey,keyboard-interactive`.
    /// sshd lets an argument be quoted and lets a comment end the line, so
    /// the quotes are dropped and the arguments stop at a `#`.
    pub fn effective_arguments(&self, directive_name: &str) -> Option<Vec<&str>> {
        self.first_line(directive_name, |_| true)
            .map(|(_, _, arguments)| list_arguments(arguments))
    }

    /// [`Self::effective_arguments`] as they would read if one file were not
    /// there.
    ///
    /// The second factor needs this for the same reason [`Self::effective_without`]
    /// exists: this tool's own fragment may be what answers today, and an apply
    /// that is about to rewrite the fragment has to know what would win without
    /// it.
    pub fn effective_arguments_without(
        &self,
        directive_name: &str,
        ignored_path: &str,
    ) -> Option<Vec<&str>> {
        self.first_line(directive_name, |path| path != ignored_path)
            .map(|(_, _, arguments)| list_arguments(arguments))
    }

    /// The first segment satisfying `considered` that supplies the directive.
    fn first_value(
        &self,
        directive_name: &str,
        considered: impl Fn(&str) -> bool,
    ) -> Option<EffectiveValue> {
        self.first_line(directive_name, considered)
            .and_then(|(source, keyword, arguments)| {
                arguments
                    .split_whitespace()
                    .next()
                    .map(|value| EffectiveValue {
                        value: value.to_string(),
                        source: source.to_string(),
                        keyword: keyword.to_string(),
                    })
            })
    }

    /// The first global line, in sshd's reading order, that sets the directive
    /// under any name sshd accepts for it: The file, the keyword as written
    /// and the text after it.
    ///
    /// A commented line needs no skip of its own. Its key begins with `#`, so
    /// it equals no keyword.
    fn first_line(
        &self,
        directive_name: &str,
        considered: impl Fn(&str) -> bool,
    ) -> Option<(&str, &str, &str)> {
        let names = spellings(&directive_name);
        self.segments
            .iter()
            .filter(|(path, _)| considered(path))
            .find_map(|(path, content)| {
                global_scope(content).lines().find_map(|line| {
                    let (keyword, arguments) = split_directive(line.trim());
                    (!arguments.is_empty()
                        && names.iter().any(|name| name.eq_ignore_ascii_case(keyword)))
                    .then_some((path.as_str(), keyword, arguments))
                })
            })
    }

    /// Every `Match` block in the files, in sshd's reading order.
    ///
    /// A block runs from its `Match` line to the next one or to the end of the
    /// file it sits in: sshd does not let an included file's block carry on
    /// into the file that included it. This reads the files as written; which
    /// connections a block matches is sshd's to say (`sshd -T -C`).
    pub fn match_blocks(&self) -> Vec<MatchBlock<'_>> {
        let mut blocks = Vec::new();
        for (path, content) in &self.segments {
            let scoped = &content[global_scope(content).len()..];
            let mut current: Option<MatchBlock<'_>> = None;
            for line in scoped.lines() {
                let (keyword, arguments) = split_directive(line.trim());
                if keyword.is_empty() || keyword.starts_with('#') {
                    continue;
                }
                if keyword.eq_ignore_ascii_case("Match") {
                    blocks.extend(current.take());
                    current = Some(MatchBlock {
                        source: path,
                        criteria: arguments,
                        lines: Vec::new(),
                    });
                } else if let Some(block) = current.as_mut() {
                    block.lines.push((keyword, arguments));
                }
            }
            blocks.extend(current);
        }
        blocks
    }

    /// Construction from raw segments, so the resolution order can be held to
    /// first-wins without an executor: the targets under `fuzz/` build
    /// configurations directly and ask `effective` what sshd would read, and
    /// the second factor's unit tests do the same.
    #[cfg(any(test, fuzzing))]
    pub fn from_segments(segments: Vec<(String, String)>) -> Self {
        Self { segments }
    }
}

/// One `Match` block as written: the file it sits in, its criteria, and the
/// keywords it sets with their arguments.
#[derive(Debug, Eq, PartialEq)]
pub struct MatchBlock<'a> {
    /// The file the block sits in.
    pub source: &'a str,
    /// The text after `Match`, such as `User root Address 192.0.2.10`.
    pub criteria: &'a str,
    /// Each line of the block, as keyword and arguments.
    pub lines: Vec<(&'a str, &'a str)>,
}

impl MatchBlock<'_> {
    /// The arguments of the block's first line setting `directive_name`, under
    /// any name sshd reads it by, the way [`ResolvedConfig::effective_arguments`]
    /// reads a global line.
    pub fn arguments(&self, directive_name: &str) -> Option<Vec<&str>> {
        let names = spellings(&directive_name);
        self.lines.iter().find_map(|(keyword, arguments)| {
            names
                .iter()
                .any(|name| name.eq_ignore_ascii_case(keyword))
                .then(|| list_arguments(arguments))
        })
    }
}

/// The arguments after a keyword, for a keyword whose value is a list. sshd
/// lets an argument be quoted and lets a comment end the line, so the quotes
/// are dropped and the arguments stop at a `#`.
fn list_arguments(arguments: &str) -> Vec<&str> {
    arguments
        .split_whitespace()
        .take_while(|argument| !argument.starts_with('#'))
        .map(|argument| argument.trim_matches('"'))
        .collect()
}

/// The main file as a staged candidate has to read it: every `Include` that
/// would pull in `fragment` spelled out file by file, with `staged` standing
/// where `fragment` sorts, or with `fragment` left out where `staged` is
/// `None`.
///
/// The candidate is checked from a scratch path, but its `Include` lines still
/// name the live drop-in directory, and the copy of this tool's fragment on
/// disk is the one about to be replaced. Validating against it checked the
/// old fragment rather than the new one: a rewrite that drops a directive was
/// judged with the dropped value still in force, and on openSUSE a stale
/// `KbdInteractiveAuthentication no` made `sshd -t` refuse the very apply
/// that would have removed it. Spelling the files out keeps the order sshd
/// reads them in and keeps each one a separate file, so a `Match` block in a
/// drop-in still ends where that file ends, which inlining the text would not.
///
/// Only the main file's own lines are rewritten. Every shipped layout includes
/// the drop-in directory from there; an `Include` of it from inside another
/// included file would still read the copy on disk.
pub(super) async fn stage_fragment_includes(
    ctx: &Context,
    main_path: &str,
    main_content: &str,
    fragment: &Path,
    staged: Option<&Path>,
) -> Result<String> {
    let (Some(fragment_dir), Some(fragment_name)) = (fragment.parent(), fragment.file_name())
    else {
        return Ok(main_content.to_string());
    };
    let fragment_name = fragment_name.to_string_lossy();

    let mut candidate = String::with_capacity(main_content.len());
    for line in main_content.lines() {
        let Some(patterns) = include_patterns(line) else {
            candidate.push_str(line);
            candidate.push('\n');
            continue;
        };

        let mut arguments = Vec::new();
        let mut rewritten = false;
        for pattern in patterns {
            if !pattern_reads(&pattern, main_path, fragment_dir, &fragment_name) {
                arguments.push(pattern);
                continue;
            }
            rewritten = true;
            let mut files: Vec<PathBuf> = expand_pattern(ctx, &pattern, main_path)
                .await?
                .into_iter()
                .filter(|file| file.as_path() != fragment)
                .collect();
            if let Some(staged) = staged {
                let at = files.partition_point(|file| file.as_path() < fragment);
                files.insert(at, staged.to_path_buf());
            }
            arguments.extend(files.iter().map(|file| quoted(&file.display().to_string())));
        }

        if !rewritten {
            candidate.push_str(line);
        } else if arguments.is_empty() {
            // Nothing left for it to read once the fragment is gone, and a
            // bare `Include` with no argument is a parse error, so the line
            // stays as a comment that says what it was.
            candidate.push_str("# ");
            candidate.push_str(line.trim());
        } else {
            candidate.push_str("Include ");
            candidate.push_str(&arguments.join(" "));
        }
        candidate.push('\n');
    }
    Ok(candidate)
}

/// Whether an `Include` pattern written in `main_path` would pull in the file
/// called `fragment_name` in `fragment_dir`.
fn pattern_reads(pattern: &str, main_path: &str, fragment_dir: &Path, fragment_name: &str) -> bool {
    absolute_pattern(pattern, main_path).is_some_and(|absolute| {
        absolute.parent() == Some(fragment_dir)
            && absolute
                .file_name()
                .is_some_and(|name| glob_matches(&name.to_string_lossy(), fragment_name))
    })
}

/// The first global line of the main file that sets `directive_name`, under
/// any name sshd reads it by, above the `Include` that reads `fragment`, or
/// `None` where no such line comes first.
///
/// sshd reads a line above that `Include` before the fragment and every other
/// drop-in, so it wins over all of them. Every validated distribution puts
/// the `Include` at the top of the file, where nothing is above it. Gentoo
/// puts it at the foot, in place of the `Subsystem` line (its
/// `openssh-9.7_p1-config-tweaks.patch`), below every commented default, and
/// an apply that writes the main file there activates the commented default
/// where it stands: above the `Include`. A main file that never includes the
/// fragment has every line ahead of it.
pub(super) fn main_line_ahead_of_dropins(
    main_content: &str,
    main_path: &str,
    directive_name: &str,
    fragment: &Path,
) -> Option<EffectiveValue> {
    let (Some(fragment_dir), Some(fragment_name)) = (fragment.parent(), fragment.file_name())
    else {
        return None;
    };
    let fragment_name = fragment_name.to_string_lossy();
    let names = spellings(&directive_name);
    for line in global_scope(main_content).lines() {
        if let Some(patterns) = include_patterns(line) {
            if patterns
                .iter()
                .any(|pattern| pattern_reads(pattern, main_path, fragment_dir, &fragment_name))
            {
                return None;
            }
            continue;
        }
        let (keyword, arguments) = split_directive(line.trim());
        if !arguments.is_empty() && names.iter().any(|name| name.eq_ignore_ascii_case(keyword)) {
            return arguments
                .split_whitespace()
                .next()
                .map(|value| EffectiveValue {
                    value: value.to_string(),
                    source: main_path.to_string(),
                    keyword: keyword.to_string(),
                });
        }
    }
    None
}

/// A path as an `Include` argument: quoted where it holds whitespace, which
/// sshd's argument splitter honours, and bare otherwise.
fn quoted(path: &str) -> String {
    if path.chars().any(char::is_whitespace) {
        format!("\"{path}\"")
    } else {
        path.to_string()
    }
}

/// The `Include` patterns on a line, or `None` when it is not a live
/// `Include`.
///
/// A commented line includes nothing. Multiple pathnames on one line are
/// permitted and are processed left to right, split the way sshd splits them
/// (see [`split_arguments`]): Gentoo's sshd_config quotes its pattern, and a
/// quote kept as part of it reads as a relative path nobody can list.
pub fn include_patterns(line: &str) -> Option<Vec<String>> {
    let trimmed = line.trim();
    if trimmed.starts_with('#') {
        return None;
    }
    let (keyword, rest) = trimmed
        .split_once(char::is_whitespace)
        .unwrap_or((trimmed, ""));
    if !keyword.eq_ignore_ascii_case("Include") {
        return None;
    }
    let patterns = split_arguments(rest);
    (!patterns.is_empty()).then_some(patterns)
}

/// The arguments of a configuration line, split as sshd's `argv_split`
/// (misc.c, OpenSSH 10.6p2) splits them: spaces and tabs separate arguments;
/// a pair of double or single quotes keeps whitespace inside one argument and
/// is itself dropped; a backslash before a quote, before a backslash, or
/// outside quotes before a space stands for that character; and a `#` where
/// an argument would start ends the line.
pub fn split_arguments(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut arguments = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        if chars[at] == ' ' || chars[at] == '\t' {
            at += 1;
            continue;
        }
        if chars[at] == '#' {
            break;
        }
        let mut quote: Option<char> = None;
        let mut argument = String::new();
        while let Some(&c) = chars.get(at) {
            if c == '\\'
                && let Some(&next) = chars.get(at + 1)
                && (next == '\'' || next == '"' || next == '\\' || (quote.is_none() && next == ' '))
            {
                argument.push(next);
                at += 2;
                continue;
            }
            if quote.is_none() && (c == ' ' || c == '\t') {
                break;
            }
            if quote.is_none() && (c == '"' || c == '\'') {
                quote = Some(c);
            } else if quote == Some(c) {
                quote = None;
            } else {
                argument.push(c);
            }
            at += 1;
        }
        arguments.push(argument);
    }
    arguments
}

/// Whether a filename matches a glob(7) pattern containing `*` and `?`.
///
/// Backtracking matcher rather than a dependency: sshd's own patterns are
/// simple, and a partial implementation that silently mismatched would
/// reintroduce the very false pass this module exists to remove. Character
/// classes are deliberately unsupported and are reported by
/// [`pattern_is_supported`] instead of being guessed at.
pub fn glob_matches(pattern: &str, name: &str) -> bool {
    let (pattern, name): (Vec<char>, Vec<char>) =
        (pattern.chars().collect(), name.chars().collect());
    let (mut p, mut n) = (0usize, 0usize);
    // Position to resume from when a `*` needs to consume one more character.
    let (mut star, mut resume) = (None, 0usize);

    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            resume = n;
            p += 1;
        } else if let Some(star_at) = star {
            p = star_at + 1;
            resume += 1;
            n = resume;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

/// Whether this module can expand a pattern faithfully.
///
/// A glob(7) character class would need real parsing, and treating an
/// unexpandable pattern as "matches nothing" would hide exactly the drop-in
/// the caller is asking about, so such a pattern is refused instead.
pub fn pattern_is_supported(pattern: &str) -> bool {
    !pattern.contains('[') && !pattern.contains(']')
}

/// Whether a relative include can be resolved for the file containing it.
///
/// sshd_config(5) resolves relative includes against sshd's compiled
/// sysconfdir. That is `/etc/ssh` where the including file is the
/// administrator's, and something this tool cannot read out of the binary
/// where the file came from the vendor layer under `/usr/etc`. Every shipped
/// layout uses absolute includes, so refusing costs nothing, whereas guessing
/// would silently mis-locate a fragment, which is the false pass this module
/// exists to prevent.
fn relative_base(including_path: &str) -> Option<&'static str> {
    including_path
        .starts_with("/etc/")
        .then_some(SSH_CONFIG_DIR)
}

/// Absolute form of an include pattern, per sshd_config(5).
///
/// `None` where the pattern is relative and its base cannot be determined.
pub fn absolute_pattern(pattern: &str, including_path: &str) -> Option<PathBuf> {
    let path = Path::new(pattern);
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    relative_base(including_path).map(|base| Path::new(base).join(path))
}

/// The files a pattern names, in the lexical order sshd processes them.
///
/// A pattern that names a single existing file needs no directory listing. A
/// pattern whose directory cannot be listed is an error rather than an empty
/// result: "no drop-ins" and "could not look" must not be the same answer.
async fn expand_pattern(
    ctx: &Context,
    pattern: &str,
    including_path: &str,
) -> Result<Vec<PathBuf>> {
    if !pattern_is_supported(pattern) {
        return Err(HardeningError::Plugin(format!(
            "Include pattern {pattern} uses a character class, which this tool cannot expand; \
             check it by hand with `sshd -T`"
        )));
    }

    let Some(absolute) = absolute_pattern(pattern, including_path) else {
        return Err(HardeningError::Plugin(format!(
            "The relative Include pattern {pattern} in {including_path} resolves against sshd's \
             compiled sysconfdir, which this tool cannot read for a file outside /etc; \
             check it by hand with `sshd -T`"
        )));
    };
    let has_wildcard = pattern.contains('*') || pattern.contains('?');
    if !has_wildcard {
        // A literal include of a file that does not exist is not an error to
        // sshd, so it is not one here either.
        return match ctx.executor().path_exists(&absolute).await {
            Ok(true) => Ok(vec![absolute]),
            Ok(false) => Ok(Vec::new()),
            Err(e) => Err(HardeningError::Plugin(format!(
                "Cannot determine whether the included file {} exists: {e}",
                absolute.display()
            ))),
        };
    }

    let (directory, file_pattern) = match (absolute.parent(), absolute.file_name()) {
        (Some(directory), Some(name)) => {
            (directory.to_path_buf(), name.to_string_lossy().to_string())
        }
        _ => {
            return Err(HardeningError::Plugin(format!(
                "Include pattern {pattern} has no directory to search"
            )));
        }
    };

    let entries = ctx.executor().read_dir(&directory).await.map_err(|e| {
        HardeningError::Plugin(format!(
            "Cannot list {} to expand the Include pattern {pattern}: {e}",
            directory.display()
        ))
    })?;

    let mut matched: Vec<PathBuf> = entries
        .into_iter()
        .filter(|entry| {
            entry
                .file_name()
                .is_some_and(|name| glob_matches(&file_pattern, &name.to_string_lossy()))
        })
        .collect();
    // glob(7) expansion is processed in lexical order.
    matched.sort();
    Ok(matched)
}

/// Reads sshd_config and every file it includes, in sshd's processing order.
///
/// Fails rather than returning a partial view: a caller uses this to decide
/// whether a host is compliant, and a silently incomplete answer is the defect
/// this replaces.
pub(super) async fn resolve(
    ctx: &Context,
    main_path: &str,
    main_content: &str,
) -> Result<ResolvedConfig> {
    let mut segments = Vec::new();
    expand_into(
        ctx,
        main_path,
        main_content,
        &mut segments,
        MAX_INCLUDE_DEPTH,
    )
    .await?;
    Ok(ResolvedConfig { segments })
}

/// Appends this file and, in place, everything it includes.
///
/// Boxed because the recursion is through an async fn.
fn expand_into<'a>(
    ctx: &'a Context,
    path: &'a str,
    content: &'a str,
    segments: &'a mut Vec<(String, String)>,
    depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        if depth == 0 {
            return Err(HardeningError::Plugin(format!(
                "Include nesting exceeded {MAX_INCLUDE_DEPTH} levels at {path}; \
                 this is a loop rather than a configuration"
            )));
        }

        // An Include takes effect where it sits, not before the file and not
        // after it. The shipped layout puts it on line 2, above every
        // directive this tool writes, so a model that placed the whole file
        // ahead of its includes would still read the main file's value first
        // and report exactly the compliance sshd does not have. The file is
        // therefore split at each Include: the lines above it, then the files
        // it names, then the lines below.
        let mut pending = String::new();
        let flush = |pending: &mut String, segments: &mut Vec<(String, String)>| {
            if !pending.is_empty() {
                segments.push((path.to_string(), std::mem::take(pending)));
            }
        };

        for line in content.lines() {
            let Some(patterns) = include_patterns(line) else {
                pending.push_str(line);
                pending.push('\n');
                continue;
            };
            flush(&mut pending, segments);
            for pattern in patterns {
                for included in expand_pattern(ctx, &pattern, path).await? {
                    let included_path = included.display().to_string();
                    let included_content =
                        ctx.executor().read_file(&included).await.map_err(|e| {
                            HardeningError::Plugin(format!(
                                "Cannot read the included file {included_path}: {e}"
                            ))
                        })?;
                    expand_into(ctx, &included_path, &included_content, segments, depth - 1)
                        .await?;
                }
            }
        }
        flush(&mut pending, segments);
        Ok(())
    })
}

#[cfg(test)]
mod tests;

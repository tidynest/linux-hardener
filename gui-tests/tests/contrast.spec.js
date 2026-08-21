// =============================================================================
// COMPUTED-CASCADE CONTRAST (T-CONTRAST) - issue #158
// =============================================================================
//
// `scripts/validate/validate_contrast.py` weighs only rules that declare BOTH a
// text colour and a background in the same block, and its docstring says why:
// a wider static parse was tried, reported five themes failing at 3.2 to 3.6:1
// on pairings that may never render together, and was rejected. A check that
// manufactures defects gets muted, and a muted check is worse than none.
//
// The cost of that scope has been paid twice. A rule declaring `color:` alone
// and taking its background from an ancestor is invisible to it. The Daywatch
// `--color-good` pair sat at 3.49:1 on the surface that actually renders,
// across 22 use sites, through six themes and 222 screenshots, and was found by
// hand arithmetic during an unrelated review.
//
// The missing capability is the computed cascade, which means a browser. This
// file is that browser. It asks the page which colour-only rules matched a
// rendered element, reads the real colour and the real backdrop off
// getComputedStyle, and weighs those. Every pairing reported provably
// rendered, so nothing here is manufactured.
//
// The scope has widened once since, and the boundary is now a rule rather than
// a habit. This file used to skip every rule declaring a background, on the
// grounds that the static parse already had those numbers. That stopped being
// true when validate_contrast.py learned to composite alpha fills: for a
// translucent background it reports the BEST of every `--bg-*` surface the
// theme declares, which is a ceiling, and its own docstring records that a
// pair failing on the darker surfaces but clearing on one goes unreported
// there. Only the browser knows which ancestor actually painted. So the split
// is now opaque-declared to the static check, translucent-declared and
// colour-only to this one, and it lives in `browserOwnsPairing` where node can
// prove it. Opaque fills are still untouched here: that half of the original
// reasoning was never wrong.
//
// Four decisions worth stating, because #158 left the first three open:
//
// 1. The selector list is DERIVED, not curated. A hand-written list of
//    "semantic-colour users" answers the question once and then rots: the
//    stylesheet grows a rule, nobody adds it, and the gap this file exists to
//    close reopens silently. The page already knows which rules matched.
// 2. Failure policy follows validate_contrast.py exactly. Everything measured
//    is REPORTED every run; only pairings absent from DEFERRED fail. A silent
//    narrowing turns an unexamined area into a green tick, which is the
//    failure mode both files exist to answer.
// 3. Font size is read from the browser, so large text gets the 3.0 bar the
//    specification actually allows rather than the flat 4.5 a static parse has
//    to assume.
// 4. Two checks may both weigh a translucent fill, and that is not the
//    duplication decision 2's rationale forbids. They answer different
//    questions - the best surface available versus the one that rendered - and
//    both answers are facts. What is forbidden is two numbers for one
//    question, which is why an opaque fill is still weighed in exactly one
//    place.
//
// The arithmetic lives in contrast-math.js and is proved by its own self-check
// against #158's hand measurements. Nothing is computed inside `page.evaluate`,
// so there is no second copy of the WCAG formula to drift from that one.
// =============================================================================

const { test, expect } = require('@playwright/test');
const {
  loadApp,
  runScan,
  runApply,
  runRollback,
  selectTheme,
  THEMES,
} = require('./helpers');
const {
  contrastRatio,
  flattenBackdrop,
  thresholdFor,
  browserOwnsPairing,
} = require('./contrast-math');

// Known failures held open on purpose, keyed `<theme value> <selector>`, each
// with the reason and who decides. Reported on every run; they merely do not
// fail. Meant to be removed rather than accumulated.
//
// It HAS run: #173 was its first container execution, and it failed all seven
// theme cases on a flattener bug that collected 0 pairings rather than on any
// colour. Keep this list empty by fixing what it finds; record a decision here
// only when the fix is a design change that is not tooling's to take.
//
// THE THIRTEEN BELOW ARE ALL ONE DISCOVERY AND NONE IS A REGRESSION. The
// `fleet, host expanded` route was added on 2026-08-20 to reach
// `.host-severity-label`, the only place `.severity_low` renders as text, and
// nothing had ever measured that panel before. The route found four rules
// short of 4.5 on the surface it paints: `.severity_exception` in six themes
// of seven, `.tally-crit` in five, and one theme each for `.severity_low` and
// `.severity_critical`. Every one is a near miss between 3.82 and 4.34, and
// every one has been failing since the panel was written; the instrument, not
// the product, is what changed. Retuning four semantic colours across six
// themes is a design decision and is not tooling's to take, so they are
// recorded here rather than fixed in the same breath as the route that found
// them. `.tally-crit` at 3.82 in Sentinel is the worst and reads a critical
// count, so it is the one to take first.
const fleetPanel = (ratio) =>
  `${ratio}:1 rendered on the fleet host panel, which no route reached until ` +
  '2026-08-20. Pre-existing rather than a regression: the route that found it ' +
  'is what changed. Maintainer design decision, see ' +
  'docs/reference/what-is-not-proven.md.';

const DEFERRED = {
  // `.severity_exception` was six of the thirteen and is FIXED, not deferred.
  // The systemic cause the six suggested was real: each theme's `--text-muted`
  // is tuned to clear 4.5 on the bare surface and the pill's 14% fill lifts
  // the backdrop under it. It moved to `--text-secondary` on 2026-08-20,
  // together with `.compliance-excluded`, which shares `--pill-muted-bg` and
  // therefore shared the defect while never being measured at all.
  // `.tally-crit` was the other five and is FIXED rather than deferred: it
  // moved to `--color-critical-bright` on 2026-08-20, the same move
  // `.partial-row-badge-failed` and `.status-error` made on 2026-08-19, taking
  // the worst case from 3.82:1 in Sentinel to 5.20:1. Its entries are gone
  // rather than left saying something true-when-written, because the lookup
  // here only happens once a pair has already failed, so an entry whose defect
  // is fixed sits reported by nothing.
  //
  // The last two, sentinel's `.severity_critical` at 4.18 and fortress's
  // `.severity_low` at 4.29, were fixed on 2026-08-20 rather than carried.
  // Both had already been given the brightest text token their family offers,
  // so neither was a token swap; what was left to move was each rule's OWN
  // translucent fill, which is what had been lifting the backdrop under its
  // text. #ef4444 became #b91c1c and #22d3ee became #0ea5e9, both at their
  // existing alpha. Each fixed its failing theme and lifted the four or five
  // others that sat within 0.21 of the bar behind it.
};

// Where to look. Not every route, because the point is coverage of the
// semantic colours rather than of the router: the dashboard after a scan
// carries the score and the severity words, History carries the checkpoint
// signature badges that motivated #158, and Analysis carries the findings
// table. Adding a route is cheap if a colour turns out to live only in one.
const ROUTES = [
  {
    path: '/',
    name: 'dashboard (post-scan)',
    setup: async (page) => {
      await runScan(page);
    },
  },
  {
    path: '/hardening',
    name: 'hardening, History tab',
    setup: async (page) => {
      await page.getByRole('tab', { name: 'History' }).click();
      // The signature badges only exist once get_checkpoints resolves.
      await expect(page.locator('.timeline-verify').first()).toBeVisible();
    },
  },
  {
    // `.partial-row-badge-failed`, one of the two translucent-fill rules that
    // carry real text, renders only after an apply that partly failed. The
    // default fixture's apply succeeds outright and reaches the done panel
    // instead, so the route needs `apply_mode=mixed`, under which
    // firewall-hardening fails alongside a success.
    path: '/hardening',
    name: 'hardening, applied (mixed)',
    query: 'apply_mode=mixed',
    setup: async (page) => {
      await runApply(page);
      // The badge lives inside this panel; without the wait the sweep can run
      // against the confirmation step and collect the route's chrome only,
      // which is how `/analysis` sat in its empty state for two runs.
      await expect(page.locator('.partial-panel')).toBeVisible({ timeout: 15000 });
    },
  },
  {
    // `.status-error` is the other one. It renders the rejection message from
    // a failed export, which needs `error_mode=export`: the mock's `all` would
    // also fail get_compliance_reports, leaving nothing to select and the
    // Export button disabled.
    path: '/analysis',
    name: 'analysis, export failed',
    query: 'error_mode=export',
    setup: async (page) => {
      await page.getByRole('tab', { name: 'Compliance' }).click();
      // Export is disabled while no framework is selected, so ENSURE one is
      // pressed rather than clicking one. Clicking blind deselected it and
      // failed all seven themes on 2026-08-20: `compliance_tab.rs:28` starts
      // with `vec!["cis"]`, so the first toggle is already pressed and a click
      // emptied the selection. These are `aria-pressed` toggles, which the
      // analysis suite also reads rather than assumes; a drive step that
      // toggles depends on the state it finds, one that asserts does not.
      const framework = page
        .getByRole('group', { name: 'Compliance frameworks' })
        .getByRole('button')
        .first();
      if ((await framework.getAttribute('aria-pressed')) !== 'true') {
        await framework.click();
      }
      await expect(framework).toHaveAttribute('aria-pressed', 'true');
      await page.getByRole('button', { name: /^Export$/ }).click();
      await expect(page.locator('.status-error')).toBeVisible({ timeout: 10000 });
    },
  },
  {
    path: '/analysis',
    name: 'analysis',
    // Scanned, not bare. The first two container runs loaded this route with
    // no scan, so it rendered "No findings yet" and the findings table did not
    // exist: the route was contributing its chrome and none of the content it
    // was added for. `analysis_page.rs:113` carries the same Run Security Scan
    // button the dashboard hero does, so the same helper drives it.
    setup: async (page) => {
      await runScan(page);
    },
  },
  {
    // `.severity_low` renders as TEXT on exactly one route, and it is this one.
    // `severity_class()` has two callers: `findings_tab.rs:221` puts it on
    // `.finding-dot`, an empty 8px span with nothing to weigh, and
    // `host_panel.rs:42` puts it on `.host-severity-label` around the words
    // "Low (1)". Only the second is a text pairing, and no route here reached
    // it, so the daywatch fix of 2026-08-20 shipped on the static parse alone
    // while a `--grep T-CONTRAST` run passed carrying zero occurrences of
    // `severity_low` in its log.
    //
    // The Low subgroup exists because the fixture's `services-002` is
    // `finding_severity: 'Low'` and its exception is `notconfigured`, which
    // `is_policy_excepted` does not count (only `Applied` is), so it stays
    // live and `group_findings_by_severity` gives it a group of its own. The
    // Findings section is `open=true`, and a `<summary>` renders even inside a
    // closed `<details>`, so the subgroup label is visible without expanding
    // the subgroup itself.
    path: '/fleet',
    name: 'fleet, host expanded',
    setup: async (page) => {
      await page.getByRole('checkbox', { name: 'Select web-01' }).check();
      // db-01 as well, and it is the fixture's failing host: its row settles on
      // `.host-row-failed`, the word "Failed" in `--color-critical`. That rule
      // and `.host-prog-failed` are the same pairing on the same surface and
      // neither had ever been measured, because until now this route scanned
      // web-01 alone and db-01 stayed merely unscanned.
      await page.getByRole('checkbox', { name: 'Select db-01' }).check();
      await page.getByRole('button', { name: /Scan Selected/i }).click();
      // Waiting on the failed row rather than on a count of unscanned ones: a
      // count of zero is also what a page that never rendered would show, and
      // this is the pairing the second host was added to reach.
      await expect(page.locator('.host-row-failed')).toBeVisible();
      const expander = page.getByRole('button', { name: 'Expand web-01' });
      await expander.click();
      await expect(expander).toHaveAttribute('aria-expanded', 'true');
      // The pairing itself, not the panel around it. Asserting the panel would
      // let the sweep run against the host's chrome while the findings were
      // still rendering, which is how `/analysis` sat in its empty state for
      // two runs.
      await expect(page.locator('.host-severity-label.severity_low')).toBeVisible();
    },
  },
  {
    // The same `.host-row-failed` as the route above, on the other surface it
    // can paint. `.host-row-open` gives an expanded row `--bg-tertiary`, and
    // `expanded` is a single Option<String>, so one host is open at a time and
    // the route above must keep web-01: this needs its own pass.
    //
    // Reaching it depends on ORDER, not on clicking harder. `hosts_page.rs:74`
    // refuses to open a failed host, deliberately, so expanding db-01 after
    // the scan is impossible and an earlier attempt at exactly that failed all
    // seven themes on `aria-expanded` staying false. The guard is
    // `is_failed && !currently_open`, so a row already open when it fails stays
    // open, which is what a reader gets by opening a host and then running a
    // scan that fails it.
    path: '/fleet',
    name: 'fleet, failed host left open',
    setup: async (page) => {
      // Before the scan, db-01 is merely unscanned and opens like any host.
      const failed = page.getByRole('button', { name: 'Expand db-01' });
      await failed.click();
      await expect(failed).toHaveAttribute('aria-expanded', 'true');
      await page.getByRole('checkbox', { name: 'Select db-01' }).check();
      await page.getByRole('button', { name: /Scan Selected/i }).click();
      await expect(page.locator('.host-row-failed')).toBeVisible();
      // The point of the route: the row is failed AND still open, so the rule
      // is weighed against `--bg-tertiary` rather than the page background.
      await expect(failed).toHaveAttribute('aria-expanded', 'true');
    },
  },
  {
    // The fleet APPLY page, which no route had ever loaded. It was found by
    // asking what else draws `.host-row-error`: `fleet_outcome_row.rs:37`
    // does, on `--bg-secondary` inside `.fleet-outcome`, and that instance was
    // failing at 4.35 in Sentinel with neither check able to say so - the
    // browser half never rendered the page and the static half skips the rule
    // because it declares no background of its own.
    //
    // Two routes, because the page has two states and they draw different
    // bands. This one is the dry-run preview: web-01 validates with changes
    // pending and db-01 fails, so one render carries `.fleet-stat` plain and
    // `.score-warning`, `.fleet-glyph-pending` and `-failed`, and the error
    // line on the surface that was never weighed.
    path: '/fleet-apply',
    name: 'fleet apply, previewed',
    setup: async (page) => {
      const hosts = page.getByRole('group', { name: 'Hosts', exact: true });
      await hosts.getByRole('checkbox', { name: /^web-01 / }).check();
      await hosts.getByRole('checkbox', { name: /^db-01 / }).check();
      await page.getByRole('button', { name: /Preview Changes/i }).click();
      // Both halves of the render, not the container around them. One host
      // contributes the bands and the other the error line, so waiting on
      // either alone would let the sweep run while the other was still absent.
      await expect(page.locator('.fleet-stat.score-warning')).toBeVisible();
      await expect(page.locator('.fleet-outcome .host-row-error')).toBeVisible();
    },
  },
  {
    // The executed half. `.score-good` and `.score-critical` exist only after
    // a real apply, so the preview route above cannot reach them however it is
    // set up: `ApplyStatus::Validated` has no "applied" cell to draw.
    //
    // This route reaches `.fleet-glyph-failed` and `.score-critical`, both from
    // web-01's `failed: 1`; db-01's `Failed` arm renders no cells at all, only
    // the error line. `.fleet-glyph-ok` is NOT reachable here for that reason,
    // and is measured by the rollback route below rather than reasoned about.
    path: '/fleet-apply',
    name: 'fleet apply, executed',
    setup: async (page) => {
      const hosts = page.getByRole('group', { name: 'Hosts', exact: true });
      await hosts.getByRole('checkbox', { name: /^web-01 / }).check();
      await hosts.getByRole('checkbox', { name: /^db-01 / }).check();
      await page.getByRole('button', { name: /Preview Changes/i }).click();
      // Execute is not rendered until a preview for the exact selection
      // exists, so its appearance is the signal the gate has opened.
      const execute = page.getByRole('button', { name: /^Execute/ });
      await expect(execute).toBeVisible();
      await execute.click();
      await page.getByRole('button', { name: /Yes, execute/i }).click();
      // The band only an executed apply produces, so this cannot pass against
      // the preview still on screen.
      await expect(page.locator('.fleet-stat.score-critical')).toBeVisible();
      await expect(page.locator('.fleet-stat.score-good')).toBeVisible();
    },
  },
  {
    // `.fleet-glyph-ok`, the last rule on this page, and it needed neither a
    // third host nor a fixture flag. Both were assumed: the note left on the
    // route above reasoned that a clean glyph wants a host that applied with
    // nothing failing, that the fixture has two, and that one of them must
    // keep failing to hold the error line - so the rule was recorded as
    // reasoned-not-measured and a third host was written down as the price.
    //
    // The assumption was about APPLY. This page has a second mode, and
    // `fleet_rollback_cells` reaches `OutcomeGlyph::Ok` by a different door:
    // its `RolledBack` arm asks only whether `failed > 0`, and the mock's
    // `run_fleet_rollback` returns `{ restored: 2, failed: 0 }` for every host
    // it is given, db-01 included, because that handler does not special-case
    // the name the apply handler fails. So the default fixture already draws
    // the rule, twice, on the surface it needed measuring against. What was
    // missing was a route that pressed Execute in rollback mode, and none
    // existed: T-FAPPLY-09 switches modes but stops at the preview, where
    // `checkpoints > 0` gives Pending.
    //
    // The cost of the wrong assumption would have been a third host rippling
    // into every test that asserts a host count, to buy a reading this gets
    // for free.
    //
    // MEASURED, arch container, 2026-08-21: 9.01 Midnight Teal, 9.77 Fortress,
    // 9.38 Sentinel, 9.38 Command, 9.06 Guardian, 6.58 Daywatch, 14.10 High
    // Contrast, every one against 4.5. The deferral note predicted "6.58 to
    // 14.10" by reasoning from `.fleet-stat.score-good`, and the range is
    // exactly that - the reasoning was correct AND unverifiable, which is the
    // distinction this route closes rather than the number. Nothing else the
    // route contributes falls below 5.05.
    path: '/fleet-apply',
    name: 'fleet apply, rolled back',
    setup: async (page) => {
      // Mode first. `set_mode` clears the preview, so switching after one
      // would re-arm the gate and Execute would be gone again.
      await page.getByRole('radio', { name: 'Roll back' }).check();
      const hosts = page.getByRole('group', { name: 'Hosts', exact: true });
      await hosts.getByRole('checkbox', { name: /^web-01 / }).check();
      await hosts.getByRole('checkbox', { name: /^db-01 / }).check();
      await page.getByRole('button', { name: /Preview Changes/i }).click();
      const execute = page.getByRole('button', { name: /^Execute/ });
      await expect(execute).toBeVisible();
      await execute.click();
      await page.getByRole('button', { name: /Yes, execute/i }).click();
      // The glyph itself, not the row around it. A preview also renders
      // `.fleet-outcome` and `.fleet-glyph`, so waiting on either would let
      // the sweep run against the Pending state this route exists to get past.
      await expect(page.locator('.fleet-glyph-ok').first()).toBeVisible();
    },
  },
  {
    // THE FIRST ROUTE THAT OPENS A MODAL. Until 2026-08-21 none did, and that
    // absence is what let two rules fail WCAG permanently in five themes each
    // while both checks reported nothing: `.modal` painted `--bg-elevated`,
    // `.restore-error` read 3.25 sentinel to 3.57 command and
    // `.exception-modal .modal-error` 3.86 to 4.29. The static half cannot see
    // either, one because it declares no background of its own and one because
    // its translucent fill is spread over all four tiers as hypotheses; the
    // browser half could have seen both and was never driven to a dialog.
    //
    // Of the thirty classes the three modal components render, three are in
    // the static corpus. This route and the one below are what put the rest
    // under a real ancestor for the first time.
    //
    // `rollback_mode=partial` because the DEFAULT fixture restores everything,
    // and this route found that out the expensive way. Its first run measured
    // fourteen `.restore-error` pairings, two per theme, and
    // `--color-critical-bright` was in none of them: both default instances are
    // overridden by a more specific rule, `.restore-warn .restore-error` in
    // amber and `.rollback-divergence-unchecked .restore-error.divergence-detail`
    // in muted grey. `rollback_modal.rs:271` and `:293` render the rule in its
    // own colour and both are guarded by `err.map(...)`, so nothing draws it
    // until a file or a reload actually fails.
    //
    // The run was green. `MUST_REACH` tests whether a SELECTOR was measured,
    // not which rule won the cascade for it, so `.restore-error` satisfied it
    // while the declaration under test went unweighed. That is the same shape
    // as `.tab-button.tab-active` in decision 2 of this file, arriving from the
    // other direction.
    path: '/hardening',
    name: 'hardening, rollback modal',
    query: 'rollback_mode=partial',
    scope: '.modal',
    setup: async (page) => {
      await runRollback(page);
      // `.restore-fail` is the failing row, so this asserts the instance whose
      // colour comes from `.restore-error` ITSELF. Asserting the bare class
      // instead is what the first version did, and it passed against a modal
      // in which the rule never won anything.
      await expect(page.locator('.restore-fail .restore-error')).toBeVisible();
    },
  },
  {
    // The other modal, and the other shape of failure. `.modal-error` renders
    // only when the exception write fails, so this is the one route in the file
    // that needs a flag invented for it: `error_mode=exception` fails
    // `add_policy_exception` alone. `all` cannot serve, because it also fails
    // `run_scan` and there is then no finding to accept and no modal at all.
    //
    // Reaching it is four steps rather than one, and each is load-bearing:
    // without the scan there are no findings, without the keyed finding there
    // is no accept control (`services-002` is the fixture's only one still
    // `NotConfigured`), without the modal there is no form, and without a
    // reason `can_submit` holds the button disabled. `findings_tab.rs:288`
    // clears the error whenever the modal reopens, so nothing here can pass on
    // a failure left over from a previous attempt.
    path: '/analysis',
    name: 'analysis, exception write failed',
    query: 'error_mode=exception',
    scope: '.modal',
    setup: async (page) => {
      await runScan(page);
      await page.getByRole('button', { name: 'Bluetooth service enabled' }).click();
      await page.getByRole('button', { name: 'Accept This Finding', exact: true }).click();
      await page.getByLabel('Reason').fill('measuring the failure surface');
      await page.getByRole('button', { name: 'Accept Finding', exact: true }).click();
      // The modal stays open on a failed write, deliberately, and this is the
      // rule that proves it did: a dialog that closed would leave the sweep
      // measuring `/analysis` and passing.
      await expect(page.locator('.exception-modal .modal-error')).toBeVisible({ timeout: 10000 });
    },
  },
];

// Selectors this check exists to reach. If a run measures nothing for one of
// them the check has quietly stopped covering the very thing it was built for,
// which is a different and worse outcome than finding a failure. Asserted per
// theme rather than once, because a theme that failed to apply would otherwise
// be measured entirely in the default theme's colours and still look covered.
// `.finding-group-count` is the tripwire for the scan on `/analysis`: it
// declares a colour and carries text, and it exists only once a severity group
// renders. Without it a runScan that silently failed would return the route to
// the empty state it was in for the first two container runs, losing the
// content this route contributes while every other assertion stayed green.
//
// The last two are the point of the whole widening: they are the only rules in
// the stylesheet that put real text over a translucent fill, both were among
// the eight cleared on 2026-08-19, and until their routes were added no run
// had ever measured either against a real ancestor. Each needs a state the
// default fixture does not produce, so each is exactly the kind of coverage
// that disappears silently when a fixture or a flag changes.
const MUST_REACH = [
  '.timeline-verify-ok',
  '.timeline-verify-bad',
  '.finding-group-count',
  '.partial-row-badge-failed',
  '.status-error',
  // Added 2026-08-20, after a run that passed while never measuring it. It is
  // the rule the daywatch --color-info fix of that day turned on, and its only
  // text pairing is `.host-severity-label` on the fleet route above; the other
  // caller draws it on an empty dot. An absence here is not a failure anywhere
  // else, which is the whole reason this list exists.
  '.severity_low',
  // Added 2026-08-20 with the second host. It guards the db-01 half of the
  // fleet route the way `.severity_low` guards the web-01 half: if the failing
  // host ever stops failing, or the selection silently drops it, this rule
  // stops being measured and nothing else in the file would say so.
  '.host-row-failed',
  // Added 2026-08-21 with the two fleet-apply routes. It cannot render unless
  // an outcome row rendered, so it guards the whole page: the preview gate,
  // the confirm modal and the fixture's two shapes all have to work for this
  // selector to appear at all, and nothing else in this file would notice if
  // one of them stopped.
  '.fleet-stat',
  // The two modal rules, added 2026-08-21 with the routes that first opened a
  // dialog. Both are here rather than one standing for the pair, because they
  // fail independently: `.restore-error` needs the fixture to keep reporting
  // divergences and `.modal-error` needs `error_mode=exception` to keep
  // failing exactly one command. Either could stop rendering while the other
  // carried on, and a route reaching a modal is not the same claim as a route
  // reaching the rule the modal was opened for.
  '.restore-error',
  '.modal-error',
  // Added 2026-08-21 with the rollback route. It is the only entry here that
  // needs a MODE as well as a state: an apply can never draw it on this
  // fixture, so if the route ever stops pressing Execute in rollback mode, or
  // the mock's rollback handler grows the failing host its apply handler has,
  // the rule silently goes back to being the reasoned-about one it was.
  '.fleet-glyph-ok',
];

// A run that measures nothing passes every assertion below it. This is a floor
// a real page clears easily; it is a tripwire for a page that never hydrated,
// not a coverage target.
const MINIMUM_PAIRS = 12;

/**
 * Every colour-only rule that matched a rendered element, with its computed
 * colour and the stack of backgrounds above the first opaque ancestor.
 *
 * Observes only. The stack is returned unflattened and the ratio is not
 * computed, so this half has one job and the arithmetic stays in one place.
 *
 * `scope` confines the sweep to one subtree, and only the modal routes pass
 * one. `backdropStack` walks ANCESTORS, and `.modal-backdrop` is an overlay
 * rather than an ancestor of the page it covers, so with a dialog open every
 * element behind it would be measured as though undimmed. That is a false PASS
 * and not merely noise: compositing rgba(0, 0, 0, .5) over text and fill alike
 * moves both luminances toward zero while the +0.05 in the ratio stays put, so
 * the rendered contrast behind a backdrop is WORSE than the number this
 * function would report for it. Everything behind the dialog is already
 * measured, undimmed and correctly, by the route it belongs to.
 */
async function collectPairs(page, routeName, scope = null) {
  const found = await page.evaluate((scopeSelector) => {
    // Flatten @media and @supports, whose rules are nested one or more levels
    // down. A theme's overrides commonly live inside one, so a walk that read
    // only top-level rules would miss precisely the interesting ones.
    // Both, in this order, and not an if/else (#173). Since CSS nesting, a
    // plain CSSStyleRule carries a `cssRules` of its own: empty, but an object,
    // and therefore truthy. Testing it first sent every style rule down the
    // recursion into nothing and pushed none of them, so this sweep collected
    // exactly 0 pairings on all six distributions and its vacuity guard was the
    // only thing that noticed. Measured in Chromium on the same page: the old
    // order collected 0 of 2 rules, this one collects 2.
    //
    // A grouping rule (@media, @keyframes) has no `.style`, so it contributes
    // only its children; a nested rule contributes itself and its children.
    const flatten = (rules, out = []) => {
      for (const rule of rules) {
        if (rule.style) out.push(rule);
        if (rule.cssRules) flatten(Array.from(rule.cssRules), out);
      }
      return out;
    };

    const parse = (value) => {
      const m = /rgba?\(([^)]+)\)/.exec(value || '');
      if (!m) return null;
      const parts = m[1].split(/[,/]/).map((p) => parseFloat(p.trim()));
      if (parts.length < 3 || parts.some((n) => Number.isNaN(n))) return null;
      return { r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1 };
    };

    // Nearest first, stopping at the first fully opaque layer. Everything
    // above it still matters, so it is all returned rather than discarded.
    const backdropStack = (el) => {
      const stack = [];
      for (let node = el; node; node = node.parentElement) {
        const bg = parse(getComputedStyle(node).backgroundColor);
        if (!bg || bg.a === 0) continue;
        stack.push(bg);
        if (bg.a === 1) break;
      }
      return stack;
    };

    // Resolve a DECLARED background value to a colour, by asking the browser.
    // `var(--pill-muted-bg)`, `transparent`, `#151b23` and `rgba(...)` all
    // appear in this stylesheet, and writing four parsers to answer one
    // question is how a second copy of something starts. A detached element
    // would not inherit the theme's custom properties, so it is parented; it
    // is cached by declaration because those properties are set on `:root`.
    const scratch = document.createElement('span');
    scratch.style.display = 'none';
    document.body.appendChild(scratch);
    const resolved = new Map();
    const resolveBackground = (value) => {
      if (!resolved.has(value)) {
        scratch.style.background = '';
        scratch.style.background = value;
        resolved.set(value, parse(getComputedStyle(scratch).backgroundColor));
      }
      return resolved.get(value);
    };

    // Resolved once. A scope that is asked for and not found is an ERROR
    // rather than a silent whole-document sweep: the route would then measure
    // the dimmed page it was written to exclude, and report more pairings than
    // before while measuring the wrong thing.
    const scopeRoot = scopeSelector ? document.querySelector(scopeSelector) : null;
    if (scopeSelector && !scopeRoot) {
      throw new Error(`contrast scope '${scopeSelector}' matched no element`);
    }

    const rules = [];
    for (const sheet of Array.from(document.styleSheets)) {
      try {
        rules.push(...flatten(Array.from(sheet.cssRules)));
      } catch {
        // A cross-origin sheet cannot be read. There are none in this bundle,
        // and skipping one is better than aborting the whole sweep.
      }
    }

    const out = [];
    const seen = new Set();
    for (const rule of rules) {
      const declaresColour = rule.style.getPropertyValue('color');
      const declaredBackground =
        rule.style.getPropertyValue('background-color') ||
        rule.style.getPropertyValue('background');
      const declaresBackground = Boolean(declaredBackground);
      // The alpha of the fill THIS RULE declares, which is the question the
      // scope test asks, and not the alpha the element ended up with. The two
      // differ wherever another rule wins: `.tab-button.tab-active` declares
      // an opaque `--bg-secondary`, but the element is also `:hover`, which
      // paints a translucent `--bg-elevated` over it. Keying on the computed
      // value admitted that rule into all seven themes on the first container
      // run, giving one selector a number here AND in validate_contrast.py -
      // measured against two different backdrops, which is precisely the
      // confusion this file's decision 2 exists to prevent.
      const declaredAlpha = declaresBackground
        ? (resolveBackground(declaredBackground) || {}).a
        : null;
      // Whether this file or validate_contrast.py owns the result is
      // `browserOwnsPairing`, applied outside `page.evaluate` so the boundary
      // is provable without a container. The only thing decided in here is
      // whether there is a pairing at all, which needs a declared text colour.
      if (!declaresColour) continue;

      let matched;
      try {
        matched = Array.from(document.querySelectorAll(rule.selectorText));
      } catch {
        // Selectors querySelectorAll cannot evaluate, ::before and the like.
        // Out of reach for this method, and never silently counted as passing.
        continue;
      }
      // Queried against the whole document and then filtered, rather than
      // queried under the root: a selector like `.exception-modal .modal-error`
      // is written from an ancestor the root itself carries, and
      // `root.querySelectorAll` would match nothing for it while every other
      // rule went on matching. That failure is silent and looks like a clean
      // sweep, so the containment test is applied to elements instead.
      if (scopeRoot) matched = matched.filter((el) => scopeRoot.contains(el));

      for (const el of matched) {
        if (!el.getClientRects().length) continue;
        // Text this element renders ITSELF. A wrapper whose colour is merely
        // inherited by children is not a text pairing, and counting it would
        // report one colour again from every ancestor that set it.
        const ownText = Array.from(el.childNodes)
          .filter((n) => n.nodeType === Node.TEXT_NODE)
          .map((n) => n.textContent.trim())
          .join('')
          .trim();
        if (!ownText) continue;

        const style = getComputedStyle(el);
        const colour = parse(style.color);
        // Translucent TEXT would need the same fold as the backdrop and is
        // rare enough not to guess at. Skipped rather than measured wrongly.
        if (!colour || colour.a !== 1) continue;
        const stack = backdropStack(el);

        // `declaresBackground` is part of the key, not decoration. Rules that
        // declare an opaque fill now reach this set, where they used to be
        // dropped before it, so without it one of them could shadow a
        // colour-only rule sharing its selector text and computed colours - a
        // base rule and its @media override, say. The shadowed entry is the
        // one this file keeps, so the loss would be silent coverage.
        const key = `${rule.selectorText}|${declaresBackground}|${style.color}|${stack.map((b) => `${b.r},${b.g},${b.b},${b.a}`).join('/')}`;
        if (seen.has(key)) continue;
        seen.add(key);

        out.push({
          selector: rule.selectorText,
          colour: [colour.r, colour.g, colour.b],
          stack,
          declaresBackground,
          backgroundAlpha: declaredAlpha === undefined ? null : declaredAlpha,
          fontSize: parseFloat(style.fontSize),
          fontWeight: parseInt(style.fontWeight, 10) || 400,
          sample: ownText.slice(0, 40),
        });
      }
    }
    return out;
  }, scope);

  return found
    .filter(browserOwnsPairing)
    .map((pair) => ({ ...pair, route: routeName }));
}

const describePair = (p) =>
  `  ${p.ratio.toFixed(2)}:1 (needs ${p.threshold}) ` +
  `rgb(${p.colour.join(',')}) on rgb(${p.backdrop.map(Math.round).join(',')})  ` +
  `${p.selector}  [${p.route}] "${p.sample}"`;

test.describe('Contrast, computed cascade', () => {
  for (const theme of THEMES) {
    test(`T-CONTRAST: rendered pairings clear WCAG in ${theme.name}`, async ({ page }) => {
      const pairs = [];
      for (const route of ROUTES) {
        await loadApp(page, route.path, route.query || '');
        await selectTheme(page, theme.value);
        await route.setup(page);
        // Park the pointer before observing. Playwright leaves the mouse where
        // the last click put it, and `route.setup` clicks different things on
        // different routes, so `:hover` matched a different element from run to
        // run: which rules match at all, and what colour the matched ones
        // compute, both moved with it. Measured across three container runs -
        // run 1 collected `.tab-button:hover` and later ones did not, and
        // entries came and went on routes whose commits changed nothing. Both
        // vacuity guards stayed green throughout, because a floor and a
        // named-selector list can see an empty sweep but not a different one.
        //
        // The corner is arbitrary but fixed, which is the whole point: this
        // buys reproducibility, not the absence of hover.
        await page.mouse.move(0, 0);
        pairs.push(...(await collectPairs(page, route.name, route.scope || null)));
      }

      // Vacuity guard. Every assertion below is satisfied by an empty list, so
      // without this the check is green against a page that never hydrated, a
      // route that 404ed, or a stylesheet that failed to load.
      expect(
        pairs.length,
        `${theme.name}: measured ${pairs.length} pairings, too few to be a real page`,
      ).toBeGreaterThanOrEqual(MINIMUM_PAIRS);

      // Reaching the selectors this check was built for is a separate claim
      // from those selectors passing. A rename or a fixture change that stopped
      // them rendering would otherwise leave the check green covering nothing.
      const measured = new Set(pairs.map((pair) => pair.selector));
      for (const selector of MUST_REACH) {
        expect(
          [...measured].some((s) => s.includes(selector)),
          `${theme.name}: ${selector} was never measured, so #158's own example is uncovered`,
        ).toBeTruthy();
      }

      // The widening has its own vacuity guard, separate from MINIMUM_PAIRS,
      // because the colour-only pairings alone clear that floor: a change that
      // silently stopped collecting translucent fills would leave every
      // assertion here green while covering exactly what it did before. Not a
      // named selector, because the claim is "the widening reached something"
      // rather than "it reached the one rule I thought of".
      //
      // Strictly between 0 and 1, not merely `declaresBackground`. A rule
      // declaring `transparent` renders exactly as a colour-only rule does and
      // was already reachable before the widening, and two of them are on
      // these routes (`.tab-button`, `.btn-secondary`), so counting those
      // would let the guard be satisfied by pairings the widening did not
      // win. Only a partly translucent fill is a thing this file can measure
      // and validate_contrast.py cannot.
      const translucent = pairs.filter(
        (pair) => pair.backgroundAlpha > 0 && pair.backgroundAlpha < 1,
      );
      expect(
        translucent.length,
        `${theme.name}: no partly-translucent fill was measured, so the ` +
          'widening past colour-only rules is covering nothing',
      ).toBeGreaterThan(0);

      // An element with no opaque ancestor is backed by the canvas, which the
      // DOM walk cannot see. Recorded as unmeasurable and named in the report
      // rather than assumed white, for the reason validate_contrast.py gives:
      // silence beats a fabricated reading.
      const unmeasurable = [];
      const weighed = [];
      for (const pair of pairs) {
        const backdrop = flattenBackdrop(pair.stack);
        if (!backdrop) {
          unmeasurable.push(pair);
          continue;
        }
        weighed.push({
          ...pair,
          backdrop,
          ratio: contrastRatio(pair.colour, backdrop),
          threshold: thresholdFor(pair),
        });
      }

      // Reported every run, passing or not. The point of this file is that
      // somebody can read the numbers; a check that speaks only when it fails
      // cannot be sanity-checked against a screenshot.
      console.log(
        `\n${theme.name}: ${weighed.length} pairings measured ` +
          `(${translucent.length} over a partly translucent fill), ` +
          `${unmeasurable.length} unmeasurable\n` +
          weighed
            .slice()
            .sort((a, b) => a.ratio - b.ratio)
            .map(describePair)
            .join('\n') +
          (unmeasurable.length
            ? `\n  unmeasurable (no opaque ancestor): ${unmeasurable
                .map((p) => p.selector)
                .join(', ')}`
            : ''),
      );

      const failures = weighed.filter(
        (p) => p.ratio < p.threshold && DEFERRED[`${theme.value} ${p.selector}`] === undefined,
      );
      expect(
        failures.map(describePair).join('\n'),
        `${theme.name}: ${failures.length} pairing(s) below the WCAG bar as rendered. ` +
          'These are the ratio on the ancestor that actually painted, so a ' +
          'translucent fill can read lower here than in validate_contrast.py, ' +
          'which reports the best surface the theme declares. Fix the colour, ' +
          'or record the decision in DEFERRED with a reason and who took it.',
      ).toBe('');
    });
  }
});

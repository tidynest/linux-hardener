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
const { loadApp, runScan, runApply, selectTheme, THEMES } = require('./helpers');
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
  // Six of seven themes. A systemic cause is likely, so read it as one
  // question about `--pill-muted-bg` against this panel rather than as six.
  'default .severity_exception': fleetPanel('4.21'),
  'daywatch .severity_exception': fleetPanel('4.23'),
  'sentinel .severity_exception': fleetPanel('4.24'),
  'guardian .severity_exception': fleetPanel('4.28'),
  'command .severity_exception': fleetPanel('4.34'),
  'fortress .severity_exception': fleetPanel('4.34'),
  // Five of seven, and the worst readings in the set.
  'sentinel .tally-crit': fleetPanel('3.82'),
  'fortress .tally-crit': fleetPanel('4.00'),
  'default .tally-crit': fleetPanel('4.11'),
  'guardian .tally-crit': fleetPanel('4.16'),
  'command .tally-crit': fleetPanel('4.20'),
  // One theme each. Daywatch's `.severity_low` passes here at 5.29:1, which is
  // the 2026-08-20 --color-info fix confirmed against a rendered ancestor.
  'sentinel .severity_critical': fleetPanel('4.18'),
  'fortress .severity_low': fleetPanel('4.29'),
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
      await page.getByRole('button', { name: /Scan Selected/i }).click();
      // db-01 was not selected, so exactly one row stays unscanned. Waiting on
      // the result rather than the button: the row cannot expand before the
      // scan lands, and a blind click would expand nothing.
      await expect(page.getByText('Not scanned yet')).toHaveCount(1);
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
 */
async function collectPairs(page, routeName) {
  const found = await page.evaluate(() => {
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
  });

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
        pairs.push(...(await collectPairs(page, route.name)));
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

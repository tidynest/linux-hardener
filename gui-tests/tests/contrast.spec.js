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
const { loadApp, runScan, selectTheme, THEMES } = require('./helpers');
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
// Empty because nothing it measures currently fails. It HAS run: #173 was its
// first container execution, and it failed all seven theme cases on a
// flattener bug that collected 0 pairings rather than on any colour. Keep this
// list empty by fixing what it finds; record a decision here only when the fix
// is a design change that is not tooling's to take.
const DEFERRED = {};

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
  { path: '/analysis', name: 'analysis', setup: async () => {} },
];

// Selectors this check exists to reach. If a run measures nothing for one of
// them the check has quietly stopped covering the very thing it was built for,
// which is a different and worse outcome than finding a failure. Asserted per
// theme rather than once, because a theme that failed to apply would otherwise
// be measured entirely in the default theme's colours and still look covered.
const MUST_REACH = ['.timeline-verify-ok', '.timeline-verify-bad'];

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
    test(`T-CONTRAST: colour-only rules clear WCAG in ${theme.name}`, async ({ page }) => {
      const pairs = [];
      for (const route of ROUTES) {
        await loadApp(page, route.path);
        await selectTheme(page, theme.value);
        await route.setup(page);
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

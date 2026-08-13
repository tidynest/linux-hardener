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
// Three decisions worth stating, because #158 left all three open:
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
//
// The arithmetic lives in contrast-math.js and is proved by its own self-check
// against #158's hand measurements. Nothing is computed inside `page.evaluate`,
// so there is no second copy of the WCAG formula to drift from that one.
// =============================================================================

const { test, expect } = require('@playwright/test');
const { loadApp, runScan, selectTheme, THEMES } = require('./helpers');
const { contrastRatio, flattenBackdrop, thresholdFor } = require('./contrast-math');

// Known failures held open on purpose, keyed `<theme value> <selector>`, each
// with the reason and who decides. Reported on every run; they merely do not
// fail. Meant to be removed rather than accumulated.
//
// Empty at the time of writing, and that is not a claim that the interface
// passes: this check has never been run, because gui-tests execute only inside
// nspawn containers. The first person to run it either fixes what it finds or
// records the decision here.
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
    const flatten = (rules, out = []) => {
      for (const rule of rules) {
        if (rule.cssRules) flatten(Array.from(rule.cssRules), out);
        else if (rule.style) out.push(rule);
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
      const declaresBackground =
        rule.style.getPropertyValue('background-color') ||
        rule.style.getPropertyValue('background');
      // Rules declaring both are already weighed by validate_contrast.py.
      // Weighing them here too would make one defect fail two checks with two
      // different numbers, which is how a team learns to read neither.
      if (!declaresColour || declaresBackground) continue;

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

        const key = `${rule.selectorText}|${style.color}|${stack.map((b) => `${b.r},${b.g},${b.b},${b.a}`).join('/')}`;
        if (seen.has(key)) continue;
        seen.add(key);

        out.push({
          selector: rule.selectorText,
          colour: [colour.r, colour.g, colour.b],
          stack,
          fontSize: parseFloat(style.fontSize),
          fontWeight: parseInt(style.fontWeight, 10) || 400,
          sample: ownText.slice(0, 40),
        });
      }
    }
    return out;
  });

  return found.map((pair) => ({ ...pair, route: routeName }));
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
        `\n${theme.name}: ${weighed.length} colour-only pairings measured, ` +
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
        `${theme.name}: ${failures.length} colour-only pairing(s) below the WCAG bar. ` +
          'Fix the colour, or record the decision in DEFERRED with a reason and who took it.',
      ).toBe('');
    });
  }
});

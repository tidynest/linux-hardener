// =============================================================================
// CONTRAST ARITHMETIC - issue #158
// =============================================================================
//
// Split out of contrast.spec.js so it can be proved without a browser. The
// spec it serves runs only inside nspawn containers, so everything in that
// file is unverifiable on a development host; this half is plain arithmetic
// over plain numbers and has no reason to share that ceiling.
//
// It also keeps the browser half to one job. `page.evaluate` reads values off
// the DOM and returns them; nothing is computed in there, so there is no
// second copy of the WCAG formula that can drift from this one.
//
// Self-check: `node gui-tests/tests/contrast-math.js`
// =============================================================================

/** WCAG 2.1 relative luminance of an [r, g, b] triple in 0..255. */
function luminance([r, g, b]) {
  const linear = [r, g, b].map((channel) => {
    const c = channel / 255;
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
}

/** WCAG 2.1 contrast ratio between two [r, g, b] triples. Order-independent. */
function contrastRatio(a, b) {
  const [la, lb] = [luminance(a), luminance(b)];
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/**
 * Flatten a stack of backgrounds, nearest first, onto the opaque one at its
 * end.
 *
 * Taking the first fully opaque ancestor and ignoring what sits over it would
 * be wrong wherever a translucent surface intervenes, and the `--color-*-bg`
 * tokens are `rgba` by design, so that case is the normal one rather than the
 * exotic one. Being confidently wrong is what this whole check exists against.
 *
 * Returns null when the stack has no opaque base: the real backing is then the
 * canvas, which the DOM walk cannot see, and reporting it as white would be a
 * fabricated reading.
 */
function flattenBackdrop(stack) {
  if (!stack.length || stack[stack.length - 1].a !== 1) return null;
  const layers = stack.slice();
  let base = layers.pop();
  while (layers.length) {
    const over = layers.pop();
    base = {
      r: over.r * over.a + base.r * (1 - over.a),
      g: over.g * over.a + base.g * (1 - over.a),
      b: over.b * over.a + base.b * (1 - over.a),
      a: 1,
    };
  }
  return [base.r, base.g, base.b];
}

/**
 * The bar this text has to clear.
 *
 * WCAG 2.1 1.4.3: large text is 24px, or 18.66px at weight 700 or above.
 * `validate_contrast.py` holds everything to 4.5 because a static parse cannot
 * know the rendered size. A browser can, so this applies the 3.0 the
 * specification actually allows rather than a stricter bar it invented.
 */
function thresholdFor({ fontSize, fontWeight }) {
  const isLarge = fontSize >= 24 || (fontSize >= 18.66 && fontWeight >= 700);
  return isLarge ? 3.0 : 4.5;
}

/**
 * Whether the browser half owns a pairing, or `validate_contrast.py` does.
 *
 * The two checks stay disjoint on purpose: one defect failing both with two
 * different numbers is how a team learns to read neither. What changed is the
 * boundary, not the principle. It used to be "declares a background", which
 * was the same thing as "the static parse already has the true number" until
 * that parse learned to composite alpha fills.
 *
 * An OPAQUE declared background is still fully determined on paper, so it is
 * the static check's alone and nothing here may touch it. A translucent one is
 * not: that check composites the fill over every `--bg-*` surface the theme
 * declares and takes the BEST, which is a ceiling rather than a reading, and
 * its own docstring records the cost - a pair failing on the darker surfaces
 * but clearing on one is not reported there. The browser knows which ancestor
 * actually rendered. The two numbers answer different questions, so the better
 * one is not a duplicate of the weaker one.
 *
 * `backgroundAlpha` is the element's COMPUTED alpha rather than the declared
 * text, because a rule may declare `var(--pill-muted-bg)` and only the cascade
 * knows what that resolved to. An unreadable one is declined rather than
 * assumed: measuring text against its ancestors while ignoring a fill we could
 * not parse would report a colour that never rendered.
 */
function browserOwnsPairing({ declaresBackground, backgroundAlpha }) {
  if (!declaresBackground) return true;
  return Number.isFinite(backgroundAlpha) && backgroundAlpha < 1;
}

module.exports = {
  luminance,
  contrastRatio,
  flattenBackdrop,
  thresholdFor,
  browserOwnsPairing,
};

// --- Self-check --------------------------------------------------------------
if (require.main === module) {
  const assert = require('node:assert');
  const near = (got, want, what) =>
    assert.ok(
      Math.abs(got - want) < 0.01,
      `${what}: expected ${want}, got ${got.toFixed(4)}`,
    );

  // The two anchors the formula is defined by.
  near(contrastRatio([0, 0, 0], [255, 255, 255]), 21, 'black on white');
  near(contrastRatio([255, 255, 255], [255, 255, 255]), 1, 'white on white');
  near(contrastRatio([255, 255, 255], [0, 0, 0]), 21, 'order does not matter');

  // Issue #158's own measurements, taken by hand against the Daywatch surface
  // that actually renders. Using them as the oracle means this file agrees
  // with the arithmetic that found the defect, rather than with itself.
  near(contrastRatio([5, 150, 105], [248, 246, 242]), 3.49, 'old --color-good');
  near(contrastRatio([16, 185, 129], [248, 246, 242]), 2.35, 'old --color-good-bright');
  near(contrastRatio([5, 150, 105], [232, 227, 219]), 2.95, 'old --color-good, worst surface');
  near(contrastRatio([3, 107, 82], [248, 246, 242]), 6.03, 'fixed --color-good');
  near(contrastRatio([6, 95, 70], [248, 246, 242]), 7.12, 'fixed --color-good-bright');

  // Compositing. Half-opacity red over white is the midpoint, and the result
  // has to differ from both the layer and the base or the fold did nothing.
  const composited = flattenBackdrop([
    { r: 255, g: 0, b: 0, a: 0.5 },
    { r: 255, g: 255, b: 255, a: 1 },
  ]);
  near(composited[0], 255, 'composite red channel');
  near(composited[1], 127.5, 'composite green channel');
  near(composited[2], 127.5, 'composite blue channel');

  // Two translucent layers fold in order, nearest last. Reversing the stack
  // must give a different answer, or the function is ignoring order and the
  // test above would pass against a plain average.
  //
  // Compared as whole triples, not on one channel. These two stacks agree
  // exactly on green and blue (95.625 both ways) and differ only in red, so a
  // check written against a single channel is a coin toss: green would have
  // reported the function as order-blind when it is not.
  const ordered = flattenBackdrop([
    { r: 0, g: 0, b: 0, a: 0.25 },
    { r: 255, g: 0, b: 0, a: 0.5 },
    { r: 255, g: 255, b: 255, a: 1 },
  ]);
  const reversed = flattenBackdrop([
    { r: 255, g: 0, b: 0, a: 0.5 },
    { r: 0, g: 0, b: 0, a: 0.25 },
    { r: 255, g: 255, b: 255, a: 1 },
  ]);
  assert.ok(
    ordered.some((channel, i) => Math.abs(channel - reversed[i]) > 1),
    `order is ignored: ${ordered} vs ${reversed}`,
  );

  // An opaque single layer passes through unchanged.
  assert.deepStrictEqual(
    flattenBackdrop([{ r: 12, g: 34, b: 56, a: 1 }]),
    [12, 34, 56],
    'an opaque backdrop is returned as-is',
  );

  // No opaque base anywhere means unmeasurable, not white.
  assert.strictEqual(flattenBackdrop([]), null, 'an empty stack is unmeasurable');
  assert.strictEqual(
    flattenBackdrop([{ r: 255, g: 0, b: 0, a: 0.5 }]),
    null,
    'a translucent-only stack is unmeasurable',
  );

  // The 3.0 bar is allowed only where the specification allows it. The 23px
  // bold case is the one a naive "bold means large" reading gets wrong.
  assert.strictEqual(thresholdFor({ fontSize: 16, fontWeight: 400 }), 4.5, 'body text');
  assert.strictEqual(thresholdFor({ fontSize: 24, fontWeight: 400 }), 3.0, '24px is large');
  assert.strictEqual(thresholdFor({ fontSize: 19, fontWeight: 700 }), 3.0, '19px bold is large');
  assert.strictEqual(thresholdFor({ fontSize: 19, fontWeight: 400 }), 4.5, '19px normal is not');
  assert.strictEqual(thresholdFor({ fontSize: 23, fontWeight: 600 }), 4.5, '23px semibold is not');

  // Scope. The colour-only case is what this file has always covered, and the
  // opaque case is the one it must never touch, because a rule declaring a
  // text colour and an opaque fill in the same block is fully weighed by
  // validate_contrast.py.
  const owns = browserOwnsPairing;
  assert.strictEqual(
    owns({ declaresBackground: false, backgroundAlpha: 0 }),
    true,
    'a colour-only rule is ours',
  );
  assert.strictEqual(
    owns({ declaresBackground: false, backgroundAlpha: 1 }),
    true,
    'a colour-only rule stays ours even where an ancestor paints an opaque fill',
  );
  assert.strictEqual(
    owns({ declaresBackground: true, backgroundAlpha: 1 }),
    false,
    "an opaque declared fill is the static check's, and weighing it here doubles one defect",
  );

  // The widening itself, and the reason it is not a duplicate: the static
  // check has a best-of-surfaces ceiling for these, never the rendered fact.
  // `.severity_medium` at rgba(227, 179, 65, 0.15) is the shape.
  assert.strictEqual(
    owns({ declaresBackground: true, backgroundAlpha: 0.15 }),
    true,
    'a translucent declared fill is ours: the static check has only a ceiling for it',
  );
  assert.strictEqual(
    owns({ declaresBackground: true, backgroundAlpha: 0 }),
    true,
    'a fully transparent declared fill renders as colour-only and is ours',
  );

  // An unreadable computed alpha is declined rather than measured. Without
  // this the pairing would be weighed against its ancestors alone, silently
  // dropping a fill that did render: a fabricated reading, which is the one
  // outcome both contrast files rank below saying nothing.
  for (const alpha of [null, undefined, NaN]) {
    assert.strictEqual(
      owns({ declaresBackground: true, backgroundAlpha: alpha }),
      false,
      `an unparseable alpha (${alpha}) is declined, not assumed transparent`,
    );
  }

  console.log('contrast-math: all checks passed');
}

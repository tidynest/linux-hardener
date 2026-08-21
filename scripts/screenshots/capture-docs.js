// Drives the harness through every state `docs/assets/screenshots/` documents
// and writes a 1920x1080 PNG per state.
//
// `shoot.py` cannot do this. It runs `chromium --headless --screenshot`, which
// loads a URL and shoots it, so it reaches the seven static ROUTES and none of
// the sixteen states behind a click: the modals, the expanded rows, the armed
// delete, the advanced panels. Those sixteen are most of the corpus, and they
// are the ones carrying the colours that go stale.
//
// Playwright comes from `gui-tests/node_modules` and drives the system
// Chromium, the same pair the container suite uses. It is required by path
// rather than by name because this file lives outside that package.
//
// **Every shot asserts the state it names before it shoots.** A capture step
// that clicked and hoped would write a plausible PNG of the wrong screen, and
// a screenshot is the one artefact nobody diffs.

const path = require('path');
const REPO = path.resolve(__dirname, '../..');
const { chromium } = require(path.join(REPO, 'gui-tests/node_modules/playwright'));

const BASE = 'http://localhost:8137';
const OUT = process.argv[2] || path.join(__dirname, 'shots');
const WIDTH = 1920;
const HEIGHT = 1080;


// The scan button's accessible name matches BOTH states on purpose: it reads
// "Scanning..." mid-scan, so a locator written only for the resting name
// resolves to nothing at exactly the moment the wait matters. Same reasoning as
// `gui-tests/tests/helpers.js`, which is where this came from.
const runScan = async (page) => {
  const button = page.getByRole('button', { name: /Run.*Scan|Scanning/i });
  await button.click();
  await page.waitForFunction(
    () =>
      !Array.from(document.querySelectorAll('button')).some((b) =>
        /Scanning/i.test(b.textContent || ''),
      ),
    null,
    { timeout: 20000 },
  );
};

// The scheduler's toggles are visually-hidden inputs behind a styled track, so
// Playwright refuses to `check()` them: the input is not the thing a reader
// clicks. Click the label, which is.
const toggle = (page, name) =>
  page.locator('.toggle-switch-label', { hasText: name }).first().click();

// name, route, ready (a selector that exists ONLY in the wanted state), steps.
const SHOTS = [
  {
    name: 'dashboard',
    route: '/',
    // The redesign replaced the numeric panel with a score bar, so the shot
    // asserts the READING rather than a container that renders empty too.
    ready: '.dashboard-page details[open] .framework-row, .dashboard-page details[open]',
    steps: async (page) => {
      await runScan(page);
      // README's alt text promises per-framework compliance, and the
      // disclosure holding it is closed on load.
      await page.getByText('Compliance by framework').click();
    },
  },

  { name: 'analysis-findings', route: '/analysis', ready: '.finding-row', steps: runScan },
  {
    name: 'analysis-finding-detail',
    route: '/analysis',
    ready: '.finding-detail',
    steps: async (page) => {
      await runScan(page);
      await page.locator('.finding-row').first().click();
    },
  },
  {
    name: 'analysis-compliance',
    route: '/analysis',
    ready: '.compliance-tab',
    steps: async (page) => {
      await runScan(page);
      await page.getByRole('tab', { name: 'Compliance' }).click();
    },
  },
  {
    name: 'analysis-history',
    route: '/analysis',
    ready: '.scan-history-tab .timeline-node',
    steps: async (page) => {
      await runScan(page);
      await page.getByRole('tab', { name: 'Scan History' }).click();
    },
  },

  { name: 'hardening', route: '/hardening', ready: '.plugin-rows .plugin-row' },
  {
    name: 'hardening-advanced',
    route: '/hardening',
    ready: '.advanced-disclosure[open] .advanced-disclosure-body',
    steps: async (page) => page.locator('.advanced-disclosure-summary').click(),
  },
  {
    name: 'hardening-preview',
    route: '/hardening',
    // The preview REPLACES the configure panel; there is no `.preview-panel`.
    // The disabled "Apply N Changes" button is what only the preview renders.
    ready: 'button:has-text("Apply")',
    steps: async (page) => page.getByRole('button', { name: /Preview Changes/i }).click(),
  },
  {
    name: 'hardening-history',
    route: '/hardening',
    ready: '.timeline-verify',
    steps: async (page) => page.getByRole('tab', { name: /History/ }).click(),
  },
  {
    name: 'hardening-checkpoint-detail',
    route: '/hardening',
    // Not a modal: the detail expands inline under the checkpoint row.
    ready: '.detail-file-list',
    steps: async (page) => {
      await page.getByRole('tab', { name: /History/ }).click();
      await page.locator('.timeline-verify').first().waitFor();
      await page.getByRole('button', { name: 'Details', exact: true }).first().click();
    },
  },
  {
    name: 'hardening-rollback-confirm',
    route: '/hardening',
    ready: '.modal',
    steps: async (page) => {
      await page.getByRole('tab', { name: /History/ }).click();
      await page.locator('.timeline-verify').first().waitFor();
      await page.getByRole('button', { name: 'Roll back', exact: true }).first().click();
    },
  },

  { name: 'fleet', route: '/fleet', ready: '.host-row' },
  {
    name: 'fleet-host-expanded',
    route: '/fleet',
    ready: '.host-panel',
    steps: async (page) => page.getByRole('button', { name: 'Expand web-01' }).click(),
  },
  {
    name: 'fleet-add-host',
    route: '/fleet',
    ready: '.host-form',
    steps: async (page) => page.getByRole('button', { name: 'Add Host', exact: true }).click(),
  },
  {
    name: 'fleet-adhoc',
    route: '/fleet',
    ready: '.hosts-adhoc-input',
    steps: async (page) =>
      page.getByRole('button', { name: /Add ad-hoc target/i }).click(),
  },
  {
    name: 'fleet-delete-armed',
    route: '/fleet',
    ready: 'text=Delete?',
    steps: async (page) => {
      await page.getByRole('button', { name: 'Expand web-01' }).click();
      await page.locator('.host-panel').waitFor();
      await page.getByRole('button', { name: 'Delete', exact: true }).first().click();
    },
  },

  {
    name: 'fleet-apply',
    route: '/fleet-apply',
    ready: '.fleet-outcome',
    steps: async (page) => {
      const hosts = page.getByRole('group', { name: 'Hosts', exact: true });
      await hosts.getByRole('checkbox', { name: /^web-01 / }).check();
      await hosts.getByRole('checkbox', { name: /^db-01 / }).check();
      await page.getByRole('button', { name: /Preview Changes/i }).click();
    },
  },
  {
    name: 'fleet-apply-rollback',
    route: '/fleet-apply',
    ready: '.fleet-glyph-ok',
    steps: async (page) => {
      await page.getByRole('radio', { name: 'Roll back' }).check();
      const hosts = page.getByRole('group', { name: 'Hosts', exact: true });
      await hosts.getByRole('checkbox', { name: /^web-01 / }).check();
      await hosts.getByRole('checkbox', { name: /^db-01 / }).check();
      await page.getByRole('button', { name: /Preview Changes/i }).click();
      const execute = page.getByRole('button', { name: /^Execute/ });
      await execute.waitFor();
      await execute.click();
      await page.getByRole('button', { name: /Yes, execute/i }).click();
    },
  },

  { name: 'scheduler', route: '/scheduler', ready: '.schedule-section' },
  {
    name: 'scheduler-enabled',
    route: '/scheduler',
    ready: '.schedule-section .form-select',
    steps: (page) => toggle(page, /Enable scheduled scanning/i),
  },
  {
    name: 'scheduler-advanced',
    route: '/scheduler',
    // Not a <details>: a button and a chevron, so there is no [open] to wait
    // on. The cron field is what only the expanded state renders.
    ready: '.schedule-section input[type=text]',
    steps: async (page) => {
      await toggle(page, /Enable scheduled scanning/i);
      await page.getByRole('button', { name: /Advanced: Custom Schedule/i }).click();
    },
  },
  {
    name: 'scheduler-webhook',
    route: '/scheduler',
    ready: '.notification-section .form-row',
    steps: (page) => toggle(page, /Enable webhook notifications/i),
  },

  { name: 'settings', route: '/settings', ready: '.theme-toggle' },
];

(async () => {
  const browser = await chromium.launch({
    executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || '/usr/bin/chromium',
    args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage'],
  });
  const failures = [];
  for (const shot of SHOTS) {
    const page = await browser.newPage({ viewport: { width: WIDTH, height: HEIGHT } });
    try {
      await page.goto(BASE + shot.route, { waitUntil: 'networkidle' });
      // The WASM boots after networkidle; wait for the shell before driving.
      await page.locator('.app-shell, .main-content, #app').first().waitFor({ timeout: 20000 });
      if (shot.steps) await shot.steps(page);
      await page.locator(shot.ready).first().waitFor({ state: 'visible', timeout: 15000 });
      // Park the pointer: a hover left where the last click put it changes
      // which rules match, exactly as it does in the contrast sweep.
      await page.mouse.move(0, 0);
      await page.waitForTimeout(400);
      await page.screenshot({ path: path.join(OUT, shot.name + '.png') });
      console.log(`  ok    ${shot.name}`);
    } catch (problem) {
      failures.push(`${shot.name}: ${String(problem).split('\n')[0]}`);
      console.log(`  FAIL  ${shot.name}: ${String(problem).split('\n')[0]}`);
    }
    await page.close();
  }
  await browser.close();
  if (failures.length) {
    console.log(`\n${failures.length} of ${SHOTS.length} states not reached.`);
    process.exit(1);
  }
  console.log(`\nAll ${SHOTS.length} states captured at ${WIDTH}x${HEIGHT}.`);
})();

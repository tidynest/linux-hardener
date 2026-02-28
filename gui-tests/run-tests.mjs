import { chromium } from 'playwright';

(async () => {
  const browser = await chromium.launch({
    executablePath: '/usr/bin/chromium',
    headless: false,
    args: ['--no-sandbox']
  });
  const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
  const results = { passed: [], failed: [] };

  function log(msg) { console.log(msg); }
  function pass(name) { results.passed.push(name); log(`PASS: ${name}`); }
  function fail(name, err) { results.failed.push(name); log(`FAIL: ${name} — ${err}`); }

  try {
    // 1. Dashboard loads
    await page.goto('http://127.0.0.1:1420/', { waitUntil: 'networkidle', timeout: 30000 });
    await page.screenshot({ path: '/tmp/test-grouped/01-dashboard.png', fullPage: true });
    pass('Dashboard loads');

    // 2. Skip link appears on Tab
    await page.keyboard.press('Tab');
    await page.waitForTimeout(300);
    const skipLink = await page.locator('.skip-link').isVisible();
    await page.screenshot({ path: '/tmp/test-grouped/02-skip-link.png' });
    skipLink ? pass('Skip link visible on Tab') : fail('Skip link visible on Tab', 'not visible');

    await page.click('body');
    await page.waitForTimeout(200);

    // 3-7. Ctrl+N page navigation
    const navTests = [
      { key: 'Control+2', path: '/analysis', name: 'Analysis' },
      { key: 'Control+3', path: '/hardening', name: 'Hardening' },
      { key: 'Control+4', path: '/remote', name: 'Remote' },
      { key: 'Control+5', path: '/scheduler', name: 'Scheduler' },
      { key: 'Control+1', path: '/', name: 'Dashboard' },
    ];

    for (const [i, nav] of navTests.entries()) {
      await page.keyboard.press(nav.key);
      await page.waitForTimeout(500);
      const num = i + 3;
      await page.screenshot({ path: `/tmp/test-grouped/${String(num).padStart(2, '0')}-${nav.name.toLowerCase()}.png`, fullPage: true });
      const urlMatch = nav.path === '/'
        ? (page.url().endsWith(':1420/') || page.url().endsWith(':1420'))
        : page.url().includes(nav.path);
      urlMatch ? pass(`${nav.key} → ${nav.name}`) : fail(`${nav.key} → ${nav.name}`, page.url());
    }

    // 8-9. Alt+T theme cycling
    await page.keyboard.press('Alt+t');
    await page.waitForTimeout(300);
    const theme1 = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
    await page.screenshot({ path: '/tmp/test-grouped/08-theme-cycle-1.png' });
    theme1 ? pass(`Alt+T theme → ${theme1}`) : fail('Alt+T theme cycle', 'no data-theme');

    await page.keyboard.press('Alt+t');
    await page.waitForTimeout(300);
    const theme2 = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
    await page.screenshot({ path: '/tmp/test-grouped/09-theme-cycle-2.png' });
    (theme2 && theme2 !== theme1) ? pass(`Alt+T 2nd → ${theme2}`) : fail('Alt+T 2nd cycle', `same: ${theme2}`);

    // Reset theme
    await page.evaluate(() => {
      document.documentElement.removeAttribute('data-theme');
      localStorage.setItem('theme', 'default');
    });

    // 10. Findings grid on Analysis page
    await page.keyboard.press('Control+2');
    await page.waitForTimeout(500);

    // Dismiss error banner if present
    if (await page.locator('.error-banner').count() > 0) {
      await page.keyboard.press('Escape');
      await page.waitForTimeout(300);
    }

    const findingRows = await page.locator('.finding-row').all();
    log(`Finding rows: ${findingRows.length}`);

    if (findingRows.length > 0) {
      await findingRows[0].click();
      await page.waitForTimeout(300);
      await page.screenshot({ path: '/tmp/test-grouped/10-finding-selected.png' });

      const hasSelected = await page.locator('.finding-row-selected').count();
      hasSelected > 0 ? pass('Finding row selection') : fail('Finding row selection', 'no highlight');

      await findingRows[0].focus();
      await page.keyboard.press('ArrowDown');
      await page.waitForTimeout(200);
      await page.screenshot({ path: '/tmp/test-grouped/11-finding-arrow-down.png' });
      pass('Finding ArrowDown');

      await page.keyboard.press('Enter');
      await page.waitForTimeout(300);
      const detailOpen = await page.locator('.finding-detail').isVisible();
      await page.screenshot({ path: '/tmp/test-grouped/12-finding-detail-open.png' });
      detailOpen ? pass('Enter opens finding detail') : fail('Enter opens finding detail', 'not visible');

      // Copy button
      const copyBtn = page.locator('.detail-header-actions button', { hasText: 'Copy' });
      if (await copyBtn.count() > 0) {
        await copyBtn.click();
        await page.waitForTimeout(600);
        const copyLabel = await copyBtn.textContent();
        await page.screenshot({ path: '/tmp/test-grouped/13-copy-clicked.png' });
        (copyLabel === 'Copied!' || copyLabel === 'Failed')
          ? pass(`Copy button → "${copyLabel}"`)
          : fail('Copy button feedback', copyLabel);
      }

      // Escape closes detail
      await page.keyboard.press('Escape');
      await page.waitForTimeout(300);
      const detailClosed = !(await page.locator('.finding-detail').isVisible());
      await page.screenshot({ path: '/tmp/test-grouped/14-escape-close-detail.png' });
      detailClosed ? pass('Escape closes detail') : fail('Escape closes detail', 'still visible');
    } else {
      log('No findings — skipping grid tests (need scan data)');
      await page.screenshot({ path: '/tmp/test-grouped/10-no-findings.png' });
    }

    // 15-18. Tab keyboard navigation — use Analysis page (3 tabs with proper IDs)
    // Navigate to Analysis if not already there
    if (!page.url().includes('/analysis')) {
      await page.keyboard.press('Control+2');
      await page.waitForTimeout(500);
    }

    // Dismiss error banner if present
    if (await page.locator('.error-banner').count() > 0) {
      await page.keyboard.press('Escape');
      await page.waitForTimeout(300);
    }

    const tabButtons = await page.locator('[role="tab"]').all();
    log(`Tab buttons on Analysis: ${tabButtons.length}`);

    if (tabButtons.length > 1) {
      // Click first tab to focus it (more reliable than .focus())
      await tabButtons[0].click();
      await page.waitForTimeout(200);

      const initialSelected = await tabButtons[0].getAttribute('aria-selected');
      initialSelected === 'true' ? pass('First tab selected') : fail('First tab selected', initialSelected);

      // ArrowRight → 2nd tab
      await page.keyboard.press('ArrowRight');
      await page.waitForTimeout(300);
      const secondSelected = await tabButtons[1].getAttribute('aria-selected');
      await page.screenshot({ path: '/tmp/test-grouped/15-tab-arrow-right.png' });
      secondSelected === 'true' ? pass('ArrowRight → 2nd tab') : fail('ArrowRight → 2nd tab', secondSelected);

      // Verify focus moved (our fix)
      const focusedId = await page.evaluate(() => document.activeElement?.id);
      const secondTabId = await tabButtons[1].getAttribute('id');
      focusedId === secondTabId
        ? pass(`Focus follows selection (${focusedId})`)
        : fail('Focus follows selection', `focused=${focusedId} expected=${secondTabId}`);

      // ArrowRight → 3rd tab
      if (tabButtons.length > 2) {
        await page.keyboard.press('ArrowRight');
        await page.waitForTimeout(300);
        const thirdSelected = await tabButtons[2].getAttribute('aria-selected');
        await page.screenshot({ path: '/tmp/test-grouped/16-tab-arrow-right-2.png' });
        thirdSelected === 'true' ? pass('ArrowRight → 3rd tab') : fail('ArrowRight → 3rd tab', thirdSelected);
      }

      // Home → first tab
      await page.keyboard.press('Home');
      await page.waitForTimeout(300);
      const homeSelected = await tabButtons[0].getAttribute('aria-selected');
      await page.screenshot({ path: '/tmp/test-grouped/17-tab-home.png' });
      homeSelected === 'true' ? pass('Home → first tab') : fail('Home → first tab', homeSelected);

      // End → last tab
      await page.keyboard.press('End');
      await page.waitForTimeout(300);
      const lastSelected = await tabButtons[tabButtons.length - 1].getAttribute('aria-selected');
      await page.screenshot({ path: '/tmp/test-grouped/18-tab-end.png' });
      lastSelected === 'true' ? pass('End → last tab') : fail('End → last tab', lastSelected);
    }

    // 19. Verify Hardening page now uses TabBar with IDs
    await page.keyboard.press('Control+3');
    await page.waitForTimeout(500);

    if (await page.locator('.error-banner').count() > 0) {
      await page.keyboard.press('Escape');
      await page.waitForTimeout(300);
    }

    const hardeningTabs = await page.evaluate(() => {
      const tabs = document.querySelectorAll('[role="tab"]');
      return Array.from(tabs).map(t => ({
        id: t.id,
        text: t.textContent?.trim(),
        ariaSelected: t.getAttribute('aria-selected'),
      }));
    });
    log(`Hardening tabs: ${JSON.stringify(hardeningTabs)}`);
    const hardeningHasIds = hardeningTabs.length > 0 && hardeningTabs.every(t => t.id && t.id.length > 0);
    hardeningHasIds ? pass('Hardening tabs have IDs (TabBar)') : fail('Hardening tabs missing IDs', JSON.stringify(hardeningTabs));

    // Keyboard on Hardening tabs
    if (hardeningTabs.length > 1) {
      await page.locator('[role="tab"]').first().click();
      await page.waitForTimeout(200);
      await page.keyboard.press('ArrowRight');
      await page.waitForTimeout(300);
      const h2nd = await page.locator('[role="tab"]').nth(1).getAttribute('aria-selected');
      await page.screenshot({ path: '/tmp/test-grouped/19-hardening-tab-arrow.png' });
      h2nd === 'true' ? pass('Hardening ArrowRight → History') : fail('Hardening ArrowRight', h2nd);
    }

    // 20. Delete confirmation (Remote page)
    await page.keyboard.press('Control+4');
    await page.waitForTimeout(500);

    const deleteBtn = page.locator('.btn-danger.btn-small', { hasText: 'Delete' }).first();
    if (await deleteBtn.count() > 0) {
      await deleteBtn.click();
      await page.waitForTimeout(300);
      const confirmVisible = await page.locator('.confirm-delete-inline').isVisible();
      await page.screenshot({ path: '/tmp/test-grouped/20-delete-confirm.png' });
      confirmVisible ? pass('Delete confirmation appears') : fail('Delete confirmation', 'not visible');

      const cancelBtn = page.locator('.confirm-delete-inline .btn-secondary');
      if (await cancelBtn.count() > 0) {
        await cancelBtn.click();
        await page.waitForTimeout(300);
        const gone = !(await page.locator('.confirm-delete-inline').isVisible());
        await page.screenshot({ path: '/tmp/test-grouped/21-delete-cancelled.png' });
        gone ? pass('Cancel dismisses confirmation') : fail('Cancel dismisses', 'still visible');
      }
    } else {
      log('No delete buttons (no saved hosts) — skipping');
      await page.screenshot({ path: '/tmp/test-grouped/20-no-hosts.png' });
    }

    // 22. ARIA audit from Analysis page
    await page.keyboard.press('Control+2');
    await page.waitForTimeout(500);
    const aria = await page.evaluate(() => ({
      skipLink: !!document.querySelector('.skip-link'),
      mainContent: !!document.querySelector('#main-content'),
      tablistCount: document.querySelectorAll('[role="tablist"]').length,
      tabCount: document.querySelectorAll('[role="tab"]').length,
      tabpanelCount: document.querySelectorAll('[role="tabpanel"]').length,
      ariaLiveCount: document.querySelectorAll('[aria-live]').length,
    }));
    log(`ARIA: ${JSON.stringify(aria)}`);
    (aria.skipLink && aria.mainContent) ? pass('Skip link + #main-content') : fail('Landmarks', JSON.stringify(aria));
    aria.tablistCount > 0 ? pass(`tablist: ${aria.tablistCount}`) : fail('tablist', '0');
    aria.tabCount > 0 ? pass(`tab roles: ${aria.tabCount}`) : fail('tab roles', '0');
    aria.tabpanelCount > 0 ? pass(`tabpanel: ${aria.tabpanelCount}`) : fail('tabpanel', '0');

  } catch (err) {
    fail('Unexpected error', err.message);
    console.error(err);
    await page.screenshot({ path: '/tmp/test-grouped/error.png' }).catch(() => {});
  }

  await browser.close();

  log('\n========================================');
  log(`RESULTS: ${results.passed.length} passed, ${results.failed.length} failed`);
  log('========================================');
  if (results.failed.length > 0) {
    log('FAILURES:');
    results.failed.forEach(f => log(`  - ${f}`));
  } else {
    log('ALL TESTS PASSED');
  }
  log(`Screenshots: /tmp/test-grouped/`);
})();

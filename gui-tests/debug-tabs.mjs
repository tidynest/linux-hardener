import { chromium } from 'playwright';

(async () => {
  const browser = await chromium.launch({
    executablePath: '/usr/bin/chromium',
    headless: false,
    args: ['--no-sandbox']
  });
  const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });

  await page.goto('http://127.0.0.1:1420/', { waitUntil: 'networkidle', timeout: 30000 });

  // Go to hardening page
  await page.keyboard.press('Control+3');
  await page.waitForTimeout(500);

  // Dismiss error banner if present (it might steal Escape)
  const errorBanner = page.locator('.error-banner');
  if (await errorBanner.count() > 0) {
    await page.keyboard.press('Escape');
    await page.waitForTimeout(300);
    console.log('Dismissed error banner');
  }

  // Debug: dump all tab-related elements
  const tabInfo = await page.evaluate(() => {
    const tablist = document.querySelector('[role="tablist"]');
    const navTabBar = document.querySelector('.tab-bar');
    const tabs = document.querySelectorAll('[role="tab"]');
    const btns = document.querySelectorAll('.tab-button');

    return {
      hasTablist: !!tablist,
      tablistTag: tablist?.tagName,
      tablistRole: tablist?.getAttribute('role'),
      hasNavTabBar: !!navTabBar,
      navTabBarTag: navTabBar?.tagName,
      navTabBarRole: navTabBar?.getAttribute('role'),
      tabCount: tabs.length,
      tabButtonCount: btns.length,
      tabs: Array.from(tabs).map(t => ({
        id: t.id,
        text: t.textContent?.trim(),
        ariaSelected: t.getAttribute('aria-selected'),
        tabindex: t.getAttribute('tabindex'),
        role: t.getAttribute('role'),
      })),
      buttons: Array.from(btns).map(b => ({
        id: b.id,
        text: b.textContent?.trim(),
        ariaSelected: b.getAttribute('aria-selected'),
        tabindex: b.getAttribute('tabindex'),
        role: b.getAttribute('role'),
      })),
    };
  });
  console.log('Tab debug info:', JSON.stringify(tabInfo, null, 2));

  // Now try focusing first tab and pressing arrow
  if (tabInfo.tabCount > 0) {
    const firstTab = page.locator('[role="tab"]').first();
    await firstTab.focus();
    await page.waitForTimeout(200);

    const beforeFocus = await page.evaluate(() => document.activeElement?.id);
    console.log('Focus before ArrowRight:', beforeFocus);

    await page.keyboard.press('ArrowRight');
    await page.waitForTimeout(500);

    const afterFocus = await page.evaluate(() => document.activeElement?.id);
    const afterTabs = await page.evaluate(() => {
      return Array.from(document.querySelectorAll('[role="tab"]')).map(t => ({
        id: t.id,
        ariaSelected: t.getAttribute('aria-selected'),
      }));
    });
    console.log('Focus after ArrowRight:', afterFocus);
    console.log('Tab states after ArrowRight:', JSON.stringify(afterTabs));

    await page.screenshot({ path: '/tmp/test-grouped/debug-after-arrowright.png' });
  }

  // Also check Analysis page for tabs
  await page.keyboard.press('Control+2');
  await page.waitForTimeout(500);

  const analysisTabInfo = await page.evaluate(() => {
    const tabs = document.querySelectorAll('[role="tab"]');
    return {
      url: window.location.href,
      tabCount: tabs.length,
      tabs: Array.from(tabs).map(t => ({
        id: t.id,
        text: t.textContent?.trim(),
        ariaSelected: t.getAttribute('aria-selected'),
      })),
    };
  });
  console.log('Analysis page tab info:', JSON.stringify(analysisTabInfo, null, 2));

  await browser.close();
})();

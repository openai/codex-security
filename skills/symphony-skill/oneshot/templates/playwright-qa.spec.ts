// Symphony OneShot — Playwright QA spec stub.
//
// The QA lane copies this file to tests/e2e/qa.spec.ts and adapts the
// flows + selectors to the actual product. The five categories below are
// MANDATORY — do not delete sections, only fill them in or mark them
// "n/a per brief.md" with a citation.
//
// Required dependencies (installed by the QA lane prompt):
//   npm i -D @playwright/test axe-playwright
//   npx playwright install chromium

import { test, expect, type Page } from '@playwright/test';
import { injectAxe, checkA11y } from 'axe-playwright';
import { mkdirSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

// Resolve vault under the project root (NOT this test's CWD, which may be elsewhere).
const ROOT =
  process.env.ONESHOT_ROOT ??
  (existsSync(join(process.cwd(), '.oneshot/.project_root'))
    ? readFileSync(join(process.cwd(), '.oneshot/.project_root'), 'utf8').trim()
    : process.cwd());
const ARTIFACT_ROOT = join(ROOT, '.oneshot/vault/artifacts');
const SCREENSHOTS = join(ARTIFACT_ROOT, 'screenshots');
mkdirSync(SCREENSHOTS, { recursive: true });

const BASE_URL = process.env.QA_BASE_URL ?? 'http://localhost:3000';

async function shot(page: Page, name: string) {
  await page.screenshot({
    path: join(SCREENSHOTS, `${name}.png`),
    fullPage: true,
  });
}

test.use({ viewport: { width: 1440, height: 900 } });

// ---------- 1. GOLDEN PATHS ----------
// One block per primary persona from brief.md "Audience". Cover the
// happy-flow end-to-end. Screenshot every visible state change.

test.describe('1. Golden paths', () => {
  test('1.1 anonymous visitor → primary CTA', async ({ page }) => {
    await page.goto(BASE_URL);
    await expect(page).toHaveTitle(/.+/);
    await shot(page, '1-1-1-landing');

    // EDIT ME: replace with the actual primary CTA selector from brief.md
    // const cta = page.getByRole('button', { name: /get started/i });
    // await expect(cta).toBeVisible();
    // await cta.click();
    // await shot(page, '1-1-2-after-cta');
    // await expect(page).toHaveURL(/.+/);
  });

  // EDIT ME: add 1.2, 1.3, ... per persona
});

// ---------- 2. EDGE CASES ----------
// At minimum: empty input, oversized input, duplicate submission,
// network drop mid-flow, back-button mid-flow.

test.describe('2. Edge cases', () => {
  test('2.1 empty form submission shows validation', async ({ page }) => {
    await page.goto(`${BASE_URL}/`); // EDIT ME: target form route
    // EDIT ME
    await shot(page, '2-1-empty-form');
  });

  test('2.2 oversized payload rejected gracefully', async ({ page }) => {
    // EDIT ME: paste 10k chars into a text field that should cap
    await page.goto(BASE_URL);
    await shot(page, '2-2-oversized');
  });

  test('2.3 duplicate submission deduped', async ({ page }) => {
    // EDIT ME: double-click submit; backend / UI must not double-create
    await page.goto(BASE_URL);
    await shot(page, '2-3-duplicate');
  });

  test('2.4 network drop mid-flow surfaces retry UI', async ({ page, context }) => {
    await context.route('**/api/**', (route) => route.abort());
    await page.goto(BASE_URL);
    // EDIT ME: trigger an API-bound action; assert retry button shown
    await shot(page, '2-4-net-drop');
  });

  test('2.5 back-button mid-flow does not corrupt state', async ({ page }) => {
    await page.goto(BASE_URL);
    // EDIT ME: navigate forward two steps, hit back, ensure state is sane
    await page.goBack();
    await shot(page, '2-5-back-button');
  });
});

// ---------- 3. AUTHENTICATION BOUNDARY (if auth in scope) ----------
// Mark "n/a per brief.md (no auth)" with citation if not applicable.

test.describe('3. Authentication boundary', () => {
  test('3.1 unauthed access to protected route redirects', async ({ page }) => {
    // EDIT ME: visit a /dashboard or /settings route
    await page.goto(`${BASE_URL}/`);
    // await expect(page).toHaveURL(/login|signin/i);
    await shot(page, '3-1-redirect-to-login');
  });

  test('3.2 logout invalidates session', async ({ page }) => {
    // EDIT ME: log in, capture cookies, log out, hit protected route again
    await page.goto(BASE_URL);
    await shot(page, '3-2-after-logout');
  });
});

// ---------- 4. ACCESSIBILITY (axe-core) ----------
// Fail on serious or critical violations. One scan per page in golden path.

test.describe('4. Accessibility', () => {
  test('4.1 landing page a11y', async ({ page }) => {
    await page.goto(BASE_URL);
    await injectAxe(page);
    await checkA11y(page, undefined, {
      detailedReport: true,
      detailedReportOptions: { html: true },
      axeOptions: {
        runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa'] },
      },
    });
    await shot(page, '4-1-a11y-landing');
  });

  // EDIT ME: 4.2 per other golden-path page
});

// ---------- 5. PERFORMANCE SMOKE (optional but recommended) ----------
// Web vitals via the standard `web-vitals` API or Playwright's
// `page.evaluate()`. Don't fail the build on perf — just record.

test.describe('5. Performance smoke', () => {
  test('5.1 capture LCP/CLS on landing', async ({ page }) => {
    await page.goto(BASE_URL, { waitUntil: 'networkidle' });
    const metrics = await page.evaluate(
      () =>
        new Promise<Record<string, number>>((resolve) => {
          const out: Record<string, number> = {};
          new PerformanceObserver((list) => {
            for (const e of list.getEntries()) {
              if (e.entryType === 'largest-contentful-paint') {
                out.lcp = e.startTime;
              }
              if (e.entryType === 'layout-shift' && !(e as any).hadRecentInput) {
                out.cls = (out.cls ?? 0) + (e as any).value;
              }
            }
          }).observe({ type: 'largest-contentful-paint', buffered: true });
          // Layout-shift observer
          new PerformanceObserver((list) => {
            for (const e of list.getEntries()) {
              if (e.entryType === 'layout-shift' && !(e as any).hadRecentInput) {
                out.cls = (out.cls ?? 0) + (e as any).value;
              }
            }
          }).observe({ type: 'layout-shift', buffered: true });
          setTimeout(() => resolve(out), 3000);
        })
    );
    test.info().annotations.push({
      type: 'perf',
      description: JSON.stringify(metrics),
    });
    await shot(page, '5-1-perf-landing');
  });
});

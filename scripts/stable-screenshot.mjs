// One screenshot call that does not flake.
//
// On 2026-09-03 sign-e2e went red on main with `page.screenshot: Timeout
// 30000ms exceeded` (run 33746496749). The same failure had already been seen
// on a pull request. It is not a product bug: a fullPage capture at
// deviceScaleFactor 2 on a loaded ubuntu runner simply needs more than
// Playwright's 30 s default, and a page that is still fetching, still swapping
// a webfont or still running an animation makes the capture wait for a stable
// frame that never comes.
//
// So every screenshot in this repo goes through here and gets three things:
//
//   1. SETTLE     network quiet and document.fonts.ready before the capture,
//                 both bounded, both best-effort. A page that never goes idle
//                 (an API stub that deliberately never answers, for instance)
//                 must still be photographable, so a timeout here is not a
//                 failure: it falls through to the capture.
//   2. ANIMATIONS `animations: 'disabled'`, which is Playwright's own knob:
//                 finite CSS animations and transitions are fast-forwarded to
//                 their end state and infinite ones are cancelled to their
//                 initial state, for the duration of the capture only. This is
//                 deliberately NOT page.emulateMedia({ reducedMotion:'reduce' }):
//                 that changes what the page renders, which would silently
//                 rewrite assertions taken after the shot and would make
//                 scripts/app-shots.mjs' reduced-motion pair identical to its
//                 normal pair, so the picture would stop proving anything.
//   3. RETRY      60 s, and on a timeout one more attempt at 120 s. Measured,
//                 not guessed: ten runs of the generator under sixteen busy
//                 cores put one capture past 60 s with a call log reading
//                 "taking page screenshot / disabled all CSS animations", so
//                 the page had settled and the raster itself was starved. No
//                 wait condition fixes that; only more budget does. A
//                 screenshot has no side effect, so taking it twice is safe,
//                 and a second attempt that still times out is reported rather
//                 than swallowed.
//
// Callers: scripts/app-shots.mjs and the suites that write a screenshot as a
// byproduct when PARAMANT_*_SCREENSHOT_PATH is set (navigation-shell,
// cosign-document-delivery, user-dashboard-documents, sign-invite-delivery,
// developer-parasign-dashboard). Those calls are env-gated and never run in CI;
// they are still routed through here because a screenshot a builder takes by
// hand on a busy laptop hits the same wall.
//
// This file lives in scripts/ and not in tests/ on purpose: tests/*.mjs is a
// glob that two workflows run as suites, so a helper there would be executed as
// a test by test.yml.

// Playwright's default is 30 s. Everything here is one screenshot, never a gate,
// so the first attempt gets double that and a retry gets double again.
export const SCREENSHOT_TIMEOUT_MS = 60_000;
export const SCREENSHOT_RETRY_TIMEOUT_MS = 120_000;

// How long we are willing to wait for the page to go quiet before shooting it
// anyway. Bounded on purpose: some shots are OF a pending state.
const SETTLE_TIMEOUT_MS = 5_000;

// Best effort, both of them. A page that never reaches networkidle, or a
// browser without the fonts API, is photographed as it is rather than failing.
export async function settleForShot(page, { networkIdleMs = SETTLE_TIMEOUT_MS, fontsMs = SETTLE_TIMEOUT_MS } = {}) {
  if (networkIdleMs > 0) {
    try { await page.waitForLoadState('networkidle', { timeout: networkIdleMs }); } catch { /* still busy: shoot it anyway */ }
  }
  if (fontsMs > 0) {
    // page.evaluate has no timeout of its own, so the bound is ours. A font
    // that never arrives must not hold the capture forever.
    const fonts = page.evaluate(() => (document.fonts ? document.fonts.ready.then(() => true) : true));
    let timer;
    try {
      await Promise.race([fonts, new Promise((resolve) => { timer = setTimeout(resolve, fontsMs); })]);
    } catch { /* no fonts API, or the page went away: shoot it anyway */ }
    clearTimeout(timer);
    fonts.catch(() => { /* already handled, and an unobserved rejection would kill the run */ });
  }
}

// Takes the shot. `target` is a Page or a Locator, so an element screenshot
// gets the same treatment as a full page one. Options are passed straight to
// Playwright, so a caller can still say fullPage, type, quality or clip, and
// can override the timeout or animations if it ever has a reason to.
export async function stableScreenshot(target, options = {}) {
  const { settle = true, networkIdleMs, fontsMs, ...shot } = options;
  const page = typeof target.page === 'function' ? target.page() : target;
  if (settle) await settleForShot(page, { networkIdleMs, fontsMs });

  const budgets = [SCREENSHOT_TIMEOUT_MS, SCREENSHOT_RETRY_TIMEOUT_MS];
  let last;
  for (const timeout of budgets) {
    try {
      return await target.screenshot({ timeout, animations: 'disabled', ...shot });
    } catch (error) {
      // Only a timeout is worth trying again. A bad path, a closed page or a
      // detached element is a real error and must surface on the first attempt.
      if (error?.name !== 'TimeoutError') throw error;
      last = error;
      // Loud on purpose: a run that quietly took twice as long is how a
      // machine that is too slow for this work stays undiagnosed.
      if (timeout !== budgets[budgets.length - 1]) {
        console.warn(`screenshot timed out after ${timeout} ms, one more attempt at ${SCREENSHOT_RETRY_TIMEOUT_MS} ms`);
        // Let the machine breathe before asking it for the same frame again.
        await page.waitForTimeout(1000);
      }
    }
  }
  throw last;
}

// Everything on the page that is NOT text, measured against the ground it sits
// on. The other half of tests/theme-contrast.test.mjs.
//
// Why this file exists. On 2026-09-04 a phone review found parts of the site
// that had gone missing under the night edition (design-system.css v5, PR
// #417): the hamburger on every page, the step indicator of the app's
// /parashare, the frames of the architecture figures, the meter on the
// dashboard. None of it was reported by anything. tests/theme-contrast.test.mjs
// walks TEXT nodes and it was green, on the same commit, on the same pages. It
// could not have caught any of this: a hamburger has no text, a frame has no
// text, and a meter has no text. Every colour that came from a token followed
// the night; every colour written as a hex in a page, a script or an SVG did
// not, and a navy bar that read fine on bone is invisible on #15191C.
//
// WCAG 2.1 SC 1.4.11 Non-text Contrast asks 3:1 for the visual information
// needed to identify user interface components and their states, and for the
// parts of a graphic that carry its meaning. That is the bar here.
//
// The measurement lives in scripts/ui-contrast-sweep.mjs, next to the comment
// that explains what each category is and why lines are judged by the grain of
// the theme rather than by the ratio alone. That file is also runnable by hand,
// with --shots, when you want to look at the pages instead of the numbers:
//
//   node scripts/ui-contrast-sweep.mjs --shots /tmp/shots
//
// Run: node --test tests/ui-elements-contrast.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { sweep, line, PUBLIC_PAGES, APP_PAGES } from '../scripts/ui-contrast-sweep.mjs';

// What is under 3:1 on purpose. Same contract as KNOWN_LIGHT in
// tests/theme-contrast.test.mjs: this list may get SHORTER and never longer. A
// finding that is not on it is a regression, whether or not anyone has noticed
// it yet. Matched on page + kind + selector, because the colour values move
// with the brand and the place does not.
const KNOWN = [
  // The radar on /architecture. Concentric rings around one point, fading
  // outwards, which is what a radar does and the whole of what it says. The
  // location itself is carried by the two lines of type around the figure and
  // by the centre dot, which is the ochre at full strength and well over 3:1.
  // The outer rings are the fade, not the message.
  { page:'/architecture', kind:'svg-stroke', sel:'circle.loc-ring in div',
    why:'the outermost radar rings fade to nothing on purpose' },
  { page:'/architecture', kind:'svg-stroke', sel:'circle.loc-ring-2 in div',
    why:'the middle radar ring is part of that fade' },
  { page:'/architecture', kind:'svg-stroke', sel:'circle.loc-ring-3 in div',
    why:'the inner radar ring is the last step of that fade, at 2.19:1' },
];

test('every non-text element clears 3:1 in dark and light, at 390 and 1440', async (t) => {
  const result = await sweep();

  t.diagnostic(`measured ${result.measured} non-text paints over ${PUBLIC_PAGES.length} public pages`
    + ` and ${APP_PAGES.length} app screens, at 390 and 1440, in dark and light`);
  t.diagnostic(`${result.decorative.length} paints under 3:1 run with the grain of the theme and are the system's own hairlines`);

  // A page that could not be rendered is a hole in this gate, not a pass.
  assert.deepEqual(result.unmeasured, [], `\nThese pages were never measured:\n  ${result.unmeasured.join('\n  ')}\n`);

  const unexpected = [];
  const stillThere = new Set();
  for (const hit of result.findings) {
    const known = KNOWN.find((k) => k.page === hit.page && k.kind === hit.kind && k.sel === hit.sel);
    if (known) { stillThere.add(`${line(hit)} :: ${known.why}`); continue; }
    unexpected.push(line(hit));
  }
  t.diagnostic(`${stillThere.size} of the ${KNOWN.length} known exceptions are still present`);
  for (const one of stillThere) t.diagnostic(`still on the known list: ${one}`);

  assert.deepEqual(unexpected, [],
    `\nNon-text contrast failures. Every one of these is under the 3:1 that WCAG 2.1 SC 1.4.11\n`
    + `asks of a meaningful graphic or a UI component, and none of them is on the known list:\n  `
    + `${unexpected.join('\n  ')}\n\n`
    + `Fix the colour with a token from frontend/design-system.css. If it is a deliberate\n`
    + `exception, add it to KNOWN with the reason. Do not loosen the ratio.`);
});

// One step at a time on /co-sign.
//
// An invitee who opens their personal link is not signed in yet. Before this
// test existed the page showed, at once: an amber "sign in" banner, a second
// amber banner in the review card saying the same thing, a dashed "choose the
// document yourself" control, a disabled "sign this document" button and a
// separate "sign in to continue" button. Two buttons, three banners, one
// possible action.
//
// These assertions fail if that comes back: the sign-in state must hide
// everything that only works once there is a session, and the technical
// paragraphs must stay collapsed behind a summary the reader can open.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PAGES = ['frontend/co-sign.html', 'frontend/en/co-sign.html'];
const JS = readFileSync(join(ROOT, 'frontend/co-sign.js'), 'utf8');

for (const page of PAGES) {
  const html = readFileSync(join(ROOT, page), 'utf8');

  test(`${page}: the review card can be hidden while signing in`, () => {
    assert.match(html, /<div class="card" id="review-card">/,
      'the review card needs an id so the needs-login state can hide it');
    assert.match(html, /body\.needs-login #review-card/,
      'needs-login must hide the review card');
    assert.match(html, /body\.needs-login #sign-confirm/,
      'needs-login must hide the disabled sign button');
  });

  test(`${page}: the manual file picker starts hidden`, () => {
    assert.match(html, /id="verify-file-cta" hidden>/,
      'the escape hatch may only appear once automatic delivery failed');
  });

  test(`${page}: the technical text sits behind a summary`, () => {
    const summaries = html.match(/<details class="how"/g) || [];
    assert.ok(summaries.length >= 3,
      `expected at least three collapsed explanations, found ${summaries.length}`);
    // Only the step the invitee has to act on. On step-done the signature is
    // already made, and naming what happened is a result, not an obstacle.
    const start = html.indexOf('id="step-cosign"');
    const end = html.indexOf('id="step-done"');
    assert.ok(start > 0 && end > start, 'expected both steps in the page');
    const acting = html.slice(start, end);
    assert.doesNotMatch(acting, /<p class="sub"[^>]*>[^<]*ML-DSA-65/,
      'the algorithm story belongs inside the collapsed block, not in the lead paragraph');
  });
}

test('co-sign.js sets and clears the needs-login state', () => {
  assert.match(JS, /classList\.add\('needs-login'\)/,
    'gate 1 must mark the page as needing a login');
  assert.match(JS, /classList\.remove\('needs-login'\)/,
    'a resolved session must release the page');
});

test('co-sign.js only reveals the manual picker on a delivery error', () => {
  assert.match(JS, /cta\.hidden = kind !== 'err'/,
    'the manual picker follows the delivery status');
});

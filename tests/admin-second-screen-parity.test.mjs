// ADMIN-47-D: frontend/admin.html (the Dutch second admin screen, 404'd on the
// live site but kept in the repo and read by ui-truthfulness) lacked three
// actions the main panel has: per-product plan, ParaSign API on/off and the
// ParaSign onboarding mail. Same routes and the same refusal handling now.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const read = (f) => fs.readFileSync(new URL('../' + f, import.meta.url), 'utf8');
const second = read('frontend/js/admin.page.js');
const main = read('admin/public/app.js');

test('every account route the main panel calls, the second screen calls too', () => {
  for (const r of ['/admin/set-product-plan', '/admin/set-parasign', '/admin/send-parasign-onboarding']) {
    assert.ok(main.includes(r), `main panel no longer calls ${r}; update this test`);
    assert.ok(second.includes(r), `frontend/js/admin.page.js does not call ${r}`);
  }
});

test('the menu offers the three actions and the dispatcher handles them', () => {
  for (const a of ['product-plan', 'parasign-toggle', 'parasign-onboard']) {
    assert.match(second, new RegExp(`data-uact="${a}"`), `no menu item for ${a}`);
    assert.match(second, new RegExp(`case '${a}'`), `uAction does not handle ${a}`);
  }
  // a lower plan is a separate, explicit step, as on the main panel
  assert.match(second, /lower_than_running/);
  assert.match(second, /downgrade:true/);
});

test('admin.html loads the new admin.page.js (cache-bust moved)', () => {
  const m = read('frontend/admin.html').match(/\/js\/admin\.page\.js\?v=(\d+)/);
  assert.ok(m && Number(m[1]) >= 5, 'admin.page.js changed, its ?v= must move');
});

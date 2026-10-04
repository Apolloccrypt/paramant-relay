'use strict';
// ACCT-26: the session list showed "Mozilla/5.0" for every browser.
const { test } = require('node:test');
const assert = require('assert');
const { uaLabel } = require('../lib/ua-label');
test('readable browser + OS', () => {
  assert.strictEqual(uaLabel('Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1'), 'Safari on iPhone');
  assert.strictEqual(uaLabel('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'), 'Chrome on Windows');
  assert.strictEqual(uaLabel('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0'), 'Edge on Windows');
  assert.strictEqual(uaLabel('Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0'), 'Firefox on Mac');
  assert.strictEqual(uaLabel(''), 'Unknown device');
  assert.notStrictEqual(uaLabel('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36'), 'Mozilla/5.0');
});

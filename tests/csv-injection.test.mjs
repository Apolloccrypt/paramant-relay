// Review 573 L4: CSV exports put a customer-chosen value (a key label, a buyer
// name, a device name) into a cell as is. A cell that starts with = + - @ (or a
// tab or CR) is a formula when the file opens in Excel. Every CSV export now
// prefixes such a cell with an apostrophe, and leaves plain numbers alone.
// Run: node --test tests/csv-injection.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const EVIL = ['=HYPERLINK("http://example.com","x")', '+cmd', '-2+3', '@SUM(A1)', '\tx', '\rx'];

// The source of one top-level browser function, by brace matching.
function fnSource(src, name) {
  const at = src.indexOf(`function ${name}(`);
  if (at < 0) return '';
  let depth = 0;
  for (let i = src.indexOf('{', at); i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) return src.slice(at, i + 1);
  }
  return '';
}

test('admin audit export (admin/public/app.js csvCell)', () => {
  const src = fs.readFileSync(path.join(ROOT, 'admin/public/app.js'), 'utf8');
  const ctx = {};
  vm.runInNewContext(fnSource(src, 'csvSafe') + '\n' + fnSource(src, 'csvCell') + '\nthis.csvCell = csvCell;', ctx);
  for (const v of EVIL) assert.ok(ctx.csvCell(v).startsWith(`"'`), `${JSON.stringify(v)} -> ${ctx.csvCell(v)}`);
  assert.equal(ctx.csvCell('-5,00'), '"-5,00"', 'a plain number stays a number');
  assert.equal(ctx.csvCell('demo'), '"demo"');
});

test('old admin page export (frontend/js/admin.page.js)', () => {
  const src = fs.readFileSync(path.join(ROOT, 'frontend/js/admin.page.js'), 'utf8');
  const link = {};
  const cell = (t) => ({ textContent: t });
  const ctx = {
    document: {
      querySelectorAll: () => [{ querySelectorAll: () => [cell('2026-10-05'), cell('=HYPERLINK("x")'), cell('@demo')] }],
      createElement: () => Object.assign(link, { click() {} }),
    },
    encodeURIComponent,
  };
  vm.runInNewContext(fnSource(src, 'csvSafe') + '\n' + fnSource(src, 'exportAuditCSV') + '\nexportAuditCSV();', ctx);
  const csv = decodeURIComponent(String(link.href).split(',').slice(1).join(','));
  assert.match(csv, /"'=HYPERLINK/);
  assert.match(csv, /"'@demo"/);
});

test('ParaSign audit export (relay/lib/parasign-audit-export.js)', () => {
  const ax = require('../relay/lib/parasign-audit-export');
  const res = { writeHead(c, h) { this.statusCode = c; this.headers = h; }, end(b) { this.body = String(b); } };
  ax.handle({
    res, J: JSON.stringify, keyData: { plan: 'business', active: true }, memberKeys: ['k1'],
    auditFor: () => [{ ts: '2026-10-05T10:00:00Z', event: 'inbound', hash: 'ab', bytes: 1, device: '=cmd|calc', chain_hash: 'h1' }],
    ctHead: () => null, verifyChain: () => true, query: { format: 'csv' },
  });
  assert.equal(res.statusCode, 200);
  assert.match(res.body, /'=cmd\|calc/);
});

test('books export (relay/lib/billing-export.js toCsv)', () => {
  const ex = require('../relay/lib/billing-export');
  const csv = ex.toCsv([{ number: 'CN-1', date: '2026-10-05', type: 'credit_note', customer_name: '=HYPERLINK("x")', customer_email: '@demo@example.com', amount_net: '-5.00', amount_vat: '-1.05', amount_gross: '-6.05', currency: 'EUR' }]);
  assert.match(csv, /"'=HYPERLINK\(""x""\)"|'=HYPERLINK/);
  assert.match(csv, /'@demo@example\.com/);
  assert.match(csv, /;-5,00;/, 'a credit-note amount stays a number');
  assert.doesNotMatch(csv, /'-5,00/);
});

test('relay /v2/audit?format=csv goes through the same guard', () => {
  const src = fs.readFileSync(path.join(ROOT, 'relay/relay.js'), 'utf8');
  const at = src.indexOf("if (path === '/v2/audit')");
  const branch = src.slice(at, src.indexOf("res.writeHead(200, { 'Content-Type': 'application/json' })", at));
  assert.match(branch, /\.map\(_csvAuditCell\)/);
  const { neutralize } = require('../relay/lib/csv-safe');
  for (const v of EVIL) assert.ok(neutralize(v).startsWith("'"), JSON.stringify(v));
  for (const v of ['-5', '+31', '-5,00', '12.5', 'demo', '']) assert.equal(neutralize(v), v);
});

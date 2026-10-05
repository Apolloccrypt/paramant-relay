'use strict';
// A filename outside Latin-1 used to reach writeHead raw, which throws
// ERR_INVALID_CHAR and turns a finished download into a 500.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { attachment } = require('../lib/content-disposition');

// What a client does with filename*: take the UTF-8 percent-encoded value.
function decodeStar(header) {
  const m = header.match(/filename\*=UTF-8''([^;]+)/);
  return m ? decodeURIComponent(m[1]) : null;
}
function plain(header) {
  const m = header.match(/filename="([^"]*)"/);
  return m ? m[1] : null;
}

test('plain ASCII goes out once, unchanged', () => {
  assert.equal(attachment('report.pdf'), 'attachment; filename="report.pdf"');
});

test('emoji: ASCII fallback plus the real name in filename*', () => {
  const name = 'contract-\u{1F4DD}.pdf';
  const h = attachment(name);
  assert.doesNotThrow(() => http.validateHeaderValue('Content-Disposition', h));
  assert.match(plain(h), /^[\x20-\x7e]+$/);
  assert.ok(plain(h).endsWith('.pdf'));
  assert.equal(decodeStar(h), name);
});

test('Cyrillic: ASCII fallback plus the real name in filename*', () => {
  const name = 'Договор № 7.pdf';
  const h = attachment(name);
  assert.doesNotThrow(() => http.validateHeaderValue('Content-Disposition', h));
  assert.match(plain(h), /^[\x20-\x7e]+\.pdf$/);
  assert.equal(decodeStar(h), name);
});

test('accents fold to their base letter in the fallback', () => {
  const h = attachment('résumé.pdf');
  assert.equal(plain(h), 'resume.pdf');
  assert.equal(decodeStar(h), 'résumé.pdf');
});

test('quotes, CR/LF and path separators cannot break out of the header', () => {
  const h = attachment('a"b\r\nSet-Cookie: x=1/..\\c.pdf');
  assert.doesNotThrow(() => http.validateHeaderValue('Content-Disposition', h));
  assert.doesNotMatch(h, /[\r\n]/);
  assert.equal((plain(h) || '').includes('"'), false);
  assert.equal((plain(h) || '').includes('/'), false);
});

test('RFC 5987 characters that encodeURIComponent leaves alone are escaped', () => {
  const h = attachment("it's (final)*é.pdf");
  const star = h.split("UTF-8''")[1];
  assert.doesNotMatch(star, /['()*]/);
  assert.equal(decodeStar(h), "it's (final)*é.pdf");
});

test('empty or missing name uses the fallback', () => {
  assert.equal(attachment('', 'document.pdf'), 'attachment; filename="document.pdf"');
  assert.equal(attachment(null, 'document.pdf'), 'attachment; filename="document.pdf"');
});

test('a real server sends the header and a client reads the name back', async () => {
  const name = '\u{1F600} привет.pdf';
  const srv = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/pdf', 'Content-Disposition': attachment(name) });
    res.end('%PDF');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const r = await fetch(`http://127.0.0.1:${srv.address().port}/`);
    assert.equal(r.status, 200);
    assert.equal(decodeStar(r.headers.get('content-disposition')), name);
  } finally {
    srv.close();
  }
});

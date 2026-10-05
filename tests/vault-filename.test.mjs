// Regression test for Paramant Vault leaking encrypted filenames through the
// downloaded .prmnt container name.
//
// Run:
//   PLAYWRIGHT_CHROMIUM_PATH=/usr/bin/google-chrome node tests/vault-filename.test.mjs

import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = {
  '.css': 'text/css',
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.png': 'image/png',
  '.svg': 'image/svg+xml'
};

const server = http.createServer((req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  const p = pathname === '/vault' ? '/vault.html' : decodeURIComponent(pathname);
  const file = path.join(ROOT, p);
  if (!file.startsWith(ROOT)) {
    res.writeHead(403);
    return res.end();
  }
  fs.readFile(file, (err, body) => {
    if (err) {
      res.writeHead(404);
      return res.end();
    }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(body);
  });
});

await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const ORIGIN = `http://localhost:${server.address().port}`;

const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });

try {
  const context = await browser.newContext({ baseURL: ORIGIN, acceptDownloads: true });
  const page = await context.newPage();
  await page.goto(`${ORIGIN}/vault`);

  const secretName = 'Acquisition_Target_Acme.pdf';
  await page.setInputFiles('#lock-input', {
    name: secretName,
    mimeType: 'application/pdf',
    buffer: Buffer.from('%PDF-1.7\nconfidential\n')
  });
  await page.fill('#lock-pw', 'correct horse battery staple');
  await page.fill('#lock-pw2', 'correct horse battery staple');

  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.click('#lock-run')
  ]);

  assert.equal(
    download.suggestedFilename(),
    'paramant-vault.prmnt',
    'encrypted Vault containers must use a neutral public filename'
  );
  assert.equal(
    download.suggestedFilename().includes(secretName),
    false,
    'encrypted Vault container names must not contain the original filename'
  );

  console.log('PASS: Vault lock downloads a neutral .prmnt name without leaking the original filename.');
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}

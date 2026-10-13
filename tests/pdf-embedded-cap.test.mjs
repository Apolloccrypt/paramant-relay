// Review 573 D-L3: a deflate bomb in an embedded file made /verify unpack
// gigabytes in the tab. pdf-embedded.js now caps the unpacked size per stream
// and over all streams, and says so (tooLarge) instead of staying silent.
// Run: node --test tests/pdf-embedded-cap.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const SRC = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend', 'js', 'pdf-embedded.js');
const mod = await import('data:text/javascript,' + encodeURIComponent(fs.readFileSync(SRC, 'utf8')));
const MB = 1024 * 1024;

function pdfWith(streams) {
  const parts = [Buffer.from('%PDF-1.7\n')];
  streams.forEach((s, i) => {
    const filter = s.deflate ? '/Filter /FlateDecode ' : '';
    const body = s.deflate ? zlib.deflateSync(s.bytes) : s.bytes;
    parts.push(Buffer.from(`${i + 10} 0 obj\n<< /Type /EmbeddedFile ${filter}/Length ${body.length} >>\nstream\n`), body, Buffer.from('\nendstream\nendobj\n'));
  });
  parts.push(Buffer.from('%%EOF\n'));
  return new Uint8Array(Buffer.concat(parts));
}

test('a small embedded original still comes out byte for byte', async () => {
  const original = Buffer.from('%PDF-1.4\n% signed original\n%%EOF\n');
  const r = await mod.embeddedFiles(pdfWith([{ bytes: original, deflate: true }]));
  assert.equal(r.length, 1);
  assert.equal(r.tooLarge, false);
  assert.equal(crypto.createHash('sha256').update(r[0].bytes).digest('hex'), crypto.createHash('sha256').update(original).digest('hex'));
});

test('one stream that unpacks past the per-stream cap is skipped and reported', async () => {
  const r = await mod.embeddedFiles(pdfWith([{ bytes: Buffer.alloc(100 * MB), deflate: true }]));
  assert.equal(r.length, 0, 'a 100 MB unpacked stream is no candidate');
  assert.equal(r.tooLarge, true, 'the caller hears that something was too large');
});

test('many streams together stop at the total cap', async () => {
  const r = await mod.embeddedFiles(pdfWith(Array.from({ length: 5 }, () => ({ bytes: Buffer.alloc(40 * MB), deflate: true }))));
  const total = r.reduce((n, c) => n + c.bytes.length, 0);
  assert.ok(total <= 128 * MB, `unpacked in total ${total} bytes`);
  assert.ok(r.length < 5);
  assert.equal(r.tooLarge, true);
});

test('/verify says out loud that an attachment was too large to check', () => {
  const v = fs.readFileSync(path.join(path.dirname(SRC), '..', 'parasign-verify.js'), 'utf8');
  assert.match(v, /embeddedTooLarge: 'Deze pdf bevat een bijlage/);
  assert.match(v, /embeddedTooLarge: 'This pdf has an attachment/);
  assert.match(v, /r\.embeddedTooLarge\) out\.push/);
});

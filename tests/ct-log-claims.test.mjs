// What the site says about the CT log, pinned to what the log really does.
//
// WHY THIS SUITE EXISTS. An independent recomputation of the log on 2026-10-06
// (paramant-bewijs/ct-onderzoek-2026-10-06/RAPPORT.md, section 4) found the
// mathematics sound and five sentences on the site that said more than the
// code does:
//
//   1. "zo werken ook de certificate transparency-logs van HTTPS" (/ct-log).
//      Same RFC 6962 tree, but HTTPS CT has several independent logs and
//      monitors; this log has one operator and no outside witness.
//   2. "bewijs in de CT-log voor elke toegang" and "/v2/ack: vertraging
//      vastleggen in de CT-log" (/docs). Only the upload is a CT leaf
//      (ctAppendTransfer); the download (outbound_burn / outbound_view) and
//      /v2/ack (ack_received) go to auditAppend, the private per-key chain.
//   3. "✓ Geverifieerd" on /ct-log was a prefix match on the list the relay
//      itself sent: no proof, no signed head, no key.
//   4. /verify said the entry "staat echt in het openbare transparantielogboek"
//      while it only folds the path inside the receipt to the root inside the
//      receipt. That proves what the relay signed then, not what the public log
//      shows now.
//   5. "Het log begint alleen opnieuw als het volume wordt verwijderd": the
//      health tree restarted in April 2026 during tests, and 39 leaves from that
//      time belong to the earlier tree.
//
// Each test reads the code that makes the corrected sentence true, so the page
// cannot drift back. Node builtins only (root integration job, no browser).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
const visible = (html) => html
  .replace(/<!--[\s\S]*?-->/g, '')
  .replace(/<script[\s\S]*?<\/script>/gi, '')
  .replace(/<style[\s\S]*?<\/style>/gi, '')
  .replace(/<[^>]+>/g, ' ')
  .replace(/&rsquo;/g, '’').replace(/&nbsp;/g, ' ')
  .replace(/\s+/g, ' ');

const PAGES = fs.readdirSync(path.join(ROOT, 'frontend')).filter((f) => f.endsWith('.html')).map((f) => `frontend/${f}`)
  .concat(fs.readdirSync(path.join(ROOT, 'frontend/en')).filter((f) => f.endsWith('.html')).map((f) => `frontend/en/${f}`));

test('no page says this log works the way the CT logs of HTTPS do, and /ct-log names the difference', () => {
  for (const p of PAGES) {
    const v = visible(read(p));
    assert.doesNotMatch(v, /zo werken ook de certificate transparency/i, `${p} still equates this log with HTTPS CT`);
    assert.doesNotMatch(v, /the way HTTPS certificate transparency logs work/i, `${p} still equates this log with HTTPS CT`);
  }
  const nl = visible(read('frontend/ct-log.html'));
  const en = visible(read('frontend/en/ct-log.html'));
  assert.match(nl, /RFC 6962/);
  assert.match(nl, /één beheerder, Paramant, en nog geen onafhankelijke bewaarder/);
  assert.match(en, /one operator, Paramant, and no independent keeper/);
});

test('downloads and /v2/ack are described as the private audit chain, because that is where relay.js writes them', () => {
  const relay = read('relay/relay.js');
  // The code facts the corrected sentences rest on.
  assert.match(relay, /auditAppend\(apiKey, 'ack_received'/, '/v2/ack no longer writes ack_received to the audit chain');
  assert.match(relay, /auditAppend\(apiKey, burned \? 'outbound_burn' : 'outbound_view'/, 'downloads no longer go to the audit chain');
  const ackStart = relay.indexOf("path === '/v2/ack'");
  assert.ok(ackStart > 0);
  const ackBody = relay.slice(ackStart, relay.indexOf('\n  if (path', ackStart + 10));
  assert.doesNotMatch(ackBody, /ctAppend/, '/v2/ack now writes a CT leaf: the docs may say so again');

  for (const p of ['frontend/docs.html', 'frontend/en/docs.html']) {
    const v = visible(read(p));
    assert.doesNotMatch(v, /voor elke toegang|of every access|per-access CT/i, `${p} still promises a CT entry per access`);
    assert.doesNotMatch(v, /vertraging vastleggen in de CT-log|log latency to CT/i, `${p} still says /v2/ack writes to the CT log`);
    assert.doesNotMatch(v, /CT-log geeft een manipulatiebestendig bewijs van aflevering|CT log provides tamper-evident proof of delivery/i,
      `${p} still says the CT log proves delivery`);
    assert.doesNotMatch(v, /Merkle-bewijs per transactie|per-transaction Merkle proof/i, `${p} still promises a proof per transaction`);
  }
  assert.match(visible(read('frontend/docs.html')), /\/v2\/ack Aflevering bevestigen; vastgelegd in de privé-auditketen van uw sleutel, niet in de CT-log/);
  assert.match(visible(read('frontend/en/docs.html')), /\/v2\/ack Confirm delivery; recorded in your key’s private audit chain, not in the CT log/);
});

test('/ct-log says "verified" only on the path that ran the cryptographic check', () => {
  for (const p of ['frontend/js/ct-log.page.js', 'frontend/js/ct-log.page.en.js']) {
    const src = read(p);
    const fn = src.slice(src.indexOf('function verifyHash()'), src.indexOf('// ── Tab switching'));
    // The green word appears once, as the head for res.verdict === 'verified',
    // and that verdict only comes out of ct-log-verify.js.
    const green = /✓ (Geverifieerd|Verified)/g;
    const hits = fn.match(green) || [];
    assert.equal(hits.length, 1, `${p}: the verified label appears ${hits.length} times in verifyHash`);
    assert.match(fn, /res\.verdict === 'verified' \? '✓ (Geverifieerd|Verified)/, `${p}: the verified label is not tied to the verdict`);
    assert.match(fn, /import\('\/js\/ct-log-verify\.js\?v=\d+'\)/, `${p}: verifyHash does not load the verifier`);
    // The column that was always n/a is gone: /v2/ct/log never publishes device_hash.
    assert.doesNotMatch(src, /device_hash/, `${p} still renders device_hash, which the public log never carries`);
  }
  const v = read('frontend/js/ct-log-verify.js');
  for (const need of ['verifySthSignature', 'verifyInclusion', 'verifyConsistency', 'anchorByHost', '/v2/sth', '/v2/ct/proof/', '/v2/sth/consistency']) {
    assert.ok(v.includes(need), `ct-log-verify.js lost ${need}`);
  }
  // The relay does not publish device_hash in the projection, so the column
  // would be n/a forever.
  assert.match(read('relay/relay.js'), /entries = pageR\.entries\.map\(\(e, i\) => \(\{ index: pageR\.start_index \+ i, type: e\.type, leaf_hash: e\.leaf_hash, tree_hash: e\.tree_hash, ts: ctCoarseTs\(e\.ts\) \}\)\)/);
  for (const p of ['frontend/ct-log.html', 'frontend/en/ct-log.html']) {
    assert.doesNotMatch(visible(read(p)), /Apparaat-hash|Device hash|device_hash/, `${p} still has a device-hash column`);
  }
});

test('/verify says what the inclusion check proves, not that the entry is in the public log now', () => {
  const src = read('frontend/js/receipt-verify.js');
  assert.doesNotMatch(src, /staat echt in het openbare transparantielogboek|really is in the public transparency log/);
  assert.match(src, /de relay heeft toen ondertekend dat deze regel in zijn transparantielogboek stond/);
  assert.match(src, /the relay signed at the time that this entry was in its transparency log/);
  // And the reason the stronger sentence is not allowed: the check folds the
  // receipt's own path to the receipt's own root, with no network call.
  const fn = src.slice(src.indexOf('export function verifyReceipt'), src.indexOf('// Visible text in both languages'));
  assert.doesNotMatch(fn, /fetch\(/, 'verifyReceipt now fetches the log: the page may say more again');
  for (const p of ['frontend/verify.html', 'frontend/en/verify.html']) {
    assert.doesNotMatch(visible(read(p)), /staat echt in het openbare transparantielogboek|really sits in the public transparency log/, p);
  }
});

test('/ct-log names the April 2026 restart instead of saying the log only restarts with the volume', () => {
  const nl = visible(read('frontend/ct-log.html'));
  const en = visible(read('frontend/en/ct-log.html'));
  assert.match(nl, /In april 2026 is het log wel opnieuw begonnen/);
  assert.match(nl, /39 vermeldingen uit die tijd \(posities 1 tot en met 34 en 42 tot en met 46\)/);
  assert.match(en, /In April 2026 the log did restart/);
  assert.match(en, /39 entries from that time \(positions 1 to 34 and 42 to 46\)/);
  // The bare sentence, without the April exception before it, is the lie.
  assert.doesNotMatch(nl, /hashes\. Het log begint alleen opnieuw als het volume/);
  assert.doesNotMatch(en, /hashes\. The log resets only when the relay volume is deleted/);
});

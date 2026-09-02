// Step (b): ParaSend, end to end, both routes.
//
// Send a file, fetch it, compare the bytes, prove it is gone. That last clause
// is not an implementation detail: burn-on-read is a promise on the front page,
// so "it is gone" is part of the product and gets asserted like everything else.
//
// The old canary did this correctly for the anonymous route and skipped the
// keyed route, because PARAMANT_CANARY_KEY does not exist. It reported that
// skip as `ok 3 - keyed transfer: upload, download, burn # SKIP` in 0.28 ms and
// the step went green. The paid route a customer actually uses has therefore
// never been checked. Here the key is required and its absence is red.
import crypto from 'node:crypto';
import { RELAY, SLOW_MS, PREFIX, DRY_RUN, assert, http, proof, requireSecret, sha256, timed } from './lib.mjs';

// Short, because a canary blob that outlives the run is litter. Ten minutes is
// enough for the run and short enough that a failed cleanup expires by itself.
const TTL_MS = 600000;

function canaryBlob(label) {
  const id = crypto.randomUUID();
  return {
    id,
    // A distinct payload per run, so two overlapping runs can never collide on
    // one hash and burn each other's blob.
    buf: Buffer.from(`${PREFIX}parasend ${label} ${id} ${new Date().toISOString()}`),
  };
}

export async function parasend(evidence) {
  const key = requireSecret('PARAMANT_CANARY_KEY', 'a relay API key for the keyed /v2/inbound route');

  if (DRY_RUN) {
    proof(evidence, 'dry run: parasend wiring exercised, nothing sent', { ttl_ms: TTL_MS, key_present: true });
    return;
  }

  // ── the anonymous route: what every visitor gets for free ─────────────────
  {
    const { id, buf } = canaryBlob('anon');
    const hash = sha256(buf);
    evidence.artifacts.anon = { canary_id: `${PREFIX}${id}`, sha256: hash, bytes: buf.length };

    const up = await timed(evidence, 'POST /v2/anon-inbound', SLOW_MS, () =>
      http(evidence, 'POST', `${RELAY}/v2/anon-inbound`, {
        body: { hash, payload: buf.toString('base64'), ttl_ms: TTL_MS },
      }));
    assert(up.status === 200, `anonymous upload rejected: HTTP ${up.status}`, up.text?.slice(0, 300));
    assert(up.json?.ok === true, 'the relay did not accept the anonymous upload',
      `Answered 200 but ok is ${JSON.stringify(up.json?.ok)}.`);
    assert(up.json?.hash === hash, 'the relay stored the blob under a different hash',
      `Sent ${hash}, relay says ${up.json?.hash}.`);
    const token = up.json?.download_token;
    assert(!!token, 'no download token, so a recipient would have no way to fetch the file');
    evidence.artifacts.anon.download_token_sha256 = sha256(Buffer.from(String(token)));

    const dl = await timed(evidence, 'GET /v2/dl/:token/get', SLOW_MS, () =>
      http(evidence, 'GET', `${RELAY}/v2/dl/${token}/get`, { raw: true }));
    assert(dl.status === 200, `anonymous download failed: HTTP ${dl.status}`);
    const back = sha256(dl.bytes);
    assert(back === hash, 'the bytes that came back are not the bytes that went in',
      `Sent sha256 ${hash}, received ${back} (${dl.bytes.length} bytes).`);

    // The read must have destroyed it. A relay that serves the same blob twice
    // is not the product that was sold.
    const again = await timed(evidence, 'GET /v2/dl/:token/get (must be burned)', SLOW_MS, () =>
      http(evidence, 'GET', `${RELAY}/v2/dl/${token}/get`));
    assert(again.status === 410, `the blob survived its read: HTTP ${again.status}`,
      'Burn-on-read is broken. A second fetch of the same token returned something other than 410 Gone.');

    proof(evidence, 'anonymous transfer: sent, fetched byte for byte, and burned', {
      canary_id: `${PREFIX}${id}`, sha256_sent: hash, sha256_received: back,
      bytes: dl.bytes.length, second_fetch_status: again.status,
    });
  }

  // ── a corrupted payload must never be stored ──────────────────────────────
  {
    const { buf } = canaryBlob('mismatch');
    const bad = await timed(evidence, 'POST /v2/anon-inbound (hash mismatch)', SLOW_MS, () =>
      http(evidence, 'POST', `${RELAY}/v2/anon-inbound`, {
        body: { hash: 'f'.repeat(64), payload: buf.toString('base64'), ttl_ms: TTL_MS },
      }));
    assert(bad.status === 400, `a payload that does not match its hash was accepted: HTTP ${bad.status}`,
      'The integrity check on upload is the reason a recipient can trust what they fetch.');
    assert(bad.json?.error === 'hash_mismatch', `refused, but with error ${JSON.stringify(bad.json?.error)}`,
      'Expected hash_mismatch. A different error means the refusal came from somewhere else, ' +
      'and the integrity check itself is unproven.');
    proof(evidence, 'a payload that does not match its hash is refused before storage', {
      status: bad.status, error: bad.json?.error,
    });
  }

  // ── the keyed route: what a paying customer gets ──────────────────────────
  {
    const { id, buf } = canaryBlob('keyed');
    const hash = sha256(buf);
    evidence.artifacts.keyed = { canary_id: `${PREFIX}${id}`, sha256: hash, bytes: buf.length };

    const up = await timed(evidence, 'POST /v2/inbound', SLOW_MS, () =>
      http(evidence, 'POST', `${RELAY}/v2/inbound`, {
        headers: { 'X-Api-Key': key },
        body: { hash, payload: buf.toString('base64'), ttl_ms: TTL_MS },
      }));
    assert(up.status !== 401 && up.status !== 403,
      `the relay refused PARAMANT_CANARY_KEY: HTTP ${up.status}`,
      'The monitoring key is set but the relay does not accept it. Either the key was revoked or the ' +
      'keyed route is broken. Both are red: a credential that no longer works measures nothing.');
    assert(up.status === 200, `keyed upload rejected: HTTP ${up.status}`, up.text?.slice(0, 300));
    assert(up.json?.ok === true, 'the relay did not accept the keyed upload');

    const dl = await timed(evidence, 'GET /v2/outbound/:hash', SLOW_MS, () =>
      http(evidence, 'GET', `${RELAY}/v2/outbound/${hash}`, {
        headers: { 'X-Api-Key': key }, raw: true,
      }));
    assert(dl.status === 200, `keyed download failed: HTTP ${dl.status}`);
    const back = sha256(dl.bytes);
    assert(back === hash, 'the bytes that came back are not the bytes that went in',
      `Sent sha256 ${hash}, received ${back} (${dl.bytes.length} bytes).`);
    const burned = dl.headers.get('x-paramant-burned');
    assert(burned === 'true', `the relay did not report the blob as burned (x-paramant-burned: ${burned})`,
      'The keyed route signals the burn in a header rather than a second 410. Absent means the blob ' +
      'may still be on disk.');

    // Belt and braces: ask again. The header is the relay's claim about itself;
    // a second fetch is the observation.
    const again = await timed(evidence, 'GET /v2/outbound/:hash (must be gone)', SLOW_MS, () =>
      http(evidence, 'GET', `${RELAY}/v2/outbound/${hash}`, { headers: { 'X-Api-Key': key } }));
    assert(again.status !== 200, `the keyed blob survived its read: HTTP ${again.status}`,
      'The relay claimed it burned the blob and then served it again.');

    proof(evidence, 'keyed transfer: sent, fetched byte for byte, and burned', {
      canary_id: `${PREFIX}${id}`, sha256_sent: hash, sha256_received: back,
      bytes: dl.bytes.length, burned_header: burned, second_fetch_status: again.status,
    });
  }

  // Nothing to clean up: both blobs were destroyed by the reads that proved
  // they could be read, which is the whole point of burn-on-read. Recorded so
  // the evidence file does not look like cleanup was forgotten.
  evidence.cleanup.push({
    what: 'parasend canary blobs',
    ok: true,
    status: 'burned by the read that verified them; nothing persists',
  });
}

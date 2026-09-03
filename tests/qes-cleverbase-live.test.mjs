// Live checks against the Cleverbase pre-production Signing API.
//
// Off by default. It only runs with CLEVERBASE_SANDBOX=1, because it makes real
// outbound calls and a test suite that needs the internet to be green is a test
// suite nobody trusts. Run it with:
//
//   CLEVERBASE_SANDBOX=1 node --test tests/qes-cleverbase-live.test.mjs
//
// What it can and cannot prove is the point of the whole prototype, so it is
// written to say so out loud:
//   - POST /csc/v1/info needs no credentials and confirms the host, the CSC
//     version and the method list. That part always runs.
//   - Anything past that needs an OAuth client, and client registration at
//     Cleverbase is a manual step with an account manager. Set
//     CLEVERBASE_CLIENT_ID and CLEVERBASE_CLIENT_SECRET to exercise it.
//   - A signature can never be produced by a test. The API offers authType
//     "oauth2code" only: a natural person has to authorise in the Cleverbase
//     app, having identified himself there with an NFC chip read plus
//     biometrics. There is no client_credentials path, in sandbox or in
//     production, and that is by design for a qualified signature.

import test from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';

const liveRequire = createRequire(import.meta.url);
const liveCleverbase = liveRequire('../relay/lib/qes/cleverbase.js');
const liveTsa = liveRequire('../relay/lib/qes/tsa.js');

const LIVE = process.env.CLEVERBASE_SANDBOX === '1';
const SKIP_REASON = 'set CLEVERBASE_SANDBOX=1 to run this; it makes real calls to '
  + liveCleverbase.SANDBOX_BASE_URL;
const liveOpts = LIVE ? {} : { skip: SKIP_REASON };

const HAS_CLIENT = LIVE && !!process.env.CLEVERBASE_CLIENT_ID && !!process.env.CLEVERBASE_CLIENT_SECRET;
const CLIENT_SKIP = 'needs CLEVERBASE_CLIENT_ID and CLEVERBASE_CLIENT_SECRET; '
  + 'Cleverbase registers OAuth clients by hand, so there is no self-service pair for the signing host';
const clientOpts = HAS_CLIENT ? {} : { skip: LIVE ? CLIENT_SKIP : SKIP_REASON };

function liveClient() {
  return new liveCleverbase.CleverbaseClient({
    env: process.env,
    baseUrl: process.env.CLEVERBASE_BASE_URL || liveCleverbase.SANDBOX_BASE_URL,
    redirectUri: process.env.CLEVERBASE_REDIRECT_URI || 'https://example.com/qes/return',
  });
}

test('the sandbox announces a CSC v1.0.4 signing service', liveOpts, async () => {
  const info = await liveClient().info();
  assert.strictEqual(info.specs, '1.0.4.0');
  assert.deepStrictEqual(info.authType, ['oauth2code'],
    'oauth2code only: every signature needs a person authorising it in the provider app');
  for (const method of ['oauth2/authorize', 'oauth2/token', 'credentials/list', 'credentials/info', 'signatures/signHash']) {
    assert.ok(info.methods.includes(method), 'expected method ' + method + ', got ' + info.methods.join(', '));
  }
  assert.ok(!info.methods.includes('signatures/signDoc'),
    'there is no document-signing method, which is exactly why the document can stay here');
  assert.ok(!info.methods.some((m) => m.includes('timestamp')),
    'no timestamp method: a qualified timestamp has to come from somewhere else');
});

test('credentials/list refuses an unauthenticated caller', liveOpts, async () => {
  const client = liveClient();
  await assert.rejects(() => client.listCredentials('not-a-token'), (e) => {
    assert.ok(e.status >= 400 && e.status < 500, 'expected a 4xx, got ' + e.status);
    return true;
  });
});

test('the OAuth client is recognised by the signing host', clientOpts, async () => {
  const client = liveClient();
  const url = client.authorizeUrl({ scope: 'service', state: crypto.randomBytes(8).toString('hex') });
  const res = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(20000) });
  const location = res.headers.get('location') || '';
  assert.ok(!location.includes('invalid_client'),
    'the signing host rejected this client id: ' + location);
});

test('a signature cannot be produced without a person, and the API says so', clientOpts, async () => {
  const client = liveClient();
  const digest = crypto.createHash('sha256').update('signed attributes').digest();
  await assert.rejects(
    () => client.signHash({ serviceToken: 'not-a-token', credentialID: 'GX0112348', sad: 'not-a-sad', hashes: [digest] }),
    (e) => {
      assert.ok(e.status >= 400 && e.status < 500,
        'signHash without a real service token and SAD must be refused, got ' + e.status);
      return true;
    }
  );
});

test('the timestamp authority answers an RFC 3161 request', liveOpts, async () => {
  const url = process.env.QES_TSA_URL || liveTsa.DEFAULT_TSA_URL;
  const digest = crypto.createHash('sha256').update('signature value').digest();
  const token = await liveTsa.stamp(digest, { url });
  assert.ok(token && token.length > 500, 'expected a timestamp token, got ' + (token && token.length));
  const parsed = liveTsa.parseTimeStampToken(token);
  assert.deepStrictEqual(parsed.hashedMessage, digest, 'the token must cover the digest we sent');
  assert.strictEqual(parsed.hashAlgorithm, '2.16.840.1.101.3.4.2.1');
  const age = Math.abs(Date.now() - Date.parse(parsed.genTime));
  assert.ok(age < 10 * 60 * 1000, 'the timestamp should be current, it reads ' + parsed.genTime);
});

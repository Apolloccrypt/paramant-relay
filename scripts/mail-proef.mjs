// One test mail through the real carrier code, for after a mail switch.
//
//   node scripts/mail-proef.mjs <to-address> [token-file]
//
// Sends through relay/lib/mail.js with MAIL_PROVIDER=lettermint, so it tests
// the same request the relay makes, not a hand-written curl. The token comes
// from the file named as the second argument, or else from LETTERMINT_API_TOKEN
// in the environment. It is never taken as a command-line value, because that
// shows up in `ps` and in shell history, and it is never printed.
//
// Prints the HTTP status and the message id Lettermint returned. A 202 means
// Lettermint accepted the mail; whether it ARRIVED is for the inbox to say.
// MAIL_FROM is honoured, otherwise the relay's default sender is used.
//
// Node builtins only.

import fs from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const mail = require('../relay/lib/mail.js');

const [naar, tokenPad] = process.argv.slice(2);
if (!naar || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(naar)) {
  console.error('usage: node scripts/mail-proef.mjs <to-address> [token-file]');
  process.exit(2);
}

let token = process.env.LETTERMINT_API_TOKEN || '';
if (tokenPad) {
  try {
    token = fs.readFileSync(tokenPad, 'utf8').trim();
  } catch (e) {
    console.error(`cannot read token file: ${e.code || e.message}`);
    process.exit(2);
  }
}
if (!token) {
  console.error('no token: pass a token file or set LETTERMINT_API_TOKEN');
  process.exit(2);
}

const env = { ...process.env, MAIL_PROVIDER: 'lettermint', LETTERMINT_API_TOKEN: token,
              MAIL_FALLBACK_PROVIDER: '' };

// Record what the API answered, without touching the request headers.
const antwoorden = [];
const meet = async (url, init) => {
  const resp = await fetch(url, init);
  const kopie = resp.clone();
  let body = null;
  try { body = await kopie.json(); } catch { body = null; }
  antwoorden.push({ status: resp.status, message_id: body && body.message_id, api_status: body && body.status });
  return resp;
};

const nu = new Date().toISOString();
const uit = await mail.stuur({
  to: naar,
  subject: `Paramant mail test ${nu}`,
  text: `Test mail from scripts/mail-proef.mjs, sent ${nu} via Lettermint. No action needed.`,
  html: `<p>Test mail from <code>scripts/mail-proef.mjs</code>, sent ${nu} via Lettermint.</p><p>No action needed.</p>`,
}, { env, fetch: meet });

const a = antwoorden[0] || {};
console.log(JSON.stringify({
  ok: uit.ok,
  provider: uit.provider,
  http_status: a.status || null,
  message_id: a.message_id || null,
  api_status: a.api_status || null,
  reason: uit.ok ? null : uit.reason,
  detail: uit.ok ? null : (uit.detail || null),
}, null, 2));
process.exit(uit.ok ? 0 : 1);

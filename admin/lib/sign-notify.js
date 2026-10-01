'use strict';
// Who hears it when somebody signs.
//
// A /v1 API customer gets signer.completed and envelope.completed as webhooks
// (relay.js, the sign path). The person who sends a document from /sign got
// nothing: after "Versturen om te laten tekenen" the only way to learn that a
// co-signer had signed was to keep opening the dashboard. For a two-person
// contract that is the whole wait, and it is where a customer gives up and
// signs "via een andere applicatie".
//
// So the admin remembers, per envelope, which account sent it, and mails that
// account when another party's signature lands. What it keeps is a hash of the
// account id and the address the session already had, for as long as the invite can
// still be signed plus one day; the record goes the moment the envelope is
// complete. What the mail carries is a count and a link, never a file name or
// a party name: those would travel to the mail provider for no gain, and the
// dashboard behind the link shows both to the one person entitled to them.

const crypto = require('crypto');

const KEY_PREFIX = 'paramant:envelope:notify:';
// Invites close SIGN_INVITE_TTL_DAYS (7) after creation (relay/envelope.js),
// so no signature can land after that. One day of slack for clock skew.
const TTL_SECONDS = 8 * 86400;
const ID_RE = /^[A-Za-z0-9_-]{6,128}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const keyFor = (envelopeId) => KEY_PREFIX + envelopeId;
// The session's user_id is still the account's API key (backlog: "de
// API-sleutel is de identiteit"). It is only ever compared here, so only its
// hash is stored: this record must not become one more copy of a credential.
const idHash = (id) => crypto.createHash('sha256').update('paramant/sign-notify\0' + String(id)).digest('hex');

// Called once an envelope with at least one other party exists. Best effort:
// a failure here costs one notification, never the envelope.
async function rememberSender(client, envelopeId, { user_id, email } = {}) {
  if (!ID_RE.test(String(envelopeId || ''))) return false;
  if (!user_id || !EMAIL_RE.test(String(email || ''))) return false;
  await client.set(keyFor(envelopeId), JSON.stringify({ uid: idHash(user_id), email: String(email).toLowerCase().trim() }), { EX: TTL_SECONDS });
  return true;
}

// The address to tell, or null. Null when nobody is remembered, when the
// relay answered a retry (no new signature), and when the sender signed their
// own slot: they know, they just did it.
async function senderToTell(client, envelopeId, { signerAccountId, idempotent } = {}) {
  if (idempotent) return null;
  if (!ID_RE.test(String(envelopeId || ''))) return null;
  const raw = await client.get(keyFor(envelopeId));
  if (!raw) return null;
  let rec; try { rec = JSON.parse(raw); } catch { return null; }
  if (!rec || !rec.email || !rec.uid) return null;
  if (signerAccountId && rec.uid === idHash(signerAccountId)) return null;
  return rec.email;
}

// A complete envelope has nothing left to report.
async function forget(client, envelopeId) {
  if (!ID_RE.test(String(envelopeId || ''))) return;
  await client.del(keyFor(envelopeId));
}

// The whole decision after a successful submit, so server.js stays one call.
// Returns what it did, for the log and the tests: 'sent', 'skipped' or 'failed'.
async function afterSignature({ client, envelopeId, signerAccountId, relayBody, sendEmail, template }) {
  try {
    const body = relayBody || {};
    const to = await senderToTell(client, envelopeId, { signerAccountId, idempotent: body.idempotent === true });
    const complete = body.status === 'complete';
    if (complete) await forget(client, envelopeId).catch(() => {});
    if (!to) return 'skipped';
    const signed = Number(body.signed_count);
    const total = Number(body.party_count);
    if (!Number.isInteger(signed) || !Number.isInteger(total) || total < 1) return 'skipped';
    await sendEmail(to, template({ signedCount: signed, partyCount: total, complete, envelopeId }));
    return 'sent';
  } catch {
    return 'failed';
  }
}

module.exports = { idHash, rememberSender, senderToTell, forget, afterSignature, KEY_PREFIX, TTL_SECONDS };

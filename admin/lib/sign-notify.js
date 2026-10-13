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
// complete. Since acceptatie r4 (Nieuw 1) it also keeps the invited addresses
// for the same window, so every party hears "Iedereen heeft getekend" once,
// also when the sender signed last. What the mail carries is a count and a link, never a file name or
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
  // 'at' is the day the request went out: the mails name the request by it,
  // since the file name may not travel (acceptatie 3.1.1, taal #45).
  await client.set(keyFor(envelopeId), JSON.stringify({ uid: idHash(user_id), email: String(email).toLowerCase().trim(), at: Date.now() }), { EX: TTL_SECONDS });
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
  await client.del(partiesKeyFor(envelopeId));
}

// The invited addresses, so they too hear "Iedereen heeft getekend"
// (acceptatie r4, Nieuw 1). The admin had each address in hand when it sent
// the invitation; it keeps them, lower-cased, under the same 8-day TTL as the
// sender's record and drops them the moment the envelope completes or is
// declined. No link is kept: the opening link holds half a document key and
// never stays on a server, so the party mail points at the invitation mail.
const PARTIES_PREFIX = 'paramant:envelope:notify-parties:';
const partiesKeyFor = (envelopeId) => PARTIES_PREFIX + envelopeId;
async function rememberParties(client, envelopeId, emails) {
  if (!ID_RE.test(String(envelopeId || ''))) return false;
  const list = [...new Set((Array.isArray(emails) ? emails : []).map((e) => String(e || '').toLowerCase().trim()).filter((e) => EMAIL_RE.test(e)))];
  if (!list.length) return false;
  await client.sAdd(partiesKeyFor(envelopeId), list);
  await client.expire(partiesKeyFor(envelopeId), TTL_SECONDS);
  return true;
}
async function partiesFor(client, envelopeId) {
  if (!ID_RE.test(String(envelopeId || ''))) return [];
  const list = await client.sMembers(partiesKeyFor(envelopeId));
  return Array.isArray(list) ? list.filter((e) => EMAIL_RE.test(String(e || ''))) : [];
}

// The link in "Iedereen heeft getekend" opens the finished document, not the
// dashboard. It still may not carry the envelope id (see the top of this
// file), so it carries an opaque reference instead: 32 random bytes that map
// to the envelope for the sending account only, for as long as the envelope
// record lives (30 days). Somebody holding the mail without that account's
// session gets nothing from it.
const RESULT_PREFIX = 'paramant:envelope:result:';
const RESULT_TTL_SECONDS = 30 * 86400;
const REF_RE = /^[A-Za-z0-9_-]{43}$/;

async function rememberResult(client, envelopeId, uidHash) {
  const ref = crypto.randomBytes(32).toString('base64url');
  await client.set(RESULT_PREFIX + ref, JSON.stringify({ id: String(envelopeId), uid: uidHash }), { EX: RESULT_TTL_SECONDS });
  return ref;
}

// The envelope id behind a reference, or null when the reference is unknown,
// expired, or belongs to another account.
async function resolveResult(client, ref, userId) {
  if (!REF_RE.test(String(ref || '')) || !userId) return null;
  const raw = await client.get(RESULT_PREFIX + ref);
  if (!raw) return null;
  let rec; try { rec = JSON.parse(raw); } catch { return null; }
  if (!rec || !ID_RE.test(String(rec.id || '')) || rec.uid !== idHash(userId)) return null;
  return rec.id;
}

async function recordFor(client, envelopeId) {
  if (!ID_RE.test(String(envelopeId || ''))) return null;
  const raw = await client.get(keyFor(envelopeId));
  if (!raw) return null;
  try { const rec = JSON.parse(raw); return rec && rec.email && rec.uid ? rec : null; } catch { return null; }
}

// The whole decision after a successful submit, so server.js stays one call.
// Returns what it did, for the log and the tests: 'sent', 'skipped' or 'failed'.
async function afterSignature({ client, envelopeId, signerAccountId, relayBody, sendEmail, template, partyTemplate, baseUrl }) {
  try {
    const body = relayBody || {};
    if (body.idempotent === true) return 'skipped';   // a retry: nothing new happened
    const complete = body.status === 'complete';
    const signed = Number(body.signed_count);
    const total = Number(body.party_count);
    const counted = Number.isInteger(signed) && Number.isInteger(total) && total >= 1;
    if (!complete) {
      // Progress: only when somebody else signed. The sender who just signed
      // their own slot knows; they did it.
      const to = await senderToTell(client, envelopeId, { signerAccountId });
      if (!to || !counted) return 'skipped';
      const r0 = await recordFor(client, envelopeId).catch(() => null);
      await sendEmail(to, template({ signedCount: signed, partyCount: total, complete, envelopeId, resultUrl: null, sentAt: r0 && r0.at }));
      return 'sent';
    }
    // Complete. Everyone hears it once, also when the sender was the last to
    // sign (acceptatie r4, Nieuw 1: then nobody got "Iedereen heeft getekend"
    // and nobody got the result link). The reference is made before the record
    // goes, from the record's own account hash: only the sender's session can
    // resolve it later.
    const rec = await recordFor(client, envelopeId).catch(() => null);
    const parties = await partiesFor(client, envelopeId).catch(() => []);
    let resultUrl = null;
    if (rec) {
      const ref = await rememberResult(client, envelopeId, rec.uid).catch(() => null);
      if (ref && baseUrl) resultUrl = String(baseUrl).replace(/\/$/, '') + '/co-sign?result=' + ref;
    }
    await forget(client, envelopeId).catch(() => {});
    let sent = 0;
    if (rec && counted) {
      await sendEmail(rec.email, template({ signedCount: signed, partyCount: total, complete, envelopeId, resultUrl, sentAt: rec.at }));
      sent++;
    }
    // One mail per address: the sender's own address, also when it was
    // invited as a party, already had the mail with the result link.
    if (typeof partyTemplate === 'function') {
      for (const to of parties) {
        if (rec && to === rec.email) continue;
        try { await sendEmail(to, partyTemplate({ partyCount: counted ? total : null, envelopeId })); sent++; }
        catch { /* one address failing must not cost the others theirs */ }
      }
    }
    return sent ? 'sent' : 'skipped';
  } catch {
    return 'failed';
  }
}

// A party refused. The request is over, so the sender hears it once and the
// record goes. Same rules as above: no names, no file name, no envelope id.
// Since acceptatie 3.1.1 (taal #42) the other invited parties hear it too:
// they had a link that now opens a closed request, and nobody told them.
async function afterDecline({ client, envelopeId, sendEmail, template, partyTemplate, declinerEmail }) {
  try {
    const rec = await recordFor(client, envelopeId);
    const parties = typeof partyTemplate === 'function' ? await partiesFor(client, envelopeId).catch(() => []) : [];
    await forget(client, envelopeId).catch(() => {});
    let sent = 0;
    if (rec) { await sendEmail(rec.email, template({ envelopeId, sentAt: rec.at })); sent++; }
    const skip = String(declinerEmail || '').toLowerCase().trim();
    for (const to of parties) {
      if (to === skip || (rec && to === rec.email)) continue;
      try { await sendEmail(to, partyTemplate({ reason: 'declined', envelopeId })); sent++; }
      catch { /* one address failing must not cost the others theirs */ }
    }
    return sent ? 'sent' : 'skipped';
  } catch {
    return 'failed';
  }
}

// The sender withdrew the request (dashboard, POST /api/user/documents/:id/
// cancel). Every invited party hears it once, so nobody opens a link to a
// closed request without knowing why (acceptatie 3.1.1, taal #42). The record
// goes. An expired request has no event to hang this on: the invitation
// already names the last day to sign.
async function afterWithdraw({ client, envelopeId, sendEmail, partyTemplate }) {
  try {
    const parties = await partiesFor(client, envelopeId).catch(() => []);
    await forget(client, envelopeId).catch(() => {});
    let sent = 0;
    for (const to of parties) {
      try { await sendEmail(to, partyTemplate({ reason: 'withdrawn', envelopeId })); sent++; }
      catch { /* one address failing must not cost the others theirs */ }
    }
    return sent ? 'sent' : 'skipped';
  } catch {
    return 'failed';
  }
}

module.exports = { idHash, rememberSender, rememberParties, partiesFor, senderToTell, forget, afterSignature, afterDecline, afterWithdraw, rememberResult, resolveResult, KEY_PREFIX, RESULT_PREFIX, PARTIES_PREFIX, TTL_SECONDS, RESULT_TTL_SECONDS };

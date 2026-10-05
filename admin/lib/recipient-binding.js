'use strict';
// Recipient-email validation for ParaSign envelope creation (audit 1.1).
//
// Every ParaSign envelope is bound to email (binding_mode:"email"): each
// co-signer must present, at co-sign time, an authenticated session whose
// verified email hashes to the party slot's stored email_hash (see
// relay/envelope.js partyEmailHash + sign() email-binding, and the admin
// activation authorize). A party slot created with an EMPTY or MALFORMED
// email therefore hashes to '' (or to a wrong value) and can NEVER be signed:
// the invite is a guaranteed dead end.
//
// The old code silently dropped empty-email recipients (`if (r && r.email)`),
// so a co-signer the sender added by name simply vanished from the envelope,
// with no link ever generated, the exact dead-end the "email is a label for
// your reference only" UI copy invited. We instead REQUIRE a syntactically
// valid email per recipient and refuse creation otherwise, so we never mint a
// doomed invite. Kept as a tiny pure module so it is unit-testable without
// booting the admin server.

// Same email shape the signup/login paths already enforce in admin/server.js.
const RECIPIENT_EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_LABEL = 80;
const MAX_EMAIL = 200;

// Build the co-signer party list (parties 1..N; party 0 = the signer, added by
// the caller). Returns { parties } on success, or { error } (a stable code the
// route maps to HTTP 400) when any non-empty recipient row lacks a valid email.
// A fully-empty row (no label, no email) is ignored, matching the frontend
// which drops blank rows before submit.
function buildRecipientParties(recipients) {
  const list = Array.isArray(recipients) ? recipients : [];
  const parties = [];
  for (const r of list) {
    if (!r || typeof r !== 'object') continue;
    const label = (r.label || '').toString().trim().slice(0, MAX_LABEL);
    const email = (r.email || '').toString().trim().slice(0, MAX_EMAIL);
    if (!label && !email) continue;                 // blank row: ignore
    if (!RECIPIENT_EMAIL_RE.test(email)) {
      return { error: 'recipient_email_required' };  // no dead-end envelopes
    }
    parties.push({ label, email });
  }
  return { parties };
}

module.exports = { buildRecipientParties, RECIPIENT_EMAIL_RE };

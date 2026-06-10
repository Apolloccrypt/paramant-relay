'use strict';
// Canonicalize an e-mail to the underlying mailbox for RATE-LIMIT keys only
// (never for storage/sending — the address the user typed is kept verbatim).
//
// Closes the trial-farming bypass (#13) where a.b+1@gmail.com, a.b@gmail.com
// and ab@gmail.com all deliver to one mailbox but counted as three distinct
// rate-limit keys, letting one Gmail account mint unlimited trial keys.
//
// Rules:
//  - lowercase + trim
//  - drop a '+tag' suffix for EVERY provider (sub-addressing routes to the
//    same mailbox, supported by Gmail, Outlook, Fastmail, Proton, ...)
//  - strip dots in the local part ONLY for Gmail (its documented
//    dot-insensitivity); googlemail.com is folded to gmail.com
// Conservative by design: for unknown providers only the +tag is removed, so
// we never collapse two genuinely different mailboxes.
function normalizeEmailForRateLimit(email) {
  const e = String(email || '').trim().toLowerCase();
  const at = e.lastIndexOf('@');
  if (at <= 0 || at === e.length - 1) return e;
  let local = e.slice(0, at);
  let domain = e.slice(at + 1);
  const plus = local.indexOf('+');
  if (plus !== -1) local = local.slice(0, plus);
  if (domain === 'googlemail.com') domain = 'gmail.com';
  if (domain === 'gmail.com') local = local.replace(/\./g, '');
  if (!local) return e; // a bare "+tag@host" -> don't collapse to "@host"
  return local + '@' + domain;
}

module.exports = { normalizeEmailForRateLimit };

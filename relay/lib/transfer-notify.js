'use strict';
// ParaSend Pro upload/download e-mail notifications. A paid capability: only
// Pro+ accounts get a mail when one of their transfers is stored (upload) or
// fetched (download). Free/community accounts trigger nothing.
//
// This module owns ONLY the decision + the message shape. The actual send is an
// injected `sendEmail` callback (relay.js passes its Resend helper), so the tier
// gate is unit-testable with a spy and zero network (test/transfer-notify.test.js).
// Pure w.r.t. I/O: it never touches Resend, env, or globals directly.
const tierGate = require('./tier-gate');

// Dutch and English (SENDNAME-23-F: a Dutch sender got "Your Paramant transfer
// is ready"). `lang` 'nl' or 'en' picks one; anything else sends Dutch with the
// English underneath, like the relay's other mails.
const SUBJECTS = {
  upload:   'Your Paramant transfer is ready',
  download: 'Your Paramant transfer was downloaded',
};
const SUBJECTS_NL = {
  upload:   'Uw Paramant-verzending staat klaar',
  download: 'Uw Paramant-verzending is opgehaald',
};

function bodies(event, hashPrefix, bytes) {
  const ref = String(hashPrefix || '').slice(0, 16);
  const nl = `Een verzending van uw Paramant-account is ${event === 'download' ? 'opgehaald' : 'opgeslagen'}.\n\n`
    + `Kenmerk: ${ref}\nGrootte: ${bytes || 0} bytes\n\n`
    + 'U krijgt deze melding omdat die bij uw plan hoort.';
  const en = `A transfer on your Paramant account was ${event === 'download' ? 'downloaded' : 'stored'}.\n\n`
    + `Reference: ${ref}\nSize: ${bytes || 0} bytes\n\n`
    + 'You get this notice because it is part of your plan.';
  return { nl, en };
}

// maybeNotify: fire an upload/download notification IFF the account is ParaSend
// Pro+ and has a contact e-mail. Returns { sent, reason }.
//   keyData   — the authenticated key record (plan info + email)
//   event     — 'upload' | 'download'
//   hashPrefix— short content-hash prefix for the message (never the payload)
//   bytes     — transfer size for the message
//   lang      - 'nl' | 'en' | anything else = both
//   sendEmail({ to, subject, text }) — injected mailer (relay: Resend helper)
function maybeNotify({ keyData, event, hashPrefix, bytes, sendEmail, lang }) {
  if (!tierGate.isParasendProPlus(keyData)) return { sent: false, reason: 'tier' };
  const to = keyData && keyData.email;
  if (!to) return { sent: false, reason: 'no_email' };
  if (typeof sendEmail !== 'function') return { sent: false, reason: 'no_mailer' };
  const ev = event === 'download' ? 'download' : 'upload';
  const { nl, en } = bodies(ev, hashPrefix, bytes);
  const subject = lang === 'en' ? SUBJECTS[ev] : lang === 'nl' ? SUBJECTS_NL[ev] : `${SUBJECTS_NL[ev]} / ${SUBJECTS[ev]}`;
  const text = lang === 'en' ? en : lang === 'nl' ? nl : `${nl}\n\n---\n\n${en}`;
  try {
    sendEmail({ to, subject, text });
    return { sent: true, reason: 'ok' };
  } catch (e) {
    return { sent: false, reason: 'send_error', error: e && e.message };
  }
}

module.exports = { maybeNotify, SUBJECTS, SUBJECTS_NL };

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

// What a reader can use: what happened and how big the file was, in KB or MB
// the way each language writes it. A content hash as "Kenmerk" and a size in
// bytes told a customer nothing (acceptatie 3.1.1, taal #38). The file name
// stays out on purpose: the mail goes through a provider, and the name is
// often the content. hashPrefix is still accepted from the caller and unused.
function humanSize(bytes, lang) {
  const b = Math.max(0, Number(bytes) || 0);
  const mb = b / (1024 * 1024);
  const v = mb >= 1 ? mb.toFixed(1) : Math.max(1, Math.round(b / 1024)).toString();
  const unit = mb >= 1 ? 'MB' : 'KB';
  return `${lang === 'nl' ? v.replace('.', ',') : v} ${unit}`;
}

function bodies(event, hashPrefix, bytes) {
  const down = event === 'download';
  const nl = (down
    ? `Een bestand dat u met Paramant verstuurde, is opgehaald (${humanSize(bytes, 'nl')}).`
    : `Een bestand dat u met Paramant verstuurt, staat klaar voor de ontvanger (${humanSize(bytes, 'nl')}).`)
    + '\n\nDe details staan op uw dashboard. U krijgt deze melding omdat die bij uw plan hoort.';
  const en = (down
    ? `A file you sent with Paramant has been picked up (${humanSize(bytes, 'en')}).`
    : `A file you are sending with Paramant is ready for the recipient (${humanSize(bytes, 'en')}).`)
    + '\n\nThe details are on your dashboard. You get this notice because it is part of your plan.';
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

module.exports = { maybeNotify, SUBJECTS, SUBJECTS_NL, humanSize };

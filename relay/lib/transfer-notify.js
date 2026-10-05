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

const SUBJECTS = {
  upload:   'Your Paramant transfer is ready',
  download: 'Your Paramant transfer was downloaded',
};

// maybeNotify: fire an upload/download notification IFF the account is ParaSend
// Pro+ and has a contact e-mail. Returns { sent, reason }.
//   keyData   — the authenticated key record (plan info + email)
//   event     — 'upload' | 'download'
//   hashPrefix— short content-hash prefix for the message (never the payload)
//   bytes     — transfer size for the message
//   sendEmail({ to, subject, text }) — injected mailer (relay: Resend helper)
function maybeNotify({ keyData, event, hashPrefix, bytes, sendEmail }) {
  if (!tierGate.isParasendProPlus(keyData)) return { sent: false, reason: 'tier' };
  const to = keyData && keyData.email;
  if (!to) return { sent: false, reason: 'no_email' };
  if (typeof sendEmail !== 'function') return { sent: false, reason: 'no_mailer' };
  const subject = SUBJECTS[event] || SUBJECTS.upload;
  const verb = event === 'download' ? 'downloaded' : 'stored';
  const text =
    `A transfer on your Paramant account was ${verb}.\n\n` +
    `Reference: ${String(hashPrefix || '').slice(0, 16)}\n` +
    `Size: ${bytes || 0} bytes\n\n` +
    `You receive these notifications because your plan includes them.`;
  try {
    sendEmail({ to, subject, text });
    return { sent: true, reason: 'ok' };
  } catch (e) {
    return { sent: false, reason: 'send_error', error: e && e.message };
  }
}

module.exports = { maybeNotify, SUBJECTS };

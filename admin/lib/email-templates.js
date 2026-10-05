'use strict';

const crypto = require('crypto');
const mailer = require('../../relay/lib/mail');

const BASE_URL = process.env.SITE_URL || 'https://paramant.app';
const FROM_ADDR = 'Paramant <hello@paramant.app>';

// Derive a short, non-reversible reference id for the X-Entity-Ref-ID mail
// header. Previously these were prefixes of the setup token / API key, which
// leaked secret material into outbound mail headers (and any mail-log that
// records them). Hash first, then truncate, so the ref stays stable per
// secret but reveals nothing about it.
const refIdHash = (secret) =>
  crypto.createHash('sha256').update(String(secret ?? '')).digest('hex').slice(0, 12);

const maskIP = (ip) => {
  if (!ip) return 'unknown';
  const m = ip.match(/^(\d+\.\d+)\.\d+\.\d+$/);
  if (m) return m[1] + '.xxx.xxx';
  return ip.slice(0, 8) + '...';
};

// HTML-escape any value that may carry user-controlled input before it lands
// in an HTML email body. Covers &, <, >, " and '. Use for email, label,
// reason, IP, etc. -- anything not built from constants in this module.
const escHtml = (s) => String(s ?? '')
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');

const formatTS = (ts) =>
  new Date(ts).toISOString().replace('T', ' ').replace(/\..*$/, '') + ' UTC';

function wrap(bodyText, bodyHtml, meta = {}) {
  return {
    from: FROM_ADDR,
    replyTo: 'hello@paramant.app',
    text: bodyText,
    html: bodyHtml,
    headers: {
      'List-Unsubscribe': '<mailto:unsubscribe@paramant.app>',
      'X-Entity-Ref-ID': meta.refId || '',
    },
  };
}

// `lang` is for the mails that are Dutch first (the signing invitation, the
// account mails). Every other mail calls this with two arguments and gets
// exactly what it had.
function htmlShell(preheader, bodyHtml, lang = 'en') {
  const nl = lang === 'nl';
  const tagline = nl
    ? 'Paramant, versleuteld versturen en ondertekenen.'
    : 'Paramant, encrypted sending and signing.';
  return `<!DOCTYPE html>
<html lang="${nl ? 'nl' : 'en'}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Paramant</title>
</head>
<body style="margin:0;padding:0;background:#F8FAFC;font-family:system-ui,-apple-system,'Segoe UI',sans-serif;color:#0B3A6A;">
<div style="display:none;max-height:0;overflow:hidden;">${preheader}&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F8FAFC;padding:40px 20px;">
  <tr><td align="center">
    <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid rgba(11,58,106,0.08);">
      <tr><td style="padding:32px 40px 16px 40px;border-bottom:1px solid rgba(11,58,106,0.08);">
        <div style="font-family:monospace;font-size:11px;letter-spacing:0.15em;color:#0B3A6A;font-weight:600;">PARAMANT</div>
      </td></tr>
      <tr><td style="padding:32px 40px;">
        ${bodyHtml}
      </td></tr>
      <tr><td style="padding:24px 40px;border-top:1px solid rgba(11,58,106,0.08);font-size:12px;color:#64748b;line-height:1.6;">
        <p style="margin:0 0 8px 0;">${tagline}</p>
        <p style="margin:0;"><a href="https://paramant.app" style="color:#1D4ED8;text-decoration:none;">paramant.app</a> &middot; <a href="https://paramant.app/security" style="color:#1D4ED8;text-decoration:none;">${nl ? 'Beveiliging' : 'Security'}</a> &middot; <a href="https://paramant.app/help" style="color:#1D4ED8;text-decoration:none;">${nl ? 'Hulp' : 'Help'}</a></p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`;
}

function btn(url, label) {
  return `<div style="margin:24px 0;"><a href="${url}" style="display:inline-block;background:#1D4ED8;color:#ffffff;text-decoration:none;padding:12px 24px;font-weight:500;font-family:system-ui,sans-serif;">${label}</a></div>`;
}

// ── DUTCH FIRST, ENGLISH BELOW ──────────────────────────────────────────────
// The account mails are Dutch since 23 September 2026, with the English text
// under it. The action that sends them (sign up, reset, deactivate) does not
// carry the language of the page it started on, so one mail serves both
// readers: Dutch on top because that is the site's main language, English
// below a clear divider for whoever came in through /en/.
function bilingualMail({ subject, preheader, nlText, enText, nlHtml, enHtml, refId }) {
  const text = `${nlText}\n\n-------- English --------\n\n${enText}`;
  const html = htmlShell(preheader, `
    <div lang="nl">${nlHtml}</div>
    <hr style="border:none;border-top:1px solid rgba(11,58,106,0.16);margin:32px 0 8px 0;">
    <p style="margin:0 0 16px 0;font-family:monospace;font-size:11px;letter-spacing:0.15em;color:#64748b;">ENGLISH</p>
    <div lang="en">${enHtml}</div>
  `, 'nl');
  return { ...wrap(text, html, { refId }), subject };
}

// The lifetime arrives as an English phrase from admin/server.js
// (setupTokenValidFor): "1 hour", "36 hours", "2 days".
function nlDuration(phrase) {
  return String(phrase)
    .replace(/\b1 hour\b/, '1 uur').replace(/\b(\d+) hours\b/, '$1 uur')
    .replace(/\b1 day\b/, '1 dag').replace(/\b(\d+) days\b/, '$1 dagen');
}

// ── 1. SETUP EMAIL ────────────────────────────────────────────────────────────
// `validFor` is the human phrase for the link's lifetime. It is a parameter and
// not a constant, because the number lives in admin/server.js
// (SETUP_TOKEN_TTL_S) and a second copy here is how the mail came to promise
// fourteen days after the link was shortened. setup-link-gate.test.js holds the
// two together.
function setupEmail({ token, requestedAt, requestIP, isReset = false, validFor = '2 days' }) {
  const url = `${BASE_URL}/auth/setup/${token}`;
  const preheader = isReset
    ? 'Uw authenticator-app is losgekoppeld. Scan de nieuwe QR-code.'
    : 'Scan de QR-code met uw authenticator-app om uw account af te maken.';

  const resetWarn = isReset
    ? '\nIMPORTANT: first delete the old Paramant entry from your authenticator app.\nIts codes no longer work.\n'
    : '';

  const enText = `Hi,

${isReset ? 'Your authenticator app has been disconnected.' : 'Welcome to Paramant.'} Connect ${isReset ? 'a new authenticator app to use your account again' : 'an authenticator app to finish your account'}.
Paramant uses it instead of a password.

${isReset ? 'Set up new authenticator app' : 'Finish your account'}:
${url}
${resetWarn}
The link opens a page with a QR code. Scan it with your authenticator app
(for example Google Authenticator, Authy or 1Password). If scanning does
not work, you can type the key in by hand.

This link works for ${validFor}.

Why an authenticator?

Passwords get reused, stolen or phished. A code from your phone
cannot be typed into a fake site or leak in a password dump.
Your bank uses the same method.

After setup you get 10 backup codes. Keep them somewhere safe
(a password manager, or on paper in a drawer) in case you lose your phone.

${isReset ? 'Did you not ask for this reset? Email hello@paramant.app straight away.' : 'Did you not sign up for Paramant? Then you can ignore this email. There is no account until setup is finished.'}

Request details:
  Time:    ${formatTS(requestedAt || Date.now())}
  From IP: ${maskIP(requestIP)}

Paramant
https://paramant.app`;

  const resetBanner = isReset
    ? `<div style="background:#FEF3C7;border-left:3px solid #D97706;padding:12px 16px;margin:0 0 20px 0;">
        <p style="margin:0;line-height:1.5;color:#92400E;font-size:14px;"><strong>Authenticator app disconnected.</strong> First delete the old Paramant entry from your app. Its codes no longer work.</p>
      </div>`
    : '';

  const enHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">${isReset ? 'Set up your new authenticator app' : 'Finish your Paramant account'}</h1>
    ${resetBanner}
    <p style="margin:0 0 16px 0;line-height:1.6;">${isReset ? 'Your authenticator app has been disconnected.' : 'Welcome to Paramant.'} Connect ${isReset ? 'a new authenticator app to use your account again' : 'an authenticator app to finish your account'}. Paramant uses it instead of a password.</p>
    ${btn(url, isReset ? 'Set up new authenticator app' : 'Finish my account')}
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:14px;">The link opens a page with a QR code. Scan it with your authenticator app (for example Google Authenticator, Authy or 1Password). You can also type the key in by hand.</p>
    <p style="margin:0 0 24px 0;line-height:1.6;color:#475569;font-size:14px;">This link works for <strong>${escHtml(validFor)}</strong>.</p>
    <hr style="border:none;border-top:1px solid rgba(11,58,106,0.08);margin:24px 0;">
    <h2 style="margin:0 0 12px 0;font-size:14px;font-weight:600;color:#0B3A6A;">Why an authenticator?</h2>
    <p style="margin:0 0 12px 0;line-height:1.6;color:#475569;font-size:13px;">Passwords get reused, stolen or phished. A code from your phone cannot be typed into a fake site or leak in a password dump. Your bank uses the same method.</p>
    <p style="margin:0 0 24px 0;line-height:1.6;color:#475569;font-size:13px;">After setup you get 10 backup codes. Keep them somewhere safe (a password manager, or on paper in a drawer) in case you lose your phone.</p>
    <hr style="border:none;border-top:1px solid rgba(11,58,106,0.08);margin:24px 0;">
    <p style="margin:0 0 8px 0;font-size:13px;color:#64748b;">${isReset ? '<strong>Did you not ask for this reset?</strong> Email <a href="mailto:hello@paramant.app" style="color:#1D4ED8;">hello@paramant.app</a> straight away.' : '<strong>Did you not sign up for Paramant?</strong> Then you can ignore this email. There is no account until setup is finished.'}</p>
    <p style="margin:16px 0 0 0;font-size:12px;color:#94a3b8;font-family:monospace;">Time: ${formatTS(requestedAt || Date.now())}<br>IP: ${escHtml(maskIP(requestIP))}</p>
  `;

  const nlValid = nlDuration(validFor);
  const nlText = `Hallo,

${isReset ? 'Uw authenticator-app is losgekoppeld.' : 'Welkom bij Paramant.'} Koppel een authenticator-app om ${isReset ? 'uw account weer te gebruiken' : 'uw account af te maken'}.
Die gebruikt Paramant in plaats van een wachtwoord.

${isReset ? 'Nieuwe authenticator-app instellen' : 'Account afmaken'}:
${url}
${isReset ? '\nBELANGRIJK: verwijder eerst de oude Paramant-regel uit uw authenticator-app.\nDie codes werken niet meer.\n' : ''}
De link opent een pagina met een QR-code. Scan die met uw authenticator-app
(bijvoorbeeld Google Authenticator, Authy of 1Password). Lukt scannen
niet, dan vult u de sleutel met de hand in. U kunt daar ook een passkey kiezen.

Deze link werkt ${nlValid}.

Na het instellen krijgt u 10 back-upcodes. Bewaar die op een veilige plek
(wachtwoordbeheerder, of op papier in een la) voor als u uw telefoon kwijtraakt.

${isReset ? 'Hebt u deze reset niet aangevraagd? Mail dan meteen hello@paramant.app.' : 'Hebt u zich niet aangemeld bij Paramant? Dan kunt u deze mail negeren. Er is pas een account als u het instellen afrondt.'}

Tijd:  ${formatTS(requestedAt || Date.now())}
IP:    ${maskIP(requestIP)}

Paramant
https://paramant.app`;

  const nlHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">${isReset ? 'Stel uw nieuwe authenticator-app in' : 'Maak uw Paramant-account af'}</h1>
    ${isReset ? `<div style="background:#FEF3C7;border-left:3px solid #D97706;padding:12px 16px;margin:0 0 20px 0;">
        <p style="margin:0;line-height:1.5;color:#92400E;font-size:14px;"><strong>Authenticator-app losgekoppeld.</strong> Verwijder eerst de oude Paramant-regel uit uw app. Die codes werken niet meer.</p>
      </div>` : ''}
    <p style="margin:0 0 16px 0;line-height:1.6;">${isReset ? 'Uw authenticator-app is losgekoppeld.' : 'Welkom bij Paramant.'} Koppel een authenticator-app of een passkey om ${isReset ? 'uw account weer te gebruiken' : 'uw account af te maken'}. Paramant gebruikt die in plaats van een wachtwoord.</p>
    ${btn(url, isReset ? 'Nieuwe authenticator-app instellen' : 'Account afmaken')}
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:14px;">De link opent een pagina met een QR-code. Scan die met uw authenticator-app (bijvoorbeeld Google Authenticator, Authy of 1Password). U kunt de sleutel ook met de hand invullen.</p>
    <p style="margin:0 0 24px 0;line-height:1.6;color:#475569;font-size:14px;">Deze link werkt <strong>${escHtml(nlValid)}</strong>.</p>
    <p style="margin:0 0 24px 0;line-height:1.6;color:#475569;font-size:13px;">Na het instellen krijgt u 10 back-upcodes. Bewaar die op een veilige plek (wachtwoordbeheerder, of op papier in een la) voor als u uw telefoon kwijtraakt.</p>
    <p style="margin:0 0 8px 0;font-size:13px;color:#64748b;">${isReset ? '<strong>Vroeg u deze reset niet aan?</strong> Mail dan meteen <a href="mailto:hello@paramant.app" style="color:#1D4ED8;">hello@paramant.app</a>.' : '<strong>Niet aangemeld bij Paramant?</strong> Dan kunt u deze mail negeren. Er is pas een account als u het instellen afrondt.'}</p>
  `;

  return bilingualMail({
    subject: isReset ? 'Stel uw nieuwe authenticator-app in voor Paramant' : 'Maak uw Paramant-account af',
    preheader, nlText, enText, nlHtml, enHtml,
    refId: 'setup-' + refIdHash(token),
  });
}

// ── 2. RESET CONFIRMATION EMAIL ───────────────────────────────────────────────
function resetConfirmationEmail({ confirmToken, requestedAt, requestIP }) {
  const url = `${BASE_URL}/auth/reset-confirm/${confirmToken}`;
  const preheader = 'Bevestig dat u een nieuwe authenticator-app wilt koppelen. De link werkt 1 uur.';

  const enText = `Hi,

Someone asked to connect a new authenticator app to your Paramant account.

Was this you? Confirm with the link below. You then get a second email
with a link to set up the new app.

Confirm reset:
${url}

This link works for 1 hour.

Was this not you? Then ignore this email. Nothing changes, and your
current authenticator app keeps working.

Why two emails? Someone who only knows your email address cannot
force a reset this way. They would also need access to your inbox.

Request details:
  Time: ${formatTS(typeof requestedAt === 'number' ? requestedAt : Date.parse(requestedAt))}
  IP:   ${maskIP(requestIP)}

Paramant
https://paramant.app`;

  const enHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Did you ask for a new authenticator app?</h1>
    <p style="margin:0 0 16px 0;line-height:1.6;">Someone asked to connect a new authenticator app to your Paramant account.</p>
    <p style="margin:0 0 16px 0;line-height:1.6;">Was this you? Confirm below. You then get a second email with a link to set up the new app.</p>
    ${btn(url, 'Confirm reset')}
    <p style="margin:0 0 24px 0;line-height:1.6;color:#475569;font-size:14px;">This link works for <strong>1 hour</strong>.</p>
    <div style="background:#F0F9FF;border-left:3px solid #1D4ED8;padding:12px 16px;margin:0 0 24px 0;">
      <p style="margin:0;line-height:1.5;color:#0B3A6A;font-size:14px;"><strong>Was this not you?</strong> Then ignore this email. Nothing changes, and your current authenticator app keeps working.</p>
    </div>
    <hr style="border:none;border-top:1px solid rgba(11,58,106,0.08);margin:24px 0;">
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:13px;">Why two emails? Someone who only knows your email address cannot force a reset this way. They would also need access to your inbox.</p>
    <p style="margin:16px 0 0 0;font-size:12px;color:#94a3b8;font-family:monospace;">
      Time: ${formatTS(typeof requestedAt === 'number' ? requestedAt : Date.parse(requestedAt))}<br>
      IP: ${escHtml(maskIP(requestIP))}
    </p>
  `;

  const when = formatTS(typeof requestedAt === 'number' ? requestedAt : Date.parse(requestedAt));
  const nlText = `Hallo,

Iemand vroeg om uw Paramant-account aan een nieuwe authenticator-app te koppelen.

Was u dat? Bevestig het dan met de link hieronder. Daarna krijgt u een tweede
mail met een link om de nieuwe authenticator-app in te stellen.

Reset bevestigen:
${url}

Deze link werkt 1 uur.

Was u dit niet? Negeer deze mail dan. Er verandert niets en uw huidige
authenticator-app blijft gewoon werken.

Waarom twee mails? Wie alleen uw e-mailadres kent, kan zo geen reset
afdwingen. Daarvoor is ook toegang tot uw inbox nodig.

Tijd: ${when}
IP:   ${maskIP(requestIP)}

Paramant
https://paramant.app`;

  const nlHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Vroeg u om een nieuwe authenticator-app?</h1>
    <p style="margin:0 0 16px 0;line-height:1.6;">Iemand vroeg om uw Paramant-account aan een nieuwe authenticator-app te koppelen.</p>
    <p style="margin:0 0 16px 0;line-height:1.6;">Was u dat? Bevestig het dan hieronder. Daarna krijgt u een tweede mail met een link om de nieuwe authenticator-app in te stellen.</p>
    ${btn(url, 'Reset bevestigen')}
    <p style="margin:0 0 24px 0;line-height:1.6;color:#475569;font-size:14px;">Deze link werkt <strong>1 uur</strong>.</p>
    <div style="background:#F0F9FF;border-left:3px solid #1D4ED8;padding:12px 16px;margin:0 0 24px 0;">
      <p style="margin:0;line-height:1.5;color:#0B3A6A;font-size:14px;"><strong>Niet aangevraagd?</strong> Negeer deze mail. Er verandert niets en uw huidige authenticator-app blijft gewoon werken.</p>
    </div>
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:13px;">Waarom twee mails? Wie alleen uw e-mailadres kent, kan zo geen reset afdwingen. Daarvoor is ook toegang tot uw inbox nodig.</p>
  `;

  return bilingualMail({
    subject: 'Nieuwe authenticator-app bevestigen · Paramant',
    preheader, nlText, enText, nlHtml, enHtml,
    refId: 'reset-confirm-' + refIdHash(confirmToken),
  });
}

// ── 3. WELCOME / API KEY EMAIL ────────────────────────────────────────────────
function welcomeEmail({ apiKey, plan, label, sectors }) {
  const preheader = 'Your Paramant API key is ready. Keep it safe.';
  const masked = apiKey.slice(0, 12) + '...' + apiKey.slice(-4);

  const text = `Hi,

We created your Paramant API key.

Plan:    ${plan}
Label:   ${label || '(unlabeled)'}
Sectors: ${(sectors || []).join(', ') || 'all'}
Key:     ${masked}

The administrator who issued the key gave you the full key separately.

What you can do now:

1. Use the key in the X-Api-Key header when calling the Paramant relay
2. Documentation: https://paramant.app/docs/api
3. Extensions: https://paramant.app/extensions

Storing your key safely:

- Keep it in a password manager, never in plain text
- Do not commit it to source control (.env files leak)
- Replace it straight away if you think someone else has it

Questions? Reply to this email.

Paramant
https://paramant.app`;

  const html = htmlShell(preheader, `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Your Paramant API key is ready</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">An administrator has issued a Paramant API key for your account.</p>
    <table style="border-collapse:collapse;margin:0 0 24px 0;width:100%;">
      <tr><td style="padding:8px 16px 8px 0;color:#64748b;font-family:monospace;font-size:11px;text-transform:uppercase;letter-spacing:0.1em;white-space:nowrap;">Plan</td><td style="padding:8px 0;"><span style="background:rgba(29,78,216,0.08);color:#1D4ED8;padding:2px 8px;font-size:12px;font-family:monospace;">${escHtml(plan)}</span></td></tr>
      <tr><td style="padding:8px 16px 8px 0;color:#64748b;font-family:monospace;font-size:11px;text-transform:uppercase;letter-spacing:0.1em;white-space:nowrap;">Label</td><td style="padding:8px 0;">${label ? escHtml(label) : '<em style="color:#94a3b8;">unlabeled</em>'}</td></tr>
      <tr><td style="padding:8px 16px 8px 0;color:#64748b;font-family:monospace;font-size:11px;text-transform:uppercase;letter-spacing:0.1em;white-space:nowrap;">Sectors</td><td style="padding:8px 0;font-family:monospace;font-size:13px;">${escHtml((sectors || []).join(', ') || 'all')}</td></tr>
      <tr><td style="padding:8px 16px 8px 0;color:#64748b;font-family:monospace;font-size:11px;text-transform:uppercase;letter-spacing:0.1em;white-space:nowrap;">Key (masked)</td><td style="padding:8px 0;font-family:monospace;font-size:13px;color:#0B3A6A;">${masked}</td></tr>
    </table>
    <p style="margin:0 0 24px 0;line-height:1.6;color:#475569;font-size:14px;">The administrator who issued the key gave you the full key separately.</p>
    <h2 style="margin:0 0 12px 0;font-size:14px;font-weight:600;color:#0B3A6A;">What you can do now</h2>
    <ul style="margin:0 0 24px 0;padding-left:20px;line-height:1.8;color:#475569;font-size:14px;">
      <li>Use the key in the <code style="background:#f1f5f9;padding:2px 5px;font-size:12px;">X-Api-Key</code> header when calling the relay</li>
      <li>Documentation: <a href="https://paramant.app/docs/api" style="color:#1D4ED8;">paramant.app/docs/api</a></li>
      <li>Extensions: <a href="https://paramant.app/extensions" style="color:#1D4ED8;">paramant.app/extensions</a></li>
    </ul>
    <hr style="border:none;border-top:1px solid rgba(11,58,106,0.08);margin:24px 0;">
    <h2 style="margin:0 0 12px 0;font-size:14px;font-weight:600;color:#0B3A6A;">Storing your key safely</h2>
    <ul style="margin:0 0 16px 0;padding-left:20px;line-height:1.7;color:#475569;font-size:13px;">
      <li>Keep it in a password manager, never in plain text</li>
      <li>Do not commit it to source control (.env files leak)</li>
      <li>Replace it straight away if you think someone else has it</li>
    </ul>
    <p style="margin:16px 0 0 0;color:#475569;font-size:14px;">Questions? Reply to this email.</p>
  `);

  return {
    ...wrap(text, html, { refId: 'welcome-' + refIdHash(apiKey) }),
    subject: 'Your Paramant API key is ready',
  };
}

// ── 4. BILLING CONFIRMATION ───────────────────────────────────────────────────
// Sent by the admin panel when a plan is set on an account from the inside.
// Every caller of this template is that path, and the note it carries used to
// say the opposite of the truth: that payments were in beta, that the customer
// would be invoiced by hand, that real invoicing was still waiting on Mollie.
// All three were false by September 2026. relay.js POST /v2/billing/checkout
// calls mollie.createPayment against api.mollie.com unconditionally, the
// webhook only grants on a re-fetched status paid (lib/billing.js), and it
// issues a numbered document per payment on its own: lib/invoice.js, series
// PS-YYYY-NNNN, an invoice when a seller VAT number is configured and a payment
// receipt when it is not, plus lib/credit-note.js (CN-YYYY-NNNN) when money
// goes back.
//
// What IS true of THIS mail is the other half: an admin-set plan is not a
// purchase. No payment was taken, so no document is issued for it, and the
// customer should not go looking for one. noPayment says exactly that and
// nothing more.
function billingConfirmationEmail({ planName, period, amountStr, noPayment = true }) {
  const preheader = `Your Paramant plan is now ${planName}.`;
  const periodLabel = period === 'yearly' ? 'Yearly' : period === 'monthly' ? 'Monthly' : 'Admin-provisioned';

  const text = `Hi,

Your Paramant plan has been upgraded.

Plan:    ${planName}
Billing: ${periodLabel}
Amount:  ${amountStr || 'N/A'}
${noPayment ? '\nNote: Paramant set this plan on your account. Nothing was charged for\nit, so this change has no invoice. A plan bought on paramant.app is paid\nthrough Mollie, and every payment gets a numbered invoice or payment\nreceipt that stays on your account page.\n' : ''}
Questions about billing? Reply to this email.

Paramant
https://paramant.app`;

  const html = htmlShell(preheader, `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Plan upgraded to ${planName}</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">Your Paramant plan has been upgraded.</p>
    <table style="border-collapse:collapse;margin:0 0 24px 0;width:100%;">
      <tr><td style="padding:10px 0;border-bottom:1px solid rgba(11,58,106,0.06);color:#64748b;font-size:14px;">Plan</td><td style="padding:10px 0;border-bottom:1px solid rgba(11,58,106,0.06);font-weight:600;text-align:right;"><span style="background:rgba(29,78,216,0.08);color:#1D4ED8;padding:2px 8px;font-size:12px;font-family:monospace;">${planName}</span></td></tr>
      <tr><td style="padding:10px 0;border-bottom:1px solid rgba(11,58,106,0.06);color:#64748b;font-size:14px;">Billing</td><td style="padding:10px 0;border-bottom:1px solid rgba(11,58,106,0.06);font-weight:600;text-align:right;">${periodLabel}</td></tr>
      <tr><td style="padding:10px 0;color:#64748b;font-size:14px;">Amount</td><td style="padding:10px 0;font-weight:700;color:#1D4ED8;text-align:right;">${amountStr || 'N/A'}</td></tr>
    </table>
    ${noPayment ? '<div style="background:rgba(11,58,106,0.04);border-left:3px solid #1D4ED8;padding:12px 16px;margin:24px 0;"><p style="margin:0;line-height:1.5;color:#475569;font-size:13px;"><strong>No payment for this change:</strong> Paramant set this plan on your account, so nothing was charged and this change has no invoice. A plan bought on paramant.app is paid through Mollie, and every payment gets a numbered invoice or payment receipt that stays on your account page.</p></div>' : ''}
    <p style="margin:16px 0 0 0;line-height:1.6;color:#475569;font-size:14px;">Questions about billing? Reply to this email.</p>
  `);

  return {
    ...wrap(text, html, { refId: 'billing-' + Date.now() }),
    subject: `Paramant plan upgraded to ${planName}`,
  };
}

// ── 4b. PER-PRODUCT PLAN CHANGE ───────────────────────────────────────────────
// Sent when an admin sets a SINGLE product's tier (ParaSign or ParaSend) without
// touching the other product or the unified plan. Deliberately carries NO
// billing note of any kind: this is a scoped entitlement change, and the mail
// above is the one that answers for a plan and its money. productName is a
// display name ("ParaSign"), tierName the tier ("Pro"); both are constants
// from the caller.
function productPlanChangeEmail({ productName, tierName }) {
  const safeProduct = escHtml(productName || 'your product');
  const safeTier = escHtml(tierName || '');
  const preheader = `Your ${safeProduct} plan is now ${safeTier}.`;

  const text = `Hi,

Your ${productName} plan has been updated.

Product: ${productName}
Tier:    ${tierName}

Only your ${productName} plan changed. Your other Paramant products
stay as they are.

Questions? Reply to this email.

Paramant
https://paramant.app`;

  const html = htmlShell(preheader, `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">${safeProduct} plan updated to ${safeTier}</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">Your ${safeProduct} plan has been updated.</p>
    <table style="border-collapse:collapse;margin:0 0 24px 0;width:100%;">
      <tr><td style="padding:10px 0;border-bottom:1px solid rgba(11,58,106,0.06);color:#64748b;font-size:14px;">Product</td><td style="padding:10px 0;border-bottom:1px solid rgba(11,58,106,0.06);font-weight:600;text-align:right;">${safeProduct}</td></tr>
      <tr><td style="padding:10px 0;color:#64748b;font-size:14px;">Tier</td><td style="padding:10px 0;font-weight:700;color:#1D4ED8;text-align:right;"><span style="background:rgba(29,78,216,0.08);color:#1D4ED8;padding:2px 8px;font-size:12px;font-family:monospace;">${safeTier}</span></td></tr>
    </table>
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:14px;">Only your ${safeProduct} plan changed. Your other Paramant products stay as they are.</p>
    <p style="margin:16px 0 0 0;line-height:1.6;color:#475569;font-size:14px;">Questions? Reply to this email.</p>
  `);

  return {
    ...wrap(text, html, { refId: 'product-plan-' + Date.now() }),
    subject: `Paramant ${productName} plan updated to ${tierName}`,
  };
}

// ── 5. BILLING CANCELLATION ───────────────────────────────────────────────────
// Dutch first, English below, like the account mails (bilingualMail). The
// cancel button sits on the Dutch /account as much as on /en/account, and the
// mail was English only (fase 1, PLAN-25). `cancelDateNl` is the same day in
// Dutch; a caller that does not pass it gets the English date in both halves.
function billingCancellationEmail({ planName, cancelDate, cancelDateNl }) {
  const dateNl = cancelDateNl || cancelDate;
  const preheader = `Uw ${planName}-plan stopt op ${dateNl}.`;

  const nlText = `Hallo,

Uw Paramant ${planName}-plan is opgezegd.

Stopt op: ${dateNl}

Tot die datum houdt u ${planName}. Daarna gaat uw account terug naar het
Community-plan.

Uw API-sleutel blijft werken. Bestanden die u al verstuurd heeft, blijven
zoals ze zijn. De toegang per sector gaat naar de grenzen van Community.

Toch niet opzeggen? Beantwoord deze mail voor de einddatum, dan zetten we het terug.

Paramant
https://paramant.app`;

  const enText = `Hi,

Your Paramant ${planName} plan has been cancelled.

Ends on: ${cancelDate}

You keep ${planName} until that date. After that, your account goes
back to the Community plan.

Your API key keeps working. Files you already sent stay as they are.
Sector access moves to the Community limits.

Changed your mind? Reply to this email before the end date and we will switch it back.

Paramant
https://paramant.app`;

  const box = (label, value) => `
    <div style="background:#F8FAFC;border:1px solid rgba(11,58,106,0.1);padding:16px 20px;margin:0 0 24px 0;">
      <p style="margin:0 0 6px 0;font-family:monospace;font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:0.1em;">${label}</p>
      <p style="margin:0;font-size:16px;font-weight:500;color:#0B3A6A;">${value}</p>
    </div>`;

  const nlHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Opzegging gepland</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">Uw Paramant ${planName}-plan is opgezegd.</p>
    ${box('Stopt op', dateNl)}
    <ul style="margin:0 0 24px 0;padding-left:20px;line-height:1.8;color:#475569;font-size:14px;">
      <li>Tot die datum houdt u <strong>${planName}</strong></li>
      <li>Daarna gaat uw account terug naar het <strong>Community</strong>-plan</li>
      <li>Uw API-sleutel blijft werken</li>
      <li>Bestanden die u al verstuurd heeft, blijven zoals ze zijn</li>
      <li>De toegang per sector gaat naar de grenzen van Community</li>
    </ul>
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:14px;">Toch niet opzeggen? Beantwoord deze mail voor de einddatum, dan zetten we het terug.</p>
  `;

  const enHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Cancellation scheduled</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">Your Paramant ${planName} plan has been cancelled.</p>
    ${box('Ends on', cancelDate)}
    <ul style="margin:0 0 24px 0;padding-left:20px;line-height:1.8;color:#475569;font-size:14px;">
      <li>You keep <strong>${planName}</strong> until that date</li>
      <li>After that, your account goes back to the <strong>Community</strong> plan</li>
      <li>Your API key keeps working</li>
      <li>Files you already sent stay as they are</li>
      <li>Sector access moves to the Community limits</li>
    </ul>
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:14px;">Changed your mind? Reply to this email before the end date and we will switch it back.</p>
  `;

  return bilingualMail({
    subject: 'Uw Paramant-plan is opgezegd / Your Paramant plan has been cancelled',
    preheader, nlText, enText, nlHtml, enHtml,
    refId: 'cancel-' + Date.now(),
  });
}

// ── 5b. KEY DISABLED ──────────────────────────────────────────────────────────
// What disable-key mails. It used to send the cancellation mail above ("your
// plan ends on ..., your API key continues to work") on the very moment the key
// stopped working (ADMIN-24). This one says what happened.
function keyDisabledEmail({ disabledAt }) {
  const preheader = 'Your Paramant API key has been disabled.';
  const text = `Hi,

We disabled your Paramant API key on ${disabledAt}. From now on it no
longer works on any Paramant server.

Files you sent before are not affected. If you did not expect this,
reply to this email and we will look into it.

Paramant
https://paramant.app`;
  const html = htmlShell(preheader, `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Your API key has been disabled</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">We disabled your Paramant API key on <strong>${disabledAt}</strong>. From now on it no longer works on any Paramant server.</p>
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:14px;">Files you sent before are not affected. If you did not expect this, reply to this email and we will look into it.</p>
  `);
  return {
    ...wrap(text, html, { refId: 'disabled-' + Date.now() }),
    subject: 'Your Paramant API key has been disabled',
  };
}

// ── 6. ACCOUNT DELETION ───────────────────────────────────────────────────────
// This mail used to say that account records were retained and that erasure was
// a separate request to privacy@. That was true while deletion only revoked the
// key and cleared Redis, leaving the email address in users.json on every sector
// (audit finding 5 of 2026-07-21). Deletion now erases the personal data itself,
// so the old wording understated what happened, and a mail that undersells an
// erasure is as untrue as one that oversells it.
function accountDeletionEmail({ email, deletedAt, reason }) {
  const preheader = 'Uw Paramant-account is gedeactiveerd.';
  const dateStr = formatTS(typeof deletedAt === 'number' ? deletedAt : Date.parse(deletedAt));

  const enText = `Hi,

Your Paramant account (${email}) was deactivated on ${dateStr}.

What this means:
- The API key no longer works
- Active sessions have ended
- The link with your authenticator app has been removed
- Your personal data has been erased from our systems
- Billing records are kept for as long as tax law requires

Questions about what was kept and why? Email privacy@paramant.app.

Reason: ${reason || 'not specified'}

Was this a mistake, or do you want access again? Email
support@paramant.app.

Paramant
https://paramant.app`;

  const enHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Account deactivated</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">Your Paramant account (${escHtml(email)}) was deactivated on <strong>${dateStr}</strong>.</p>
    <h2 style="margin:24px 0 12px 0;font-size:14px;font-weight:600;color:#0B3A6A;">What this means</h2>
    <ul style="margin:0 0 24px 0;padding-left:20px;line-height:1.8;color:#475569;font-size:14px;">
      <li>The API key no longer works</li>
      <li>Active sessions have ended</li>
      <li>The link with your authenticator app has been removed</li>
      <li>Your personal data has been erased from our systems</li>
      <li>Billing records are kept for as long as tax law requires</li>
    </ul>
    <p style="margin:0 0 20px 0;line-height:1.6;color:#475569;font-size:14px;">Questions about what was kept and why? Email <a href="mailto:privacy@paramant.app" style="color:#1D4ED8;">privacy@paramant.app</a>.</p>
    <div style="background:#F8FAFC;border:1px solid rgba(11,58,106,0.1);padding:12px 16px;margin:0 0 24px 0;">
      <p style="margin:0;font-size:13px;color:#475569;"><strong>Reason:</strong> ${reason ? escHtml(reason) : 'not specified'}</p>
    </div>
    <p style="margin:16px 0 0 0;line-height:1.6;color:#475569;font-size:14px;">Was this a mistake, or do you want access again? Email <a href="mailto:support@paramant.app" style="color:#1D4ED8;">support@paramant.app</a>.</p>
  `;

  const nlText = `Hallo,

Uw Paramant-account (${email}) is op ${dateStr} gedeactiveerd.

Wat dit betekent:
- De API-sleutel werkt niet meer
- Actieve sessies zijn beëindigd
- De koppeling met uw authenticator-app is verwijderd
- Uw persoonsgegevens zijn uit onze systemen gewist
- Betaalgegevens bewaren wij zo lang als de belastingwet vraagt

Vragen over wat er bewaard is en waarom? Mail privacy@paramant.app.

Reden: ${reason || 'niet opgegeven'}

Was dit een vergissing, of wilt u weer toegang? Mail support@paramant.app.

Paramant
https://paramant.app`;

  const nlHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Account gedeactiveerd</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">Uw Paramant-account (${escHtml(email)}) is op <strong>${dateStr}</strong> gedeactiveerd.</p>
    <ul style="margin:0 0 24px 0;padding-left:20px;line-height:1.8;color:#475569;font-size:14px;">
      <li>De API-sleutel werkt niet meer</li>
      <li>Actieve sessies zijn beëindigd</li>
      <li>De koppeling met uw authenticator-app is verwijderd</li>
      <li>Uw persoonsgegevens zijn uit onze systemen gewist</li>
      <li>Betaalgegevens bewaren wij zo lang als de belastingwet vraagt</li>
    </ul>
    <p style="margin:0 0 20px 0;line-height:1.6;color:#475569;font-size:14px;">Vragen over wat er bewaard is en waarom? Mail <a href="mailto:privacy@paramant.app" style="color:#1D4ED8;">privacy@paramant.app</a>.</p>
    <p style="margin:0 0 20px 0;font-size:13px;color:#475569;"><strong>Reden:</strong> ${reason ? escHtml(reason) : 'niet opgegeven'}</p>
    <p style="margin:0;line-height:1.6;color:#475569;font-size:14px;">Was dit een vergissing, of wilt u weer toegang? Mail <a href="mailto:support@paramant.app" style="color:#1D4ED8;">support@paramant.app</a>.</p>
  `;

  return bilingualMail({
    subject: 'Uw Paramant-account is gedeactiveerd',
    preheader, nlText, enText, nlHtml, enHtml,
    refId: 'deletion-' + Date.now(),
  });
}

// ── SIGNUP VERIFICATION EMAIL ────────────────────────────────────────────────
function signupVerificationEmail({ email, token, requestedAt, requestIP }) {
  const url = `${BASE_URL}/api/user/signup/verify/${token}`;
  const dateStr = formatTS(requestedAt);
  const maskedIp = maskIP(requestIP);

  const preheader = 'Bevestig uw e-mailadres om uw Paramant-account te activeren.';
  const enText = [
    'Verify your Paramant account',
    '',
    `You asked for a Paramant account for ${email}.`,
    `Open the link below to confirm your email address and activate your account:`,
    '',
    url,
    '',
    'This link works for 24 hours. Did you not ask for this? Then you can ignore this email.',
    '',
    `Requested: ${dateStr}${requestIP ? ' · IP: ' + maskedIp : ''}`,
    '',
    'Paramant',
  ].join('\n');

  const enHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Confirm your email address</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">
      You asked for a Paramant account for <strong>${escHtml(email)}</strong>. Click the button to confirm your email address and activate your account.
    </p>
    <div style="text-align:center;margin:0 0 28px 0;">
      <a href="${url}" style="display:inline-block;background:#1D4ED8;color:#ffffff;font-size:15px;font-weight:600;padding:14px 32px;border-radius:6px;text-decoration:none;letter-spacing:0.01em;">Confirm email address</a>
    </div>
    <p style="margin:0 0 8px 0;font-size:13px;color:#64748B;">
      Or copy this link into your browser:<br>
      <a href="${url}" style="color:#1D4ED8;word-break:break-all;">${url}</a>
    </p>
    <div style="background:#F8FAFC;border:1px solid rgba(11,58,106,0.08);padding:12px 16px;margin:24px 0 0 0;border-radius:4px;">
      <p style="margin:0;font-size:12px;color:#94A3B8;line-height:1.6;">
        This link works for <strong>24 hours</strong>. Did you not ask for a Paramant account? Then ignore this email. No account will be created.
        <br>Requested ${dateStr}${requestIP ? ' · IP: ' + escHtml(maskedIp) : ''}.
      </p>
    </div>
  `;

  const nlText = [
    'Bevestig uw Paramant-account',
    '',
    `U vroeg een account aan voor ${email}.`,
    'Open de link hieronder om uw e-mailadres te bevestigen en uw account te activeren:',
    '',
    url,
    '',
    'Deze link werkt 24 uur. Vroeg u dit niet aan? Dan kunt u deze mail negeren.',
    '',
    `Aangevraagd: ${dateStr}${requestIP ? ' · IP: ' + maskedIp : ''}`,
    '',
    'Paramant',
  ].join('\n');

  const nlHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Bevestig uw e-mailadres</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">
      U vroeg een Paramant-account aan voor <strong>${escHtml(email)}</strong>. Klik op de knop om uw e-mailadres te bevestigen en uw account te activeren.
    </p>
    <div style="text-align:center;margin:0 0 28px 0;">
      <a href="${url}" style="display:inline-block;background:#1D4ED8;color:#ffffff;font-size:15px;font-weight:600;padding:14px 32px;border-radius:6px;text-decoration:none;letter-spacing:0.01em;">E-mailadres bevestigen</a>
    </div>
    <p style="margin:0 0 8px 0;font-size:13px;color:#64748B;">
      Of kopieer deze link naar uw browser:<br>
      <a href="${url}" style="color:#1D4ED8;word-break:break-all;">${url}</a>
    </p>
    <p style="margin:16px 0 0 0;font-size:12px;color:#94A3B8;line-height:1.6;">
      Deze link werkt <strong>24 uur</strong>. Vroeg u geen Paramant-account aan? Negeer deze mail dan. Er komt dan geen account.
      <br>Aangevraagd ${dateStr}${requestIP ? ' · IP: ' + escHtml(maskedIp) : ''}.
    </p>
  `;

  return bilingualMail({
    subject: 'Bevestig uw Paramant-account',
    preheader, nlText, enText, nlHtml, enHtml,
    refId: 'verify-' + refIdHash(token),
  });
}

// ── DUPLICATE SIGNUP ATTEMPT NOTICE ─────────────────────────────────────────
// Sent to the existing account owner when someone tries to sign up using
// their email. Required so the signup endpoint does the same kind of work
// (Redis write + outbound mail) on the existing-email branch as on the
// new-email branch, removing the ~50ms-vs-~500ms enumeration side-channel.
function duplicateSignupAttemptEmail({ email, requestedAt, requestIP }) {
  const dateStr = formatTS(requestedAt);
  const maskedIp = maskIP(requestIP);
  const loginUrl = `${BASE_URL}/auth/login`;

  const preheader = 'Iemand probeerde een Paramant-account te maken met uw e-mailadres.';
  const enText = [
    'Signup attempt on your Paramant account',
    '',
    `Someone just tried to create a Paramant account with ${email}.`,
    'Your existing account was not changed and no new account was created.',
    '',
    'Were you trying to sign in? Use the login page:',
    loginUrl,
    '',
    'Was this not you? Then ignore this email. We limit how often this can be tried.',
    '',
    `Attempt at: ${dateStr}${requestIP ? ' . IP: ' + maskedIp : ''}`,
    '',
    'Paramant',
  ].join('\n');

  const enHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Signup attempt on your account</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">
      Someone just tried to create a Paramant account with <strong>${escHtml(email)}</strong>. Your existing account was not changed and no new account was created.
    </p>
    <p style="margin:0 0 20px 0;line-height:1.6;">
      Were you trying to sign in? Use the login page:
    </p>
    <div style="text-align:center;margin:0 0 28px 0;">
      <a href="${loginUrl}" style="display:inline-block;background:#1D4ED8;color:#ffffff;font-size:15px;font-weight:600;padding:14px 32px;border-radius:6px;text-decoration:none;letter-spacing:0.01em;">Sign in to Paramant</a>
    </div>
    <div style="background:#F8FAFC;border:1px solid rgba(11,58,106,0.08);padding:12px 16px;margin:24px 0 0 0;border-radius:4px;">
      <p style="margin:0;font-size:12px;color:#94A3B8;line-height:1.6;">
        Was this not you? Then ignore this email. We limit how often this can be tried, and no account was created.
        <br>Attempt at ${dateStr}${requestIP ? ' . IP: ' + escHtml(maskedIp) : ''}.
      </p>
    </div>
  `;

  const nlText = [
    'Aanmeldpoging op uw Paramant-account',
    '',
    `Iemand probeerde net een Paramant-account te maken met ${email}.`,
    'Uw bestaande account is niet veranderd en er is geen nieuw account gemaakt.',
    '',
    'Wilde u zelf inloggen? Gebruik dan de inlogpagina:',
    loginUrl,
    '',
    'Was u dit niet? Negeer deze mail dan. Wij beperken hoe vaak dit kan.',
    '',
    `Poging op: ${dateStr}${requestIP ? ' . IP: ' + maskedIp : ''}`,
    '',
    'Paramant',
  ].join('\n');

  const nlHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Aanmeldpoging op uw account</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">
      Iemand probeerde net een Paramant-account te maken met <strong>${escHtml(email)}</strong>. Uw bestaande account is niet veranderd en er is geen nieuw account gemaakt.
    </p>
    <p style="margin:0 0 20px 0;line-height:1.6;">Wilde u zelf inloggen? Gebruik dan de inlogpagina:</p>
    <div style="text-align:center;margin:0 0 28px 0;">
      <a href="${loginUrl}" style="display:inline-block;background:#1D4ED8;color:#ffffff;font-size:15px;font-weight:600;padding:14px 32px;border-radius:6px;text-decoration:none;letter-spacing:0.01em;">Inloggen bij Paramant</a>
    </div>
    <p style="margin:0;font-size:12px;color:#94A3B8;line-height:1.6;">
      Was u dit niet? Negeer deze mail dan. Wij beperken hoe vaak dit kan, en er is geen account gemaakt.
      <br>Poging op ${dateStr}${requestIP ? ' . IP: ' + escHtml(maskedIp) : ''}.
    </p>
  `;

  return bilingualMail({
    subject: 'Aanmeldpoging op uw Paramant-account',
    preheader, nlText, enText, nlHtml, enHtml,
    refId: 'dup-' + Date.now().toString(36),
  });
}

// ── BACKUP CODES RESET NOTIFICATION ─────────────────────────────────────────
function backupCodesResetEmail({ email, requestedAt }) {
  const dateStr = formatTS(requestedAt);
  const preheader = 'Your Paramant backup codes were reset. Please make new ones.';

  const text = [
    'Security notification: Paramant backup codes reset',
    '',
    `This is a security notification for ${email}.`,
    '',
    'During an internal security check we found that backup codes were stored',
    'in a way that did not meet our zero-knowledge standard. We fixed this and,',
    'to be safe, cancelled the affected backup codes.',
    '',
    'Your authenticator app keeps working as normal.',
    'Only your offline backup codes were affected.',
    '',
    'What to do:',
    '  Sign in and create a new set of backup codes.',
    '  Keep them in your password manager.',
    '',
    `Detected: ${dateStr}`,
    'We found no sign that anyone else got in. We send this to be safe.',
    '',
    'Questions: privacy@paramant.app',
    '',
    'Paramant',
  ].join('\n');

  const html = htmlShell(preheader, `
    <div style="background:#FEF2F2;border:1px solid #FECACA;padding:16px;border-radius:4px;margin:0 0 24px 0;">
      <p style="margin:0;font-size:13px;font-weight:600;color:#991B1B;">Security notification</p>
    </div>
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Backup codes reset</h1>
    <p style="margin:0 0 16px 0;line-height:1.6;">
      During an internal security check we found that your backup codes were stored in a way that did not meet our zero-knowledge standard.
      We fixed this and, to be safe, cancelled the affected codes.
    </p>
    <p style="margin:0 0 16px 0;line-height:1.6;">
      <strong>Your authenticator app keeps working as normal.</strong> Only your offline backup codes were affected.
    </p>
    <div style="background:#F8FAFC;border:1px solid rgba(11,58,106,0.1);padding:16px;margin:0 0 24px 0;border-radius:4px;">
      <p style="margin:0 0 8px 0;font-weight:600;color:#0B3A6A;">What to do</p>
      <p style="margin:0;color:#475569;font-size:14px;line-height:1.6;">Sign in and create a new set of backup codes. Keep them in your password manager.</p>
    </div>
    <div style="text-align:center;margin:0 0 24px 0;">
      <a href="${BASE_URL}/account" style="display:inline-block;background:#1D4ED8;color:#ffffff;font-size:15px;font-weight:600;padding:14px 32px;border-radius:6px;text-decoration:none;">Go to account</a>
    </div>
    <div style="border-top:1px solid rgba(11,58,106,0.08);padding-top:16px;margin-top:8px;">
      <p style="margin:0;font-size:12px;color:#94A3B8;line-height:1.6;">
        Detected ${formatTS(requestedAt)}. We found no sign that anyone else got in. We send this to be safe.
        Questions: <a href="mailto:privacy@paramant.app" style="color:#1D4ED8;">privacy@paramant.app</a>
      </p>
    </div>
  `);

  return { ...wrap(text, html, { refId: 'backup-reset-' + requestedAt }), subject: 'Your Paramant backup codes were reset: please make new ones' };
}

// ── SEND HELPER ───────────────────────────────────────────────────────────────
// ── PARASIGN ONBOARDING (NL) ──────────────────────────────────────────────────
// Onboarding for the ParaSign /v1 signing API. Sent by an admin after the
// `parasign` grant is toggled on. Mirrors welcomeEmail's security posture: only
// a MASKED key appears in the body -- the full key was issued separately -- so
// no secret lands in the mailbox or the Resend logs. Content is Dutch (NL).
function parasignOnboardingEmail({ apiKey, plan, label, enabled = true }) {/*MARK:parasign_tpl*/
  const preheader = 'Uw ParaSign-API staat aan. Zo ondertekent u uw eerste document.';
  const masked = apiKey.slice(0, 12) + '...' + apiKey.slice(-4);
  const docsUrl = `${BASE_URL}/docs`;

  const text = `Hallo,

De ParaSign-API voor ondertekenen (/v1) staat nu aan voor uw account.

Plan:        ${plan}
Label:       ${label || '(geen label)'}
API-sleutel: ${masked}

De beheerder heeft u de volledige sleutel apart gegeven.

Aan de slag:

1. Zet uw sleutel in de X-Api-Key-header bij elke aanroep van de ParaSign-API
2. Documentatie: ${docsUrl}
3. De ParaSign-endpoints staan onder /v1 op de Paramant-relay

Uw sleutel veilig bewaren:

- Bewaar hem in een wachtwoordbeheerder, nooit als gewone tekst
- Zet hem niet in versiebeheer (.env-bestanden lekken)
- Vervang hem meteen als u denkt dat iemand anders hem kent

Vragen? Antwoord gewoon op deze mail.

Paramant
${BASE_URL}`;

  const html = htmlShell(preheader, `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Uw ParaSign-API staat aan</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">Een beheerder heeft de ParaSign-API voor ondertekenen (<code style="background:#f1f5f9;padding:2px 5px;font-size:12px;">/v1</code>) voor uw account aangezet.</p>
    <table style="border-collapse:collapse;margin:0 0 24px 0;width:100%;">
      <tr><td style="padding:8px 16px 8px 0;color:#64748b;font-family:monospace;font-size:11px;text-transform:uppercase;letter-spacing:0.1em;white-space:nowrap;">Plan</td><td style="padding:8px 0;"><span style="background:rgba(29,78,216,0.08);color:#1D4ED8;padding:2px 8px;font-size:12px;font-family:monospace;">${escHtml(plan)}</span></td></tr>
      <tr><td style="padding:8px 16px 8px 0;color:#64748b;font-family:monospace;font-size:11px;text-transform:uppercase;letter-spacing:0.1em;white-space:nowrap;">Label</td><td style="padding:8px 0;">${label ? escHtml(label) : '<em style="color:#94a3b8;">geen label</em>'}</td></tr>
      <tr><td style="padding:8px 16px 8px 0;color:#64748b;font-family:monospace;font-size:11px;text-transform:uppercase;letter-spacing:0.1em;white-space:nowrap;">API-sleutel</td><td style="padding:8px 0;font-family:monospace;font-size:13px;color:#0B3A6A;">${masked}</td></tr>
    </table>
    <p style="margin:0 0 24px 0;line-height:1.6;color:#475569;font-size:14px;">De beheerder die de sleutel uitgaf, heeft u de volledige sleutel apart gegeven.</p>
    <h2 style="margin:0 0 12px 0;font-size:14px;font-weight:600;color:#0B3A6A;">Aan de slag</h2>
    <ul style="margin:0 0 24px 0;padding-left:20px;line-height:1.8;color:#475569;font-size:14px;">
      <li>Zet uw sleutel in de <code style="background:#f1f5f9;padding:2px 5px;font-size:12px;">X-Api-Key</code>-header bij elke aanroep</li>
      <li>De ParaSign-endpoints staan onder <code style="background:#f1f5f9;padding:2px 5px;font-size:12px;">/v1</code> op de relay</li>
    </ul>
    ${btn(docsUrl, 'Bekijk de documentatie')}
    <hr style="border:none;border-top:1px solid rgba(11,58,106,0.08);margin:24px 0;">
    <h2 style="margin:0 0 12px 0;font-size:14px;font-weight:600;color:#0B3A6A;">Uw sleutel veilig bewaren</h2>
    <ul style="margin:0 0 16px 0;padding-left:20px;line-height:1.7;color:#475569;font-size:13px;">
      <li>Bewaar hem in een wachtwoordbeheerder, nooit als gewone tekst</li>
      <li>Zet hem niet in versiebeheer (.env-bestanden lekken)</li>
      <li>Vervang hem meteen als u denkt dat iemand anders hem kent</li>
    </ul>
    <p style="margin:16px 0 0 0;color:#475569;font-size:14px;">Vragen? Antwoord gewoon op deze mail.</p>
  `);

  return {
    ...wrap(text, html, { refId: 'parasign-' + refIdHash(apiKey) }),
    subject: 'Uw ParaSign-API staat aan',
  };
}

// The invitation to sign, and the same mail sent a second time on request.
//
// WHAT THIS MAIL MAY NOT CARRY, AND WHY THE RULE IS ABSOLUTE.
// A signing link has two halves. Everything before the '#' names the request;
// the fragment after it IS the AES key to the document. This message is posted
// to a mail provider incorporated in the United States, so a fragment reaching
// this function would put the decryption key, the address of the ciphertext and
// the recipient in one American mailbox. Six sentences on paramant.app promise
// that no US party ever holds a key. So the mail carries the notice and never
// the key: the sender passes the opening link on over a channel they choose.
//
// The filename is out for the same reason. "opzegging-huurcontract.pdf" is the
// content, not a label for it, and /dpa promises filenames are not stored or
// handled in readable form. The recipient reads the name once the link has
// opened the document in their own browser.
//
// SINCE 2026-10-04: HALF A KEY, NEVER A KEY. A link that only named the request
// meant the invitee could not see the document without a second link from the
// sender, and a customer's counterparty then signed blind or gave up. So the
// sender's browser splits the document key in two: A xor B = K. The mail link
// carries A ('#ks=v1.<43>'), the relay keeps B next to the ciphertext and
// releases it only to the invited mailbox after it signs in. The mail provider
// holds A and no ciphertext; the relay holds B and the ciphertext; neither can
// open the document, and the site's promise that no US party holds a key
// stays true. A whole key ('#doc=') is still cut off below, whatever happens
// upstream.
function signingInviteEmail({ inviteUrl, recipientLabel, senderLabel, expiresAt, subject, message, envelopeId, partyIndex, lang, asksParaaf }) {
  // The last gate before the mail provider, and the one that holds even when
  // the two in front of it are wrong. Only a key SHARE survives; any other
  // fragment (a whole '#doc=' key above all) is cut off here, again.
  const [beforeHash, fragment] = String(inviteUrl || '').split('#');
  const share = /^ks=v1\.[A-Za-z0-9_-]{43}$/.test(fragment || '') ? '#' + fragment : '';
  const noticeUrl = beforeHash + share;
  const opensDocument = !!share;
  // The paraaf is only promised when the sender asked for one: a request field
  // with all_pages (retest 04-10). Without it the mail names the signature only.
  const paraaf = !!asksParaaf;
  // Dutch first with the English underneath, because the sender does not know
  // which language the recipient reads. A caller that does know passes
  // lang 'nl' or 'en' and gets that one language only.
  const langs = lang === 'nl' ? ['nl'] : lang === 'en' ? ['en'] : ['nl', 'en'];
  const DEFAULT_SUBJECT = { nl: 'Verzoek om te ondertekenen', en: 'Signature requested' };
  const safeSubject = String(subject || '').trim().slice(0, 140)
    || langs.map((l) => DEFAULT_SUBJECT[l]).join(' / ');
  const expiryTs = expiresAt ? formatTS(expiresAt) : '';
  const note = String(message || '').trim().slice(0, 1000);
  const W = {
    nl: {
      greeting: recipientLabel ? `Beste ${recipientLabel},` : 'Beste,',
      sender: senderLabel || 'Een Paramant-gebruiker',
      asks: 'heeft u gevraagd een document te bekijken en te ondertekenen.',
      carries: opensDocument
        ? `Log in, dan opent de link het document in uw browser. U leest het, zet uw ${paraaf ? 'paraaf en handtekening' : 'handtekening'} en bent klaar. Zonder inloggen opent de link niets.`
        : 'Deze link opent het verzoek, maar niet het document. De sleutel van het document staat bewust niet in deze mail. Hebt u een eerdere uitnodiging voor dit verzoek? Gebruik dan de link uit die mail. Die opent het document wel. Lukt dat niet? Vraag de afzender dan om de link opnieuw te sturen.',
      open: opensDocument ? 'Open het document' : 'Open het verzoek',
      fromSender: 'Bericht van de afzender:',
      signIn: 'Log in met het e-mailadres waarop u bent uitgenodigd. Stuur de link niet door.',
      closes: `Ondertekenen kan tot ${expiryTs || '7 dagen na het aanmaken'}.`,
      heading: 'Verzoek om te ondertekenen',
      pre: 'Er wacht een document op uw handtekening in Paramant.',
    },
    en: {
      greeting: recipientLabel ? `Hi ${recipientLabel},` : 'Hi,',
      sender: senderLabel || 'A Paramant user',
      asks: 'has asked you to review and sign a document.',
      carries: opensDocument
        ? `Sign in and the link opens the document in your browser. Read it, ${paraaf ? 'add your initials and signature' : 'add your signature'}, and you are done. Without signing in, the link opens nothing.`
        : 'This link opens the request, but not the document. The document key is deliberately not in this email. Do you have an earlier invitation for this request? Use the link from that email. That one does open the document. Otherwise, ask the sender to send you the link again.',
      open: opensDocument ? 'Open the document' : 'Open the request',
      fromSender: 'Message from the sender:',
      signIn: 'Sign in with the email address this invitation went to. Do not forward the link.',
      closes: `You can sign until ${expiryTs || '7 days after the request was made'}.`,
      heading: 'Signature requested',
      pre: 'A document is waiting for your signature in Paramant.',
    },
  };
  const textBlock = (w) => `${w.greeting}

${w.sender} ${w.asks}
${w.carries}

${w.open}:
${noticeUrl}

${note ? `${w.fromSender}\n${note}\n\n` : ''}${w.signIn}
${w.closes}`;
  const text = langs.map((l) => textBlock(W[l])).join('\n\n---\n\n') + `

Paramant
${BASE_URL}`;
  const htmlBlock = (w, first) => `
    <h1 style="margin:${first ? '0' : '32px'} 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">${escHtml(w.heading)}</h1>
    <p style="margin:0 0 16px 0;line-height:1.6;">${escHtml(w.greeting)}</p>
    <p style="margin:0 0 16px 0;line-height:1.6;"><strong>${escHtml(w.sender)}</strong> ${escHtml(w.asks)}</p>
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:14px;">${escHtml(w.carries)}</p>
    ${note && first ? `<div style="margin:20px 0;padding:14px 16px;background:#F8FAFC;border:1px solid #E2E8F0;line-height:1.6;color:#334155;">${escHtml(note).replace(/\n/g, '<br>')}</div>` : ''}
    ${btn(noticeUrl, escHtml(w.open))}
    <p style="margin:20px 0 8px 0;line-height:1.6;color:#92400E;font-size:13px;"><strong>${escHtml(w.signIn)}</strong></p>
    <p style="margin:0;color:#64748b;font-size:12px;">${escHtml(w.closes)}</p>`;
  const html = htmlShell(langs.map((l) => W[l].pre).join(' '),
    langs.map((l, i) => htmlBlock(W[l], i === 0)).join('\n    <hr style="margin:32px 0 0 0;border:0;border-top:1px solid #E2E8F0;">'),
    langs[0]);
  return {
    ...wrap(text, html, { refId: 'sign-' + refIdHash(`${envelopeId}:${partyIndex}`) }),
    subject: safeSubject,
  };
}

// To the person who sent a document for signing, when somebody else signs it.
// A count and a link, nothing else: no file name and no party names, because
// those would travel to the mail provider for no gain, and the dashboard
// behind the link shows both to the one person entitled to them. Dutch first
// with the English underneath, like the invitation: the sender's language is
// not stored with the envelope.
//
// When everyone has signed, the button opens the finished document itself
// (resultUrl, an opaque one-off reference from lib/sign-notify.js, never the
// envelope id). Without one it falls back to the dashboard.
function signatureReceivedEmail({ signedCount, partyCount, complete, envelopeId, resultUrl }) {
  const n = Math.max(0, parseInt(signedCount, 10) || 0);
  const m = Math.max(1, parseInt(partyCount, 10) || 1);
  const safeResult = complete && /^https:\/\/[^\s#]+\/co-sign\?result=[A-Za-z0-9_-]{43}$/.test(String(resultUrl || '')) ? String(resultUrl) : '';
  const dashUrl = safeResult || `${BASE_URL}/dashboard`;
  const heeft = n === 1 ? 'heeft' : 'hebben';
  const has = n === 1 ? 'has' : 'have';
  const W = {
    nl: complete ? {
      heading: 'Iedereen heeft getekend',
      line: m === 1 ? 'De ondertekenaar heeft uw document getekend.' : `Alle ${m} ondertekenaars hebben uw document getekend.`,
      next: safeResult
        ? 'Open het document met alle handtekeningen en download het bewijs. Log in met dit account. De link werkt 30 dagen.'
        : 'Het getekende document en het bewijs staan bij uw documenten.',
      pre: 'Uw document is door iedereen ondertekend.',
      subject: 'Iedereen heeft getekend',
    } : {
      heading: 'Er is getekend',
      line: `${n} van de ${m} ondertekenaars ${heeft} nu getekend.`,
      next: 'U krijgt weer bericht als de volgende tekent.',
      pre: `${n} van de ${m} ondertekenaars ${heeft} getekend.`,
      subject: `Er is getekend (${n} van ${m})`,
    },
    en: complete ? {
      heading: 'Everyone has signed',
      line: m === 1 ? 'The signer has signed your document.' : `All ${m} signers have signed your document.`,
      next: safeResult
        ? 'Open the document with every signature and download the proof. Sign in with this account. The link works for 30 days.'
        : 'The signed document and its proof are with your documents.',
      pre: 'Your document has been signed by everyone.',
      subject: 'Everyone has signed',
    } : {
      heading: 'Someone signed',
      line: `${n} of ${m} signers ${has} now signed.`,
      next: 'We will let you know again when the next person signs.',
      pre: `${n} of ${m} signers ${has} signed.`,
      subject: `Someone signed (${n} of ${m})`,
    },
  };
  const open = safeResult
    ? { nl: 'Open het getekende document', en: 'Open the signed document' }
    : { nl: 'Naar mijn documenten', en: 'Go to my documents' };
  const textBlock = (l) => `${W[l].heading}

${W[l].line}
${W[l].next}

${open[l]}:
${dashUrl}`;
  const text = `${textBlock('nl')}\n\n---\n\n${textBlock('en')}

Paramant
${BASE_URL}`;
  const htmlBlock = (l, first) => `
    <h1 style="margin:${first ? '0' : '32px'} 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">${escHtml(W[l].heading)}</h1>
    <p style="margin:0 0 16px 0;line-height:1.6;">${escHtml(W[l].line)}</p>
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:14px;">${escHtml(W[l].next)}</p>
    ${btn(dashUrl, escHtml(open[l]))}`;
  const html = htmlShell(`${W.nl.pre} ${W.en.pre}`,
    htmlBlock('nl', true) + '\n    <hr style="margin:32px 0 0 0;border:0;border-top:1px solid #E2E8F0;">' + htmlBlock('en', false),
    'nl');
  return {
    ...wrap(text, html, { refId: 'signed-' + refIdHash(`${envelopeId}:${n}`) }),
    subject: `${W.nl.subject} / ${W.en.subject}`,
  };
}

// To an invited party, when the last signature has landed (acceptatie r4,
// Nieuw 1). The sender's mail carries a result link; this one cannot: the link
// that opens the document for this party holds half of the document key and
// was never kept on a server. Their own invitation link opens the finished
// document, so the mail says to use that. No file name, no names, no
// envelope id, like every mail in this family.
function everyoneSignedPartyEmail({ partyCount, envelopeId }) {
  const m = Number.isInteger(partyCount) && partyCount > 1 ? partyCount : null;
  const W = {
    nl: { heading: 'Iedereen heeft getekend', line: m ? `Alle ${m} ondertekenaars hebben het document getekend dat u ook tekende.` : 'Iedereen heeft het document getekend dat u ook tekende.',
      next: 'Open de link uit uw uitnodiging en log in met dit e-mailadres. Daar downloadt u het complete document met alle handtekeningen en het bewijs.', pre: 'Het document is door iedereen ondertekend.', subject: 'Iedereen heeft getekend' },
    en: { heading: 'Everyone has signed', line: m ? `All ${m} signers have now signed the document you signed.` : 'Everyone has now signed the document you signed.',
      next: 'Open the link from your invitation and sign in with this email address. There you can download the complete document with every signature, and the proof.', pre: 'The document has been signed by everyone.', subject: 'Everyone has signed' },
  };
  const textBlock = (l) => `${W[l].heading}

${W[l].line}
${W[l].next}`;
  const text = `${textBlock('nl')}\n\n---\n\n${textBlock('en')}

Paramant
${BASE_URL}`;
  const htmlBlock = (l, first) => `
    <h1 style="margin:${first ? '0' : '32px'} 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">${escHtml(W[l].heading)}</h1>
    <p style="margin:0 0 16px 0;line-height:1.6;">${escHtml(W[l].line)}</p>
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:14px;">${escHtml(W[l].next)}</p>`;
  const html = htmlShell(`${W.nl.pre} ${W.en.pre}`,
    htmlBlock('nl', true) + '\n    <hr style="margin:32px 0 0 0;border:0;border-top:1px solid #E2E8F0;">' + htmlBlock('en', false),
    'nl');
  return {
    ...wrap(text, html, { refId: 'complete-' + refIdHash(`${envelopeId}:party`) }),
    subject: `${W.nl.subject} / ${W.en.subject}`,
  };
}

// To the sender, when an invited party refused to sign. The request is then
// over for everybody. No names, no file name, no envelope id (the same rule as
// signatureReceivedEmail); the dashboard shows who.
function signatureDeclinedEmail({ envelopeId }) {
  const dashUrl = `${BASE_URL}/dashboard`;
  const W = {
    nl: { heading: 'Er is geweigerd', line: 'Een ondertekenaar heeft uw verzoek geweigerd. Het verzoek is daarmee gestopt. Niemand kan nog tekenen.', next: 'Bij uw documenten ziet u wie het was. Wilt u het opnieuw proberen? Stuur dan een nieuw verzoek.', open: 'Naar mijn documenten', subject: 'Verzoek geweigerd' },
    en: { heading: 'A signer declined', line: 'A signer declined your request. The request has stopped, and nobody can sign it any more.', next: 'Your documents show who it was. To try again, send a new request.', open: 'Go to my documents', subject: 'Request declined' },
  };
  const textBlock = (l) => `${W[l].heading}

${W[l].line}
${W[l].next}

${W[l].open}:
${dashUrl}`;
  const text = `${textBlock('nl')}\n\n---\n\n${textBlock('en')}

Paramant
${BASE_URL}`;
  const htmlBlock = (l, first) => `
    <h1 style="margin:${first ? '0' : '32px'} 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">${escHtml(W[l].heading)}</h1>
    <p style="margin:0 0 16px 0;line-height:1.6;">${escHtml(W[l].line)}</p>
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:14px;">${escHtml(W[l].next)}</p>
    ${btn(dashUrl, escHtml(W[l].open))}`;
  const html = htmlShell(`${W.nl.line} ${W.en.line}`,
    htmlBlock('nl', true) + '\n    <hr style="margin:32px 0 0 0;border:0;border-top:1px solid #E2E8F0;">' + htmlBlock('en', false),
    'nl');
  return {
    ...wrap(text, html, { refId: 'declined-' + refIdHash(String(envelopeId)) }),
    subject: `${W.nl.subject} / ${W.en.subject}`,
  };
}

// Every message this file sends goes through the one door in lib/mail.js.
//
// This used to POST straight to api.resend.com with RESEND_API_KEY, which meant
// it was NOT part of "mail goes through one provider": the relay could be moved
// to a European carrier while every account mail, signing invitation and
// invoice from the admin kept flowing to a US company. Nothing would have
// noticed, because it worked.
//
// Through the door, MAIL_PROVIDER decides, one setting for the whole product.
async function sendEmail(to, templateResult) {
  const r = await mailer.stuur({
    to,
    from: templateResult.from || FROM_ADDR,
    subject: templateResult.subject,
    html: templateResult.html,
    text: templateResult.text,
    headers: templateResult.headers || undefined,
    attachments: templateResult.attachments || undefined,
  });
  // The reason, never the provider's response body: an error payload echoes
  // the submitted message back, including the recipient address and sometimes
  // the body, which would otherwise land verbatim in our logs.
  if (!r || !r.ok) {
    throw new Error('mail failed: ' + ((r && r.reason) || 'unknown')
                    + ' via ' + ((r && r.provider) || '?'));
  }
}

module.exports = {
  backupCodesResetEmail,
  setupEmail,
  signupVerificationEmail,
  duplicateSignupAttemptEmail,
  resetConfirmationEmail,
  welcomeEmail,
  parasignOnboardingEmail, /*MARK:parasign_export*/
  signingInviteEmail,
  signatureReceivedEmail,
  everyoneSignedPartyEmail,
  signatureDeclinedEmail,
  billingConfirmationEmail,
  productPlanChangeEmail,
  billingCancellationEmail,
  keyDisabledEmail,
  accountDeletionEmail,
  sendEmail,
  FROM_ADDR,
  BASE_URL,
};

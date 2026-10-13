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


// HTML-escape any value that may carry user-controlled input before it lands
// in an HTML email body. Covers &, <, >, " and '. Use for email, label,
// reason, IP, etc. -- anything not built from constants in this module.
const escHtml = (s) => String(s ?? '')
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');

// Day and time as a reader in the Netherlands says them, in Amsterdam time:
// "12 oktober 2026 om 18:53" / "12 October 2026 at 18:53 (Amsterdam time)".
// It used to print "2026-10-12 18:53:33 UTC" in every mail, while the screens
// said "12 oktober 2026" (acceptatie 3.1.1, taal #19 and #49).
function formatTS(ts, lang = 'en') {
  const d = new Date(typeof ts === 'number' ? ts : Date.parse(ts));
  if (Number.isNaN(d.getTime())) return '';
  const nl = lang === 'nl';
  const loc = nl ? 'nl-NL' : 'en-GB';
  const day = d.toLocaleDateString(loc, { timeZone: 'Europe/Amsterdam', day: 'numeric', month: 'long', year: 'numeric' });
  const time = d.toLocaleTimeString(loc, { timeZone: 'Europe/Amsterdam', hour: '2-digit', minute: '2-digit', hour12: false });
  return nl ? `${day} om ${time}` : `${day} at ${time} (Amsterdam time)`;
}

function wrap(bodyText, bodyHtml, meta = {}) {
  return {
    from: FROM_ADDR,
    // The address the site names everywhere (acceptatie 3.1.1, taal #22).
    replyTo: 'privacy@paramant.app',
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
function setupEmail({ token, requestedAt, isReset = false, validFor = '2 days' }) {
  const url = `${BASE_URL}/auth/setup/${token}`;
  const preheader = isReset
    ? 'Uw authenticator-app is losgekoppeld. Scan de nieuwe QR-code.'
    : 'Scan de QR-code met uw authenticator-app om uw account af te maken.';

  // NL and EN say the same thing (acceptatie 3.1.1, taal #21): both name the
  // passkey, both carry the short why, and the time is Amsterdam time without
  // an IP address (#49). Contact is privacy@paramant.app, the address the site
  // names everywhere (#22).
  const resetWarn = isReset
    ? '\nIMPORTANT: first delete the old Paramant entry from your authenticator app.\nIts codes no longer work.\n'
    : '';
  const whenEn = formatTS(requestedAt || Date.now(), 'en');
  const whenNl = formatTS(requestedAt || Date.now(), 'nl');

  const enText = `Hi,

${isReset ? 'Your authenticator app has been disconnected.' : 'Welcome to Paramant.'} Connect an authenticator app or a passkey to ${isReset ? 'use your account again' : 'finish your account'}.
Paramant uses it instead of a password.

${isReset ? 'Set up new authenticator app' : 'Finish your account'}:
${url}
${resetWarn}
The link opens a page with a QR code. Scan it with your authenticator app
(for example Google Authenticator, Authy or 1Password). If scanning does
not work, you can type the code in by hand. You can also choose a passkey there.

This link works for ${validFor}.

Why no password? A code from your phone cannot leak with a list of stolen
passwords, and it only works for a short while. Type it only on paramant.app.

After setup you get 10 backup codes. Keep them somewhere safe
(a password manager, or on paper in a drawer) in case you lose your phone.

${isReset ? 'Did you not ask for this reset? Email privacy@paramant.app straight away.' : 'Did you not sign up for Paramant? Then you can ignore this email. There is no account until setup is finished.'}

Requested on ${whenEn}.

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
    <p style="margin:0 0 16px 0;line-height:1.6;">${isReset ? 'Your authenticator app has been disconnected.' : 'Welcome to Paramant.'} Connect an authenticator app or a passkey to ${isReset ? 'use your account again' : 'finish your account'}. Paramant uses it instead of a password.</p>
    ${btn(url, isReset ? 'Set up new authenticator app' : 'Finish my account')}
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:14px;">The link opens a page with a QR code. Scan it with your authenticator app (for example Google Authenticator, Authy or 1Password). You can also type the code in by hand, or choose a passkey.</p>
    <p style="margin:0 0 24px 0;line-height:1.6;color:#475569;font-size:14px;">This link works for <strong>${escHtml(validFor)}</strong>.</p>
    <p style="margin:0 0 12px 0;line-height:1.6;color:#475569;font-size:13px;">Why no password? A code from your phone cannot leak with a list of stolen passwords, and it only works for a short while. Type it only on paramant.app.</p>
    <p style="margin:0 0 24px 0;line-height:1.6;color:#475569;font-size:13px;">After setup you get 10 backup codes. Keep them somewhere safe (a password manager, or on paper in a drawer) in case you lose your phone.</p>
    <p style="margin:0 0 8px 0;font-size:13px;color:#64748b;">${isReset ? '<strong>Did you not ask for this reset?</strong> Email <a href="mailto:privacy@paramant.app" style="color:#1D4ED8;">privacy@paramant.app</a> straight away.' : '<strong>Did you not sign up for Paramant?</strong> Then you can ignore this email. There is no account until setup is finished.'}</p>
    <p style="margin:16px 0 0 0;font-size:12px;color:#94a3b8;">Requested on ${escHtml(whenEn)}.</p>
  `;

  const nlValid = nlDuration(validFor);
  const nlText = `Hallo,

${isReset ? 'Uw authenticator-app is losgekoppeld.' : 'Welkom bij Paramant.'} Koppel een authenticator-app of een passkey om ${isReset ? 'uw account weer te gebruiken' : 'uw account af te maken'}.
Die gebruikt Paramant in plaats van een wachtwoord.

${isReset ? 'Nieuwe authenticator-app instellen' : 'Account afmaken'}:
${url}
${isReset ? '\nBELANGRIJK: verwijder eerst de oude Paramant-regel uit uw authenticator-app.\nDie codes werken niet meer.\n' : ''}
De link opent een pagina met een QR-code. Scan die met uw authenticator-app
(bijvoorbeeld Google Authenticator, Authy of 1Password). Lukt scannen
niet, dan typt u de code over. U kunt daar ook een passkey kiezen.

Deze link werkt ${nlValid}.

Waarom geen wachtwoord? Een code van uw telefoon lekt niet uit met een
lijst gestolen wachtwoorden, en hij werkt maar kort. Typ hem alleen op
paramant.app.

Na het instellen krijgt u 10 back-upcodes. Bewaar die op een veilige plek
(wachtwoordbeheerder, of op papier in een la) voor als u uw telefoon kwijtraakt.

${isReset ? 'Heeft u deze reset niet aangevraagd? Mail dan meteen privacy@paramant.app.' : 'Heeft u zich niet aangemeld bij Paramant? Dan kunt u deze mail negeren. Er is pas een account als u het instellen afrondt.'}

Aangevraagd op ${whenNl}.

Paramant
https://paramant.app`;

  const nlHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">${isReset ? 'Stel uw nieuwe authenticator-app in' : 'Maak uw Paramant-account af'}</h1>
    ${isReset ? `<div style="background:#FEF3C7;border-left:3px solid #D97706;padding:12px 16px;margin:0 0 20px 0;">
        <p style="margin:0;line-height:1.5;color:#92400E;font-size:14px;"><strong>Authenticator-app losgekoppeld.</strong> Verwijder eerst de oude Paramant-regel uit uw app. Die codes werken niet meer.</p>
      </div>` : ''}
    <p style="margin:0 0 16px 0;line-height:1.6;">${isReset ? 'Uw authenticator-app is losgekoppeld.' : 'Welkom bij Paramant.'} Koppel een authenticator-app of een passkey om ${isReset ? 'uw account weer te gebruiken' : 'uw account af te maken'}. Paramant gebruikt die in plaats van een wachtwoord.</p>
    ${btn(url, isReset ? 'Nieuwe authenticator-app instellen' : 'Account afmaken')}
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:14px;">De link opent een pagina met een QR-code. Scan die met uw authenticator-app (bijvoorbeeld Google Authenticator, Authy of 1Password). U kunt de code ook overtypen, of een passkey kiezen.</p>
    <p style="margin:0 0 24px 0;line-height:1.6;color:#475569;font-size:14px;">Deze link werkt <strong>${escHtml(nlValid)}</strong>.</p>
    <p style="margin:0 0 12px 0;line-height:1.6;color:#475569;font-size:13px;">Waarom geen wachtwoord? Een code van uw telefoon lekt niet uit met een lijst gestolen wachtwoorden, en hij werkt maar kort. Typ hem alleen op paramant.app.</p>
    <p style="margin:0 0 24px 0;line-height:1.6;color:#475569;font-size:13px;">Na het instellen krijgt u 10 back-upcodes. Bewaar die op een veilige plek (wachtwoordbeheerder, of op papier in een la) voor als u uw telefoon kwijtraakt.</p>
    <p style="margin:0 0 8px 0;font-size:13px;color:#64748b;">${isReset ? '<strong>Vroeg u deze reset niet aan?</strong> Mail dan meteen <a href="mailto:privacy@paramant.app" style="color:#1D4ED8;">privacy@paramant.app</a>.' : '<strong>Niet aangemeld bij Paramant?</strong> Dan kunt u deze mail negeren. Er is pas een account als u het instellen afrondt.'}</p>
    <p style="margin:16px 0 0 0;font-size:12px;color:#94a3b8;">Aangevraagd op ${escHtml(whenNl)}.</p>
  `;

  return bilingualMail({
    subject: isReset ? 'Stel uw nieuwe authenticator-app in voor Paramant' : 'Maak uw Paramant-account af',
    preheader, nlText, enText, nlHtml, enHtml,
    refId: 'setup-' + refIdHash(token),
  });
}

// ── 2. RESET CONFIRMATION EMAIL ───────────────────────────────────────────────
function resetConfirmationEmail({ confirmToken, requestedAt }) {
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

Why this extra step? A reset needs one of your backup codes and access
to your mailbox. Access to your mailbox alone is not enough.

Requested on ${formatTS(requestedAt, 'en')}.

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
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:13px;">Why this extra step? A reset needs one of your backup codes and access to your mailbox. Access to your mailbox alone is not enough.</p>
    <p style="margin:16px 0 0 0;font-size:12px;color:#94a3b8;">Requested on ${escHtml(formatTS(requestedAt, 'en'))}.</p>
  `;

  const when = formatTS(requestedAt, 'nl');
  const nlText = `Hallo,

Iemand vroeg om uw Paramant-account aan een nieuwe authenticator-app te koppelen.

Was u dat? Bevestig het dan met de link hieronder. Daarna krijgt u een tweede
mail met een link om de nieuwe authenticator-app in te stellen.

Reset bevestigen:
${url}

Deze link werkt 1 uur.

Was u dit niet? Negeer deze mail dan. Er verandert niets en uw huidige
authenticator-app blijft gewoon werken.

Waarom deze extra stap? Voor een reset zijn een van uw back-upcodes en
toegang tot uw mailbox nodig. Toegang tot uw mailbox alleen is niet genoeg.

Aangevraagd op ${when}.

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
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:13px;">Waarom deze extra stap? Voor een reset zijn een van uw back-upcodes en toegang tot uw mailbox nodig. Toegang tot uw mailbox alleen is niet genoeg.</p>
    <p style="margin:16px 0 0 0;font-size:12px;color:#94a3b8;">Aangevraagd op ${escHtml(when)}.</p>
  `;

  return bilingualMail({
    subject: 'Nieuwe authenticator-app bevestigen · Paramant',
    preheader, nlText, enText, nlHtml, enHtml,
    refId: 'reset-confirm-' + refIdHash(confirmToken),
  });
}

// ── 3. WELCOME / API KEY EMAIL ────────────────────────────────────────────────
function welcomeEmail({ apiKey, plan, label, sectors }) {
  // Dutch on top and English below, like the other account mails: the admin
  // who issues the key does not know which language the customer reads
  // (acceptatie 3.1.1, taal 40). Only a MASKED key: the full key went
  // separately, so no secret lands in the mailbox or the provider logs.
  const preheader = 'Uw Paramant-API-sleutel staat klaar. / Your Paramant API key is ready.';
  const masked = apiKey.slice(0, 12) + '...' + apiKey.slice(-4);
  const planName = displayPlanName(plan) || plan;
  const sectorList = (sectors || []).join(', ');
  const row = (k, v) => `<tr><td style="padding:8px 16px 8px 0;color:#64748b;font-family:monospace;font-size:11px;text-transform:uppercase;letter-spacing:0.1em;white-space:nowrap;">${k}</td><td style="padding:8px 0;font-size:13px;">${v}</td></tr>`;
  const block = (w) => `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">${w.h1}</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">${w.intro}</p>
    <table style="border-collapse:collapse;margin:0 0 24px 0;width:100%;">
      ${row('Plan', escHtml(planName))}
      ${row(w.labelK, label ? escHtml(label) : `<em style="color:#94a3b8;">${w.noLabel}</em>`)}
      ${row(w.sectorsK, escHtml(sectorList || w.all))}
      ${row(w.keyK, `<span style="font-family:monospace;color:#0B3A6A;">${masked}</span>`)}
    </table>
    <p style="margin:0 0 24px 0;line-height:1.6;color:#475569;font-size:14px;">${w.separate}</p>
    <h2 style="margin:0 0 12px 0;font-size:14px;font-weight:600;color:#0B3A6A;">${w.nowH}</h2>
    <ul style="margin:0 0 24px 0;padding-left:20px;line-height:1.8;color:#475569;font-size:14px;">
      <li>${w.header}</li>
      <li>${w.docs}: <a href="https://paramant.app/docs/api" style="color:#1D4ED8;">paramant.app/docs/api</a></li>
      <li>${w.ext}: <a href="https://paramant.app/extensions" style="color:#1D4ED8;">paramant.app/extensions</a></li>
    </ul>
    <h2 style="margin:0 0 12px 0;font-size:14px;font-weight:600;color:#0B3A6A;">${w.safeH}</h2>
    <ul style="margin:0 0 16px 0;padding-left:20px;line-height:1.7;color:#475569;font-size:13px;">
      ${w.safe.map((x) => `<li>${x}</li>`).join('')}
    </ul>
    <p style="margin:16px 0 0 0;color:#475569;font-size:14px;">${w.q}</p>`;
  const W = {
    nl: {
      h1: 'Uw Paramant-API-sleutel staat klaar', hi: 'Hallo,',
      intro: 'Een beheerder heeft een API-sleutel voor uw account gemaakt.',
      labelK: 'Naam', noLabel: 'geen naam', sectorsK: 'Sectoren', all: 'alle', keyK: 'Sleutel (deels verborgen)',
      separate: 'De volledige sleutel heeft de beheerder u apart gegeven.',
      nowH: 'Wat u nu kunt doen',
      header: 'Zet de sleutel in de X-Api-Key-header als u de relay aanroept',
      docs: 'Documentatie', ext: 'Extensies',
      safeH: 'Uw sleutel veilig bewaren',
      safe: ['Bewaar hem in een wachtwoordbeheerder, nooit als gewone tekst', 'Zet hem niet in versiebeheer (.env-bestanden lekken)', 'Vervang hem meteen als u denkt dat iemand anders hem kent'],
      q: 'Vragen? Antwoord gewoon op deze mail.',
    },
    en: {
      h1: 'Your Paramant API key is ready', hi: 'Hi,',
      intro: 'An administrator has created an API key for your account.',
      labelK: 'Name', noLabel: 'no name', sectorsK: 'Sectors', all: 'all', keyK: 'Key (partly hidden)',
      separate: 'The administrator gave you the full key separately.',
      nowH: 'What you can do now',
      header: 'Put the key in the X-Api-Key header when you call the relay',
      docs: 'Documentation', ext: 'Extensions',
      safeH: 'Storing your key safely',
      safe: ['Keep it in a password manager, never in plain text', 'Do not commit it to source control (.env files leak)', 'Replace it straight away if you think someone else has it'],
      q: 'Questions? Just reply to this email.',
    },
  };
  const textBlock = (w) => `${w.hi}

${w.intro}

Plan:    ${planName}
${w.labelK}: ${label || w.noLabel}
${w.sectorsK}: ${sectorList || w.all}
${w.keyK}: ${masked}

${w.separate}

${w.nowH}:
1. ${w.header}
2. ${w.docs}: https://paramant.app/docs/api
3. ${w.ext}: https://paramant.app/extensions

${w.safeH}:
${w.safe.map((x) => '- ' + x).join('\n')}

${w.q}

Paramant
https://paramant.app`;
  return bilingualMail({
    subject: 'Uw Paramant-API-sleutel staat klaar / Your Paramant API key is ready',
    preheader,
    nlText: textBlock(W.nl), enText: textBlock(W.en),
    nlHtml: block(W.nl), enHtml: block(W.en),
    refId: 'welcome-' + refIdHash(apiKey),
  });
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
// The names /pricing sells (acceptatie 3.1.1, taal #4 and #47): the tier key
// 'pro' is Firm on both products, 'free' is Community. Callers pass the key or
// a capitalised key ("Pro"); the customer reads the plan name.
function displayPlanName(name) {
  const k = String(name || '').trim().toLowerCase();
  return { pro: 'Firm', firm: 'Firm', free: 'Community', community: 'Community', business: 'Business', enterprise: 'Enterprise' }[k] || String(name || '');
}

// Dutch first with the English underneath, like the account mails: the admin
// action that sends it does not know the customer's language, and the mail
// was English only (acceptatie 3.1.1, taal #40).
function billingConfirmationEmail({ planName, period, amountStr, noPayment = true }) {
  const plan = displayPlanName(planName);
  const safePlan = escHtml(plan);
  const preheader = `Uw Paramant-plan is nu ${safePlan}.`;
  const periodNl = period === 'yearly' ? 'Per jaar' : period === 'monthly' ? 'Per maand' : 'Ingesteld door Paramant';
  const periodEn = period === 'yearly' ? 'Yearly' : period === 'monthly' ? 'Monthly' : 'Set by Paramant';
  // 'admin-provisioned' is a code, not an amount. An amount arrives as
  // "€35.09/mo" and is written the way each language writes money.
  const isAmount = amountStr && amountStr !== 'admin-provisioned' && amountStr !== 'N/A';
  const amountEn = isAmount ? String(amountStr).replace(/(\d),(\d{2})\b/, '$1.$2') : (noPayment ? 'Nothing charged' : '');
  const amountNl = isAmount
    ? String(amountStr).replace(/(\d)\.(\d{2})\b/, '$1,$2').replace('/mo', ' per maand').replace('/yr', ' per jaar').replace(/^Free$/, 'Gratis')
    : (noPayment ? 'Niets afgeschreven' : '');

  const nlText = `Hallo,

Uw Paramant-plan is nu ${plan}.

Plan:    ${plan}
Periode: ${periodNl}
Bedrag:  ${amountNl}
${noPayment ? '\nParamant heeft dit plan op uw account gezet. Er is niets voor afgeschreven,\ndus bij deze wijziging hoort geen factuur. Een plan dat u op paramant.app\nkoopt, betaalt u via Mollie. Elke betaling krijgt een genummerde factuur of\nbetaalbewijs, en dat staat op uw accountpagina.\n' : ''}
Vragen over betalen? Beantwoord deze mail.

Paramant
https://paramant.app`;

  const enText = `Hi,

Your Paramant plan is now ${plan}.

Plan:    ${plan}
Billing: ${periodEn}
Amount:  ${amountEn}
${noPayment ? '\nNote: Paramant set this plan on your account. Nothing was charged for\nit, so this change has no invoice. A plan bought on paramant.app is paid\nthrough Mollie, and every payment gets a numbered invoice or payment\nreceipt that stays on your account page.\n' : ''}
Questions about billing? Reply to this email.

Paramant
https://paramant.app`;

  const table = (rows) => `<table style="border-collapse:collapse;margin:0 0 24px 0;width:100%;">${rows.map(([k, v], i) => `<tr><td style="padding:10px 0;${i < rows.length - 1 ? 'border-bottom:1px solid rgba(11,58,106,0.06);' : ''}color:#64748b;font-size:14px;">${k}</td><td style="padding:10px 0;${i < rows.length - 1 ? 'border-bottom:1px solid rgba(11,58,106,0.06);' : ''}font-weight:600;text-align:right;">${v}</td></tr>`).join('')}</table>`;
  const note = (t) => `<div style="background:rgba(11,58,106,0.04);border-left:3px solid #1D4ED8;padding:12px 16px;margin:24px 0;"><p style="margin:0;line-height:1.5;color:#475569;font-size:13px;">${t}</p></div>`;

  const nlHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Uw plan is nu ${safePlan}</h1>
    ${table([['Plan', safePlan], ['Periode', periodNl], ['Bedrag', escHtml(amountNl)]])}
    ${noPayment ? note('<strong>Geen betaling bij deze wijziging:</strong> Paramant heeft dit plan op uw account gezet. Er is niets afgeschreven, dus er hoort geen factuur bij. Een plan dat u op paramant.app koopt, betaalt u via Mollie. Elke betaling krijgt een genummerde factuur of betaalbewijs, en dat staat op uw accountpagina.') : ''}
    <p style="margin:16px 0 0 0;line-height:1.6;color:#475569;font-size:14px;">Vragen over betalen? Beantwoord deze mail.</p>
  `;
  const enHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Your plan is now ${safePlan}</h1>
    ${table([['Plan', safePlan], ['Billing', periodEn], ['Amount', escHtml(amountEn)]])}
    ${noPayment ? note('<strong>No payment for this change:</strong> Paramant set this plan on your account, so nothing was charged and this change has no invoice. A plan bought on paramant.app is paid through Mollie, and every payment gets a numbered invoice or payment receipt that stays on your account page.') : ''}
    <p style="margin:16px 0 0 0;line-height:1.6;color:#475569;font-size:14px;">Questions about billing? Reply to this email.</p>
  `;

  return bilingualMail({
    subject: `Uw Paramant-plan is nu ${plan} / Your Paramant plan is now ${plan}`,
    preheader, nlText, enText, nlHtml, enHtml,
    refId: 'billing-' + Date.now(),
  });
}

// ── 4b. PER-PRODUCT PLAN CHANGE ───────────────────────────────────────────────
// Sent when an admin sets a SINGLE product's tier (ParaSign or ParaSend) without
// touching the other product or the unified plan. Deliberately carries NO
// billing note of any kind: this is a scoped entitlement change, and the mail
// above is the one that answers for a plan and its money. productName is a
// display name ("ParaSign"), tierName the tier ("Pro"); both are constants
// from the caller. The customer reads Ondertekenen / Versturen and the plan
// name, in Dutch first (acceptatie 3.1.1, taal #40).
function productPlanChangeEmail({ productName, tierName }) {
  const isSign = /sign/i.test(String(productName || ''));
  const prodNl = isSign ? 'Ondertekenen' : 'Versturen';
  const prodEn = isSign ? 'Signing' : 'Sending';
  const tier = escHtml(displayPlanName(tierName));
  const preheader = `${prodNl} staat nu op ${tier}.`;

  const nlText = `Hallo,

${prodNl} staat in uw Paramant-account nu op ${tier}.

Alleen ${prodNl.toLowerCase()} is veranderd. De rest van uw account blijft zoals het was.

Vragen? Beantwoord deze mail.

Paramant
https://paramant.app`;
  const enText = `Hi,

${prodEn} in your Paramant account is now on ${tier}.

Only ${prodEn.toLowerCase()} changed. The rest of your account stays as it was.

Questions? Reply to this email.

Paramant
https://paramant.app`;
  const nlHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">${prodNl}: ${tier}</h1>
    <p style="margin:0 0 16px 0;line-height:1.6;">${prodNl} staat in uw Paramant-account nu op <strong>${tier}</strong>.</p>
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:14px;">Alleen ${prodNl.toLowerCase()} is veranderd. De rest van uw account blijft zoals het was.</p>
    <p style="margin:16px 0 0 0;line-height:1.6;color:#475569;font-size:14px;">Vragen? Beantwoord deze mail.</p>
  `;
  const enHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">${prodEn}: ${tier}</h1>
    <p style="margin:0 0 16px 0;line-height:1.6;">${prodEn} in your Paramant account is now on <strong>${tier}</strong>.</p>
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:14px;">Only ${prodEn.toLowerCase()} changed. The rest of your account stays as it was.</p>
    <p style="margin:16px 0 0 0;line-height:1.6;color:#475569;font-size:14px;">Questions? Reply to this email.</p>
  `;
  return bilingualMail({
    subject: `${prodNl} staat nu op ${tier} / ${prodEn} is now on ${tier}`,
    preheader, nlText, enText, nlHtml, enHtml,
    refId: 'product-plan-' + Date.now(),
  });
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

Uw Paramant ${planName}-plan is opgezegd per ${dateNl}. Tot die datum loopt het gewoon door.

Stopt op: ${dateNl}

Tot die datum houdt u ${planName}. Daarna gaat uw account terug naar het
Community-plan.

Uw API-sleutel blijft werken. Bestanden die u al verstuurd heeft, blijven
zoals ze zijn. De toegang per sector gaat naar de grenzen van Community.

Toch niet opzeggen? Beantwoord deze mail voor de einddatum, dan zetten we het terug.

Paramant
https://paramant.app`;

  const enText = `Hi,

Your Paramant ${planName} plan is cancelled as of ${cancelDate}. Until that date it keeps running as usual.

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
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Opgezegd per ${dateNl}</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">Uw Paramant ${planName}-plan is opgezegd per ${dateNl}. Tot die datum loopt het gewoon door.</p>
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
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Cancelled as of ${cancelDate}</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">Your Paramant ${planName} plan is cancelled as of ${cancelDate}. Until that date it keeps running as usual.</p>
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
    // Kop en onderwerp noemen de einddatum: opgezegd PER die dag, niet nu
    // gestopt (review 573). NL en EN zeggen hetzelfde.
    subject: `Uw Paramant-plan is opgezegd per ${dateNl} / Your Paramant plan is cancelled as of ${cancelDate}`,
    preheader, nlText, enText, nlHtml, enHtml,
    refId: 'cancel-' + Date.now(),
  });
}

// ── 5b. KEY DISABLED ──────────────────────────────────────────────────────────
// What disable-key mails. It used to send the cancellation mail above ("your
// plan ends on ..., your API key continues to work") on the very moment the key
// stopped working (ADMIN-24). This one says what happened.
function keyDisabledEmail({ disabledAt, disabledAtNl }) {
  // Dutch first, English below (acceptatie 3.1.1, taal #40). disabledAt is
  // the English date the caller formats; disabledAtNl the same day in Dutch.
  const dayEn = escHtml(disabledAt || '');
  const dayNl = escHtml(disabledAtNl || disabledAt || '');
  const preheader = 'Uw Paramant API-sleutel is uitgeschakeld.';
  const nlText = `Hallo,

Wij hebben uw Paramant API-sleutel op ${dayNl} uitgeschakeld. Hij werkt
vanaf nu op geen enkele Paramant-server meer.

Bestanden die u eerder verstuurde, blijven zoals ze waren. Had u dit niet
verwacht? Beantwoord deze mail, dan zoeken wij het uit.

Paramant
https://paramant.app`;
  const enText = `Hi,

We disabled your Paramant API key on ${dayEn}. From now on it no
longer works on any Paramant server.

Files you sent before are not affected. If you did not expect this,
reply to this email and we will look into it.

Paramant
https://paramant.app`;
  const nlHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Uw API-sleutel is uitgeschakeld</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">Wij hebben uw Paramant API-sleutel op <strong>${dayNl}</strong> uitgeschakeld. Hij werkt vanaf nu op geen enkele Paramant-server meer.</p>
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:14px;">Bestanden die u eerder verstuurde, blijven zoals ze waren. Had u dit niet verwacht? Beantwoord deze mail, dan zoeken wij het uit.</p>
  `;
  const enHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Your API key has been disabled</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">We disabled your Paramant API key on <strong>${dayEn}</strong>. From now on it no longer works on any Paramant server.</p>
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:14px;">Files you sent before are not affected. If you did not expect this, reply to this email and we will look into it.</p>
  `;
  return bilingualMail({
    subject: 'Uw Paramant API-sleutel is uitgeschakeld / Your Paramant API key has been disabled',
    preheader, nlText, enText, nlHtml, enHtml,
    refId: 'disabled-' + Date.now(),
  });
}

// ── 6. ACCOUNT DELETION ───────────────────────────────────────────────────────
// This mail used to say that account records were retained and that erasure was
// a separate request to privacy@. That was true while deletion only revoked the
// key and cleared Redis, leaving the email address in users.json on every sector
// (audit finding 5 of 2026-07-21). Deletion now erases the personal data itself,
// so the old wording understated what happened, and a mail that undersells an
// erasure is as untrue as one that oversells it.
function accountDeletionEmail({ email, deletedAt, reason }) {
  // Says what the code does, the same way /account says it (acceptatie 3.1.1,
  // taal #8): the key stops, sessions and the authenticator link go, the
  // email address and the other personal fields are erased on every sector
  // (/v2/admin/keys/erase, keysTable.erasePersonalData), and payment documents
  // stay as long as tax law requires. After an erasure there is nothing to
  // switch back on, so the mail no longer offers "access again": it points to
  // a new account. A machine code as reason ("user_request") is never shown
  // raw (#39); a reason typed by a person is.
  const preheader = 'Uw Paramant-account is gedeactiveerd en uw gegevens zijn gewist.';
  const dateNl = formatTS(deletedAt, 'nl');
  const dateEn = formatTS(deletedAt, 'en');
  const KNOWN = {
    user_request: { nl: 'op uw eigen verzoek', en: 'at your own request' },
    'admin action': { nl: 'door Paramant', en: 'by Paramant' },
  };
  const raw = String(reason || '').trim();
  const known = KNOWN[raw];
  const isCode = /^[a-z0-9_]+$/.test(raw);
  const reasonNl = known ? known.nl : (raw && !isCode ? raw : '');
  const reasonEn = known ? known.en : (raw && !isCode ? raw : '');

  const enText = `Hi,

Your Paramant account (${email}) was deactivated on ${dateEn}${reasonEn ? ', ' + reasonEn : ''}.

What happened:
- Your API key no longer works
- Your sessions and the link with your authenticator app are gone
- Your email address and other personal data have been erased
- Invoices are kept for as long as tax law requires

Was this a mistake? Email privacy@paramant.app. Want to use Paramant again
later? Then create a new account at https://paramant.app/signup.

Paramant
https://paramant.app`;

  const enHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Account deactivated</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">Your Paramant account (${escHtml(email)}) was deactivated on <strong>${escHtml(dateEn)}</strong>${reasonEn ? ', ' + escHtml(reasonEn) : ''}.</p>
    <ul style="margin:0 0 24px 0;padding-left:20px;line-height:1.8;color:#475569;font-size:14px;">
      <li>Your API key no longer works</li>
      <li>Your sessions and the link with your authenticator app are gone</li>
      <li>Your email address and other personal data have been erased</li>
      <li>Invoices are kept for as long as tax law requires</li>
    </ul>
    <p style="margin:0;line-height:1.6;color:#475569;font-size:14px;">Was this a mistake? Email <a href="mailto:privacy@paramant.app" style="color:#1D4ED8;">privacy@paramant.app</a>. Want to use Paramant again later? Then <a href="${BASE_URL}/en/signup" style="color:#1D4ED8;">create a new account</a>.</p>
  `;

  const nlText = `Hallo,

Uw Paramant-account (${email}) is op ${dateNl} gedeactiveerd${reasonNl ? ', ' + reasonNl : ''}.

Wat er is gebeurd:
- Uw API-sleutel werkt niet meer
- Uw sessies en de koppeling met uw authenticator-app zijn weg
- Uw e-mailadres en andere persoonsgegevens zijn gewist
- Facturen bewaren wij zo lang als de belastingwet vraagt

Was dit een vergissing? Mail privacy@paramant.app. Wilt u Paramant later
weer gebruiken? Maak dan een nieuw account op https://paramant.app/signup.

Paramant
https://paramant.app`;

  const nlHtml = `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Account gedeactiveerd</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">Uw Paramant-account (${escHtml(email)}) is op <strong>${escHtml(dateNl)}</strong> gedeactiveerd${reasonNl ? ', ' + escHtml(reasonNl) : ''}.</p>
    <ul style="margin:0 0 24px 0;padding-left:20px;line-height:1.8;color:#475569;font-size:14px;">
      <li>Uw API-sleutel werkt niet meer</li>
      <li>Uw sessies en de koppeling met uw authenticator-app zijn weg</li>
      <li>Uw e-mailadres en andere persoonsgegevens zijn gewist</li>
      <li>Facturen bewaren wij zo lang als de belastingwet vraagt</li>
    </ul>
    <p style="margin:0;line-height:1.6;color:#475569;font-size:14px;">Was dit een vergissing? Mail <a href="mailto:privacy@paramant.app" style="color:#1D4ED8;">privacy@paramant.app</a>. Wilt u Paramant later weer gebruiken? Maak dan <a href="${BASE_URL}/signup" style="color:#1D4ED8;">een nieuw account</a>.</p>
  `;

  return bilingualMail({
    subject: 'Uw Paramant-account is gedeactiveerd / Your Paramant account was deactivated',
    preheader, nlText, enText, nlHtml, enHtml,
    refId: 'deletion-' + Date.now(),
  });
}

// ── SIGNUP VERIFICATION EMAIL ────────────────────────────────────────────────
function signupVerificationEmail({ email, token, requestedAt }) {
  const url = `${BASE_URL}/api/user/signup/verify/${token}`;
  // The day and time in Amsterdam, without UTC or an IP address (acceptatie
  // 3.1.1, taal #49).
  const dateEn = formatTS(requestedAt, 'en');
  const dateNl = formatTS(requestedAt, 'nl');

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
    `Requested on ${dateEn}.`,
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
        <br>Requested on ${escHtml(dateEn)}.
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
    `Aangevraagd op ${dateNl}.`,
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
      <br>Aangevraagd op ${escHtml(dateNl)}.
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
function duplicateSignupAttemptEmail({ email, requestedAt }) {
  const dateEn = formatTS(requestedAt, 'en');
  const dateNl = formatTS(requestedAt, 'nl');
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
    `Attempt on ${dateEn}.`,
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
        <br>Attempt on ${escHtml(dateEn)}.
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
    `Poging op ${dateNl}.`,
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
      <br>Poging op ${escHtml(dateNl)}.
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
  // Dutch first, English below, and without the jargon "zero-knowledge
  // standard" (acceptatie 3.1.1, taal #40).
  const dateEn = formatTS(requestedAt, 'en');
  const dateNl = formatTS(requestedAt, 'nl');
  const preheader = 'Uw Paramant back-upcodes zijn vervangen. Maak nieuwe aan.';

  const nlText = [
    'Beveiligingsbericht: uw back-upcodes zijn ongeldig gemaakt',
    '',
    `Dit is een beveiligingsbericht voor ${email}.`,
    '',
    'Bij een eigen controle zagen wij dat uw back-upcodes niet zo veilig waren',
    'opgeslagen als wij willen. Dat hebben wij hersteld, en voor de zekerheid',
    'hebben wij de oude codes ongeldig gemaakt.',
    '',
    'Uw authenticator-app werkt gewoon. Alleen de back-upcodes zijn geraakt.',
    '',
    'Wat u doet:',
    '  Log in en maak een nieuwe set back-upcodes.',
    '  Bewaar ze in uw wachtwoordbeheerder.',
    '',
    `Gezien op ${dateNl}. Wij zagen geen teken dat iemand anders binnenkwam.`,
    '',
    'Vragen: privacy@paramant.app',
    '',
    'Paramant',
  ].join('\n');

  const enText = [
    'Security notice: your backup codes were cancelled',
    '',
    `This is a security notice for ${email}.`,
    '',
    'During our own check we found that your backup codes were not stored as',
    'safely as we want. We fixed this and, to be safe, cancelled the old codes.',
    '',
    'Your authenticator app keeps working. Only the backup codes were affected.',
    '',
    'What to do:',
    '  Sign in and create a new set of backup codes.',
    '  Keep them in your password manager.',
    '',
    `Found on ${dateEn}. We saw no sign that anyone else got in.`,
    '',
    'Questions: privacy@paramant.app',
    '',
    'Paramant',
  ].join('\n');

  const body = (t) => `
    <div style="background:#FEF2F2;border:1px solid #FECACA;padding:16px;border-radius:4px;margin:0 0 24px 0;">
      <p style="margin:0;font-size:13px;font-weight:600;color:#991B1B;">${t.notice}</p>
    </div>
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">${t.h}</h1>
    <p style="margin:0 0 16px 0;line-height:1.6;">${t.what}</p>
    <p style="margin:0 0 16px 0;line-height:1.6;"><strong>${t.app}</strong></p>
    <div style="background:#F8FAFC;border:1px solid rgba(11,58,106,0.1);padding:16px;margin:0 0 24px 0;border-radius:4px;">
      <p style="margin:0 0 8px 0;font-weight:600;color:#0B3A6A;">${t.todoH}</p>
      <p style="margin:0;color:#475569;font-size:14px;line-height:1.6;">${t.todo}</p>
    </div>
    <div style="text-align:center;margin:0 0 24px 0;">
      <a href="${t.url}" style="display:inline-block;background:#1D4ED8;color:#ffffff;font-size:15px;font-weight:600;padding:14px 32px;border-radius:6px;text-decoration:none;">${t.btn}</a>
    </div>
    <p style="margin:0;font-size:12px;color:#94A3B8;line-height:1.6;">${t.foot} <a href="mailto:privacy@paramant.app" style="color:#1D4ED8;">privacy@paramant.app</a></p>`;

  const nlHtml = body({
    notice: 'Beveiligingsbericht', h: 'Uw back-upcodes zijn ongeldig gemaakt',
    what: 'Bij een eigen controle zagen wij dat uw back-upcodes niet zo veilig waren opgeslagen als wij willen. Dat hebben wij hersteld, en voor de zekerheid hebben wij de oude codes ongeldig gemaakt.',
    app: 'Uw authenticator-app werkt gewoon. Alleen de back-upcodes zijn geraakt.',
    todoH: 'Wat u doet', todo: 'Log in en maak een nieuwe set back-upcodes. Bewaar ze in uw wachtwoordbeheerder.',
    url: `${BASE_URL}/account`, btn: 'Naar uw account',
    foot: `Gezien op ${escHtml(dateNl)}. Wij zagen geen teken dat iemand anders binnenkwam. Vragen:`,
  });
  const enHtml = body({
    notice: 'Security notice', h: 'Your backup codes were cancelled',
    what: 'During our own check we found that your backup codes were not stored as safely as we want. We fixed this and, to be safe, cancelled the old codes.',
    app: 'Your authenticator app keeps working. Only the backup codes were affected.',
    todoH: 'What to do', todo: 'Sign in and create a new set of backup codes. Keep them in your password manager.',
    url: `${BASE_URL}/en/account`, btn: 'Go to your account',
    foot: `Found on ${escHtml(dateEn)}. We saw no sign that anyone else got in. Questions:`,
  });

  return bilingualMail({
    subject: 'Maak nieuwe back-upcodes aan voor Paramant / Please create new Paramant backup codes',
    preheader, nlText, enText, nlHtml, enHtml,
    refId: 'backup-reset-' + requestedAt,
  });
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
  // Amsterdam time, as the screen says it (acceptatie 3.1.1, taal #19).
  const expiryNl = expiresAt ? formatTS(expiresAt, 'nl') : '';
  const expiryEn = expiresAt ? formatTS(expiresAt, 'en') : '';
  const note = String(message || '').trim().slice(0, 1000);
  const W = {
    nl: {
      greeting: recipientLabel ? `Beste ${recipientLabel},` : 'Beste,',
      sender: senderLabel || 'Een Paramant-gebruiker',
      asks: 'heeft u gevraagd een document te bekijken en te ondertekenen.',
      // One truth with /sign and /co-sign (acceptatie 3.1.1, taal #1 and #2):
      // the link opens the request without signing in; the document opens
      // after signing in with the invited address; a new signer first makes a
      // free account on that address, through the same link.
      carries: opensDocument
        ? `De link opent het verzoek. Het document zelf opent zodra u inlogt met het e-mailadres waarop u bent uitgenodigd. Heeft u nog geen account? Dan maakt u via de link gratis een account op dit adres. Daarna leest u het document, zet u uw ${paraaf ? 'paraaf en handtekening' : 'handtekening'} en bent u klaar.`
        : 'Deze link opent het verzoek, maar niet het document. Heeft u een eerdere uitnodiging voor dit verzoek? Gebruik dan de link uit die mail, die opent het document wel. Lukt dat niet? Vraag de afzender dan om de uitnodiging opnieuw te sturen vanuit zijn overzicht. Die uitnodiging opent het document wel.',
      open: opensDocument ? 'Open het document' : 'Open het verzoek',
      fromSender: 'Bericht van de afzender:',
      signIn: 'Stuur de link niet door. Hij werkt alleen met het e-mailadres waarop u bent uitgenodigd.',
      closes: `Ondertekenen kan tot ${expiryNl || '7 dagen na het aanmaken'}.`,
      heading: 'Verzoek om te ondertekenen',
      pre: 'Er wacht een document op uw handtekening in Paramant.',
    },
    en: {
      greeting: recipientLabel ? `Hi ${recipientLabel},` : 'Hi,',
      sender: senderLabel || 'A Paramant user',
      asks: 'has asked you to review and sign a document.',
      carries: opensDocument
        ? `The link opens the request. The document itself opens as soon as you sign in with the email address this invitation went to. No account yet? Then create a free account on this address through the link. After that you read the document, ${paraaf ? 'add your initials and signature' : 'add your signature'}, and you are done.`
        : 'This link opens the request, but not the document. Do you have an earlier invitation for this request? Use the link from that email, that one does open the document. Otherwise, ask the sender to send the invitation again from their overview. That invitation does open the document.',
      open: opensDocument ? 'Open the document' : 'Open the request',
      fromSender: 'Message from the sender:',
      signIn: 'Do not forward the link. It only works with the email address this invitation went to.',
      closes: `You can sign until ${expiryEn || '7 days after the request was made'}.`,
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

// "uw verzoek van 5 oktober 2026" when the day it was sent is known, else
// "uw verzoek" (acceptatie 3.1.1, taal #45).
function requestNames(sentAt) {
  const ok = Number.isFinite(Number(sentAt)) && Number(sentAt) > 0;
  const dayOf = (loc) => new Date(Number(sentAt)).toLocaleDateString(loc, { timeZone: 'Europe/Amsterdam', day: 'numeric', month: 'long', year: 'numeric' });
  return { reqNl: ok ? `uw verzoek van ${dayOf('nl-NL')}` : 'uw verzoek', reqEn: ok ? `your request of ${dayOf('en-GB')}` : 'your request' };
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
function signatureReceivedEmail({ signedCount, partyCount, complete, envelopeId, resultUrl, sentAt }) {
  // Which request: the day it was sent, since the file name may not travel
  // to the mail provider (acceptatie 3.1.1, taal #45). "Alle 2" reads as
  // "beide" (#20).
  const n = Math.max(0, parseInt(signedCount, 10) || 0);
  const m = Math.max(1, parseInt(partyCount, 10) || 1);
  const safeResult = complete && /^https:\/\/[^\s#]+\/co-sign\?result=[A-Za-z0-9_-]{43}$/.test(String(resultUrl || '')) ? String(resultUrl) : '';
  const dashUrl = safeResult || `${BASE_URL}/dashboard`;
  const heeft = n === 1 ? 'heeft' : 'hebben';
  const has = n === 1 ? 'has' : 'have';
  const { reqNl, reqEn } = requestNames(sentAt);
  const allNl = m === 2 ? 'Beide ondertekenaars hebben' : `Alle ${m} ondertekenaars hebben`;
  const allEn = m === 2 ? 'Both signers have' : `All ${m} signers have`;
  const W = {
    nl: complete ? {
      heading: 'Iedereen heeft getekend',
      line: m === 1 ? `De ondertekenaar heeft het document van ${reqNl} getekend.` : `${allNl} het document van ${reqNl} getekend.`,
      next: safeResult
        ? 'Open het document met alle handtekeningen en download het bewijs. Log in met het account waarmee u het verzoek verstuurde. De link werkt 30 dagen.'
        : 'Het getekende document en het bewijs staan bij uw documenten.',
      pre: 'Uw document is door iedereen ondertekend.',
      subject: 'Iedereen heeft getekend',
    } : {
      heading: 'Er is getekend',
      line: `${n} van de ${m} ondertekenaars van ${reqNl} ${heeft} nu getekend.`,
      next: 'U krijgt weer bericht als de volgende tekent.',
      pre: `${n} van de ${m} ondertekenaars ${heeft} getekend.`,
      subject: `Er is getekend (${n} van ${m})`,
    },
    en: complete ? {
      heading: 'Everyone has signed',
      line: m === 1 ? `The signer has signed the document of ${reqEn}.` : `${allEn} signed the document of ${reqEn}.`,
      next: safeResult
        ? 'Open the document with every signature and download the proof. Sign in with the account you sent the request from. The link works for 30 days.'
        : 'The signed document and its proof are with your documents.',
      pre: 'Your document has been signed by everyone.',
      subject: 'Everyone has signed',
    } : {
      heading: 'Someone signed',
      line: `${n} of ${m} signers of ${reqEn} ${has} now signed.`,
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
    nl: { heading: 'Iedereen heeft getekend', line: m ? `${m === 2 ? 'Beide ondertekenaars hebben' : `Alle ${m} ondertekenaars hebben`} het document getekend dat u ook tekende.` : 'Iedereen heeft het document getekend dat u ook tekende.',
      next: 'Open de link uit uw uitnodiging en log in met dit e-mailadres. Daar downloadt u het complete document met alle handtekeningen en het bewijs.', pre: 'Het document is door iedereen ondertekend.', subject: 'Iedereen heeft getekend' },
    en: { heading: 'Everyone has signed', line: m ? `${m === 2 ? 'Both signers have' : `All ${m} signers have`} now signed the document you signed.` : 'Everyone has now signed the document you signed.',
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
function signatureDeclinedEmail({ envelopeId, sentAt }) {
  const dashUrl = `${BASE_URL}/dashboard`;
  const { reqNl, reqEn } = requestNames(sentAt);
  const W = {
    nl: { heading: 'Verzoek geweigerd', line: `Een ondertekenaar heeft ${reqNl} geweigerd. Het verzoek is daarmee gestopt. Niemand kan nog tekenen.`, next: 'Bij uw documenten ziet u wie het was. Wilt u het opnieuw proberen? Stuur dan een nieuw verzoek.', open: 'Naar mijn documenten', subject: 'Verzoek geweigerd' },
    en: { heading: 'Request declined', line: `A signer declined ${reqEn}. The request has stopped, and nobody can sign it any more.`, next: 'Your documents show who it was. To try again, send a new request.', open: 'Go to my documents', subject: 'Request declined' },
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

// To an invited party, when the request stopped before everyone signed: the
// sender withdrew it, or another party declined (acceptatie 3.1.1, taal #42).
// No names, no file name, no envelope id, like every mail in this family.
function requestStoppedPartyEmail({ reason, envelopeId }) {
  // Three reasons, each in its own words. Anything that is not a decline used
  // to read "ingetrokken door de afzender", so an expired request would have
  // blamed the sender for a deadline (acceptatie 3.1.1, taal #42).
  const kind = reason === 'declined' ? 'declined' : reason === 'expired' ? 'expired' : 'withdrawn';
  const W = {
    nl: {
      heading: { declined: 'Het verzoek is gestopt', expired: 'Het verzoek is verlopen', withdrawn: 'Het verzoek is ingetrokken' }[kind],
      line: {
        declined: 'Een andere ondertekenaar heeft het verzoek geweigerd dat u ook kreeg. Daarmee is het gestopt. Niemand kan nog tekenen.',
        expired: 'De termijn om te tekenen is voorbij voordat iedereen had getekend. Niemand kan nog tekenen.',
        withdrawn: 'De afzender heeft het verzoek ingetrokken dat u kreeg. Niemand kan nog tekenen.',
      }[kind],
      next: 'U hoeft niets te doen. Handtekeningen die al gezet zijn, blijven vastgelegd. Heeft u vragen? Neem dan contact op met de afzender.',
      subject: { declined: 'Verzoek gestopt', expired: 'Verzoek verlopen', withdrawn: 'Verzoek ingetrokken' }[kind],
    },
    en: {
      heading: { declined: 'The request has stopped', expired: 'The request has expired', withdrawn: 'The request was withdrawn' }[kind],
      line: {
        declined: 'Another signer declined the request you also received. That stopped it, and nobody can sign it any more.',
        expired: 'The time to sign ran out before everyone had signed. Nobody can sign it any more.',
        withdrawn: 'The sender withdrew the request you received. Nobody can sign it any more.',
      }[kind],
      next: 'You do not need to do anything. Signatures already given stay on record. Questions? Contact the sender.',
      subject: { declined: 'Request stopped', expired: 'Request expired', withdrawn: 'Request withdrawn' }[kind],
    },
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
  const html = htmlShell(`${W.nl.line} ${W.en.line}`,
    htmlBlock('nl', true) + '\n    <hr style="margin:32px 0 0 0;border:0;border-top:1px solid #E2E8F0;">' + htmlBlock('en', false),
    'nl');
  return {
    ...wrap(text, html, { refId: 'stopped-' + refIdHash(`${envelopeId}:${reason}`) }),
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
  requestStoppedPartyEmail,
  billingConfirmationEmail,
  productPlanChangeEmail,
  billingCancellationEmail,
  keyDisabledEmail,
  accountDeletionEmail,
  sendEmail,
  FROM_ADDR,
  BASE_URL,
};

'use strict';

const BASE_URL = process.env.SITE_URL || 'https://paramant.app';
const FROM_ADDR = 'Paramant <hello@paramant.app>';

const maskIP = (ip) => {
  if (!ip) return 'unknown';
  const m = ip.match(/^(\d+\.\d+)\.\d+\.\d+$/);
  if (m) return m[1] + '.xxx.xxx';
  return ip.slice(0, 8) + '...';
};

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

function htmlShell(preheader, bodyHtml) {
  return `<!DOCTYPE html>
<html lang="en">
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
        <p style="margin:0 0 8px 0;">Paramant &mdash; post-quantum encrypted file relay.</p>
        <p style="margin:0;"><a href="https://paramant.app" style="color:#1D4ED8;text-decoration:none;">paramant.app</a> &middot; <a href="https://paramant.app/security" style="color:#1D4ED8;text-decoration:none;">Security</a> &middot; <a href="https://paramant.app/help" style="color:#1D4ED8;text-decoration:none;">Help</a></p>
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

// ── 1. SETUP EMAIL ────────────────────────────────────────────────────────────
function setupEmail({ token, requestedAt, requestIP, isReset = false }) {
  const url = `${BASE_URL}/auth/setup/${token}`;
  const preheader = isReset
    ? 'Your TOTP authenticator has been cleared. Scan the QR code to re-enroll.'
    : 'Scan the QR code with your authenticator app to finish signup.';

  const resetWarn = isReset
    ? '\nIMPORTANT: delete your old Paramant entry from your authenticator app\nbefore scanning the new QR code — the old entry no longer works.\n'
    : '';

  const text = `Hi,

${isReset ? 'Your TOTP authenticator has been reset.' : 'Welcome to Paramant.'} To ${isReset ? 'reset your' : 'finish setting up your'} account,
connect an authenticator app. This is what Paramant uses instead of a password.

Complete setup:
${url}
${resetWarn}
The link opens a page with a QR code. Scan it with your authenticator app
(Google Authenticator, Authy, 1Password, or any TOTP app). You can also
enter the secret manually if scanning does not work.

This link is valid for 14 days.

Why an authenticator?

Passwords get reused, stolen, or phished. A TOTP code from your phone
cannot be typed into a fake site or intercepted in a credential dump.
It is the same mechanism your bank uses.

After setup you receive 10 backup codes. Save them somewhere safe
(password manager, printed copy in a drawer) in case you lose your phone.

${isReset ? 'Did not request this reset? Contact support immediately at hello@paramant.app.' : 'Did not sign up for Paramant? Ignore this email. No account is created until you complete setup.'}

Request details:
  Time:    ${formatTS(requestedAt || Date.now())}
  From IP: ${maskIP(requestIP)}

Paramant
https://paramant.app`;

  const resetBanner = isReset
    ? `<div style="background:#FEF3C7;border-left:3px solid #D97706;padding:12px 16px;margin:0 0 20px 0;">
        <p style="margin:0;line-height:1.5;color:#92400E;font-size:14px;"><strong>Authenticator reset.</strong> Delete the old Paramant entry from your app before scanning the new QR code &mdash; the old entry no longer works.</p>
      </div>`
    : '';

  const html = htmlShell(preheader, `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">${isReset ? 'Set up your new Paramant authenticator' : 'Complete your Paramant account setup'}</h1>
    ${resetBanner}
    <p style="margin:0 0 16px 0;line-height:1.6;">${isReset ? 'Your TOTP authenticator has been reset.' : 'Welcome to Paramant.'} To ${isReset ? 'reset your' : 'finish setting up your'} account, connect an authenticator app &mdash; this is what Paramant uses instead of a password.</p>
    ${btn(url, isReset ? 'Set up new authenticator' : 'Complete setup')}
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:14px;">The link opens a page with a QR code. Scan it with your authenticator app (Google Authenticator, Authy, 1Password, or any TOTP app). You can also enter the secret manually.</p>
    <p style="margin:0 0 24px 0;line-height:1.6;color:#475569;font-size:14px;">This link is valid for <strong>14 days</strong>.</p>
    <hr style="border:none;border-top:1px solid rgba(11,58,106,0.08);margin:24px 0;">
    <h2 style="margin:0 0 12px 0;font-size:14px;font-weight:600;color:#0B3A6A;">Why an authenticator?</h2>
    <p style="margin:0 0 12px 0;line-height:1.6;color:#475569;font-size:13px;">Passwords get reused, stolen, or phished. A TOTP code from your phone cannot be typed into a fake site or intercepted in a credential dump. It is the same mechanism your bank uses.</p>
    <p style="margin:0 0 24px 0;line-height:1.6;color:#475569;font-size:13px;">After setup you receive 10 backup codes. Save them somewhere safe (password manager, printed copy in a drawer) in case you lose your phone.</p>
    <hr style="border:none;border-top:1px solid rgba(11,58,106,0.08);margin:24px 0;">
    <p style="margin:0 0 8px 0;font-size:13px;color:#64748b;">${isReset ? '<strong>Did not request this reset?</strong> Contact support immediately at <a href="mailto:hello@paramant.app" style="color:#1D4ED8;">hello@paramant.app</a>.' : '<strong>Did not sign up for Paramant?</strong> Ignore this email. No account is created until you complete setup.'}</p>
    <p style="margin:16px 0 0 0;font-size:12px;color:#94a3b8;font-family:monospace;">Time: ${formatTS(requestedAt || Date.now())}<br>IP: ${maskIP(requestIP)}</p>
  `);

  return {
    ...wrap(text, html, { refId: 'setup-' + token.slice(0, 8) }),
    subject: isReset ? 'Set up your new Paramant authenticator' : 'Complete your Paramant account setup',
  };
}

// ── 2. RESET CONFIRMATION EMAIL ───────────────────────────────────────────────
function resetConfirmationEmail({ confirmToken, requestedAt, requestIP }) {
  const url = `${BASE_URL}/auth/reset-confirm/${confirmToken}`;
  const preheader = 'Confirm that you requested a TOTP authenticator reset — link expires in 1 hour.';

  const text = `Hi,

Someone requested a reset of your Paramant authenticator (TOTP).

If this was you, click the link below to confirm. You will then receive
a second email with your new authenticator setup link.

Confirm reset:
${url}

This link is valid for 1 hour.

If you did not request this, ignore this email. Nothing will change.
Your current authenticator keeps working as normal.

Why two emails?

This two-step flow protects you from accidental or malicious resets.
An attacker who knows your email address alone cannot force a reset —
they would also need access to your inbox to click this link.

Request details:
  Time: ${formatTS(typeof requestedAt === 'number' ? requestedAt : Date.parse(requestedAt))}
  IP:   ${requestIP || 'unknown'}

Paramant
https://paramant.app`;

  const html = htmlShell(preheader, `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Did you request a TOTP reset?</h1>
    <p style="margin:0 0 16px 0;line-height:1.6;">Someone requested a reset of your Paramant authenticator (TOTP).</p>
    <p style="margin:0 0 16px 0;line-height:1.6;">If this was you, click below to confirm. You will then receive a second email with your new authenticator setup link.</p>
    ${btn(url, 'Confirm TOTP reset')}
    <p style="margin:0 0 24px 0;line-height:1.6;color:#475569;font-size:14px;">This link is valid for <strong>1 hour</strong>.</p>
    <div style="background:#F0F9FF;border-left:3px solid #1D4ED8;padding:12px 16px;margin:0 0 24px 0;">
      <p style="margin:0;line-height:1.5;color:#0B3A6A;font-size:14px;"><strong>Did not request this?</strong> Ignore this email. Nothing will change. Your current authenticator keeps working as normal.</p>
    </div>
    <hr style="border:none;border-top:1px solid rgba(11,58,106,0.08);margin:24px 0;">
    <h2 style="margin:0 0 12px 0;font-size:14px;font-weight:600;color:#0B3A6A;">Why two emails?</h2>
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:13px;">This two-step flow protects you from accidental or malicious resets. An attacker who knows your email address alone cannot force a reset &mdash; they would also need access to your inbox to click this link.</p>
    <p style="margin:16px 0 0 0;font-size:12px;color:#94a3b8;font-family:monospace;">
      Time: ${formatTS(typeof requestedAt === 'number' ? requestedAt : Date.parse(requestedAt))}<br>
      IP: ${requestIP || 'unknown'}
    </p>
  `);

  return {
    ...wrap(text, html, { refId: 'reset-confirm-' + confirmToken.slice(0, 8) }),
    subject: 'Did you request a TOTP reset? — Paramant',
  };
}

// ── 3. WELCOME / API KEY EMAIL ────────────────────────────────────────────────
function welcomeEmail({ apiKey, plan, label, sectors }) {
  const preheader = 'Your Paramant API key is ready. Store it securely.';
  const masked = apiKey.slice(0, 12) + '...' + apiKey.slice(-4);

  const text = `Hi,

Your Paramant API key has been created.

Plan:    ${plan}
Label:   ${label || '(unlabeled)'}
Sectors: ${(sectors || []).join(', ') || 'all'}
Key:     ${masked}

The full key was provided separately by the administrator who issued it.

What you can do now:

1. Use the key in the X-Api-Key header when calling the Paramant relay
2. Documentation: https://paramant.app/docs/api
3. Extensions: https://paramant.app/extensions

Storing your key safely:

- Use a password manager — do not store it in plain text
- Do not commit it to source control (.env files get leaked)
- Rotate it immediately if you suspect exposure

Questions? Reply to this email.

Paramant
https://paramant.app`;

  const html = htmlShell(preheader, `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Your Paramant API key is ready</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">An administrator has issued a Paramant API key for your account.</p>
    <table style="border-collapse:collapse;margin:0 0 24px 0;width:100%;">
      <tr><td style="padding:8px 16px 8px 0;color:#64748b;font-family:monospace;font-size:11px;text-transform:uppercase;letter-spacing:0.1em;white-space:nowrap;">Plan</td><td style="padding:8px 0;"><span style="background:rgba(29,78,216,0.08);color:#1D4ED8;padding:2px 8px;font-size:12px;font-family:monospace;">${plan}</span></td></tr>
      <tr><td style="padding:8px 16px 8px 0;color:#64748b;font-family:monospace;font-size:11px;text-transform:uppercase;letter-spacing:0.1em;white-space:nowrap;">Label</td><td style="padding:8px 0;">${label || '<em style="color:#94a3b8;">unlabeled</em>'}</td></tr>
      <tr><td style="padding:8px 16px 8px 0;color:#64748b;font-family:monospace;font-size:11px;text-transform:uppercase;letter-spacing:0.1em;white-space:nowrap;">Sectors</td><td style="padding:8px 0;font-family:monospace;font-size:13px;">${(sectors || []).join(', ') || 'all'}</td></tr>
      <tr><td style="padding:8px 16px 8px 0;color:#64748b;font-family:monospace;font-size:11px;text-transform:uppercase;letter-spacing:0.1em;white-space:nowrap;">Key (masked)</td><td style="padding:8px 0;font-family:monospace;font-size:13px;color:#0B3A6A;">${masked}</td></tr>
    </table>
    <p style="margin:0 0 24px 0;line-height:1.6;color:#475569;font-size:14px;">The full key was provided separately by the administrator who issued it.</p>
    <h2 style="margin:0 0 12px 0;font-size:14px;font-weight:600;color:#0B3A6A;">What you can do now</h2>
    <ul style="margin:0 0 24px 0;padding-left:20px;line-height:1.8;color:#475569;font-size:14px;">
      <li>Use the key in the <code style="background:#f1f5f9;padding:2px 5px;font-size:12px;">X-Api-Key</code> header when calling the relay</li>
      <li>Documentation: <a href="https://paramant.app/docs/api" style="color:#1D4ED8;">paramant.app/docs/api</a></li>
      <li>Extensions: <a href="https://paramant.app/extensions" style="color:#1D4ED8;">paramant.app/extensions</a></li>
    </ul>
    <hr style="border:none;border-top:1px solid rgba(11,58,106,0.08);margin:24px 0;">
    <h2 style="margin:0 0 12px 0;font-size:14px;font-weight:600;color:#0B3A6A;">Storing your key safely</h2>
    <ul style="margin:0 0 16px 0;padding-left:20px;line-height:1.7;color:#475569;font-size:13px;">
      <li>Use a password manager &mdash; do not store it in plain text</li>
      <li>Do not commit it to source control (.env files get leaked)</li>
      <li>Rotate it immediately if you suspect exposure</li>
    </ul>
    <p style="margin:16px 0 0 0;color:#475569;font-size:14px;">Questions? Reply to this email.</p>
  `);

  return {
    ...wrap(text, html, { refId: 'welcome-' + apiKey.slice(0, 8) }),
    subject: 'Your Paramant API key is ready',
  };
}

// ── 4. BILLING CONFIRMATION ───────────────────────────────────────────────────
function billingConfirmationEmail({ planName, period, amountStr, stub = true }) {
  const preheader = `Your Paramant plan is now ${planName}.`;
  const periodLabel = period === 'yearly' ? 'Yearly' : period === 'monthly' ? 'Monthly' : 'Admin-provisioned';

  const text = `Hi,

Your Paramant plan has been upgraded.

Plan:    ${planName}
Billing: ${periodLabel}
Amount:  ${amountStr || 'N/A'}
${stub ? '\nNote: payment processing is in beta. This confirmation reflects the\nplan change on your account. Formal invoicing follows when Stripe\nintegration goes live.\n' : ''}
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
    ${stub ? '<div style="background:#FEF3C7;border-left:3px solid #D97706;padding:12px 16px;margin:24px 0;"><p style="margin:0;line-height:1.5;color:#92400E;font-size:13px;"><strong>Beta note:</strong> payment processing is not yet live. This confirmation reflects the plan change on your account. Formal invoicing follows when Stripe integration goes live.</p></div>' : ''}
    <p style="margin:16px 0 0 0;line-height:1.6;color:#475569;font-size:14px;">Questions about billing? Reply to this email.</p>
  `);

  return {
    ...wrap(text, html, { refId: 'billing-' + Date.now() }),
    subject: `Paramant plan upgraded to ${planName}`,
  };
}

// ── 5. BILLING CANCELLATION ───────────────────────────────────────────────────
function billingCancellationEmail({ planName, cancelDate }) {
  const preheader = `Your ${planName} plan ends on ${cancelDate}.`;

  const text = `Hi,

We have scheduled the cancellation of your Paramant ${planName} plan.

Ends on: ${cancelDate}

You keep ${planName} access until that date. After that, your account
reverts to the Community plan.

Your API key continues to work. Files you have already relayed are
not affected. Sector access adjusts to Community tier limits.

Changed your mind? Reply to this email before the end date to reactivate.

Paramant
https://paramant.app`;

  const html = htmlShell(preheader, `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Cancellation scheduled</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">We have scheduled the cancellation of your Paramant ${planName} plan.</p>
    <div style="background:#F8FAFC;border:1px solid rgba(11,58,106,0.1);padding:16px 20px;margin:0 0 24px 0;">
      <p style="margin:0 0 6px 0;font-family:monospace;font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:0.1em;">Ends on</p>
      <p style="margin:0;font-size:16px;font-weight:500;color:#0B3A6A;">${cancelDate}</p>
    </div>
    <ul style="margin:0 0 24px 0;padding-left:20px;line-height:1.8;color:#475569;font-size:14px;">
      <li>You keep <strong>${planName}</strong> access until that date</li>
      <li>After that, your account reverts to the <strong>Community</strong> plan</li>
      <li>Your API key continues to work</li>
      <li>Files you have already relayed are not affected</li>
      <li>Sector access adjusts to Community tier limits</li>
    </ul>
    <p style="margin:0 0 16px 0;line-height:1.6;color:#475569;font-size:14px;">Changed your mind? Reply to this email before the end date to reactivate.</p>
  `);

  return {
    ...wrap(text, html, { refId: 'cancel-' + Date.now() }),
    subject: 'Your Paramant plan cancellation is scheduled',
  };
}

// ── 6. ACCOUNT DELETION ───────────────────────────────────────────────────────
function accountDeletionEmail({ email, deletedAt, reason }) {
  const preheader = 'Your Paramant account has been deleted.';
  const dateStr = formatTS(typeof deletedAt === 'number' ? deletedAt : Date.parse(deletedAt));

  const text = `Hi,

Your Paramant account (${email}) was deleted on ${dateStr}.

What this means:
- API key no longer works
- Active sessions terminated
- Personal data removed from our systems
- Audit logs retained for 90 days per compliance policy
- Files already relayed are not affected (end-to-end encrypted)

Reason: ${reason || 'not specified'}

If this was a mistake or you want to return later, sign up again
at https://paramant.app/signup with a new account.

Paramant
https://paramant.app`;

  const html = htmlShell(preheader, `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Account deleted</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">Your Paramant account (${email}) was deleted on <strong>${dateStr}</strong>.</p>
    <h2 style="margin:24px 0 12px 0;font-size:14px;font-weight:600;color:#0B3A6A;">What this means</h2>
    <ul style="margin:0 0 24px 0;padding-left:20px;line-height:1.8;color:#475569;font-size:14px;">
      <li>API key no longer works</li>
      <li>Active sessions terminated</li>
      <li>Personal data removed from our systems</li>
      <li>Audit logs retained for 90 days per compliance policy</li>
      <li>Files already relayed are not affected (end-to-end encrypted)</li>
    </ul>
    <div style="background:#F8FAFC;border:1px solid rgba(11,58,106,0.1);padding:12px 16px;margin:0 0 24px 0;">
      <p style="margin:0;font-size:13px;color:#475569;"><strong>Reason:</strong> ${reason || 'not specified'}</p>
    </div>
    <p style="margin:16px 0 0 0;line-height:1.6;color:#475569;font-size:14px;">If this was a mistake or you want to return later, <a href="https://paramant.app/signup" style="color:#1D4ED8;">sign up again</a> with a new account.</p>
  `);

  return { ...wrap(text, html, { refId: 'deletion-' + Date.now() }), subject: 'Your Paramant account has been deleted' };
}

// ── SIGNUP VERIFICATION EMAIL ────────────────────────────────────────────────
function signupVerificationEmail({ email, token, requestedAt, requestIP }) {
  const url = `${BASE_URL}/api/user/signup/verify/${token}`;
  const dateStr = formatTS(requestedAt);
  const maskedIp = maskIP(requestIP);

  const preheader = 'Confirm your email to activate your Paramant account.';
  const text = [
    'Verify your Paramant account',
    '',
    `You requested an account for ${email}.`,
    `Click the link below to verify your email and activate your account:`,
    '',
    url,
    '',
    'This link expires in 24 hours. If you did not request this, you can safely ignore this email.',
    '',
    `Requested: ${dateStr}${requestIP ? ' · IP: ' + maskedIp : ''}`,
    '',
    '— Paramant',
  ].join('\n');

  const html = htmlShell(preheader, `
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Verify your email</h1>
    <p style="margin:0 0 20px 0;line-height:1.6;">
      You requested a Paramant account for <strong>${email}</strong>. Click the button below to confirm your email address and activate your account.
    </p>
    <div style="text-align:center;margin:0 0 28px 0;">
      <a href="${url}" style="display:inline-block;background:#1D4ED8;color:#ffffff;font-size:15px;font-weight:600;padding:14px 32px;border-radius:6px;text-decoration:none;letter-spacing:0.01em;">Verify email &amp; activate account</a>
    </div>
    <p style="margin:0 0 8px 0;font-size:13px;color:#64748B;">
      Or copy this link into your browser:<br>
      <a href="${url}" style="color:#1D4ED8;word-break:break-all;">${url}</a>
    </p>
    <div style="background:#F8FAFC;border:1px solid rgba(11,58,106,0.08);padding:12px 16px;margin:24px 0 0 0;border-radius:4px;">
      <p style="margin:0;font-size:12px;color:#94A3B8;line-height:1.6;">
        This link expires in <strong>24 hours</strong>. If you did not request a Paramant account, ignore this email — no account will be created.
        <br>Requested ${dateStr}${requestIP ? ' · IP: ' + maskedIp : ''}.
      </p>
    </div>
  `);

  return { ...wrap(text, html, { refId: 'verify-' + token.slice(0, 8) }), subject: 'Verify your Paramant account' };
}

// ── BACKUP CODES RESET NOTIFICATION ─────────────────────────────────────────
function backupCodesResetEmail({ email, requestedAt }) {
  const dateStr = formatTS(requestedAt);
  const preheader = 'Your Paramant backup codes have been reset. Action required.';

  const text = [
    'Security notification: Paramant backup codes reset',
    '',
    `This is a security notification for ${email}.`,
    '',
    'During an internal security audit we identified that backup codes were retained',
    'in a format that did not meet our zero-knowledge standard. We have fixed the issue',
    'and invalidated the affected backup codes as a precaution.',
    '',
    'Your TOTP authenticator continues to work normally.',
    'Only your offline backup codes were affected.',
    '',
    'Action required:',
    '  Sign in to your account and generate a new set of backup codes.',
    '  Store them in your password manager.',
    '',
    `Detected: ${dateStr}`,
    'No evidence of external access. This notification is precautionary.',
    '',
    'Questions: privacy@paramant.app',
    '',
    '— Paramant',
  ].join('\n');

  const html = htmlShell(preheader, `
    <div style="background:#FEF2F2;border:1px solid #FECACA;padding:16px;border-radius:4px;margin:0 0 24px 0;">
      <p style="margin:0;font-size:13px;font-weight:600;color:#991B1B;">Security notification</p>
    </div>
    <h1 style="margin:0 0 16px 0;font-size:22px;font-weight:500;color:#0B3A6A;">Backup codes reset</h1>
    <p style="margin:0 0 16px 0;line-height:1.6;">
      During an internal security audit, we identified that your backup codes were retained in a format that did not meet our zero-knowledge standard.
      We fixed the issue and invalidated the affected codes as a precaution.
    </p>
    <p style="margin:0 0 16px 0;line-height:1.6;">
      <strong>Your TOTP authenticator continues to work normally.</strong> Only your offline backup codes were affected.
    </p>
    <div style="background:#F8FAFC;border:1px solid rgba(11,58,106,0.1);padding:16px;margin:0 0 24px 0;border-radius:4px;">
      <p style="margin:0 0 8px 0;font-weight:600;color:#0B3A6A;">Action required</p>
      <p style="margin:0;color:#475569;font-size:14px;line-height:1.6;">Sign in to your account and generate a new set of backup codes. Store them in your password manager.</p>
    </div>
    <div style="text-align:center;margin:0 0 24px 0;">
      <a href="${BASE_URL}/account" style="display:inline-block;background:#1D4ED8;color:#ffffff;font-size:15px;font-weight:600;padding:14px 32px;border-radius:6px;text-decoration:none;">Go to account</a>
    </div>
    <div style="border-top:1px solid rgba(11,58,106,0.08);padding-top:16px;margin-top:8px;">
      <p style="margin:0;font-size:12px;color:#94A3B8;line-height:1.6;">
        Detected ${formatTS(requestedAt)}. No evidence of external access — this is precautionary.
        Questions: <a href="mailto:privacy@paramant.app" style="color:#1D4ED8;">privacy@paramant.app</a>
      </p>
    </div>
  `);

  return { ...wrap(text, html, { refId: 'backup-reset-' + requestedAt }), subject: 'Paramant backup codes reset — action required' };
}

// ── SEND HELPER ───────────────────────────────────────────────────────────────
async function sendEmail(to, templateResult) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) throw new Error('RESEND_API_KEY not set');
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: templateResult.from || FROM_ADDR,
      to: [to],
      subject: templateResult.subject,
      html: templateResult.html,
      text: templateResult.text,
      headers: templateResult.headers || {},
    }),
  });
  if (!res.ok) throw new Error(`Resend ${res.status}: ${await res.text().catch(() => '')}`);
}

module.exports = {
  backupCodesResetEmail,
  setupEmail,
  signupVerificationEmail,
  resetConfirmationEmail,
  welcomeEmail,
  billingConfirmationEmail,
  billingCancellationEmail,
  accountDeletionEmail,
  sendEmail,
  FROM_ADDR,
  BASE_URL,
};

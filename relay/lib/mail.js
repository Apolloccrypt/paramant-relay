'use strict';

// One way out for every message Paramant sends.
//
// WHY THIS EXISTS. Paramant sells European storage and no US cloud statute, and
// says so in the footer of its own mail. Meanwhile every invitation, pickup
// notice and trial key went straight to a US provider, carrying the recipient's
// address and the document name. That is the half-told story this product
// criticises in others.
//
// It also stopped being a side channel. A send to a named group is up to thirty
// personal mails with a token each, so delivery is now part of whether the
// product works at all.
//
// So: callers describe a message, this file decides who carries it. Swapping
// provider becomes an environment variable instead of a rebuild, and nothing
// above this line has to know the difference.
//
// PROVIDERS. Every one speaks plain HTTPS+JSON, so there is no new dependency
// and no SMTP library in a codebase that has to stay auditable.
//   scaleway  Transactional Email. French company, French/Dutch regions, no
//             parent outside the EU. The straight answer for a product whose
//             whole claim is continental.
//   resend    what runs today. Kept so the switch is reversible in one setting.
//   dryrun    writes the message to the log and returns ok. For a relay that
//             must not mail during tests or a rehearsal.
//
// Choosing one is MAIL_PROVIDER. Anything unknown falls back to dryrun rather
// than silently picking a provider the operator did not ask for.

const PROVIDERS = ['scaleway', 'resend', 'dryrun'];

function config(env) {
  const e = env || process.env;
  const naam = String(e.MAIL_PROVIDER || 'resend').trim().toLowerCase();
  return {
    provider: PROVIDERS.includes(naam) ? naam : 'dryrun',
    gevraagd: naam,
    from: e.MAIL_FROM || 'PARAMANT <noreply@paramant.app>',
    resendKey: e.RESEND_API_KEY || '',
    scalewayKey: e.SCALEWAY_SECRET_KEY || '',
    scalewayProject: e.SCALEWAY_PROJECT_ID || '',
    scalewayRegion: e.SCALEWAY_REGION || 'fr-par',
  };
}

// A message the rest of the codebase can describe without knowing the carrier.
// Returns the normalised form, or throws with a reason a log can be read by.
function normaliseer(msg) {
  const naar = []
    .concat(msg && msg.to ? msg.to : [])
    .map(v => String(v || '').trim())
    .filter(Boolean);
  if (!naar.length) throw new Error('mail: no recipient');
  const onderwerp = String((msg && msg.subject) || '').trim();
  if (!onderwerp) throw new Error('mail: no subject');
  const html = (msg && msg.html) || '';
  const text = (msg && msg.text) || '';
  if (!html && !text) throw new Error('mail: no body');
  // { filename, content } with content base64. One caller uses it, the invoice
  // mail, and it must survive a provider swap or that invoice arrives empty.
  const bijlagen = [].concat((msg && msg.attachments) || [])
    .filter(a => a && a.filename && a.content);
  return {
    to: naar,
    cc: [].concat((msg && msg.cc) || []).map(v => String(v || '').trim()).filter(Boolean),
    subject: onderwerp,
    html,
    text,
    attachments: bijlagen,
    from: (msg && msg.from) || null,
    replyTo: (msg && (msg.replyTo || msg.reply_to)) || null,
    headers: (msg && msg.headers) || null,
  };
}

// Scaleway Transactional Email. One address per call in their model, so a
// message to several people becomes several calls; the caller sees one result.
async function viaScaleway(m, cfg, fetchImpl) {
  if (!cfg.scalewayKey || !cfg.scalewayProject) {
    return { ok: false, provider: 'scaleway', reason: 'not_configured' };
  }
  const url = `https://api.scaleway.com/transactional-email/v1alpha1/regions/${encodeURIComponent(cfg.scalewayRegion)}/emails`;
  const afzender = ontleedAfzender(m.from || cfg.from);
  for (const adres of m.to) {
    const resp = await fetchImpl(url, {
      method: 'POST',
      headers: { 'X-Auth-Token': cfg.scalewayKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: { email: afzender.email, name: afzender.name },
        to: [{ email: adres }],
        subject: m.subject,
        text: m.text || stripHtml(m.html),
        html: m.html || undefined,
        project_id: cfg.scalewayProject,
        // Scaleway carries extra headers rather than a dedicated reply-to
        // field, and Reply-To is a normal header, so it rides along there.
        // Verify this on the first live send before trusting it in production.
        additional_headers: bouwHeaders(m),
        attachments: m.attachments.length
          ? m.attachments.map(a => ({
              name: a.filename,
              type: a.type || 'application/octet-stream',
              content: a.content,
            }))
          : undefined,
      }),
    });
    if (!resp || !resp.ok) {
      const body = resp && resp.text ? await resp.text().catch(() => '') : '';
      return { ok: false, provider: 'scaleway', reason: 'http_' + ((resp && resp.status) || 0),
               detail: String(body).slice(0, 200) };
    }
  }
  return { ok: true, provider: 'scaleway', count: m.to.length };
}

// What runs today. Unchanged behaviour, now behind the same door.
async function viaResend(m, cfg, fetchImpl) {
  if (!cfg.resendKey) return { ok: false, provider: 'resend', reason: 'not_configured' };
  const resp = await fetchImpl('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + cfg.resendKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: m.from || cfg.from,
      to: m.to,
      cc: m.cc.length ? m.cc : undefined,
      subject: m.subject,
      html: m.html || undefined,
      text: m.text || undefined,
      replyTo: m.replyTo || undefined,
      headers: m.headers || undefined,
      attachments: m.attachments.length ? m.attachments : undefined,
    }),
  });
  if (!resp || !resp.ok) {
    const body = resp && resp.text ? await resp.text().catch(() => '') : '';
    return { ok: false, provider: 'resend', reason: 'http_' + ((resp && resp.status) || 0),
             detail: String(body).slice(0, 200) };
  }
  return { ok: true, provider: 'resend', count: m.to.length };
}

function viaDryrun(m) {
  return Promise.resolve({ ok: true, provider: 'dryrun', count: m.to.length, delivered: false });
}

// Extra headers for a carrier that has no dedicated reply-to field. Reply-To is
// an ordinary header, so a message keeps its behaviour whoever carries it.
function bouwHeaders(m) {
  const uit = Object.assign({}, m.headers || {});
  if (m.replyTo && !uit['Reply-To'] && !uit['reply-to']) uit['Reply-To'] = m.replyTo;
  return Object.keys(uit).length ? uit : undefined;
}

// "PARAMANT <noreply@paramant.app>" -> { name, email }
function ontleedAfzender(waarde) {
  const s = String(waarde || '').trim();
  const m = s.match(/^\s*(.*?)\s*<([^>]+)>\s*$/);
  if (m) return { name: m[1].replace(/^"|"$/g, '') || undefined, email: m[2].trim() };
  return { name: undefined, email: s };
}

// A plain-text fallback so a message is never body-less for a reader who blocks
// HTML, and so providers that require text have something real to send.
function stripHtml(html) {
  return String(html || '')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|h\d|li|tr)>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// Send one message. Never throws for a delivery problem: it returns a result
// the caller can log and act on, because a failed notification must not take
// down the request that triggered it.
async function stuur(msg, opts) {
  const o = opts || {};
  const cfg = o.config || config(o.env);
  const fetchImpl = o.fetch || globalThis.fetch;
  let m;
  try {
    m = normaliseer(msg);
  } catch (e) {
    return { ok: false, provider: cfg.provider, reason: 'invalid', detail: e.message };
  }
  if (typeof fetchImpl !== 'function' && cfg.provider !== 'dryrun') {
    return { ok: false, provider: cfg.provider, reason: 'no_fetch' };
  }
  try {
    if (cfg.provider === 'scaleway') return await viaScaleway(m, cfg, fetchImpl);
    if (cfg.provider === 'resend') return await viaResend(m, cfg, fetchImpl);
    return await viaDryrun(m);
  } catch (e) {
    return { ok: false, provider: cfg.provider, reason: 'threw',
             detail: String((e && e.message) || e).slice(0, 200) };
  }
}

// Can this relay send mail at all? Callers used to ask "is RESEND_API_KEY set",
// which after the switch would refuse to send over a perfectly configured
// Scaleway account. Ask the question about mail, not about one carrier.
function gereed(env) {
  const cfg = config(env);
  if (cfg.provider === 'dryrun') return true;
  if (cfg.provider === 'scaleway') return Boolean(cfg.scalewayKey && cfg.scalewayProject);
  return Boolean(cfg.resendKey);
}

module.exports = { PROVIDERS, config, normaliseer, stripHtml, ontleedAfzender, stuur, gereed };

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
//   mailjet   THE ONE WE USE. Mailjet SAS, Paris, owned by Sinch AB of Sweden:
//             European company, European parent, no US entity anywhere in the
//             chain and therefore nothing for the CLOUD Act to reach. Their own
//             security page states customer data is "stored in secure data
//             centers located exclusively within the European Union", and they
//             hold ISO 27001 plus the AFNOR GDPR certification.
//             It is also the one that can actually be switched on: 6,000 mails
//             a month with NO CARD AT SIGN-UP, which is precisely where
//             Scaleway stopped. A provider you cannot pay is not a provider.
//             Two others were measured and dropped: Bird (Amsterdam on paper,
//             but its mail runs on AWS with the US as default and Ireland as an
//             option, prices in dollars only) and OVHcloud, which turns out to
//             have no transactional send product at all -- only mailbox
//             hosting.
//   scaleway  Scaleway S.A.S. (Paris, iliad Group). On paper the best of the
//             lot: the whole TEM stack runs in fr-par with no non-EU
//             sub-processor at all, and EUR 0.25 per 1,000 makes it an order of
//             magnitude cheaper. It is kept wired up for the day the door
//             opens. Today it does not: their terms refuse "all virtual payment
//             or prepaid cards", a valid credit card must be on file BEFORE a
//             SEPA mandate can be added and cannot be removed afterwards, and
//             anything past 10,000 mails a month needs a KYC that asks a Dutch
//             BV for a signed statement on letterhead with a company stamp.
//             That is exactly where this account stopped.
//   resend    what ran before. US company, and that is the whole reason to
//             leave. Kept only so the switch is reversible in one setting while
//             the new sender reputation builds.
//   dryrun    writes the message to the log and returns ok. For a relay that
//             must not mail during tests or a rehearsal.
//
// Choosing one is MAIL_PROVIDER. Anything unknown falls back to dryrun rather
// than silently picking a provider the operator did not ask for.

const PROVIDERS = ['mailjet', 'scaleway', 'resend', 'dryrun'];

function config(env) {
  const e = env || process.env;
  const naam = String(e.MAIL_PROVIDER || 'mailjet').trim().toLowerCase();
  return {
    provider: PROVIDERS.includes(naam) ? naam : 'dryrun',
    gevraagd: naam,
    from: e.MAIL_FROM || 'PARAMANT <noreply@paramant.app>',
    resendKey: e.RESEND_API_KEY || '',
    mailjetKey: e.MAILJET_API_KEY || '',
    mailjetSecret: e.MAILJET_SECRET_KEY || '',
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

// Mailjet Send API v3.1. POST https://api.mailjet.com/v3.1/send with HTTP Basic
// auth over the public key and the secret.
//
// ONE MESSAGE PER ADDRESS, and that is a rule rather than a style. Mailjet will
// happily take several entries in one `To` array, and then those people see
// each other. For an invitation to collect a confidential document, who ELSE
// received it is not for the group to know -- that is the whole reason the
// caller loops per recipient upstream, and this must not undo it one layer
// down.
async function viaMailjet(m, cfg, fetchImpl) {
  if (!cfg.mailjetKey || !cfg.mailjetSecret) {
    return { ok: false, provider: 'mailjet', reason: 'not_configured' };
  }
  const afzender = ontleedAfzender(m.from || cfg.from);
  const auth = 'Basic ' + Buffer.from(cfg.mailjetKey + ':' + cfg.mailjetSecret).toString('base64');
  const beantwoord = m.replyTo ? ontleedAfzender(m.replyTo) : null;

  // Attachments: Mailjet names these Base64Content/ContentType/Filename, which
  // differs from every other provider here. Only the invoice mail sends one, so
  // if the shape is ever wrong it shows up there and nowhere else -- and it
  // shows up loudly, because a failed send is logged as mail_failed with the
  // provider's own message rather than swallowed.
  const bijlagen = m.attachments.length
    ? m.attachments.map(a => ({
        ContentType: a.type || 'application/octet-stream',
        Filename: a.filename,
        Base64Content: a.content,
      }))
    : undefined;

  const berichten = m.to.map(adres => ({
    From: { Email: afzender.email, Name: afzender.name || undefined },
    To: [{ Email: adres }],
    Cc: m.cc.length ? m.cc.map(c => ({ Email: c })) : undefined,
    Subject: m.subject,
    TextPart: m.text || stripHtml(m.html),
    HTMLPart: m.html || undefined,
    ReplyTo: beantwoord ? { Email: beantwoord.email, Name: beantwoord.name || undefined } : undefined,
    Headers: m.headers || undefined,
    Attachments: bijlagen,
  }));

  const resp = await fetchImpl('https://api.mailjet.com/v3.1/send', {
    method: 'POST',
    headers: { Authorization: auth, 'Content-Type': 'application/json' },
    body: JSON.stringify({ Messages: berichten }),
  });
  if (!resp || !resp.ok) {
    const body = resp && resp.text ? await resp.text().catch(() => '') : '';
    return { ok: false, provider: 'mailjet', reason: 'http_' + ((resp && resp.status) || 0),
             detail: String(body).slice(0, 200) };
  }
  // A 200 is not yet a delivery: Mailjet answers per message, and one address
  // can be refused while the rest go through. Reading that back is the
  // difference between "we sent thirty" and "twenty-nine left and one did not".
  let uit = null;
  try { uit = resp.json ? await resp.json() : null; } catch (e) { uit = null; }
  const regels = (uit && Array.isArray(uit.Messages)) ? uit.Messages : [];
  const mislukt = regels.filter(r => r && r.Status && r.Status !== 'success');
  if (mislukt.length) {
    return { ok: false, provider: 'mailjet', reason: 'rejected',
             detail: JSON.stringify(mislukt[0]).slice(0, 200),
             count: regels.length - mislukt.length };
  }
  return { ok: true, provider: 'mailjet', count: regels.length || m.to.length };
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

// Writes the message where an operator can see it, which is what the header of
// this file always claimed it did and what it never actually did. A rehearsal
// you cannot read is indistinguishable from mail that vanished.
function viaDryrun(m, cfg, fetchImpl, logImpl) {
  const schrijf = logImpl || ((niveau, gebeurtenis, velden) =>
    console.log(JSON.stringify({ level: niveau, event: gebeurtenis, ...velden })));
  schrijf('info', 'mail_dryrun', {
    to: m.to, subject: m.subject, from: m.from || (cfg && cfg.from) || '',
    reply_to: m.replyTo || null, bytes: (m.html || m.text || '').length,
    attachments: m.attachments.length,
  });
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

// WHO THE RECIPIENT SEES, and it is the difference between a mail somebody
// opens and one their IT department quarantines.
//
// Up to thirty people who never signed up with us get a mail about a
// confidential document. Sent as a bare "PARAMANT <noreply@paramant.app>" with
// no human in it, that mail has every marker of phishing: an unknown domain,
// no sender, no reason, one coloured button, and a six-digit code arriving
// separately from a DIFFERENT address. That is the exact shape banks spend
// their days warning people about.
//
// So the customer's name rides in the display name and Paramant stays in the
// envelope. "Anna de Vries via Paramant <post@paramant.app>" is the form
// mailing lists have used for twenty years: SPF and DKIM still pass, because
// the domain is ours, and the reader still learns who sent it. Reply-To points
// at the customer, so "who is this?" reaches the one person who can answer.
//
// The name is stripped of anything that could break the header. It comes out of
// our own key table, not off the wire, but a From line is not the place to find
// out that an assumption was wrong.
function veiligeNaam(waarde) {
  return String(waarde || '')
    .replace(/[\r\n]+/g, ' ')          // no header injection, ever
    .replace(/["\\<>]/g, '')            // no quoting games in a display name
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 60);
}

// Builds `"<name> via Paramant" <address>` from the configured MAIL_FROM and
// whatever the customer is called. No name means the plain configured sender.
function afzenderNamens(basis, naam) {
  const b = ontleedAfzender(basis);
  const schoon = veiligeNaam(naam);
  if (!schoon) return basis;
  return '"' + schoon + ' via Paramant" <' + b.email + '>';
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
    if (cfg.provider === 'mailjet') return await viaMailjet(m, cfg, fetchImpl);
    if (cfg.provider === 'scaleway') return await viaScaleway(m, cfg, fetchImpl);
    if (cfg.provider === 'resend') return await viaResend(m, cfg, fetchImpl);
    return await viaDryrun(m, cfg, fetchImpl, o.log);
  } catch (e) {
    return { ok: false, provider: cfg.provider, reason: 'threw',
             detail: String((e && e.message) || e).slice(0, 200) };
  }
}

// Can this relay send mail at all? Callers used to ask "is RESEND_API_KEY set",
// which after the switch would refuse to send over a perfectly configured
// Mailjet account. Ask the question about mail, not about one carrier.
function gereed(env) {
  const cfg = config(env);
  if (cfg.provider === 'dryrun') return true;
  if (cfg.provider === 'mailjet') return Boolean(cfg.mailjetKey && cfg.mailjetSecret);
  if (cfg.provider === 'scaleway') return Boolean(cfg.scalewayKey && cfg.scalewayProject);
  return Boolean(cfg.resendKey);
}

// Everything an operator needs to see at boot, in one object.
//
// The trap this closes: MAIL_PROVIDER with a typo falls back to dryrun, dryrun
// answers ok, and the route counts thirty invitations that never left. Nothing
// in a log said so. Now a fallback is a distinct, loud state, and the relay can
// refuse to start in it rather than mail into a drawer for a week.
function diagnose(env) {
  const cfg = config(env);
  const terugval = cfg.gevraagd && cfg.gevraagd !== cfg.provider;
  return {
    provider: cfg.provider,
    gevraagd: cfg.gevraagd || '(leeg)',
    terugval,
    gereed: gereed(env),
    stil: cfg.provider === 'dryrun',
    from: cfg.from,
    waarschuwing: terugval
      ? 'MAIL_PROVIDER is "' + cfg.gevraagd + '", which is not a provider. '
        + 'Falling back to dryrun: nothing will be delivered. Expected one of: '
        + PROVIDERS.join(', ')
      : (!gereed(env)
          ? 'MAIL_PROVIDER is "' + cfg.provider + '" but its credentials are missing.'
          : null),
  };
}

module.exports = { PROVIDERS, config, normaliseer, stripHtml, ontleedAfzender,
                   veiligeNaam, afzenderNamens, stuur, gereed, diagnose };

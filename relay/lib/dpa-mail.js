'use strict';
// The confirmation mail after an electronic DPA signature (POST /v2/sign-dpa).
// It used to be English for everyone, also for a Dutch office that signed the
// Dutch agreement on /dpa (fase 2 SITE-11-A). The page now says which language
// it was signed in (lang: 'nl' | 'en'); anything else falls back to English.

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const TEXT = {
  nl: {
    subject: (org, ref) => `Verwerkersovereenkomst ondertekend: ${org} (${ref})`,
    dear: (n) => `Beste ${n},`,
    body: (o) => `Deze e-mail bevestigt dat namens <strong style="color:#ededed">${o}</strong> een verwerkersovereenkomst (AVG art. 28) is ondertekend.`,
    details: 'Gegevens van de overeenkomst',
    ref: 'Referentie', org: 'Organisatie', who: 'Ondertekenaar', at: 'Ondertekend op', version: 'Versie',
    processor: 'Verwerker', processorValue: 'PARAMANT, Hetzner, Duitsland',
    full: (url) => `De volledige tekst staat op <a href="${url}" style="color:#888">paramant.app/dpa</a>. Bewaar deze e-mail en het referentienummer bij uw administratie.`,
    foot: 'Vragen: privacy@paramant.app &nbsp;·&nbsp; EU/DE-rechtsgebied &nbsp;·&nbsp; AVG art. 28',
    url: 'https://paramant.app/dpa',
    date: 'nl-NL',
  },
  en: {
    subject: (org, ref) => `DPA signed: ${org} (${ref})`,
    dear: (n) => `Dear ${n},`,
    body: (o) => `This email confirms that a Data Processing Agreement (GDPR Art. 28) has been signed on behalf of <strong style="color:#ededed">${o}</strong>.`,
    details: 'Agreement details',
    ref: 'Reference', org: 'Organisation', who: 'Signatory', at: 'Signed at', version: 'DPA version',
    processor: 'Processor', processorValue: 'PARAMANT, Hetzner, Germany',
    full: (url) => `The full agreement text is available at <a href="${url}" style="color:#888">paramant.app/en/dpa</a>. Keep this email and the reference number for your records.`,
    foot: 'Questions: privacy@paramant.app &nbsp;·&nbsp; EU/DE jurisdiction &nbsp;·&nbsp; GDPR Art. 28',
    url: 'https://paramant.app/en/dpa',
    date: 'en-GB',
  },
};

function dpaConfirmation({ name, title, org, ref, signed_at, version, lang }) {
  const t = TEXT[lang === 'nl' ? 'nl' : 'en'];
  const when = (() => {
    const d = new Date(signed_at);
    if (isNaN(d)) return esc(signed_at);
    return esc(d.toLocaleString(t.date, { timeZone: 'Europe/Amsterdam', dateStyle: 'long', timeStyle: 'short' })) + ' (' + esc(signed_at) + ')';
  })();
  const row = (k, v, first) => `<tr><td style="color:#555;padding:4px 0${first ? ';width:40%' : ''}">${k}</td><td style="color:#ededed">${v}</td></tr>`;
  const html = `<div style="font-family:monospace;background:#0c0c0c;color:#ededed;padding:40px;max-width:600px">
  <div style="font-size:16px;font-weight:600;margin-bottom:24px;letter-spacing:.08em">PARAMANT</div>
  <p style="color:#888;margin-bottom:16px">${t.dear(esc(name))}</p>
  <p style="color:#888;margin-bottom:24px">${t.body(esc(org))}</p>
  <div style="background:#111;border:1px solid #1a1a1a;border-radius:6px;padding:20px;margin-bottom:24px;font-size:13px">
    <div style="color:#555;font-size:11px;letter-spacing:.08em;text-transform:uppercase;margin-bottom:12px">${t.details}</div>
    <table style="width:100%;border-collapse:collapse">
      ${row(t.ref, esc(ref), true)}
      ${row(t.org, esc(org))}
      ${row(t.who, esc(name) + (title ? ', ' + esc(title) : ''))}
      ${row(t.at, when)}
      ${row(t.version, esc(version))}
      ${row(t.processor, t.processorValue)}
    </table>
  </div>
  <p style="color:#888;font-size:13px;margin-bottom:24px">${t.full(t.url)}</p>
  <p style="color:#555;font-size:12px">${t.foot}</p>
</div>`;
  return { subject: t.subject(org, ref), html };
}

module.exports = { dpaConfirmation };

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
    body: (o) => `Deze e-mail bevestigt dat namens <strong>${o}</strong> een verwerkersovereenkomst (AVG art. 28) is ondertekend.`,
    details: 'Gegevens van de overeenkomst',
    ref: 'Referentie', org: 'Organisatie', who: 'Ondertekenaar', at: 'Ondertekend op', version: 'Versie',
    processor: 'Verwerker', processorValue: 'PARAMANT, Hetzner, Duitsland',
    full: (url) => `De volledige tekst staat op <a href="${url}" style="color:#1D4ED8">paramant.app/dpa</a>. Bewaar deze e-mail en het referentienummer bij uw administratie.`,
    foot: 'Vragen: privacy@paramant.app &nbsp;·&nbsp; EU/DE-rechtsgebied &nbsp;·&nbsp; AVG art. 28',
    url: 'https://paramant.app/dpa',
    date: 'nl-NL',
    dateAt: (day, time) => `${day} om ${time}`,
  },
  en: {
    subject: (org, ref) => `DPA signed: ${org} (${ref})`,
    dear: (n) => `Dear ${n},`,
    body: (o) => `This email confirms that a Data Processing Agreement (GDPR Art. 28) has been signed on behalf of <strong>${o}</strong>.`,
    details: 'Agreement details',
    ref: 'Reference', org: 'Organisation', who: 'Signatory', at: 'Signed at', version: 'DPA version',
    processor: 'Processor', processorValue: 'PARAMANT, Hetzner, Germany',
    full: (url) => `The full agreement text is available at <a href="${url}" style="color:#1D4ED8">paramant.app/en/dpa</a>. Keep this email and the reference number for your records.`,
    foot: 'Questions: privacy@paramant.app &nbsp;·&nbsp; EU/DE jurisdiction &nbsp;·&nbsp; GDPR Art. 28',
    url: 'https://paramant.app/en/dpa',
    date: 'en-GB',
    dateAt: (day, time) => `${day} at ${time} (Amsterdam time)`,
  },
};

function dpaConfirmation({ name, title, org, ref, signed_at, version, lang }) {
  const t = TEXT[lang === 'nl' ? 'nl' : 'en'];
  const when = (() => {
    const d = new Date(signed_at);
    if (isNaN(d)) return esc(signed_at);
    // Day and time in Amsterdam, said once. The raw ISO stamp used to follow in
    // brackets; it added nothing a reader can use (acceptatie 3.1.1, taal #51).
    const day = d.toLocaleDateString(t.date, { timeZone: 'Europe/Amsterdam', day: 'numeric', month: 'long', year: 'numeric' });
    const time = d.toLocaleTimeString(t.date, { timeZone: 'Europe/Amsterdam', hour: '2-digit', minute: '2-digit', hour12: false });
    return esc(t.dateAt(day, time));
  })();
  // The light house style of every other Paramant mail; this one used to be
  // the only dark mail (acceptatie 3.1.1, taal #51).
  const row = (k, v, first) => `<tr><td style="color:#64748b;padding:4px 0${first ? ';width:40%' : ''}">${k}</td><td style="color:#0B3A6A">${v}</td></tr>`;
  const html = `<div style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#ffffff;color:#0B3A6A;padding:40px;max-width:600px;border:1px solid rgba(11,58,106,0.08)">
  <div style="font-family:monospace;font-size:11px;font-weight:600;margin-bottom:24px;letter-spacing:.15em">PARAMANT</div>
  <p style="margin:0 0 16px 0;line-height:1.6">${t.dear(esc(name))}</p>
  <p style="margin:0 0 24px 0;line-height:1.6">${t.body(esc(org))}</p>
  <div style="background:#F8FAFC;border:1px solid rgba(11,58,106,0.08);padding:20px;margin-bottom:24px;font-size:14px">
    <div style="color:#64748b;font-size:11px;letter-spacing:.08em;text-transform:uppercase;margin-bottom:12px">${t.details}</div>
    <table style="width:100%;border-collapse:collapse">
      ${row(t.ref, esc(ref), true)}
      ${row(t.org, esc(org))}
      ${row(t.who, esc(name) + (title ? ', ' + esc(title) : ''))}
      ${row(t.at, when)}
      ${row(t.version, esc(version))}
      ${row(t.processor, t.processorValue)}
    </table>
  </div>
  <p style="color:#475569;font-size:14px;line-height:1.6;margin-bottom:24px">${t.full(t.url)}</p>
  <p style="color:#64748b;font-size:12px">${t.foot}</p>
</div>`;
  return { subject: t.subject(org, ref), html };
}

module.exports = { dpaConfirmation };

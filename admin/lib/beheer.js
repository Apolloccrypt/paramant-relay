'use strict';
// Het beheerscherm voor één eigenaar.
//
// WAAROM DIT BESTAND ER IS. Het paneel liet de ruwe opslag zien: een audit met
// een kolom pgp_-sleutels en een uitklapper met {}, een MRR die vast op null
// stond en een Billing-tab die betalingen niet kende. Wat de eigenaar wil weten
// ("wie deed wat, verdien ik iets, brandt er iets") stond wel in redis, maar
// werd nergens vertaald. Dit bestand vertaalt, en doet verder niets: het leest
// wat de relays en de webhook al wegschrijven en maakt er zinnen en getallen
// van. Het schrijft alleen zijn eigen tellers (mislukte mails, 429's, de
// omvang van het transparantielogboek per uur), met een TTL, onder
// paramant:admin:tel:*.
//
// Twee regels die hier worden afgedwongen en niet alleen beschreven:
//   - Geen volle sleutel naar de browser. scrubKeys() maskeert elke pgp_/psk_
//     in een gebeurtenis, ook diep in de details, en auditRow() geeft nooit een
//     user_id terug die een sleutel is.
//   - Geen getal zonder meting. Een meting die niet lukte heet 'niet gemeten',
//     zoals op de standpagina, en wordt nooit een 0.

const KEY_RE = /\b(pgp|psk)_[0-9a-f]{8,}\b/gi;

function maskKey(k) {
  const s = String(k || '');
  return s.length > 12 ? s.slice(0, 8) + '...' + s.slice(-4) : s;
}

function isKey(s) {
  return typeof s === 'string' && /^(pgp|psk)_[0-9a-f]{8,}$/i.test(s);
}

// Een kopie waarin elke sleutel gemaskeerd is, in waarden en in namen.
function scrubKeys(value, depth = 0) {
  if (depth > 6) return '[diep]';
  if (typeof value === 'string') return value.replace(KEY_RE, (m) => maskKey(m));
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => scrubKeys(v, depth + 1));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[scrubKeys(k, depth + 1)] = scrubKeys(v, depth + 1);
    return out;
  }
  return value;
}

// ── Gebeurtenissen in gewone taal ───────────────────────────────────────────
// Elke naam die logAuditEvent in deze codebase schrijft, plus de drie die de
// betaalgeschiedenis kent. Een naam die hier niet staat valt terug op een
// leesbare versie van de code zelf; hij verdwijnt nooit.
const EVENT_NL = {
  admin_account_deleted: 'Account gedeactiveerd door jou',
  admin_config_backup_created: 'Reservekopie van de instellingen gemaakt',
  admin_config_changed: 'Instellingen gewijzigd',
  admin_config_restart_requested: 'Herstart van de dienst aangevraagd',
  admin_coupon_created: 'Cadeaucode aangemaakt',
  admin_coupon_revoked: 'Cadeaucode ingetrokken',
  admin_key_disabled: 'Sleutel uitgezet door jou',
  admin_key_revoked: 'Sleutel ingetrokken door jou',
  admin_key_viewed: 'Sleutel bekeken door jou',
  admin_parasign_enabled: 'ParaSign-API aangezet door jou',
  admin_parasign_disabled: 'ParaSign-API uitgezet door jou',
  admin_parasign_onboarding_sent: 'ParaSign-startmail verstuurd',
  admin_plan_changed: 'Plan gewijzigd door jou',
  admin_product_plan_changed: 'Plan van één product gewijzigd door jou',
  admin_relay_reload_all: 'Alle relays herladen',
  admin_sessions_revoked: 'Alle sessies van de klant beëindigd',
  admin_setup_resent: 'Link voor de authenticator-app opnieuw verstuurd',
  admin_totp_required_toggled: 'Verplichte tweestapsverificatie aangepast',
  admin_totp_reset_initiated: 'Reset van de tweestapsverificatie gestart',
  admin_user_viewed: 'Klantgegevens bekeken door jou',
  admin_welcome_sent: 'Welkomstmail verstuurd',
  account_deleted_self: 'Klant heeft het account zelf opgeheven',
  account_key_revealed: 'Klant heeft de eigen sleutel bekeken',
  parasign_doc_declined: 'Ondertekenen geweigerd',
  parasign_doc_signed: 'Document ondertekend',
  passkey_removed: 'Passkey verwijderd',
  plan_cancellation_scheduled: 'Opzegging ingepland',
  plan_changed: 'Plan gewijzigd',
  plan_downgraded: 'Plan verlaagd',
  session_client_changed: 'Sessie afgebroken: inlog gebruikt vanuit een andere browser',
  totp_reset_confirmed: 'Tweestapsverificatie opnieuw ingesteld',
  totp_reset_requested: 'Reset van de tweestapsverificatie aangevraagd',
  webauthn_account_passkey_added: 'Passkey toegevoegd',
  webauthn_counter_regression: 'Waarschuwing: passkey-teller liep terug, mogelijk een gekopieerde sleutel',
  webauthn_login: 'Ingelogd met passkey',
  webauthn_register: 'Passkey geregistreerd',
  cli_command_started: 'Terminalopdracht gestart',
  cli_command_completed: 'Terminalopdracht afgerond',
  cli_command_denied: 'Terminalopdracht geweigerd',
  cli_command_error: 'Terminalopdracht mislukt',
  cli_command_cancelled: 'Terminalopdracht afgebroken',
};

function eventLabel(type) {
  const t = String(type || '');
  if (EVENT_NL[t]) return EVENT_NL[t];
  if (!t) return 'Onbekende gebeurtenis';
  const s = t.replace(/^admin_/, '').replace(/_/g, ' ');
  return s.charAt(0).toUpperCase() + s.slice(1);
}

const PRODUCT_NL = { parasign: 'ParaSign', parasend: 'ParaSend' };
const VIA_NL = { totp: 'authenticator-app', webauthn: 'passkey', webauthn_xdev: 'passkey op ander apparaat', backup_code: 'herstelcode', user_request: 'op verzoek van de klant' };
const REASON_NL = { unknown_command: 'onbekende opdracht', invalid_args: 'ongeldige invoer', totp_required: 'code nodig', rate_limited: 'te vaak achter elkaar' };

function datum(v) {
  const ms = typeof v === 'number' ? v : Date.parse(v);
  if (!Number.isFinite(ms)) return String(v || '');
  return new Date(ms).toISOString().slice(0, 10);
}

// Eén regel: wat er gebeurde, in woorden. Leeg als de details niets zeggen.
function summarize(type, meta) {
  const m = (meta && typeof meta === 'object') ? meta : {};
  const p = (x) => PRODUCT_NL[x] || x;
  switch (type) {
    case 'admin_plan_changed':
    case 'plan_changed':
      return `van ${m.from || 'onbekend'} naar ${m.to || 'onbekend'}`;
    case 'plan_downgraded':
      return `naar ${m.to || 'Community'}`;
    case 'admin_product_plan_changed':
      return `${p(m.product || 'product')} naar ${m.tier || 'onbekend'}`;
    case 'admin_totp_required_toggled':
      return (m.after ? 'nu verplicht' : 'niet meer verplicht') + (m.reason ? `, reden: ${m.reason}` : '');
    case 'admin_totp_reset_initiated':
      return (m.mode === 'direct' ? 'direct gereset' : 'bevestigingsmail gestuurd') + (m.email ? ` naar ${m.email}` : '');
    case 'admin_welcome_sent':
    case 'admin_setup_resent':
    case 'admin_parasign_onboarding_sent':
      return m.email ? `naar ${m.email}` : '';
    case 'admin_sessions_revoked':
      return `${Number(m.count) || 0} sessie${Number(m.count) === 1 ? '' : 's'} beëindigd`;
    case 'admin_key_disabled':
      return (m.reason ? `reden: ${m.reason}` : 'geen reden opgegeven') + (m.notify ? ', klant gemaild' : '');
    case 'admin_account_deleted':
      return m.email ? `account van ${m.email}` : '';
    case 'admin_coupon_created':
      return `code ${m.code || '?'}` + (m.max ? `, ${m.max} keer te gebruiken` : '');
    case 'admin_coupon_revoked':
      return `code ${m.code || '?'}`;
    case 'admin_config_changed': {
      const keys = Array.isArray(m.changed) ? m.changed : (Array.isArray(m.keys) ? m.keys : Object.keys(m.changes || {}));
      return keys.length ? `${keys.length} instelling${keys.length === 1 ? '' : 'en'}: ${keys.slice(0, 4).join(', ')}` : '';
    }
    case 'admin_config_backup_created':
      return m.backup_file ? `bestand ${String(m.backup_file).split('/').pop()}` : '';
    case 'plan_cancellation_scheduled':
      return (m.plan ? `${m.plan}, ` : '') + (m.cancel_at ? `stopt op ${datum(m.cancel_at)}` : 'einddatum onbekend');
    case 'parasign_doc_signed':
    case 'parasign_doc_declined':
      return m.envelope ? `verzoek ${m.envelope}` + (m.party != null ? `, ondertekenaar ${Number(m.party) + 1}` : '') : '';
    case 'totp_reset_confirmed':
      return m.age_sec != null ? `${Math.round(Number(m.age_sec) / 60)} min na de aanvraag` : '';
    case 'session_client_changed':
    case 'webauthn_login':
    case 'account_key_revealed':
      return m.via ? `via ${VIA_NL[m.via] || m.via}` : '';
    case 'webauthn_counter_regression':
      return `teller was ${m.stored}, kreeg ${m.presented}`;
    case 'account_deleted_self':
      return m.envelopes_voided ? `${m.envelopes_voided} open ondertekenverzoek${m.envelopes_voided === 1 ? '' : 'en'} ingetrokken` : '';
    case 'cli_command_started':
    case 'cli_command_completed':
    case 'cli_command_denied':
    case 'cli_command_error':
    case 'cli_command_cancelled':
      return [m.command, m.reason ? (REASON_NL[m.reason] || m.reason) : '', m.error || '', m.exit_code != null ? `afgesloten met code ${m.exit_code}` : ''].filter(Boolean).join(', ');
    default: {
      // Onbekende soort: de eerste paar eenvoudige velden, zonder IP of browser.
      const skip = new Set(['admin_ip', 'ip', 'ua', 'ts', 'user_id', 'event', 'event_type']);
      const parts = [];
      for (const [k, v] of Object.entries(m)) {
        if (skip.has(k) || v == null || typeof v === 'object') continue;
        parts.push(`${k.replace(/_/g, ' ')}: ${String(v).slice(0, 60)}`);
        if (parts.length >= 3) break;
      }
      return parts.join(', ');
    }
  }
}

// ── Wie ─────────────────────────────────────────────────────────────────────
// whoMap: Map(volle sleutel -> { email, label, kid }). Gebouwd op de server uit
// de accountlijst; de volle sleutel blijft daar.
function buildWhoMap(users) {
  const map = new Map();
  for (const u of users || []) {
    if (!u || !u._full) continue;
    map.set(u._full, { email: u.email || null, label: u.label || null, kid: u.key_id || null });
  }
  return map;
}

function whoFor(userId, meta, whoMap) {
  const id = String(userId || '');
  const m = (meta && typeof meta === 'object') ? meta : {};
  if (id === 'admin') return { name: 'Jij (beheer)', kind: 'beheer', kid: null, key_masked: null };
  if (id === 'cli' || /^adm_[0-9a-f]{6,}$/.test(id)) return { name: 'Jij (terminal)', kind: 'beheer', kid: null, key_masked: null };
  const known = whoMap && whoMap.get(id);
  if (known) {
    return {
      name: known.email || known.label || 'Klant zonder e-mailadres',
      kind: 'klant',
      kid: known.kid,
      key_masked: isKey(id) ? maskKey(id) : null,
    };
  }
  if (isKey(id)) {
    return { name: m.email || 'Account bestaat niet meer', kind: 'klant', kid: null, key_masked: maskKey(id) };
  }
  if (/@/.test(id)) return { name: id, kind: 'klant', kid: null, key_masked: null };
  return { name: id ? scrubKeys(id) : 'Systeem', kind: id ? 'onbekend' : 'systeem', kid: null, key_masked: null };
}

function eventTimeMs(ts) {
  if (typeof ts === 'number') return ts;
  const n = Number(ts);
  if (typeof ts === 'string' && ts.trim() !== '' && Number.isFinite(n)) return n;
  const p = Date.parse(ts);
  return Number.isFinite(p) ? p : 0;
}

// Oude, verkeerd opgeslagen regels hadden type en gebruiker omgewisseld
// (event_type was een object). Dezelfde terugval als het paneel al deed.
function normalizeEvent(ev) {
  if (ev && ev.event_type && typeof ev.event_type === 'object') {
    const inner = ev.event_type;
    return {
      ts: ev.ts,
      event_type: typeof ev.user_id === 'string' ? ev.user_id : 'onbekend',
      user_id: String(inner.user_id || inner.account || ''),
      metadata: inner,
    };
  }
  return { ts: ev && ev.ts, event_type: ev && ev.event_type, user_id: ev && ev.user_id, metadata: (ev && ev.metadata) || {} };
}

function auditRow(raw, whoMap) {
  const ev = normalizeEvent(raw || {});
  const meta = scrubKeys(ev.metadata || {});
  const who = whoFor(ev.user_id, ev.metadata, whoMap);
  const ms = eventTimeMs(ev.ts);
  return {
    ts: ms,
    iso: ms ? new Date(ms).toISOString() : null,
    event_type: String(ev.event_type || ''),
    label: eventLabel(ev.event_type),
    summary: scrubKeys(summarize(ev.event_type, ev.metadata)),
    who: who.name,
    who_kind: who.kind,
    kid: who.kid,
    key_masked: who.key_masked,
    // user_id blijft bestaan voor oude lezers, maar nooit als volle sleutel.
    user_id: isKey(ev.user_id) ? maskKey(ev.user_id) : scrubKeys(String(ev.user_id || '')),
    metadata: meta,
  };
}

// ── Geld ────────────────────────────────────────────────────────────────────
function cents(v) {
  const s = String(v == null ? '' : v).trim();
  if (!/^-?\d+(\.\d{1,2})?$/.test(s)) return NaN;
  const neg = s.startsWith('-');
  const [i, f = ''] = s.replace('-', '').split('.');
  const c = Number(i) * 100 + Number((f + '00').slice(0, 2));
  return neg ? -c : c;
}

const INTERVAL_MONTHS = { month: 1, monthly: 1, '1 month': 1, quarter: 3, '3 months': 3, year: 12, yearly: 12, annual: 12, '12 months': 12 };
function intervalMonths(record) {
  const iv = String((record && record.interval) || '').toLowerCase();
  if (INTERVAL_MONTHS[iv]) return INTERVAL_MONTHS[iv];
  // Geen interval op het document: afleiden uit de looptijd.
  const start = Date.parse(record && (record.paid_at || record.issued_at));
  const end = Date.parse(record && record.service_period_end);
  if (Number.isFinite(start) && Number.isFinite(end) && end > start) {
    return Math.max(1, Math.round((end - start) / (30.44 * 86400000)));
  }
  return 1;
}

// credits: Map(factuurnummer -> totaal teruggeboekt in centen, positief).
function creditsByInvoice(records) {
  const out = new Map();
  for (const r of records || []) {
    if (r && r.kind === 'credit_note' && r.credit_for) {
      const g = Math.abs(cents(r.amount_gross));
      if (Number.isFinite(g)) out.set(r.credit_for, (out.get(r.credit_for) || 0) + g);
    }
  }
  return out;
}

const KIND_NL = { invoice: 'Factuur', receipt: 'Betaalbewijs', credit_note: 'Creditnota' };

// Status van één document in gewone taal.
function documentStatus(record, credits, now = Date.now()) {
  if (!record) return { code: 'onbekend', text: 'Onbekend' };
  if (record.kind === 'credit_note') {
    return { code: 'terugbetaald', text: `Terugbetaald op ${record.credit_for || 'een factuur'}` };
  }
  const gross = cents(record.amount_gross);
  const back = (credits && credits.get(record.number)) || 0;
  if (back > 0 && Number.isFinite(gross) && back >= gross) return { code: 'terugbetaald', text: 'Betaald en volledig terugbetaald' };
  if (back > 0) return { code: 'deels_terug', text: 'Betaald, deels terugbetaald' };
  const end = Date.parse(record.service_period_end);
  if (Number.isFinite(end)) {
    return end > now
      ? { code: 'loopt', text: `Betaald, loopt tot ${new Date(end).toISOString().slice(0, 10)}` }
      : { code: 'verlopen', text: `Betaald, periode afgelopen op ${new Date(end).toISOString().slice(0, 10)}` };
  }
  return { code: 'betaald', text: 'Betaald' };
}

// De omschrijving staat in het Engels op het document ("Paramant ParaSign
// Pro, yearly plan"). Op het scherm in gewone taal; het document zelf blijft.
const INTERVAL_NL = { yearly: 'jaarplan', monthly: 'maandplan', quarterly: 'kwartaalplan', annual: 'jaarplan' };
function describeNl(d) {
  const s = String(d || '');
  const m = s.match(/^Paramant (.+?), (\w+) plan$/);
  if (m) return `${m[1].replace(/ and /g, ' en ')}, ${INTERVAL_NL[m[2].toLowerCase()] || m[2] + ' plan'}`;
  return s;
}

function documentRow(record, credits, now) {
  const buyer = (record && record.buyer) || {};
  const st = documentStatus(record, credits, now);
  return {
    number: record.number || '',
    date: record.invoice_date || '',
    kind: record.kind || '',
    kind_nl: KIND_NL[record.kind] || 'Document',
    customer: buyer.company || buyer.email || '',
    email: buyer.email || '',
    description: describeNl(record.description),
    amount_net: record.amount_net || '',
    amount_gross: record.amount_gross || '',
    currency: record.currency || 'EUR',
    method: record.payment_method || null,
    period_end: record.service_period_end || null,
    credit_for: record.credit_for || null,
    status: st.code,
    status_nl: st.text,
    account_id: record.account_id || null, // alleen server-intern; wordt weggehaald voor het de deur uit gaat
  };
}

function ymOf(ms) { return new Date(ms).toISOString().slice(0, 7); }

// Omzet in een maand: alle documenten met die maand als datum, creditnota's
// negatief (zo staan ze opgeslagen). Netto en bruto apart.
function monthRevenue(records, ym) {
  let net = 0; let gross = 0; let n = 0;
  for (const r of records || []) {
    if (!r || String(r.invoice_date || '').slice(0, 7) !== ym) continue;
    const a = cents(r.amount_net); const b = cents(r.amount_gross);
    if (Number.isFinite(a)) net += a;
    if (Number.isFinite(b)) gross += b;
    n++;
  }
  return { month: ym, net_cents: net, gross_cents: gross, documents: n };
}

// MRR: elke betaalde periode die nu loopt, omgerekend naar een maand. Een
// jaar voor 120 euro telt als 10 per maand. Teruggeboekte bedragen gaan eraf,
// naar rato. Per account en product telt alleen de laatste lopende betaling,
// zodat een verlenging die al binnen is niet dubbel telt. Netto, zonder btw.
function computeMrr(records, now = Date.now()) {
  const credits = creditsByInvoice(records);
  const latest = new Map();
  for (const r of records || []) {
    if (!r || r.kind === 'credit_note') continue;
    const end = Date.parse(r.service_period_end);
    if (!Number.isFinite(end) || end <= now) continue;
    const net = cents(r.amount_net);
    if (!Number.isFinite(net) || net <= 0) continue;
    const gross = cents(r.amount_gross);
    const back = credits.get(r.number) || 0;
    const share = Number.isFinite(gross) && gross > 0 ? Math.max(0, 1 - back / gross) : 1;
    if (share <= 0) continue;
    const key = `${r.account_id || r.number}|${r.product || ''}`;
    const prev = latest.get(key);
    const at = Date.parse(r.paid_at || r.issued_at) || 0;
    if (!prev || at > prev.at) latest.set(key, { at, monthly: (net * share) / intervalMonths(r), account: r.account_id || null });
  }
  let total = 0;
  const accounts = new Set();
  for (const v of latest.values()) { total += v.monthly; if (v.account) accounts.add(v.account); }
  return { mrr_cents: Math.round(total), basis: latest.size, paying_accounts: accounts };
}

function euro(c) {
  if (!Number.isFinite(c)) return 'niet gemeten';
  const neg = c < 0;
  const abs = Math.abs(Math.round(c));
  const s = `${Math.floor(abs / 100)},${String(abs % 100).padStart(2, '0')}`;
  return (neg ? '-' : '') + '€ ' + s.replace(/\B(?=(\d{3})+(?!\d))/g, '.');
}

// ── Relays ──────────────────────────────────────────────────────────────────
function parseMetrics(text) {
  const out = {};
  for (const line of String(text || '').split('\n')) {
    const m = line.match(/^paramant_([a-z_]+)\{[^}]*\}\s+([-\d.eE+]+)/);
    if (m) out[m[1]] = Number(m[2]);
  }
  return out;
}

function parseRedisInfo(text) {
  const out = {};
  for (const line of String(text || '').split(/\r?\n/)) {
    const i = line.indexOf(':');
    if (i > 0 && !line.startsWith('#')) out[line.slice(0, i)] = line.slice(i + 1).trim();
  }
  const num = (k) => (out[k] != null && out[k] !== '' && Number.isFinite(Number(out[k])) ? Number(out[k]) : null);
  return {
    used_bytes: num('used_memory'),
    peak_bytes: num('used_memory_peak'),
    max_bytes: num('maxmemory'),
    rss_bytes: num('used_memory_rss'),
    policy: out.maxmemory_policy || null,
  };
}

function mb(b) { return b == null ? null : Math.round((b / 1048576) * 10) / 10; }

// ── Tellers per uur ─────────────────────────────────────────────────────────
// Eén sleutel per soort per uur, drie dagen bewaard. Lezen kost 24 GETs.
const TEL_TTL_S = 3 * 86400;
function hourKey(kind, ms) {
  const d = new Date(ms);
  const h = d.toISOString().slice(0, 13).replace(/[-T]/g, '');
  return `paramant:admin:tel:${kind}:${h}`;
}

async function countHit(redisClient, kind, now = Date.now()) {
  if (!redisClient) return;
  const k = hourKey(kind, now);
  try {
    const n = await redisClient.incr(k);
    if (n === 1) await redisClient.expire(k, TEL_TTL_S);
  } catch { /* een teller is nooit een poort */ }
}

async function read24h(redisClient, kind, now = Date.now()) {
  const hours = [];
  for (let i = 23; i >= 0; i--) hours.push(now - i * 3600000);
  const vals = await Promise.all(hours.map((ms) => redisClient.get(hourKey(kind, ms)).then((v) => Number(v) || 0)));
  let total = 0; let peak = { hour: null, count: 0 };
  vals.forEach((v, i) => {
    total += v;
    if (v > peak.count) peak = { hour: new Date(hours[i]).toISOString().slice(0, 13) + ':00Z', count: v };
  });
  return { total, peak, per_hour: vals };
}

// Omvang van het transparantielogboek, een monster per sector per uur.
const CT_KEY = (sector) => `paramant:admin:tel:ctlog:${sector}`;
async function sampleCt(redisClient, sector, size, now = Date.now()) {
  if (!redisClient || !Number.isFinite(size)) return;
  const key = CT_KEY(sector);
  try {
    const last = await redisClient.zRange(key, -1, -1, { WITHSCORES: false });
    const lastTs = last && last[0] ? Number(String(last[0]).split(':')[0]) : 0;
    if (now - lastTs >= 3600000) {
      await redisClient.zAdd(key, { score: now, value: `${now}:${size}` });
      await redisClient.zRemRangeByScore(key, 0, now - TEL_TTL_S * 1000);
    }
  } catch { /* monster is best effort */ }
}

async function ctGrowth24h(redisClient, sector, size, now = Date.now()) {
  try {
    const rows = await redisClient.zRangeByScore(CT_KEY(sector), now - 26 * 3600000, now - 22 * 3600000);
    if (!rows || !rows.length) return null;
    const then = Number(String(rows[0]).split(':')[1]);
    return Number.isFinite(then) && Number.isFinite(size) ? size - then : null;
  } catch { return null; }
}

// ── Problemen ───────────────────────────────────────────────────────────────
// Elk punt heeft een niveau en een zin. Zonder meting: 'niet_gemeten'.
const GOED = 'goed'; const LET_OP = 'let_op'; const KAPOT = 'kapot'; const NIET = 'niet_gemeten';

function problems({ relays, mails, http429, ct, redisMem }) {
  const out = [];
  // Relays
  if (Array.isArray(relays) && relays.length) {
    const down = relays.filter((r) => !r.ok);
    out.push({
      id: 'relays', level: down.length ? KAPOT : GOED, tab: 'relay',
      title: 'Relays',
      text: down.length
        ? `${down.length} van de ${relays.length} relays antwoordt niet: ${down.map((r) => r.sector).join(', ')}.`
        : `Alle ${relays.length} relays antwoorden.`,
    });
  } else {
    out.push({ id: 'relays', level: NIET, tab: 'relay', title: 'Relays', text: 'Geen relay gaf antwoord op de vraag.' });
  }
  // Mislukte mails
  if (mails) {
    out.push({
      id: 'mails', level: mails.total > 0 ? (mails.total >= 5 ? KAPOT : LET_OP) : GOED, tab: 'audit',
      title: 'Mislukte mails',
      text: mails.total > 0
        ? `${mails.total} mail${mails.total === 1 ? '' : 's'} kon${mails.total === 1 ? '' : 'den'} de laatste 24 uur niet weg vanaf de beheerkant.`
        : 'Geen mislukte mails de laatste 24 uur (beheerkant).',
    });
  } else out.push({ id: 'mails', level: NIET, tab: 'audit', title: 'Mislukte mails', text: 'De teller kwam niet terug.' });
  // 429
  if (http429) {
    const piek = http429.peak && http429.peak.count ? `, piek ${http429.peak.count} om ${http429.peak.hour.slice(11, 16)} UTC` : '';
    out.push({
      id: 'http429', level: http429.peak.count >= 50 ? LET_OP : GOED, tab: 'overview',
      title: 'Te veel verzoeken (429)',
      text: `${http429.total} keer "te veel verzoeken" de laatste 24 uur${piek}. Geteld op de beheer- en accountkant.`,
    });
  } else out.push({ id: 'http429', level: NIET, tab: 'overview', title: 'Te veel verzoeken (429)', text: 'De teller kwam niet terug.' });
  // Transparantielogboek
  if (Array.isArray(ct) && ct.length) {
    const forked = ct.filter((c) => c.forked);
    const ram = ct.filter((c) => c.persisted === false);
    const groei = ct.filter((c) => c.growth_24h != null);
    const parts = [];
    if (forked.length) parts.push(`gesplitst op ${forked.map((c) => c.sector).join(', ')}`);
    if (ram.length) parts.push(`alleen in geheugen op ${ram.map((c) => c.sector).join(', ')}`);
    const groeiZin = groei.length
      ? `groei laatste 24 uur: ${groei.map((c) => `${c.sector} +${c.growth_24h}`).join(', ')}`
      : 'groei wordt gemeten vanaf nu, over 24 uur staat hier een getal';
    out.push({
      id: 'ctlog', level: forked.length ? KAPOT : (ram.length ? LET_OP : GOED), tab: 'relay',
      title: 'Transparantielogboek',
      text: (parts.length ? parts.join('; ') + '. ' : '') + groeiZin + '.',
    });
  } else out.push({ id: 'ctlog', level: NIET, tab: 'relay', title: 'Transparantielogboek', text: 'Geen relay gaf zijn logboekomvang.' });
  // Redis
  if (redisMem && redisMem.used_bytes != null) {
    const pct = redisMem.max_bytes ? Math.round((redisMem.used_bytes / redisMem.max_bytes) * 100) : null;
    out.push({
      id: 'redis', level: pct != null && pct >= 85 ? KAPOT : (pct != null && pct >= 70 ? LET_OP : GOED), tab: 'relay',
      title: 'Geheugen van de opslag (redis)',
      text: `${mb(redisMem.used_bytes)} MB in gebruik` + (pct != null ? ` van ${mb(redisMem.max_bytes)} MB (${pct}%)` : ', geen bovengrens ingesteld') + (redisMem.peak_bytes ? `, piek ${mb(redisMem.peak_bytes)} MB.` : '.'),
    });
  } else out.push({ id: 'redis', level: NIET, tab: 'relay', title: 'Geheugen van de opslag (redis)', text: 'redis gaf geen geheugencijfers.' });
  return out;
}

module.exports = {
  maskKey, isKey, scrubKeys, EVENT_NL, eventLabel, summarize, buildWhoMap, whoFor,
  normalizeEvent, auditRow, eventTimeMs, cents, intervalMonths, creditsByInvoice,
  documentStatus, documentRow, describeNl, monthRevenue, computeMrr, euro, ymOf, parseMetrics,
  parseRedisInfo, mb, hourKey, countHit, read24h, sampleCt, ctGrowth24h, problems,
  GOED, LET_OP, KAPOT, NIET, KIND_NL,
};

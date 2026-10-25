// Stukken opvragen, the office's side (/opvragen, /en/opvragen).
//
// Two views on one page: the list of requests (what came in, what is still
// missing) and the form that makes a new link. Everything that needs a key
// happens here, in this browser:
//
//   making a link   a fresh ML-KEM-768 + ECDH P-256 pair; the hash of the
//                   request goes in the #fragment; the private half is locked
//                   under the vault key (opvragen-kluis.js) before it is sent
//   downloading     the locked private half comes back, opens with the vault
//                   key, and decrypts each file with decrypt_blob
//
// The server sees public keys, a locked box and ciphertext.

import { decryptBlob, initCrypto } from '/crypto-bridge.js?v=6';
import { ml_kem768 } from '/noble-mlkem-bundle.js';
import { b64u, fromB64u, rand, pinOf, sealSk, openSk, unpackFile, zipStore, safeName, initials } from '/js/opvragen-kern.js?v=1';
import { openVault, vaultForNew } from '/js/opvragen-kluis.js?v=1';

const LANG = (document.documentElement.lang || 'nl').slice(0, 2) === 'en' ? 'en' : 'nl';
const PREFIX = LANG === 'en' ? '/en' : '';
const LOC = LANG === 'en' ? 'en-GB' : 'nl-NL';
const JAAR = new Date().getFullYear() - 1;
const T = {
  nl: {
    standaard: ['Kopie paspoort', 'Loonstrook', 'Jaaropgave ' + JAAR],
    zelf: 'Zelf iets typen',
    dagen: (n, d) => n + ' dagen, tot ' + d,
    open: (n) => 'Open (' + n + ')', compleet: (n) => 'Compleet (' + n + ')',
    aangevraagd: (d) => 'Aangevraagd op ' + d,
    vanTot: (a, b) => a + ' van ' + b,
    compleetPill: 'Compleet', gesloten: 'Gesloten',
    ontbreekt: 'ontbreekt nog', vandaag: 'vandaag', gisteren: 'gisteren',
    bestanden: (n) => n + ' bestanden',
    nogNiets: 'Nog niets binnen', binnen: (a, b) => a + ' van ' + b + ' binnen',
    nogDagen: (n) => n === 1 ? 'Nog 1 dag' : 'Nog ' + n + ' dagen', laatsteDag: 'Laatste dag',
    herinnering: 'Herinnering sturen', downloaden: 'Downloaden',
    linkKopieren: 'Link kopiëren', sluiten: 'Verzoek sluiten', verwijderen: 'Verwijderen',
    leegOpen: 'Geen open verzoeken. Vraag stukken op bij een klant met Nieuw.',
    leegKlaar: 'Nog niets compleet.',
    lijstFout: 'De lijst kon niet worden geladen. Ververs de pagina om het opnieuw te proberen.',
    bezig: 'Bezig…', sleutels: 'Sleutels maken…', passkey: 'Bevestig met je passkey…', ontgrendel: 'Ontgrendel met je passkey…',
    kies: 'Vink minstens één stuk aan.', naamNodig: 'Vul de naam van je klant in.', mailFout: 'Dit e-mailadres klopt niet.',
    teVeelStukken: (n) => 'Je kunt tot ' + n + ' stukken tegelijk opvragen.',
    teVeelOpen: (n) => (n === 1 ? 'Je abonnement laat één verzoek tegelijk toe.' : 'Je hebt al ' + n + ' verzoeken.') + ' Een gesloten verzoek met bestanden telt mee tot je het verwijdert.',
    geenKantoornaam: 'Vul eerst de naam van je kantoor in bij je factuurgegevens op de accountpagina. Die naam ziet je klant.',
    alleenBetaald: 'Herinneringen per mail horen bij Firm en hoger. Deel de link zelf opnieuw.',
    maakFout: 'De link kon niet worden gemaakt. Probeer het opnieuw.',
    geenOpslag: 'Deze browser kan de sleutel niet bewaren (privévenster?). Gebruik een gewoon venster, of voeg een passkey toe aan je account.',
    alleenHier: 'Je kunt deze stukken alleen openen in deze browser. Voeg een passkey toe aan je account om ze ook op een andere computer te openen.',
    gekopieerd: 'Gekopieerd', linkGekopieerd: 'Link gekopieerd.',
    bericht: (naam, link, kantoor) => 'Hoi ' + naam + ', wil je je stukken voor ' + kantoor + ' sturen via deze link? Je hebt geen account nodig. ' + link,
    onderwerp: (kantoor) => 'Stukken voor ' + kantoor,
    nietHier: 'Deze stukken kun je alleen openen in de browser waarin je de link maakte.',
    openen: (i, n) => 'Bezig met openen, ' + i + ' van ' + n + '…',
    gedownload: 'Gedownload.', openFout: 'Openen is niet gelukt. Probeer het opnieuw.',
    vreemd: 'Een bestand hoorde niet bij dit verzoek en is overgeslagen.',
    herinnerd: 'Herinnering verstuurd.', teSnel: 'Je hebt net een herinnering gestuurd. Probeer het over een uur nog eens.',
    maxHerinnering: (n) => 'Je hebt al ' + n + ' herinneringen gestuurd.',
    herinnerFout: 'De herinnering kon niet worden verstuurd.',
    geenMail: 'Geen e-mailadres ingevuld. Deel de link zelf opnieuw.',
    zekerSluiten: 'Verzoek sluiten? Je klant kan daarna niets meer sturen. Wat binnen is kun je nog downloaden tot de einddatum.',
    zekerWeg: 'Dit verzoek en alle bestanden verwijderen? Dit kan niet ongedaan worden.',
    stukken: 'stukken',
  },
  en: {
    standaard: ['Copy of passport', 'Payslip', 'Annual statement ' + JAAR],
    zelf: 'Type your own',
    dagen: (n, d) => n + ' days, until ' + d,
    open: (n) => 'Open (' + n + ')', compleet: (n) => 'Complete (' + n + ')',
    aangevraagd: (d) => 'Requested on ' + d,
    vanTot: (a, b) => a + ' of ' + b,
    compleetPill: 'Complete', gesloten: 'Closed',
    ontbreekt: 'still missing', vandaag: 'today', gisteren: 'yesterday',
    bestanden: (n) => n + ' files',
    nogNiets: 'Nothing in yet', binnen: (a, b) => a + ' of ' + b + ' in',
    nogDagen: (n) => n === 1 ? '1 day left' : n + ' days left', laatsteDag: 'Last day',
    herinnering: 'Send reminder', downloaden: 'Download',
    linkKopieren: 'Copy link', sluiten: 'Close request', verwijderen: 'Delete',
    leegOpen: 'No open requests. Ask a client for documents with New.',
    leegKlaar: 'Nothing complete yet.',
    lijstFout: 'The list could not be loaded. Refresh the page to try again.',
    bezig: 'Working…', sleutels: 'Making keys…', passkey: 'Confirm with your passkey…', ontgrendel: 'Unlock with your passkey…',
    kies: 'Tick at least one document.', naamNodig: 'Fill in your client\'s name.', mailFout: 'This email address is not right.',
    teVeelStukken: (n) => 'You can ask for up to ' + n + ' documents at once.',
    teVeelOpen: (n) => (n === 1 ? 'Your plan allows one request at a time.' : 'You already have ' + n + ' requests.') + ' A closed request with files counts until you delete it.',
    geenKantoornaam: 'First fill in your office name in your billing details on the account page. Your client sees that name.',
    alleenBetaald: 'Email reminders come with Firm and up. Share the link again yourself.',
    maakFout: 'The link could not be made. Please try again.',
    geenOpslag: 'This browser cannot keep the key (private window?). Use a normal window, or add a passkey to your account.',
    alleenHier: 'You can open these documents in this browser only. Add a passkey to your account to open them on another computer too.',
    gekopieerd: 'Copied', linkGekopieerd: 'Link copied.',
    bericht: (naam, link, kantoor) => 'Hi ' + naam + ', could you send your documents for ' + kantoor + ' through this link? You do not need an account. ' + link,
    onderwerp: (kantoor) => 'Documents for ' + kantoor,
    nietHier: 'You can open these documents only in the browser where you made the link.',
    openen: (i, n) => 'Opening, ' + i + ' of ' + n + '…',
    gedownload: 'Downloaded.', openFout: 'Opening did not work. Please try again.',
    vreemd: 'A file did not belong to this request and was skipped.',
    herinnerd: 'Reminder sent.', teSnel: 'You just sent a reminder. Try again in an hour.',
    maxHerinnering: (n) => 'You have already sent ' + n + ' reminders.',
    herinnerFout: 'The reminder could not be sent.',
    geenMail: 'No email address given. Share the link again yourself.',
    zekerSluiten: 'Close this request? Your client cannot send anything after this. What came in can still be downloaded until the end date.',
    zekerWeg: 'Delete this request and all its files? This cannot be undone.',
    stukken: 'documents',
  },
}[LANG];

const $ = (id) => document.getElementById(id);
function ico(name, size) { return '<svg width="' + size + '" height="' + size + '"><use href="#i-' + name + '"/></svg>'; }

async function api(pad, opts = {}) {
  const r = await fetch('/api/user/opvragen' + pad, {
    method: opts.method || 'GET', credentials: 'include', cache: 'no-store',
    headers: opts.body ? { 'Content-Type': 'application/json', 'Accept': 'application/json' } : { 'Accept': 'application/json' },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (r.status === 401) { location.href = PREFIX + '/auth/login?next=' + encodeURIComponent(location.pathname); throw new Error('login'); }
  return r;
}

let INFO = null;
let LIST = [];
let tab = 'open';
const expanded = new Set();
let firstRender = true;

// ── the list ────────────────────────────────────────────────────────────────
function dag(ms) { return new Date(ms).toLocaleDateString(LOC, { day: 'numeric', month: 'short' }).replace('.', ''); }
function wanneer(ms) {
  const d = new Date(ms); const nu = new Date();
  const tijd = d.toLocaleTimeString(LOC, { hour: 'numeric', minute: '2-digit' });
  const zelfde = (a, b) => a.toDateString() === b.toDateString();
  const gister = new Date(nu); gister.setDate(nu.getDate() - 1);
  if (zelfde(d, nu)) return T.vandaag + ' ' + tijd;
  if (zelfde(d, gister)) return T.gisteren + ' ' + tijd;
  return dag(ms) + ' ' + tijd;
}
function dagenOver(ms) { return Math.max(0, Math.ceil((ms - Date.now()) / 86400000)); }

async function loadList() {
  $('list-err').hidden = true;
  try {
    const r = await api('');
    if (!r.ok) throw new Error('http ' + r.status);
    LIST = (await r.json()).requests || [];
  } catch (e) {
    if (e.message === 'login') return;
    $('list-err').textContent = T.lijstFout; $('list-err').hidden = false; LIST = [];
  }
  renderList();
}

function renderList() {
  const open = LIST.filter((x) => x.state === 'open');
  const klaar = LIST.filter((x) => x.state !== 'open');
  $('seg-open').textContent = T.open(open.length);
  $('seg-done').textContent = T.compleet(klaar.length);
  $('seg-open').classList.toggle('on', tab === 'open');
  $('seg-done').classList.toggle('on', tab === 'done');
  $('seg-open').setAttribute('aria-selected', String(tab === 'open'));
  $('seg-done').setAttribute('aria-selected', String(tab === 'done'));
  const rows = tab === 'open' ? open : klaar;
  if (firstRender && rows.length) { expanded.add(rows[0].id); firstRender = false; }
  const box = $('list');
  box.textContent = '';
  if (!rows.length) {
    const p = document.createElement('p'); p.className = 'empty';
    p.textContent = tab === 'open' ? T.leegOpen : T.leegKlaar;
    box.appendChild(p);
    return;
  }
  let group = null;
  for (const r of rows) {
    if (expanded.has(r.id)) { box.appendChild(card(r)); group = null; continue; }
    if (!group) { group = document.createElement('div'); group.className = 'group'; box.appendChild(group); }
    group.appendChild(mini(r));
  }
}

function mini(r) {
  const b = document.createElement('button'); b.type = 'button'; b.className = 'mini';
  b.innerHTML = '<div class="avatar"></div><div><div class="nm"></div><div class="sub"></div></div><span class="pill grey"></span>'
    + '<svg width="18" height="18" style="color:var(--label-3);margin-left:-4px"><use href="#i-chev"/></svg>';
  b.querySelector('.avatar').textContent = initials(r.client_name);
  b.querySelector('.nm').textContent = r.client_name;
  b.querySelector('.sub').textContent = r.received ? T.binnen(r.received, r.total) : T.nogNiets;
  const n = dagenOver(r.expires_at);
  b.querySelector('.pill').textContent = r.state === 'closed' ? T.gesloten : r.state === 'complete' ? T.compleetPill : (n <= 1 ? T.laatsteDag : T.nogDagen(n));
  b.addEventListener('click', () => { expanded.add(r.id); renderList(); });
  return b;
}

function card(r) {
  const c = document.createElement('div'); c.className = 'client'; c.dataset.id = r.id;
  const pill = r.state === 'closed' ? '<span class="pill grey"></span>' : r.state === 'complete' ? '<span class="pill ok"></span>' : '<span class="pill warn"></span>';
  c.innerHTML = '<div class="ch"><div class="avatar"></div><div><div class="nm"></div><div class="sub"></div></div>' + pill + '</div>'
    + '<div class="prog"><i></i></div>';
  c.querySelector('.avatar').textContent = initials(r.client_name);
  c.querySelector('.nm').textContent = r.client_name;
  c.querySelector('.sub').textContent = T.aangevraagd(dag(r.created_at));
  c.querySelector('.pill').textContent = r.state === 'closed' ? T.gesloten : r.state === 'complete' ? T.compleetPill : T.vanTot(r.received, r.total);
  c.querySelector('.prog i').style.width = (100 * r.received / Math.max(1, r.total)).toFixed(1) + '%';
  for (const it of r.items) {
    const d = document.createElement('div');
    d.className = 'ov-doc' + (it.count ? '' : ' miss');
    d.innerHTML = it.count ? '<span class="ov-dot ok">' + ico('check', 13) + '</span><span></span><span class="ov-meta"></span>'
                           : '<span class="ov-dot no"></span><span></span><span class="ov-meta"></span>';
    d.children[1].textContent = it.label;
    d.children[2].textContent = it.count ? (it.count > 1 ? T.bestanden(it.count) + ' · ' : '') + wanneer(it.last_at) : T.ontbreekt;
    c.appendChild(d);
  }
  const acts = document.createElement('div'); acts.className = 'acts';
  acts.innerHTML = '<button type="button" class="ov-btn ghost sm" data-a="remind">' + ico('bell', 18) + '<span></span></button>'
    + '<button type="button" class="ov-btn primary sm" data-a="download">' + ico('down', 18) + '<span></span></button>';
  acts.children[0].querySelector('span').textContent = T.herinnering;
  acts.children[1].querySelector('span').textContent = T.downloaden;
  acts.children[0].disabled = r.state !== 'open' || r.reminders >= r.max_reminders || !INFO.limits.reminders;
  if (r.state === 'open' && !r.has_email) acts.children[0].title = T.geenMail;
  acts.children[1].disabled = r.files === 0;
  c.appendChild(acts);
  const links = document.createElement('div'); links.className = 'links';
  if (r.state !== 'closed' && r.state !== 'complete') {
    links.innerHTML = '<button type="button" data-a="copy"></button><button type="button" data-a="close"></button>';
    links.children[0].textContent = T.linkKopieren; links.children[1].textContent = T.sluiten;
  } else {
    links.innerHTML = '<button type="button" data-a="delete"></button>';
    links.children[0].textContent = T.verwijderen;
  }
  c.appendChild(links);
  const say = document.createElement('p'); say.className = 'say'; say.hidden = true; say.setAttribute('role', 'status');
  c.appendChild(say);
  c.addEventListener('click', (e) => {
    const b = e.target.closest('button[data-a]');
    if (!b || b.disabled) return;
    const a = b.dataset.a;
    if (a === 'remind') return remind(r, say, b);
    if (a === 'download') return download(r, say, b);
    if (a === 'copy') return copyLink(r, say);
    if (a === 'close') return closeReq(r, say);
    if (a === 'delete') return deleteReq(r, say);
  });
  return c;
}

function zeg(el, text, fout) { el.textContent = text; el.className = 'say' + (fout ? ' err' : ''); el.hidden = !text; }

function linkFor(id, pin) {
  return location.origin + PREFIX + '/v/' + id + (INFO && INFO.sector && INFO.sector !== 'health' ? '?r=' + INFO.sector : '') + '#' + pin;
}

// The private keys and the hash of one request, out of their locked box.
async function unlock(r, say) {
  const dr = await api('/' + encodeURIComponent(r.id));
  if (!dr.ok) throw new Error('detail ' + dr.status);
  const det = await dr.json();
  let key;
  try {
    zeg(say, T.ontgrendel);
    key = await openVault(det.kluis_id, INFO.kluizen);
  } catch (e) {
    const err = new Error('not_here'); err.code = 'not_here'; throw err;
  }
  const sk = await openSk(key, det.id, det.sk_wrapped);
  // What the server returns now must still be what this browser hashed when it
  // made the link. A changed request is not ours to open.
  if ((await pinOf(det.descriptor)) !== sk.pin) throw new Error('descriptor changed');
  return { det, sk };
}

async function download(r, say, btn) {
  btn.disabled = true;
  try {
    const { det, sk } = await unlock(r, say);
    await initCrypto();
    const kem = fromB64u(sk.kem_sk);
    const ecdh = fromB64u(sk.ecdh_d);
    const uit = []; const namen = new Set(); let vreemd = 0;
    for (let i = 0; i < det.file_list.length; i++) {
      const f = det.file_list[i];
      zeg(say, T.openen(i + 1, det.file_list.length));
      const fr = await api('/' + encodeURIComponent(det.id) + '/bestand/' + f.n);
      if (!fr.ok) throw new Error('file ' + fr.status);
      const plain = await decryptBlob(new Uint8Array(await fr.arrayBuffer()), kem, ecdh);
      const { meta, bytes } = unpackFile(plain);
      // The document a file belongs to is inside the ciphertext too. A file the
      // server filed under another document is not shown as that document.
      if (meta.item !== f.item) { vreemd++; continue; }
      let naam = safeName(det.descriptor.items[f.item] + ' - ' + meta.name);
      let k = 2; const basis = naam;
      while (namen.has(naam)) naam = basis.replace(/(\.[^.]*)?$/, ' (' + (k++) + ')$1');
      namen.add(naam);
      uit.push({ name: naam, bytes, type: meta.type });
    }
    kem.fill(0); ecdh.fill(0);
    const a = document.createElement('a');
    if (uit.length === 1) {
      a.href = URL.createObjectURL(new Blob([uit[0].bytes], { type: uit[0].type || 'application/octet-stream' }));
      a.download = uit[0].name;
    } else {
      a.href = URL.createObjectURL(zipStore(uit));
      a.download = safeName(r.client_name + ' - ' + T.stukken) + '.zip';
    }
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 60000);
    zeg(say, vreemd ? T.vreemd : T.gedownload, !!vreemd);
  } catch (e) {
    zeg(say, e && e.code === 'not_here' ? T.nietHier : T.openFout, true);
  } finally { btn.disabled = false; }
}

async function remind(r, say, btn) {
  if (!INFO.limits.reminders) return zeg(say, T.alleenBetaald, true);
  if (!r.has_email) return zeg(say, T.geenMail, true);
  btn.disabled = true;
  try {
    const rr = await api('/' + encodeURIComponent(r.id) + '/herinnering', { method: 'POST', body: {} });
    const b = await rr.json().catch(() => ({}));
    if (rr.ok) { zeg(say, T.herinnerd); r.reminders = b.reminders; btn.disabled = r.reminders >= r.max_reminders; return; }
    btn.disabled = false;
    if (b.error === 'reminder_too_soon' || b.error === 'too_many_invitations') return zeg(say, T.teSnel, true);
    if (b.error === 'reminder_limit') return zeg(say, T.maxHerinnering(b.limit || 3), true);
    if (b.error === 'paid_only') return zeg(say, T.alleenBetaald, true);
    return zeg(say, T.herinnerFout, true);
  } catch (e) {
    btn.disabled = false;
    zeg(say, T.herinnerFout, true);
  }
}

async function copyLink(r, say) {
  try {
    const { sk } = await unlock(r, say);
    await navigator.clipboard.writeText(linkFor(r.id, sk.pin));
    zeg(say, T.linkGekopieerd);
  } catch (e) { zeg(say, e && e.code === 'not_here' ? T.nietHier : T.openFout, true); }
}

async function closeReq(r, say) {
  if (!confirm(T.zekerSluiten)) return;
  const rr = await api('/' + encodeURIComponent(r.id) + '/sluiten', { method: 'POST', body: {} });
  if (!rr.ok) return zeg(say, T.openFout, true);
  await loadList();
}
async function deleteReq(r, say) {
  if (!confirm(T.zekerWeg)) return;
  const rr = await api('/' + encodeURIComponent(r.id) + '/verwijderen', { method: 'POST', body: {} });
  if (!rr.ok) return zeg(say, T.openFout, true);
  expanded.delete(r.id);
  await loadList();
}

// ── a new request ──────────────────────────────────────────────────────────
function itemRow(label, checked) {
  const l = document.createElement('label'); l.className = 'item';
  l.innerHTML = '<input type="checkbox"><span class="check">' + ico('check', 14) + '</span><span></span>';
  l.querySelector('input').checked = checked;
  l.querySelector('input').value = label;
  l.lastChild.textContent = label;
  return l;
}
function clean(s) { return String(s || '').normalize('NFC').replace(/[\u0000-\u001f\u007f<>]/g, ' ').replace(/\s+/g, ' ').trim(); }

function renderForm() {
  const box = $('items');
  box.textContent = '';
  for (const s of T.standaard) box.appendChild(itemRow(s, true));
  const add = document.createElement('div'); add.className = 'item add';
  add.innerHTML = ico('plus', 22) + '<input id="own" maxlength="60" enterkeyhint="done">';
  box.appendChild(add);
  const own = add.querySelector('input');
  own.placeholder = T.zelf;
  own.setAttribute('aria-label', T.zelf);
  const voegToe = () => {
    const v = clean(own.value).slice(0, 60).trim();
    if (!v) return;
    const bestaat = [...box.querySelectorAll('input[type=checkbox]')].find((x) => x.value.toLowerCase() === v.toLowerCase());
    if (bestaat) bestaat.checked = true; else box.insertBefore(itemRow(v, true), add);
    own.value = '';
  };
  own.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); voegToe(); } });
  own.addEventListener('blur', voegToe);

  const sel = $('ttl');
  sel.textContent = '';
  const max = INFO ? Math.floor(INFO.limits.ttl_ms / 86400000) : 7;
  const keuzes = [3, 7, 14, 30].filter((n) => n <= max);
  for (const n of keuzes) {
    const o = document.createElement('option');
    o.value = String(n);
    o.textContent = T.dagen(n, dag(Date.now() + n * 86400000));
    sel.appendChild(o);
  }
  sel.value = keuzes.includes(7) ? '7' : String(keuzes[keuzes.length - 1]);
  $('client-name').value = '';
  $('client-email').value = '';
  $('make').disabled = false;
  $('linkcard').hidden = true;
  $('make-err').hidden = true;
}

function fout(text) { const e = $('make-err'); e.textContent = text; e.hidden = !text; }

async function passkeys() {
  try {
    const r = await fetch('/api/user/account/webauthn/credentials', { credentials: 'include', cache: 'no-store' });
    if (!r.ok) return [];
    const b = await r.json();
    return (b.passkeys || []).filter((p) => p && p.credId && p.prfSupported !== false);
  } catch { return []; }
}

async function make(e) {
  e.preventDefault();
  fout('');
  $('own') && $('own').blur();
  const items = [...$('items').querySelectorAll('input[type=checkbox]')].filter((x) => x.checked).map((x) => x.value);
  const naam = clean($('client-name').value).slice(0, 80).trim();
  const mail = $('client-email').value.trim();
  if (!items.length) return fout(T.kies);
  if (!naam) return fout(T.naamNodig);
  if (mail && !$('client-email').checkValidity()) return fout(T.mailFout);
  if (items.length > INFO.limits.items) return fout(T.teVeelStukken(INFO.limits.items));
  const btn = $('make');
  const tekst = btn.textContent;
  btn.disabled = true; btn.textContent = T.bezig;
  try {
    const vault = await vaultForNew({
      kluizen: INFO.kluizen, passkeys: await passkeys(),
      post: async (k) => {
        const r = await api('/kluis', { method: 'POST', body: k });
        if (!r.ok) throw new Error('kluis ' + r.status);
        INFO.kluizen = (await r.json()).kluizen || INFO.kluizen;
      },
      onStatus: (s) => { btn.textContent = s === 'passkey' ? T.passkey : T.ontgrendel; },
    });
    btn.textContent = T.sleutels;
    const kp = ml_kem768.keygen();
    const ec = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const ecPub = new Uint8Array(await crypto.subtle.exportKey('raw', ec.publicKey));
    const ecD = (await crypto.subtle.exportKey('jwk', ec.privateKey)).d;
    const greet = clean(naam.split(' ')[0]).slice(0, 40).trim();
    const days = Number($('ttl').value) || 7;
    let out = null;
    for (let poging = 0; poging < 2 && !out; poging++) {
      const d = { v: 1, id: b64u(rand(18)), office: INFO.office, greet, items,
                  expires_at: Math.floor((Date.now() + days * 86400000) / 60000) * 60000,
                  kem_pub: b64u(kp.publicKey), ecdh_pub: b64u(ecPub) };
      const pin = await pinOf(d);
      const sk = await sealSk(vault.key, d.id, { v: 1, kem_sk: b64u(kp.secretKey), ecdh_d: ecD, pin });
      const r = await api('', { method: 'POST', body: { descriptor: d, client_name: naam, client_email: mail,
        lang: LANG, sk_wrapped: sk, kluis_id: vault.kluisId } });
      const b = await r.json().catch(() => ({}));
      if (r.status === 201) { out = { d, pin }; break; }
      if (b.error === 'too_many_open') throw Object.assign(new Error('open'), { open: b.limit });
      if (b.error === 'no_office_name') throw Object.assign(new Error('naam'), { naam: true });
      if (b.error === 'office_changed') { await loadInfo(); continue; }
      if (b.error === 'id_taken') continue;
      throw new Error('create ' + r.status + ' ' + (b.error || ''));
    }
    kp.secretKey.fill(0);
    if (!out) throw new Error('create failed');
    const link = linkFor(out.d.id, out.pin);
    $('link-url').textContent = link.replace(/^https?:\/\//, '');
    $('link-url').title = link;
    $('copy').onclick = async () => {
      try { await navigator.clipboard.writeText(link); $('copy-t').textContent = T.gekopieerd; } catch { /* clipboard off */ }
    };
    const msg = T.bericht(greet || naam, link, INFO.office);
    $('wa').href = 'https://wa.me/?text=' + encodeURIComponent(msg);
    $('mail').href = 'mailto:' + encodeURIComponent(mail) + '?subject=' + encodeURIComponent(T.onderwerp(INFO.office)) + '&body=' + encodeURIComponent(msg);
    $('carry-note').textContent = vault.carried ? '' : T.alleenHier;
    $('carry-note').hidden = vault.carried;
    $('linkcard').hidden = false;
    btn.textContent = tekst;
    btn.disabled = false;
    INFO.open = (INFO.open || 0) + 1;
    loadList();
  } catch (err) {
    btn.disabled = false; btn.textContent = tekst;
    if (err && err.message === 'login') return;
    if (err && err.open) return fout(T.teVeelOpen(err.open));
    if (err && err.naam) return fout(T.geenKantoornaam);
    if (err && err.code === 'no_storage') return fout(T.geenOpslag);
    fout(T.maakFout);
  }
}

// ── the page ────────────────────────────────────────────────────────────────
async function loadInfo() {
  const r = await api('/info');
  if (!r.ok) throw new Error('info ' + r.status);
  INFO = await r.json();
  const ini = initials(INFO.office);
  $('avatar-1').textContent = ini; $('avatar-2').textContent = ini;
}

function view() {
  const nieuw = location.hash === '#nieuw';
  $('v-lijst').hidden = nieuw;
  $('v-nieuw').hidden = !nieuw;
  if (nieuw) renderForm();
  window.scrollTo(0, 0);
}

$('to-new').addEventListener('click', () => { if (location.hash === '#nieuw') view(); else location.hash = 'nieuw'; });
$('to-list').addEventListener('click', () => { history.pushState(null, '', location.pathname); view(); loadList(); });
$('seg-open').addEventListener('click', () => { tab = 'open'; renderList(); });
$('seg-done').addEventListener('click', () => { tab = 'done'; firstRender = true; renderList(); });
$('form').addEventListener('submit', make);
window.addEventListener('hashchange', view);

(async () => {
  try { await loadInfo(); } catch (e) {
    if (e.message === 'login') return;
    $('v-lijst').hidden = false;
    $('list-err').textContent = T.lijstFout; $('list-err').hidden = false;
    return;
  }
  view();
  await loadList();
})();

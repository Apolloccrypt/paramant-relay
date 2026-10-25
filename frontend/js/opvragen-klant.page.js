// Stukken opvragen, the client's phone (/v/<id>#<hash>, /en/v/<id>#<hash>).
//
// No account and no session. The page reads the request, checks it against
// the hash in the #fragment, and locks every file to the office's key with
// encrypt_blob before a single byte is sent. The relay stores what it gets and
// cannot open it.

import { encryptBlob, initCrypto } from '/crypto-bridge.js?v=6';
import { checkDescriptor, packFile, trimPacket, formatSize, initials, fromB64u, PACKET_OVERHEAD } from '/js/opvragen-kern.js?v=1';

const LANG = (document.documentElement.lang || 'nl').slice(0, 2) === 'en' ? 'en' : 'nl';
const T = {
  nl: {
    intro: (g) => (g ? 'Hoi ' + g + ', we' : 'Hoi, we') + ' hebben een paar stukken van je nodig. Stuur deze stukken:',
    calm: (o) => 'Je bestanden gaan op slot op je telefoon. Alleen ' + o + ' kan ze openen.',
    foot: (d) => 'Deze link werkt tot ' + d + '.',
    foto: 'Foto maken', bestand: 'Bestand kiezen', toegevoegd: 'Toegevoegd', ontvangen: 'Al ontvangen',
    nogEen: 'Nog een toevoegen', fotoNaam: (label) => 'Foto ' + label.toLowerCase().replace(/^kopie /, ''),
    weg: 'Weghalen',
    versturen: 'Versturen', bezig: (i, n) => 'Bezig met versturen, ' + i + ' van ' + n + '…',
    slot: 'Bezig met op slot zetten…',
    doneLead: (o) => o + ' heeft je stukken.',
    badLinkT: 'Deze link klopt niet', badLink: 'Vraag het kantoor om de link opnieuw te sturen. Er is niets verstuurd.',
    goneT: 'Deze link werkt niet meer', gone: 'Het verzoek is verlopen of verwijderd. Vraag het kantoor om een nieuwe link.',
    closed: 'Het verzoek is gesloten. Je hoeft niets meer te sturen.',
    netT: 'Het lukt nu even niet', net: 'Het verzoek kon niet worden geopend. Probeer het zo nog eens.',
    tooBig: (mb) => 'Dit bestand is te groot. Een bestand mag tot ' + mb + ' MB zijn.',
    full: 'Bij dit stuk kunnen geen bestanden meer bij.',
    sendFail: 'Versturen is niet gelukt. Je bestanden staan nog klaar, probeer het opnieuw.',
    busy: 'Het lukt nu even niet. Probeer het over een kwartier nog eens.',
    requestFull: 'Er past niets meer bij dit verzoek. Neem contact op met het kantoor.',
    noCrypto: 'Je browser kan de bestanden niet op slot zetten. Probeer een andere browser.',
  },
  en: {
    intro: (g) => (g ? 'Hi ' + g + ', we' : 'Hi, we') + ' need a few documents from you. Please send these:',
    calm: (o) => 'Your files are locked on your phone. Only ' + o + ' can open them.',
    foot: (d) => 'This link works until ' + d + '.',
    foto: 'Take photo', bestand: 'Choose file', toegevoegd: 'Added', ontvangen: 'Already received',
    nogEen: 'Add another', fotoNaam: (label) => 'Photo ' + label.toLowerCase().replace(/^copy of /, ''),
    weg: 'Remove',
    versturen: 'Send', bezig: (i, n) => 'Sending, ' + i + ' of ' + n + '…',
    slot: 'Locking your files…',
    doneLead: (o) => o + ' has your documents.',
    badLinkT: 'This link is not right', badLink: 'Ask the office to send the link again. Nothing was sent.',
    goneT: 'This link no longer works', gone: 'The request has expired or was removed. Ask the office for a new link.',
    closed: 'The request is closed. You do not need to send anything else.',
    netT: 'Not working right now', net: 'The request could not be opened. Please try again in a moment.',
    tooBig: (mb) => 'This file is too big. A file can be up to ' + mb + ' MB.',
    full: 'No more files fit with this document.',
    sendFail: 'Sending did not work. Your files are still here, please try again.',
    busy: 'Not working right now. Please try again in fifteen minutes.',
    requestFull: 'Nothing more fits in this request. Please contact the office.',
    noCrypto: 'Your browser cannot lock the files. Please try another browser.',
  },
}[LANG];

const $ = (id) => document.getElementById(id);
function show(id) { for (const v of ['v-laden', 'v-stop', 'v-form', 'v-done']) $(v).hidden = v !== id; }
function stop(title, text) { $('stop-title').textContent = title; $('stop-text').textContent = text; show('v-stop'); }

// /v/<id> or /en/v/<id>; the hash after #.
const ID = (location.pathname.match(/\/v\/([A-Za-z0-9_-]{24})\/?$/) || [])[1] || '';
const PIN = location.hash.replace(/^#/, '');
// Which relay holds the request: an account lives on one sector, as with
// /ontvang (ophalen.page.js). Same origin off paramant.app, for a local test.
const SECTOREN = { health: 'https://health.paramant.app', legal: 'https://legal.paramant.app',
                   finance: 'https://finance.paramant.app', iot: 'https://iot.paramant.app' };
const RELAY = (() => {
  if (!/(^|\.)paramant\.app$/.test(location.hostname)) return '';
  const r = new URLSearchParams(location.search).get('r') || '';
  return Object.prototype.hasOwnProperty.call(SECTOREN, r) ? SECTOREN[r] : '';
})();

function ico(name, size) {
  return '<svg width="' + size + '" height="' + size + '"><use href="#i-' + name + '"/></svg>';
}

let D = null;           // the checked descriptor
let LIMITS = null;
const pending = [];     // [{ item, file, name, size }]
let received = [];

function datum(ms) {
  return new Date(ms).toLocaleDateString(LANG === 'en' ? 'en-GB' : 'nl-NL', { weekday: 'long', day: 'numeric', month: 'long' });
}

async function load() {
  if (!ID || !PIN) return stop(T.badLinkT, T.badLink);
  let r;
  try { r = await fetch(RELAY + '/v2/opvraag/' + ID, { cache: 'no-store', referrerPolicy: 'no-referrer' }); }
  catch { return stop(T.netT, T.net); }
  if (r.status === 404) return stop(T.goneT, T.gone);
  // Closed: a plain answer. The name in a 410 comes from the relay, unchecked
  // by any hash, so it is not shown.
  if (r.status === 410) return stop(T.goneT, T.closed);
  if (!r.ok) return stop(T.netT, T.net);
  const v = await r.json().catch(() => null);
  // The whole point: what the relay hands out must hash to what the office put
  // in the link. Anything else, and not one byte goes up.
  if (!v || !(await checkDescriptor(v.descriptor, ID, PIN))) return stop(T.badLinkT, T.badLink);
  D = v.descriptor;
  LIMITS = { fileMax: Math.max(0, (v.file_max_bytes || 5 * 1048576) - PACKET_OVERHEAD), perItem: v.files_per_item || 3 };
  received = Array.isArray(v.received) ? v.received : D.items.map(() => 0);
  render();
  show('v-form');
  initCrypto().catch(() => {});
}

function render() {
  $('logo').textContent = initials(D.office);
  $('office').textContent = D.office;
  $('intro').textContent = T.intro(D.greet);
  $('calm').textContent = T.calm(D.office);
  $('foot').textContent = T.foot(datum(D.expires_at));
  const box = $('reqs');
  box.textContent = '';
  D.items.forEach((label, i) => {
    const mine = pending.filter((p) => p.item === i);
    const binnen = received[i] || 0;
    const card = document.createElement('div');
    card.className = 'req' + (mine.length ? ' ok' : '') + (binnen && !mine.length ? ' done' : '');
    const t = document.createElement('div'); t.className = 't';
    const tl = document.createElement('span'); tl.textContent = label; t.appendChild(tl);
    if (mine.length || binnen) {
      const b = document.createElement('span'); b.className = 'badge-ok';
      b.innerHTML = ico('check', 16);
      b.appendChild(document.createTextNode(mine.length ? T.toegevoegd : T.ontvangen));
      t.appendChild(b);
    }
    card.appendChild(t);
    for (const p of mine) {
      const f = document.createElement('div'); f.className = 'file';
      f.innerHTML = '<span class="thumb">' + ico(/^image\//.test(p.type) ? 'image' : 'file', 20) + '</span><div><div class="fn"></div><div class="fs"></div></div>'
        + '<button type="button" class="x">' + ico('x', 18) + '</button>';
      f.querySelector('.fn').textContent = p.name;
      f.querySelector('.fs').textContent = formatSize(p.size, LANG);
      const x = f.querySelector('.x');
      x.setAttribute('aria-label', T.weg + ': ' + p.name);
      x.addEventListener('click', () => { pending.splice(pending.indexOf(p), 1); render(); });
      card.appendChild(f);
    }
    const room = LIMITS.perItem - binnen - mine.length;
    if (!binnen && !mine.length) {
      const acts = document.createElement('div'); acts.className = 'acts';
      acts.innerHTML = '<button class="ov-btn ghost" type="button">' + ico('camera', 18) + '<span></span></button>'
        + '<button class="ov-btn ghost" type="button">' + ico('file', 18) + '<span></span></button>';
      const [bf, bb] = acts.querySelectorAll('button');
      bf.querySelector('span').textContent = T.foto; bb.querySelector('span').textContent = T.bestand;
      bf.addEventListener('click', () => pick(i, true));
      bb.addEventListener('click', () => pick(i, false));
      card.appendChild(acts);
    } else if (mine.length && room > 0) {
      const more = document.createElement('button'); more.type = 'button'; more.className = 'more';
      more.innerHTML = ico('plus', 16); more.appendChild(document.createTextNode(T.nogEen));
      more.addEventListener('click', () => pick(i, false));
      card.appendChild(more);
    }
    box.appendChild(card);
  });
  $('send').disabled = pending.length === 0;
}

function pick(item, camera) {
  const inp = document.createElement('input');
  inp.type = 'file';
  if (camera) { inp.accept = 'image/*'; inp.setAttribute('capture', 'environment'); }
  inp.style.display = 'none';
  inp.addEventListener('change', async () => {
    const file = inp.files && inp.files[0];
    inp.remove();
    if (file) await add(item, file, camera);
  });
  document.body.appendChild(inp);
  inp.click();
}

// A photo straight off a phone camera can be larger than one packet holds.
// Then it is made smaller here, on the phone, before it is locked.
async function shrink(file) {
  if (!/^image\/(jpeg|png|webp)$/.test(file.type) || typeof createImageBitmap !== 'function') return null;
  try {
    const bmp = await createImageBitmap(file);
    for (const side of [3000, 2400, 1800]) {
      const s = Math.min(1, side / Math.max(bmp.width, bmp.height));
      const c = document.createElement('canvas');
      c.width = Math.round(bmp.width * s); c.height = Math.round(bmp.height * s);
      c.getContext('2d').drawImage(bmp, 0, 0, c.width, c.height);
      const blob = await new Promise((res) => c.toBlob(res, 'image/jpeg', 0.85));
      if (blob && blob.size <= LIMITS.fileMax) return blob;
    }
  } catch { /* not decodable here: refuse below */ }
  return null;
}

async function add(item, file, camera) {
  showErr('');
  if (pending.filter((p) => p.item === item).length + (received[item] || 0) >= LIMITS.perItem) return showErr(T.full);
  let blob = file;
  let type = file.type || '';
  if (file.size > LIMITS.fileMax) {
    const small = await shrink(file);
    if (!small) return showErr(T.tooBig(Math.floor(LIMITS.fileMax / 1048576)));
    blob = small; type = 'image/jpeg';
  }
  const label = D.items[item];
  let name = camera ? T.fotoNaam(label) : (file.name || label);
  if (blob !== file && !/\.jpe?g$/i.test(name)) name = name.replace(/\.[^.]+$/, '') + (camera ? '' : '.jpg');
  pending.push({ item, file: blob, name, type, size: blob.size, camera });
  render();
}

function showErr(text) { const e = $('send-err'); e.textContent = text; e.hidden = !text; }

async function send() {
  if (!pending.length) return;
  const btn = $('send');
  btn.disabled = true;
  showErr('');
  let kem, ecdh;
  try { await initCrypto(); kem = fromB64u(D.kem_pub); ecdh = fromB64u(D.ecdh_pub); }
  catch { btn.disabled = false; return showErr(T.noCrypto); }
  const sent = [];
  const todo = pending.slice();
  for (let k = 0; k < todo.length; k++) {
    const p = todo[k];
    btn.textContent = T.bezig(k + 1, todo.length);
    let packet;
    try {
      const bytes = new Uint8Array(await p.file.arrayBuffer());
      // The real name travels inside: for a camera shot the phone's own name
      // (IMG_0412.jpg) says nothing, so it gets the document's.
      const naam = p.camera ? p.name + '.jpg' : p.name;
      packet = trimPacket(await encryptBlob(packFile(bytes, { item: p.item, label: D.items[p.item], name: naam, type: p.type }), kem, ecdh));
    } catch { btn.textContent = T.versturen; btn.disabled = false; return showErr(T.noCrypto); }
    let r;
    try {
      r = await fetch(RELAY + '/v2/opvraag/' + ID + '/stuk/' + p.item, { method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' }, body: packet, referrerPolicy: 'no-referrer' });
    } catch { r = null; }
    if (!r || r.status !== 201) {
      const b = r ? await r.json().catch(() => ({})) : {};
      btn.textContent = T.versturen; btn.disabled = false;
      if (r && r.status === 404) return stop(T.goneT, T.gone);
      if (r && r.status === 410) return stop(T.goneT, T.closed);
      if (b.error === 'item_full') return showErr(T.full);
      if (b.error === 'request_full' || b.error === 'account_full') return showErr(T.requestFull);
      if (r && (r.status === 503 || r.status === 429)) return showErr(T.busy);
      return showErr(T.sendFail);
    }
    pending.splice(pending.indexOf(p), 1);
    received[p.item] = (received[p.item] || 0) + 1;
    sent.push(p);
  }
  done(sent);
}

function done(sent) {
  $('done-lead').textContent = T.doneLead(D.office);
  const box = $('receipt');
  box.textContent = '';
  D.items.forEach((label, i) => {
    const mine = sent.filter((p) => p.item === i);
    if (!mine.length) return;
    const row = document.createElement('div'); row.className = 'item';
    row.innerHTML = '<span class="ov-dot ok">' + ico('check', 13) + '</span><span></span><span class="ov-meta"></span>';
    row.children[1].textContent = label;
    row.children[2].textContent = formatSize(mine.reduce((s, p) => s + p.size, 0), LANG);
    box.appendChild(row);
  });
  show('v-done');
  window.scrollTo(0, 0);
}

$('send').addEventListener('click', send);
load();

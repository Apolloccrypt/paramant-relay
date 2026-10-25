// STUKKEN OPVRAGEN: WAT DE SERVER ZIET.
//
// Een echte relay, de echte cryptografie (de WASM van crypto-wasm en
// ML-KEM-768 van noble, precies wat de browser laadt) en de gedeelde code van
// de pagina's (frontend/js/opvragen-kern.js). Geen browser: dit gaat over de
// bytes, niet over de knoppen.
//
// Bewezen wordt:
//   1. wat de relay ontvangt en opslaat is ciphertext: geen inhoud, geen
//      bestandsnaam, ook niet in zijn eigen log;
//   2. alleen de privesleutel van het kantoor opent het, een andere niet;
//   3. de sleuteldoos die de relay bewaart is dicht zonder de kluissleutel;
//   4. een relay die een eigen publieke sleutel voorschuift wordt door de
//      hash in de link betrapt.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { startRelay } from './_relay-stack.mjs';

const HIER = path.dirname(fileURLToPath(import.meta.url));
const FRONT = path.join(HIER, '..', 'frontend');
const kern = await import(pathToFileURL(path.join(FRONT, 'js', 'opvragen-kern.js')).href);
const wasm = await import(pathToFileURL(path.join(FRONT, 'pkg', 'paramant_crypto.js')).href);
wasm.initSync({ module: fs.readFileSync(path.join(FRONT, 'pkg', 'paramant_crypto_bg.wasm')) });
const { ml_kem768 } = await import(pathToFileURL(path.join(HIER, '..', 'relay', 'node_modules', '@noble', 'post-quantum', 'ml-kem.js')).href);

const SLEUTEL = 'pgp_opvragen_e2e';
const INTERN = 'e'.repeat(40);
let stack;
const logregels = [];

before(async () => {
  stack = await startRelay({
    onLine: (r) => logregels.push(r),
    env: { INTERNAL_AUTH_TOKEN: INTERN, USERS_JSON: JSON.stringify({ api_keys: [{ key: SLEUTEL, active: true,
      plan: 'pro', plan_parasend: 'pro', label: 'Acme Administratie', email: 'kantoor@example.com', account_id: 'acct_demo' }] }) },
  });
});
after(() => stack && stack.stop());

const intern = (op, body) => fetch(stack.basis + '/v2/user/opvraag/' + op, { method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-Internal-Auth': INTERN }, body: JSON.stringify({ user_id: SLEUTEL, ...body }) });

// Wat de kantoorbrowser doet bij "Maak link".
async function kantoorMaakt(items) {
  const info = await (await intern('info', {})).json();
  const kp = ml_kem768.keygen();
  const ec = await crypto.webcrypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const ecPub = new Uint8Array(await crypto.webcrypto.subtle.exportKey('raw', ec.publicKey));
  const ecD = (await crypto.webcrypto.subtle.exportKey('jwk', ec.privateKey)).d;
  const kluis = await crypto.webcrypto.subtle.importKey('raw', crypto.randomBytes(32), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  const kluisId = crypto.randomBytes(16).toString('base64url');
  await intern('kluis', { kluis_id: kluisId });
  const d = { v: 1, id: crypto.randomBytes(18).toString('base64url'), office: info.office, greet: 'Demo', items,
              expires_at: Date.now() + 2 * 86400_000, kem_pub: kern.b64u(kp.publicKey), ecdh_pub: kern.b64u(ecPub) };
  const pin = await kern.pinOf(d);
  const skWrapped = await kern.sealSk(kluis, d.id, { v: 1, kem_sk: kern.b64u(kp.secretKey), ecdh_d: ecD, pin });
  const r = await intern('create', { descriptor: d, client_name: 'Demo Klant', client_email: '', lang: 'nl',
    sk_wrapped: skWrapped, kluis_id: kluisId });
  assert.equal(r.status, 201, await r.clone().text());
  return { d, pin, kp, ecD, kluis, skWrapped };
}

// Wat de telefoon van de klant doet bij "Versturen".
async function klantStuurt(id, pin, item, naam, inhoud) {
  const v = await (await fetch(stack.basis + '/v2/opvraag/' + id)).json();
  assert.ok(await kern.checkDescriptor(v.descriptor, id, pin), 'de hash in de link klopt met wat de relay geeft');
  const plain = kern.packFile(inhoud, { item, label: v.descriptor.items[item], name: naam, type: 'application/pdf' });
  const pakket = kern.trimPacket(wasm.encrypt_blob(plain, kern.fromB64u(v.descriptor.kem_pub), kern.fromB64u(v.descriptor.ecdh_pub)));
  const r = await fetch(stack.basis + '/v2/opvraag/' + id + '/stuk/' + item, { method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' }, body: pakket });
  assert.equal(r.status, 201);
  return pakket;
}

test('de relay ontvangt en bewaart alleen ciphertext, en alleen het kantoor opent het', async () => {
  const k = await kantoorMaakt(['Loonstrook', 'Jaaropgave 2025']);
  const merk = 'GEHEIM-LOONSTROOK-' + crypto.randomBytes(6).toString('hex');
  const naam = 'loonstrook-' + crypto.randomBytes(4).toString('hex') + '.pdf';
  const inhoud = Buffer.concat([Buffer.from('%PDF-1.4\n' + merk + '\n'), crypto.randomBytes(200 * 1024)]);
  const verstuurd = await klantStuurt(k.d.id, k.pin, 0, naam, inhoud);

  assert.equal(verstuurd[0], 3, 'een encrypt_blob-pakket');
  assert.equal(verstuurd.length % 65536, 0, 'de willekeurige opvulling is tot op 64 KiB ingekort');
  for (const vorm of [merk, naam]) {
    assert.equal(Buffer.from(verstuurd).includes(Buffer.from(vorm)), false, vorm + ' staat niet in de upload');
  }

  // Wat de relay teruggeeft is precies wat hij kreeg: hij heeft er niets mee gekund.
  const opgeslagen = Buffer.from(await (await intern('file', { id: k.d.id, n: 0 })).arrayBuffer());
  assert.ok(opgeslagen.equals(Buffer.from(verstuurd)));

  // Het kantoor opent het met zijn eigen sleutel.
  const plain = wasm.decrypt_blob(new Uint8Array(opgeslagen), k.kp.secretKey, kern.fromB64u(k.ecD));
  const { meta, bytes } = kern.unpackFile(plain);
  assert.ok(Buffer.from(bytes).equals(inhoud));
  assert.equal(meta.name, naam);
  assert.equal(meta.item, 0);

  // Een andere sleutel niet.
  const ander = ml_kem768.keygen();
  const ec2 = await crypto.webcrypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const d2 = (await crypto.webcrypto.subtle.exportKey('jwk', ec2.privateKey)).d;
  assert.throws(() => wasm.decrypt_blob(new Uint8Array(opgeslagen), ander.secretKey, kern.fromB64u(d2)));

  // De relay heeft het niet in zijn log gezet.
  const log = logregels.join('\n');
  assert.equal(log.includes(merk), false);
  assert.equal(log.includes(naam), false);
});

test('de sleuteldoos op de server is dicht zonder de kluissleutel van het kantoor', async () => {
  const k = await kantoorMaakt(['Kopie paspoort']);
  const det = await (await intern('detail', { id: k.d.id })).json();
  assert.equal(det.sk_wrapped, k.skWrapped);
  const doos = kern.fromB64u(det.sk_wrapped);
  const kemSk = Buffer.from(k.kp.secretKey);
  assert.equal(Buffer.from(doos).includes(kemSk.subarray(0, 64)), false, 'geen stuk van de ML-KEM-privesleutel in de doos');
  assert.equal(det.sk_wrapped.includes(kern.b64u(k.kp.secretKey).slice(0, 64)), false);
  // Met de echte kluissleutel gaat hij open, met een andere niet, en niet onder een ander id.
  const open = await kern.openSk(k.kluis, k.d.id, det.sk_wrapped);
  assert.equal(open.pin, k.pin);
  const vreemd = await crypto.webcrypto.subtle.importKey('raw', crypto.randomBytes(32), { name: 'AES-GCM' }, false, ['decrypt']);
  await assert.rejects(kern.openSk(vreemd, k.d.id, det.sk_wrapped));
  await assert.rejects(kern.openSk(k.kluis, crypto.randomBytes(18).toString('base64url'), det.sk_wrapped));
});

test('een voorgeschoven publieke sleutel valt op tegen de hash in de link', async () => {
  const k = await kantoorMaakt(['Loonstrook']);
  const v = await (await fetch(stack.basis + '/v2/opvraag/' + k.d.id)).json();
  assert.equal(await kern.checkDescriptor(v.descriptor, k.d.id, k.pin), true);
  const nep = ml_kem768.keygen();
  for (const wijzig of [
    (d) => { d.kem_pub = kern.b64u(nep.publicKey); },
    (d) => { const b = kern.fromB64u(d.ecdh_pub); b[10] ^= 1; d.ecdh_pub = kern.b64u(b); },
    (d) => { d.office = 'Een Ander Kantoor'; },
    (d) => { d.items = ['Loonstrook', 'Pincode']; },
    (d) => { d.expires_at += 86400_000; },
  ]) {
    const d = JSON.parse(JSON.stringify(v.descriptor));
    wijzig(d);
    assert.equal(await kern.checkDescriptor(d, k.d.id, k.pin), false);
  }
});

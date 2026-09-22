'use strict';

// A send to named recipients, end to end, against a store that behaves like the
// durable one. What these tests hold:
//
//   one file, not one per person
//   one collection per person, and the second click gets nothing
//   the file goes when the last person is settled, not when the first collects
//   withdrawing one person leaves the rest working
//   the plan decides how many people may be addressed
//   a sender's overview never carries a token or a hash

const assert = require('node:assert/strict');
const test = require('node:test');

const { createSendStore, MAX_REMINDERS } = require('../lib/send');
const { sealedVoor } = require('./_sealed');

// Stands in for parasign-store: same five calls, same shapes.
function nepStore() {
  const blobs = new Map();
  const meta = new Map();
  return {
    blobs, meta,
    async putBlob(id, buf, ttl) { blobs.set(id, { buf: Buffer.from(buf), ttl }); },
    async getBlob(id) { const r = blobs.get(id); return r ? Buffer.from(r.buf) : null; },
    async delBlob(id) { blobs.delete(id); },
    async putMeta(id, obj, ttl) { meta.set(id, { obj: JSON.parse(JSON.stringify(obj)), ttl }); },
    async delMeta(id) { meta.delete(id); },
    async getMeta(id) { const r = meta.get(id); return r ? JSON.parse(JSON.stringify(r.obj)) : null; },
  };
}

const DRIE = ['anna@example.org', 'bob@example.org', 'carla@example.org'];
const INHOUD = Buffer.from('a confidential report');

// Collecting is two steps now: prove the mailbox, then take the file. Tests
// that only care about the outcome use this; the code itself has its own tests.
async function haalOp(sends, token) {
  const vraag = await sends.requestPickup(token);
  if (!vraag.ok) return vraag;
  return sends.collect(token, vraag.code);
}

function maakStore(extra) {
  const store = nepStore();
  const opties = Object.assign({}, extra || {});
  // Een verzetbare klok, voor de tests die moeten kijken wat er gebeurt NADAT
  // een ophaling niet meer kan lopen. De bescherming die het bestand vasthoudt
  // zolang er bytes onderweg kunnen zijn, is per definitie tijdgebonden.
  let nu = 1_000_000;
  const klok = { vooruit: (ms) => { nu += ms; }, nu: () => nu };
  if (opties.metKlok) { delete opties.metKlok; opties.now = klok.nu; }
  return { store, klok, sends: createSendStore(Object.assign({ store }, opties)) };
}

test('one file for thirty people, not thirty files', async () => {
  const { store, sends } = maakStore();
  const dertig = Array.from({ length: 30 }, (_, i) => `p${i}@example.org`);

  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: dertig, sealed: sealedVoor(dertig),
                                 filename: 'rapport.pdf' });
  assert.equal(r.ok, true);
  assert.equal(r.count, 30);
  assert.equal(Object.keys(r.tokens).length, 30, 'thirty tokens');
  assert.equal(store.blobs.size, 1, 'and one blob');
});

test('a token collects once, and the second attempt gets nothing', async () => {
  const { sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE, sealed: sealedVoor(DRIE),
                                 filename: 'rapport.pdf' });

  const eerst = await haalOp(sends, r.tokens['bob@example.org']);
  assert.equal(eerst.ok, true);
  assert.equal(eerst.blob.toString(), 'a confidential report');
  assert.equal(eerst.email, 'bob@example.org');
  assert.equal(eerst.remaining, 2, 'two people still to come');

  const tweede = await haalOp(sends, r.tokens['bob@example.org']);
  assert.equal(tweede.ok, false);
  assert.equal(tweede.reason, 'already_collected');
});

test('one person collecting leaves the file for the others', async () => {
  const { store, sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE, sealed: sealedVoor(DRIE) });

  await haalOp(sends, r.tokens['anna@example.org']);
  assert.equal(store.blobs.size, 1, 'the file is still there');

  const bob = await haalOp(sends, r.tokens['bob@example.org']);
  assert.equal(bob.ok, true, 'and the next person still gets it');
});

test('the file goes when the last person is settled', async () => {
  const { store, sends, klok } = maakStore({ metKlok: true });
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE, sealed: sealedVoor(DRIE) });

  await haalOp(sends, r.tokens['anna@example.org']);
  await haalOp(sends, r.tokens['bob@example.org']);
  assert.equal(store.blobs.size, 1);

  const laatste = await haalOp(sends, r.tokens['carla@example.org']);
  assert.equal(laatste.settled, true);

  // NOT gone yet, and that is the fix. The file used to be dropped the moment
  // the last recipient was marked collected, which is before a single byte has
  // left. Measured on 3 MB with the connection cut after the first chunk: the
  // recipient got fragments, the retry said already_collected, the file was
  // gone, and the sender's dashboard reported a delivery that never happened.
  assert.equal(store.blobs.size, 1,
    'the file has to survive until the bytes are actually out the door');

  // De route roept dit aan op de 'finish' van het antwoord zelf. Hier eerst de
  // klok vooruit: zolang een claim vers is houdt drained() het bestand met
  // opzet vast, want dan kunnen er nog bytes over de lijn gaan.
  assert.equal((await sends.drained(r.id)).kept, true,
    'vers geclaimd, dus nog even vasthouden');
  klok.vooruit(120000);
  const weg = await sends.drained(r.id);
  assert.equal(weg.dropped, true);
  assert.equal(store.blobs.size, 0, 'and then it goes');

  // The record survives: the sender must still be able to see who collected.
  const view = await sends.overview(r.id);
  assert.equal(view.collected, 3);
});

test('a connection that dies hands the collection back', async () => {
  // Without this a dropped mobile connection costs somebody their only
  // collection, and the sender is shown a delivery that never happened.
  const { store, sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE, sealed: sealedVoor(DRIE) });
  const token = r.tokens['anna@example.org'];

  const uit = await haalOp(sends, token);
  assert.equal(uit.ok, true);
  assert.equal((await sends.overview(r.id)).collected, 1);

  await sends.releaseClaim(token);
  assert.equal((await sends.overview(r.id)).collected, 0,
    'de ophaling telde niet, want de bytes kwamen nooit aan');
  assert.equal(store.blobs.size, 1, 'en het bestand staat er nog');

  // En ze kan het gewoon opnieuw proberen.
  assert.equal((await haalOp(sends, token)).ok, true);
});

test('withdrawing one person does not touch the rest', async () => {
  const { sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE, sealed: sealedVoor(DRIE) });

  assert.equal((await sends.revoke(r.id, 'carla@example.org')).ok, true);
  const carla = await haalOp(sends, r.tokens['carla@example.org']);
  assert.equal(carla.ok, false);
  assert.equal(carla.reason, 'revoked');

  assert.equal((await haalOp(sends, r.tokens['anna@example.org'])).ok, true);
});

test('withdrawing the last outstanding person drops the file', async () => {
  const { store, sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE, sealed: sealedVoor(DRIE) });

  // Klok ver genoeg vooruit dat de twee ophalingen hierboven niet meer als
  // "in de lucht" tellen: anders houdt de nieuwe bescherming de blob vast,
  // en dat is precies de bedoeling (zie de test hieronder).
  const { store: st2, sends: s2, klok } = maakStore({ metKlok: true });
  const r2 = await s2.create({ plan: 'business', blob: INHOUD, addresses: DRIE, sealed: sealedVoor(DRIE) });
  await haalOp(s2, r2.tokens['anna@example.org']);
  await haalOp(s2, r2.tokens['bob@example.org']);
  klok.vooruit(120000);
  const uit = await s2.revoke(r2.id, 'carla@example.org');
  assert.equal(uit.settled, true);
  assert.equal(st2.blobs.size, 0, 'nobody can still collect, so nothing is kept');
});

test('maar intrekken vernietigt niets onder een ophaling die nog loopt', async () => {
  // De spiegel van de ophaalkant. Trek je de laatste wachtende in terwijl
  // iemands bytes nog over de lijn gaan, dan werd het bestand daar weggegooid:
  // die ophaler kreeg 'expired' met uren op de klok, en de afzender zag hem
  // wachten op een bestand dat niet meer bestond.
  const { store, sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE, sealed: sealedVoor(DRIE) });

  await haalOp(sends, r.tokens['anna@example.org']);
  await haalOp(sends, r.tokens['bob@example.org']);   // net geclaimd, nog onderweg
  const uit = await sends.revoke(r.id, 'carla@example.org');
  assert.equal(uit.settled, true, 'iedereen is afgehandeld');
  assert.equal(store.blobs.size, 1,
    'maar het bestand blijft staan zolang er nog bytes kunnen lopen');
});

test('a reminder does not replace the link, and has a ceiling', async () => {
  const { sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE, sealed: sealedVoor(DRIE) });
  const token = r.tokens['bob@example.org'];

  const eerste = await sends.reinvite(r.id, 'bob@example.org');
  assert.equal(eerste.ok, true);
  assert.equal(eerste.token, undefined, 'a reminder hands out no new token');
  assert.equal(eerste.reminders, 1);

  // The link they already have still collects. Minting a new one would have
  // left them with bytes their token cannot open, because the wrapping in the
  // store belongs to this token and the relay cannot make another.
  assert.equal((await haalOp(sends, token)).ok, true,
    'the invitation in their mailbox is still the one that works');

  // And a sender cannot keep nudging a stranger for ever.
  const tweede = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE, sealed: sealedVoor(DRIE) });
  for (let i = 1; i <= MAX_REMINDERS; i++) {
    assert.equal((await sends.reinvite(tweede.id, 'bob@example.org')).ok, true, 'reminder ' + i);
  }
  const over = await sends.reinvite(tweede.id, 'bob@example.org');
  assert.equal(over.ok, false);
  assert.equal(over.reason, 'reminder_limit');
});

test('the plan decides how many people may be addressed', async () => {
  const { sends } = maakStore();
  const twintig = Array.from({ length: 20 }, (_, i) => `p${i}@example.org`);

  const gratis = await sends.create({ plan: 'community', blob: INHOUD, addresses: twintig, sealed: sealedVoor(twintig) });
  assert.equal(gratis.ok, false);
  assert.equal(gratis.reason, 'over_limit');
  assert.equal(gratis.limit, 1);

  assert.equal((await sends.create({ plan: 'business', blob: INHOUD, addresses: twintig, sealed: sealedVoor(twintig) })).ok, true);
});

test('a bad address is refused before anything is stored', async () => {
  const { store, sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD,
                                 addresses: ['ok@example.org', 'a@x.org\nBcc: derde@x.org'], sealed: sealedVoor(['ok@example.org', 'a@x.org\nBcc: derde@x.org']) });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'invalid_address');
  assert.equal(store.blobs.size, 0, 'no file is written for a send that cannot go out');
  assert.equal(store.meta.size, 0);
});

test('an unknown token says so without revealing whether the send exists', async () => {
  const { sends } = maakStore();
  await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE, sealed: sealedVoor(DRIE) });
  for (const bad of ['', 'x', 'a'.repeat(500), null, undefined]) {
    const r = await haalOp(sends, bad);
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'unknown_token');
  }
});

test('a file that is already gone does not count as collected', async () => {
  const { store, sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE, sealed: sealedVoor(DRIE) });
  store.blobs.clear();                       // the window closed, or a restart

  const p = await haalOp(sends, r.tokens['anna@example.org']);
  assert.equal(p.ok, false);
  assert.equal(p.reason, 'expired');

  const view = await sends.overview(r.id);
  assert.equal(view.collected, 0,
    'a collection that handed nothing over must not show as one');
});

test('the window is capped by the plan, not by what the sender asks', async () => {
  const { sends } = maakStore();
  const jaar = 365 * 24 * 3600 * 1000;

  const gratis = await sends.create({ plan: 'community', blob: INHOUD,
                                      addresses: ['a@example.org'], sealed: sealedVoor(['a@example.org']), ttlMs: jaar });
  assert.ok(gratis.expires_at - Date.now() <= 3_600_000 + 1000, 'community is one hour');

  const zaak = await sends.create({ plan: 'business', blob: INHOUD,
                                    addresses: DRIE, sealed: sealedVoor(DRIE), ttlMs: jaar });
  assert.ok(zaak.expires_at - Date.now() <= 604_800_000 + 1000, 'business is seven days');
});

test('the overview shows people, never a token or a hash', async () => {
  const { sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE, sealed: sealedVoor(DRIE),
                                 filename: 'rapport.pdf' });
  const view = await sends.overview(r.id);
  const raw = JSON.stringify(view);

  assert.equal(view.total, 3);
  assert.equal(view.outstanding, 3);
  assert.equal(view.filename, 'rapport.pdf');
  assert.ok(!raw.includes('token'), 'no token anywhere in what the sender sees');
  assert.ok(!raw.includes('hash'));
  for (const t of Object.values(r.tokens)) assert.ok(!raw.includes(t));
});

test('a send nobody knows gets a refusal, not a crash', async () => {
  const { sends } = maakStore();
  for (const id of ['nope', '', null, undefined]) {
    assert.equal((await sends.overview(id)).ok, false);
    assert.equal((await sends.revoke(id, 'a@example.org')).ok, false);
    assert.equal((await sends.reinvite(id, 'a@example.org')).ok, false);
  }
});

test('a sender sees their own sends, newest first, and nobody else\'s', async () => {
  const { sends } = maakStore();
  const een = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE, sealed: sealedVoor(DRIE),
                                   filename: 'een.pdf', accountId: 'acct-1' });
  const twee = await sends.create({ plan: 'business', blob: INHOUD, addresses: ['x@example.org'], sealed: sealedVoor(['x@example.org']),
                                    filename: 'twee.pdf', accountId: 'acct-1' });
  await sends.create({ plan: 'business', blob: INHOUD, addresses: ['y@example.org'], sealed: sealedVoor(['y@example.org']),
                       filename: 'anders.pdf', accountId: 'acct-2' });

  const lijst = await sends.list('acct-1');
  assert.deepEqual(lijst.sends.map(s => s.filename), ['twee.pdf', 'een.pdf'],
    'newest first, because a dashboard is about what just happened');
  assert.equal(lijst.sends.length, 2, 'and never another account\'s work');

  const ander = await sends.list('acct-2');
  assert.deepEqual(ander.sends.map(s => s.filename), ['anders.pdf']);
  assert.equal((await sends.list(null)).sends.length, 0, 'no account, no list');
  assert.ok(twee.id && een.id);
});

test('the list answers the one question a sender has: who has not been yet', async () => {
  const { sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE, sealed: sealedVoor(DRIE),
                                 filename: 'rapport.pdf', accountId: 'acct-1' });
  await haalOp(sends, r.tokens['anna@example.org']);
  await sends.revoke(r.id, 'bob@example.org');

  const rij = (await sends.list('acct-1')).sends[0];
  assert.equal(rij.total, 3);
  assert.equal(rij.collected, 1);
  assert.equal(rij.revoked, 1);
  assert.equal(rij.outstanding, 1, 'one person is still expected');
  assert.equal(rij.status, 'open');
});

test('a send whose window closed stays in the list, marked expired', async () => {
  const { store, sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE, sealed: sealedVoor(DRIE),
                                 filename: 'oud.pdf', accountId: 'acct-1' });
  store.meta.delete(r.id);                       // the window closed

  const lijst = await sends.list('acct-1');
  assert.equal(lijst.sends.length, 1, 'a list that quietly shrinks looks like a loss');
  assert.equal(lijst.sends[0].status, 'expired');
  assert.equal(lijst.sends[0].id, r.id);
});

test('a send belongs to one account, and a stranger gets the same answer as a wrong id', async () => {
  const { sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE, sealed: sealedVoor(DRIE),
                                 accountId: 'acct-1' });

  assert.equal(await sends.ownedBy(r.id, 'acct-1'), true);
  assert.equal(await sends.ownedBy(r.id, 'acct-2'), false, 'not yours');
  assert.equal(await sends.ownedBy(r.id, null), false);
  assert.equal(await sends.ownedBy('nope', 'acct-1'), false, 'and never existed looks the same');
});

test('the owner is not part of what a sender looks at', async () => {
  const { sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE, sealed: sealedVoor(DRIE),
                                 accountId: 'acct-geheim' });
  const raw = JSON.stringify(await sends.overview(r.id));
  assert.ok(!raw.includes('acct-geheim'),
    'a field that travels to a browser is a field that can end up elsewhere');
});

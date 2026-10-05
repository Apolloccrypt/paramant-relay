'use strict';

// De rem op uitnodigingen.
//
// Deze bestond niet toen Firm tien ontvangers had, en werd nodig op het moment
// dat het er dertig werden. Zonder rem is een betaald account een manier om
// onbeperkt post in de bus van vreemden te leggen met paramant.app op de
// envelop, en wat dat kost is geen rekening maar de reputatie van het domein.
//
// De bestaande outboundRateOk telt DOWNLOADS: werk dat een ontvanger zelf
// vraagt op een link die hij al heeft. Dit telt wat wij versturen aan mensen
// die geen klant zijn. Twee verschillende dingen, twee tellers.

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('fs');
const path = require('path');

const BRON = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');

function blokVanaf(anker, lengte) {
  const i = BRON.indexOf(anker);
  assert.ok(i > 0, 'niet gevonden in relay.js: ' + anker);
  return BRON.slice(i, i + lengte);
}

test('de rem wordt gevraagd voordat er iets wordt weggeschreven', () => {
  // De volgorde is het hele punt. Vuurt de rem pas tijdens de mailronde, dan
  // is de verzending al gemaakt: twaalf mensen uitgenodigd, achttien niet, en
  // een record dat dertig zegt.
  const remOp = BRON.indexOf('const _rem = inviteRateOk(');
  const create = BRON.indexOf('const made = await _sendStore().create(');
  const mailen = BRON.indexOf("(wieRuw ? wieRuw + ' heeft u een bestand gestuurd'");
  assert.ok(remOp > 0 && create > 0 && mailen > 0, 'ankers niet gevonden');
  assert.ok(remOp < create, 'de rem moet voor create komen, niet erna');
  assert.ok(create < mailen, 'en create voor de mailronde');
});

test('de hele verzending vraagt zijn plaatsen in een keer', () => {
  const blok = blokVanaf('function inviteRateOk(', 900);
  assert.match(blok, /c\.count \+ n > max/,
    'per mail tellen laat een verzending half gebeuren; het moet alles of niets zijn');
  assert.match(blok, /retry_after_s/, 'en zeggen wanneer het weer mag');
});

test('een geweigerde verzending geeft de plaatsen terug', () => {
  // Anders kost een afzender die tegen het ontvangersplafond loopt ook nog een
  // uur van zijn uitnodigingsbudget, voor post die nooit vertrok.
  const blok = blokVanaf('if (!made.ok) {', 500);
  assert.match(blok, /inviteRateGeef\(/, 'de plaatsen moeten terug bij een weigering');
});

test('het plafond komt van de productas, niet van het oude plan-veld', () => {
  const blok = blokVanaf('function inviteRateOk(', 400);
  assert.match(blok, /parasendLimitsOf\(rec\)\.limits\.outbound_per_hour/,
    'kd.plan lezen is precies de fout die parasendLimitsOf bestaat om te stoppen');
});

test('onbeperkt blijft onbeperkt', () => {
  const blok = blokVanaf('function inviteRateOk(', 400);
  assert.match(blok, /if \(max === Infinity\) return \{ ok: true \}/,
    'enterprise mag niet op een teller stuklopen');
});

test('de weigering is een 429 met Retry-After, geen kale fout', () => {
  const blok = blokVanaf("log('warn', 'invite_rate_limited'", 700);
  assert.match(blok, /writeHead\(429/);
  assert.match(blok, /'Retry-After'/);
  assert.match(blok, /too_many_invitations/);
  assert.match(blok, /hint:/, 'de afzender moet kunnen lezen wat er aan de hand is');
});

test('de teller loopt niet vol met dode accounts', () => {
  const blok = blokVanaf('const inviteRateMap = new Map()', 1800);
  assert.match(blok, /setInterval\([\s\S]*inviteRateMap\.delete\(k\)/,
    'zonder opruiming groeit deze map per account dat ooit iets stuurde');
});

// ── En het getal waar dit allemaal om begon ────────────────────────────────

test('Firm draagt de dertig ontvangers waar het product op verkocht wordt', () => {
  const tiers = require('../lib/tiers');
  assert.equal(tiers.tierLimitNum('pro', 'max_recipients'), 30,
    'een zorgorganisatie vroeg om twintig; op tien was het antwoord nee');
  assert.equal(tiers.tierLimitNum('community', 'max_recipients'), 1,
    'en gratis blijft een ontvanger, anders is er niets te kopen');
});

test('dertig ontvangers passen binnen de uurrem van het plan dat ze koopt', () => {
  // Dertig ontvangers is zestig mails: de uitnodiging en, als iedereen ophaalt,
  // de code. Kan een Firm-klant een volle verzending doen zonder de rem te
  // raken, dan klopt het aanbod met zichzelf.
  const tiers = require('../lib/tiers');
  const perUur = tiers.tierLimitNum('pro', 'outbound_per_hour');
  const ontvangers = tiers.tierLimitNum('pro', 'max_recipients');
  assert.ok(perUur >= ontvangers,
    'een enkele volle verzending mag nooit op de eigen rem stuklopen: '
    + perUur + ' per uur tegen ' + ontvangers + ' ontvangers');
  assert.ok(Math.floor(perUur / ontvangers) >= 10,
    'en er moet ruimte zijn voor meer dan een handvol per uur, nu: '
    + Math.floor(perUur / ontvangers));
});

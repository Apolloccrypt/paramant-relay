'use strict';
// Een schrijfactie naar users.json die te laat landt, op bestelling.
//
// WAAROM. POST /v2/reload-users leest users.json opnieuw in. De relay antwoordt
// op een wijziging (set-product-plan) al voordat zijn eigen schrijfactie naar
// dat bestand klaar is: _mutateUsersJson loopt los in een wachtrij. De admin
// roept direct daarna reload-users aan. Wacht die niet op de wachtrij, dan leest
// hij het oude bestand en zet hij de oude stand terug in het geheugen, terwijl
// het nieuwe bestand een tel later alsnog op schijf komt (review #515, ronde 2).
// Op een snelle schijf is dat venster een paar milliseconden, dus een test
// zonder hulp is een trekking. Deze hulp maakt het venster zo breed als de test
// wil, zodat de race zonder de fix elke keer rood is.
//
// HOE. Geladen met --require in een relay-proces (NODE_OPTIONS). Zolang er naast
// users.json een bestand users.json.traag staat, wacht elke rename naar
// users.json het aantal milliseconden dat in dat bestand staat. De atomische
// schrijver van relay.js (tmp + rename) laat het oude bestand dus zo lang
// staan. Zonder vlagbestand verandert er niets.
const fs = require('fs');

const origineel = fs.promises.rename.bind(fs.promises);
fs.promises.rename = async function traagHernoemen(van, naar) {
  const doel = String(naar);
  if (doel.endsWith('users.json')) {
    let ms = 0;
    try { ms = parseInt(fs.readFileSync(`${doel}.traag`, 'utf8'), 10) || 0; } catch { ms = 0; }
    if (ms > 0) await new Promise((r) => setTimeout(r, ms));
  }
  return origineel(van, naar);
};

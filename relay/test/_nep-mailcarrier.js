'use strict';

// Een neppe mailprovider IN het relayproces, via NODE_OPTIONS=--require.
//
// lib/mail.js praat met api.mailjet.com over globalThis.fetch. Die wordt hier
// onderschept voordat relay.js ook maar geladen is, zodat een test een
// provider halverwege kan laten omvallen zonder dat er ooit een pakketje het
// netwerk op gaat. Elke "bezorging" wordt als JSON-regel op stdout gezet, dus
// de test telt wat er ECHT weg zou zijn in plaats van wat de route beweert.
//
// NEPMAIL_OK_TOT   hoeveel berichten worden aangenomen voordat de API stuk gaat
// NEPMAIL_WEIGER   comma-lijst adressen die per stuk geweigerd worden

const OK_TOT = parseInt(process.env.NEPMAIL_OK_TOT || '1000000', 10);
const WEIGER = String(process.env.NEPMAIL_WEIGER || '').split(',').filter(Boolean);

let geteld = 0;
const echt = globalThis.fetch;

globalThis.fetch = async function (url, opts) {
  const u = String(url || '');
  if (!u.includes('api.mailjet.com')) return echt(url, opts);

  const body = JSON.parse(opts.body);
  const adressen = body.Messages.map(m => m.To.map(t => t.Email).join('+'));
  const regels = [];
  let stuk = false;
  for (const a of adressen) {
    geteld += 1;
    if (geteld > OK_TOT) { stuk = true; break; }
    if (WEIGER.includes(a)) { regels.push({ Status: 'error', Email: a }); continue; }
    // Dit is de enige plek die "er is post bezorgd" mag zeggen.
    console.log(JSON.stringify({ level: 'info', event: 'nepmail_bezorgd', naar: a,
                                 from: body.Messages[0].From, n: geteld }));
    regels.push({ Status: 'success', Email: a });
  }
  if (stuk) {
    console.log(JSON.stringify({ level: 'info', event: 'nepmail_stuk', n: geteld }));
    return { ok: false, status: 503, text: async () => 'carrier down' };
  }
  return { ok: true, status: 200, json: async () => ({ Messages: regels }),
           text: async () => '{}' };
};

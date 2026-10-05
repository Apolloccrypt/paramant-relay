'use strict';

// EEN OPZETTELIJK TRAGE REDIS, in Node, voor de racetests.
//
// WAAROM DIT ER MOET ZIJN. De verzendlaag (relay/lib/send.js) doet overal
// lees-wijzig-schrijf: getMeta, iets veranderen, putMeta. De wachtrij
// `opVolgorde` bestaat om te voorkomen dat een tweede verzoek tussen die twee
// door glipt. Zonder redis valt parasign-store terug op een Map in het
// geheugen (lib/parasign-store.js:91) en dan lost elke get/put SYNCHROON op:
// er is geen enkel opschortpunt tussen lezen en schrijven, dus het gat dat de
// wachtrij moet dichten bestaat in die opstelling helemaal niet. Een groene
// test op de geheugenbackend bewijst dus vrijwel niets over productie, waar
// elke get en put een netwerkronde is.
//
// Deze stub is die netwerkronde, met een instelbare vertraging erbovenop, zodat
// het venster tussen lezen en schrijven zo breed wordt dat een verloren
// schrijfactie NIET aan toeval kan ontsnappen.
//
// Het is geen redis. Het spreekt genoeg RESP om node-redis 5.x tevreden te
// houden voor wat de relay ermee doet: GET/SET/DEL op base64-strings
// (parasign-store seal() levert base64, lib/parasign-store.js:45) plus de
// huishoudelijke commando's die de client bij het verbinden stuurt.

const net = require('net');

function bulk(s) {
  if (s === null || s === undefined) return '$-1\r\n';
  const b = Buffer.from(String(s));
  return Buffer.concat([Buffer.from('$' + b.length + '\r\n'), b, Buffer.from('\r\n')]);
}
const simple = (s) => Buffer.from('+' + s + '\r\n');
const getal  = (n) => Buffer.from(':' + n + '\r\n');
const fout   = (s) => Buffer.from('-ERR ' + s + '\r\n');
const leeg   = () => Buffer.from('*0\r\n');

// Eén RESP-array uit de buffer halen. Geeft { args, rest } of null als er nog
// niet genoeg bytes zijn.
function hapArray(buf) {
  if (!buf.length) return null;
  if (buf[0] !== 0x2a) {                     // geen '*': inline commando
    const eind = buf.indexOf('\r\n');
    if (eind < 0) return null;
    const regel = buf.subarray(0, eind).toString().trim();
    return { args: regel ? regel.split(/\s+/) : [], rest: buf.subarray(eind + 2) };
  }
  let p = buf.indexOf('\r\n');
  if (p < 0) return null;
  const n = parseInt(buf.subarray(1, p).toString(), 10);
  p += 2;
  const args = [];
  for (let i = 0; i < n; i++) {
    if (p >= buf.length || buf[p] !== 0x24) return null;   // '$'
    const q = buf.indexOf('\r\n', p);
    if (q < 0) return null;
    const len = parseInt(buf.subarray(p + 1, q).toString(), 10);
    const start = q + 2;
    if (buf.length < start + len + 2) return null;
    args.push(buf.subarray(start, start + len).toString('latin1'));
    p = start + len + 2;
  }
  return { args, rest: buf.subarray(p) };
}

// vertragingMs: hoeveel echte tijd elke GET/SET/DEL kost. Dat is precies het
// venster waarin een tweede verzoek tussen lezen en schrijven kan komen.
function startTraagRedis({ vertragingMs = 8 } = {}) {
  const data = new Map();            // key -> { val, expiresAt }
  const tel = { get: 0, set: 0, del: 0, overig: 0 };
  const server = net.createServer((sock) => {
    let buf = Buffer.alloc(0);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      for (;;) {
        const hap = hapArray(buf);
        if (!hap) break;
        buf = hap.rest;
        beantwoord(sock, hap.args);
      }
    });
    sock.on('error', () => { /* client ging weg */ });
  });

  // Het commando wordt UITGEVOERD op het moment dat het binnenkomt, precies
  // zoals redis dat doet; alleen het antwoord wordt opgehouden. Zo zit de
  // vertraging in de transportlaag en niet in de uitvoering, blijft de volgorde
  // van de effecten die van aankomst, en lopen honderd verzoeken door elkaar in
  // plaats van achter elkaar. Alle antwoorden krijgen dezelfde vertraging, dus
  // ze vertrekken in dezelfde volgorde als ze binnenkwamen -- wat RESP eist.
  function beantwoord(sock, args) {
    const cmd = String(args[0] || '').toUpperCase();
    const reply = antwoord(cmd, args);
    // Elk antwoord krijgt DEZELFDE vertraging. Een sneller antwoord zou een
    // langzamer antwoord inhalen en dan klopt de volgorde op de socket niet meer.
    if (vertragingMs > 0) {
      setTimeout(() => { if (!sock.destroyed) sock.write(reply); }, vertragingMs);
    } else if (!sock.destroyed) {
      sock.write(reply);
    }
  }

  function antwoord(cmd, args) {
    const nu = Date.now();
    switch (cmd) {
      case 'GET': {
        tel.get++;
        const r = data.get(args[1]);
        if (!r) return bulk(null);
        if (r.expiresAt && nu > r.expiresAt) { data.delete(args[1]); return bulk(null); }
        return bulk(r.val);
      }
      case 'SET': {
        tel.set++;
        let px = null;
        for (let i = 3; i < args.length; i++) {
          const o = String(args[i]).toUpperCase();
          if (o === 'PX') px = Number(args[i + 1]);
          if (o === 'EX') px = Number(args[i + 1]) * 1000;
        }
        data.set(args[1], { val: args[2], expiresAt: px ? nu + px : 0 });
        return simple('OK');
      }
      case 'SETEX':
        tel.set++;
        data.set(args[1], { val: args[3], expiresAt: nu + Number(args[2]) * 1000 });
        return simple('OK');
      case 'DEL': {
        tel.del++;
        let n = 0;
        for (let i = 1; i < args.length; i++) if (data.delete(args[i])) n++;
        return getal(n);
      }
      case 'EXISTS': {
        let n = 0;
        for (let i = 1; i < args.length; i++) if (data.has(args[i])) n++;
        return getal(n);
      }
      case 'INCR': case 'INCRBY': {
        const stap = cmd === 'INCR' ? 1 : Number(args[2]) || 1;
        const r = data.get(args[1]);
        const v = (r ? Number(r.val) || 0 : 0) + stap;
        data.set(args[1], { val: String(v), expiresAt: r ? r.expiresAt : 0 });
        return getal(v);
      }
      case 'TTL': case 'PTTL': {
        const r = data.get(args[1]);
        if (!r) return getal(-2);
        if (!r.expiresAt) return getal(-1);
        const over = r.expiresAt - nu;
        return getal(cmd === 'TTL' ? Math.ceil(over / 1000) : over);
      }
      case 'EXPIRE': case 'PEXPIRE': {
        const r = data.get(args[1]);
        if (!r) return getal(0);
        r.expiresAt = nu + Number(args[2]) * (cmd === 'EXPIRE' ? 1000 : 1);
        return getal(1);
      }
      case 'PING':
        return args[1] ? bulk(args[1]) : simple('PONG');
      case 'INFO':
        return bulk('# Server\r\nredis_version:0.0.0-traag-stub\r\n');
      case 'SUBSCRIBE': case 'PSUBSCRIBE':
        return Buffer.concat([Buffer.from('*3\r\n'), bulk(cmd.toLowerCase()),
                              bulk(args[1] || ''), getal(1)]);
      case 'UNSUBSCRIBE': case 'PUNSUBSCRIBE':
        return Buffer.concat([Buffer.from('*3\r\n'), bulk(cmd.toLowerCase()),
                              bulk(args[1] || ''), getal(0)]);
      case 'PUBLISH':
        return getal(0);
      case 'KEYS': case 'SMEMBERS': case 'LRANGE': case 'HGETALL': case 'HKEYS':
        return leeg();
      case 'SCAN':
        return Buffer.concat([Buffer.from('*2\r\n'), bulk('0'), leeg()]);
      case 'HGET': case 'LPOP': case 'RPOP': case 'GETDEL':
        return bulk(null);
      case 'HSET': case 'SADD': case 'SREM': case 'LPUSH': case 'RPUSH': case 'ZADD':
        return getal(1);
      // De quotapoorten draaien een Lua-script (lib/quota.js:156 en verder) en
      // verwachten een array van strings terug: { status, used }. Altijd 'ok',
      // want deze suite meet gelijktijdigheid, niet plafonds.
      case 'EVAL': case 'EVALSHA': case 'FCALL':
        return Buffer.concat([Buffer.from('*2\r\n'), bulk('ok'), bulk('1')]);
      case 'SCRIPT':
        return bulk('0'.repeat(40));
      case 'HELLO':
        // RESP3 wordt geweigerd, zodat node-redis op RESP2 blijft.
        return fout("unknown command 'HELLO'");
      case 'CLIENT': case 'SELECT': case 'AUTH': case 'CONFIG': case 'QUIT':
      case 'COMMAND': case 'RESET':
        tel.overig++;
        return simple('OK');
      default:
        tel.overig++;
        return simple('OK');
    }
  }

  return new Promise((klaar) => {
    server.listen(0, '127.0.0.1', () => {
      klaar({
        url: 'redis://127.0.0.1:' + server.address().port,
        port: server.address().port,
        tel,
        data,
        stop: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

module.exports = { startTraagRedis };

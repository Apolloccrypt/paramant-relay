'use strict';
// One answer per request, also when the request arrives twice.
//
// WHY. A double click on "send" made two envelopes and mailed every party
// twice (sweep-chaos, race.mjs). The key is the client's Idempotency-Key header
// when it sends one, else a hash of the request body: the same body from the
// same account within the window IS the same request. The first request runs;
// a second one that arrives while it is running waits for its answer, and one
// that arrives later gets the stored answer. Only 2xx answers are stored, so a
// failed first try can be retried at once.
const crypto = require('crypto');

function middleware({ redis, scope, windowSec = 120, waitMs = 10000 }) {
  return async function idempotent(req, res, next) {
    const who = (req.userSession && req.userSession.user_id) || '';
    if (!who) return next();
    const given = String(req.get('idempotency-key') || '').trim();
    const basis = given && /^[A-Za-z0-9_.:-]{8,128}$/.test(given)
      ? `k:${given}`
      : `b:${crypto.createHash('sha256').update(JSON.stringify(req.body || {})).digest('hex')}`;
    const id = crypto.createHash('sha256').update(`${scope}|${who}|${req.originalUrl.split('?')[0]}|${basis}`).digest('hex').slice(0, 40);
    const key = `paramant:idem:${id}`;
    let r;
    try { r = redis(); } catch { return next(); }
    let claimed;
    try { claimed = await r.set(key, JSON.stringify({ state: 'running' }), { NX: true, EX: windowSec }); }
    catch { return next(); } // no redis: behave as before rather than refuse
    if (claimed) {
      const json = res.json.bind(res);
      res.json = (body) => {
        const status = res.statusCode || 200;
        const store = status >= 200 && status < 300
          ? r.set(key, JSON.stringify({ state: 'done', status, body }), { EX: windowSec })
          : r.del(key);
        Promise.resolve(store).catch(() => {});
        return json(body);
      };
      return next();
    }
    // A twin. Wait for the first one's answer.
    const until = Date.now() + waitMs;
    while (Date.now() < until) {
      let rec = null;
      try { rec = JSON.parse((await r.get(key)) || 'null'); } catch { rec = null; }
      if (!rec) return next(); // the first one failed and gave the key back
      if (rec.state === 'done') {
        res.set('Idempotent-Replay', 'true');
        return res.status(rec.status).json(rec.body);
      }
      await new Promise((x) => setTimeout(x, 150));
    }
    return res.status(409).json({ error: 'request_in_progress', message: 'The same request is still being handled. Wait a moment and reload.' });
  };
}

module.exports = { middleware };

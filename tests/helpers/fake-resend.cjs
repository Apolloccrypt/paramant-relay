'use strict';
// A stand-in for api.resend.com: the mailbox a test can read.
// Everything the buyer is promised in writing (his invoice, the warning seven
// days before his term ends, the confirmation that his plan ended, the
// cancellation mail) leaves through this one API, and with RESEND_API_KEY unset
// the relay skips sending WITHOUT failing anything. So "no mail arrived" is
// indistinguishable from "everything is fine" unless a test can actually look
// in the mailbox.

const http = require('http');

function create() {
  const mails = [];
  const server = http.createServer((req, res) => {
    if (req.method !== 'POST' || !req.url.startsWith('/emails')) {
      res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end('{}');
    }
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let body = {};
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (_) { /* keep {} */ }
      mails.push({ at: new Date().toISOString(), ...body });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ id: 'msg_' + mails.length }));
    });
  });
  return {
    mails,
    async listen() { await new Promise((r) => server.listen(0, '127.0.0.1', r)); return `http://127.0.0.1:${server.address().port}`; },
    close() { return new Promise((r) => server.close(r)); },
    // Every mail whose subject matches, newest last.
    matching(re) { return mails.filter((m) => re.test(String(m.subject || ''))); },
    clear() { mails.length = 0; },
  };
}

module.exports = { create };

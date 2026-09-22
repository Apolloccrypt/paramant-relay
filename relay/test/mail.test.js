'use strict';

// One way out for every message, with the carrier behind a setting. These tests
// hold the two things that matter for a switch: the caller never learns which
// provider ran, and a delivery problem never becomes a thrown error inside the
// request that triggered the mail.

const assert = require('node:assert/strict');
const test = require('node:test');

const mail = require('../lib/mail');

function nepFetch(antwoorden) {
  const calls = [];
  const rij = [].concat(antwoorden);
  const fn = async (url, init) => {
    calls.push({ url, init, body: init && init.body ? JSON.parse(init.body) : null });
    const a = rij.length > 1 ? rij.shift() : rij[0];
    return {
      ok: a.ok !== false,
      status: a.status || (a.ok === false ? 500 : 200),
      text: async () => a.text || '',
    };
  };
  fn.calls = calls;
  return fn;
}

const bericht = { to: 'anna@example.org', subject: 'Your document', html: '<p>Hello <b>Anna</b></p>' };

test('an unknown provider name falls back to dryrun, never to a live carrier', () => {
  for (const naam of ['', 'postmark', 'sendgrid', 'nonsense']) {
    const cfg = mail.config({ MAIL_PROVIDER: naam });
    assert.equal(cfg.provider, naam === '' ? 'resend' : 'dryrun',
      'an empty setting keeps today\'s provider, a wrong one sends nothing');
  }
  assert.equal(mail.config({ MAIL_PROVIDER: ' Scaleway ' }).provider, 'scaleway',
    'case and spaces do not decide who carries the mail');
});

test('scaleway gets one call per address, in its own shape', async () => {
  const f = nepFetch({ ok: true });
  const r = await mail.stuur(
    { to: ['anna@example.org', 'bob@example.org'], subject: 'Signed', text: 'Done' },
    { fetch: f, env: { MAIL_PROVIDER: 'scaleway', SCALEWAY_SECRET_KEY: 'k', SCALEWAY_PROJECT_ID: 'p' } });
  assert.equal(r.ok, true);
  assert.equal(r.provider, 'scaleway');
  assert.equal(f.calls.length, 2, 'two recipients, two calls');
  assert.match(f.calls[0].url, /transactional-email/);
  assert.match(f.calls[0].url, /fr-par/, 'the region is part of the address');
  assert.equal(f.calls[0].init.headers['X-Auth-Token'], 'k');
  assert.deepEqual(f.calls[1].body.to, [{ email: 'bob@example.org' }]);
  assert.equal(f.calls[0].body.project_id, 'p');
});

test('resend keeps working unchanged, one call for the whole list', async () => {
  const f = nepFetch({ ok: true });
  const r = await mail.stuur(
    { to: ['anna@example.org', 'bob@example.org'], subject: 'Signed', html: '<p>Done</p>' },
    { fetch: f, env: { MAIL_PROVIDER: 'resend', RESEND_API_KEY: 'k' } });
  assert.equal(r.ok, true);
  assert.equal(f.calls.length, 1);
  assert.match(f.calls[0].url, /api\.resend\.com/);
  assert.equal(f.calls[0].init.headers.Authorization, 'Bearer k');
});

test('a provider without credentials says so instead of pretending', async () => {
  const r = await mail.stuur(bericht,
    { fetch: nepFetch({ ok: true }), env: { MAIL_PROVIDER: 'scaleway' } });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'not_configured');
});

test('a refusing carrier becomes a result, never a thrown error', async () => {
  const r = await mail.stuur(bericht,
    { fetch: nepFetch({ ok: false, status: 422, text: 'domain not verified' }),
      env: { MAIL_PROVIDER: 'resend', RESEND_API_KEY: 'k' } });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'http_422');
  assert.match(r.detail, /domain not verified/);
});

test('a carrier that blows up is caught, because a notice must not kill a request', async () => {
  const boem = async () => { throw new Error('socket hang up'); };
  const r = await mail.stuur(bericht,
    { fetch: boem, env: { MAIL_PROVIDER: 'resend', RESEND_API_KEY: 'k' } });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'threw');
  assert.match(r.detail, /socket hang up/);
});

test('a message without a recipient, subject or body is refused before it is sent', async () => {
  const env = { MAIL_PROVIDER: 'resend', RESEND_API_KEY: 'k' };
  const f = nepFetch({ ok: true });
  for (const slecht of [
    { subject: 'x', text: 'y' },
    { to: 'a@example.org', text: 'y' },
    { to: 'a@example.org', subject: 'x' },
    { to: ['  ', ''], subject: 'x', text: 'y' },
  ]) {
    const r = await mail.stuur(slecht, { fetch: f, env });
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'invalid');
  }
  assert.equal(f.calls.length, 0, 'nothing reached the carrier');
});

test('dryrun reports success but says it delivered nothing', async () => {
  const f = nepFetch({ ok: true });
  const r = await mail.stuur(bericht, { fetch: f, env: { MAIL_PROVIDER: 'dryrun' } });
  assert.equal(r.ok, true);
  assert.equal(r.delivered, false);
  assert.equal(f.calls.length, 0);
});

test('html gets a readable plain-text fallback', () => {
  const t = mail.stripHtml('<p>Hello <b>Anna</b></p><br><div>Your file is ready</div><script>x</script>');
  assert.match(t, /Hello Anna/);
  assert.match(t, /Your file is ready/);
  assert.ok(!t.includes('<'), 'no tags survive');
  assert.ok(!t.includes('x'), 'script content is dropped, not flattened into the text');
});

test('the from line is split the way a carrier expects it', () => {
  assert.deepEqual(mail.ontleedAfzender('PARAMANT <noreply@paramant.app>'),
    { name: 'PARAMANT', email: 'noreply@paramant.app' });
  assert.deepEqual(mail.ontleedAfzender('noreply@paramant.app'),
    { name: undefined, email: 'noreply@paramant.app' });
});

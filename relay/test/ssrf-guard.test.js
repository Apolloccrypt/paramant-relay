'use strict';
// URL-level SSRF guard, incl. the IPv4-in-IPv6 embeddings closed in #21.
const test = require('node:test');
const assert = require('node:assert/strict');
const { isSsrfSafeUrl } = require('../lib/ssrf-guard');

const blocked = [
  ['https://[64:ff9b::127.0.0.1]/', 'NAT64 -> loopback'],
  ['https://[64:ff9b::a9fe:a9fe]/', 'NAT64 -> 169.254.169.254 (cloud metadata)'],
  ['https://[64:ff9b:1::7f00:1]/', 'NAT64 local-use prefix'],
  ['https://[2002:7f00:0001::]/', '6to4 -> 127.0.0.1'],
  ['https://[64:ff9b::8.8.8.8]/', 'NAT64 to a public v4 is still not followed'],
  ['https://[::ffff:127.0.0.1]/', 'IPv4-mapped loopback'],
  ['https://[::1]/', 'IPv6 loopback'],
  ['https://127.0.0.1/', 'IPv4 loopback'],
  ['https://169.254.169.254/', 'link-local metadata'],
  ['https://10.0.0.5/', 'RFC1918 10/8'],
  ['https://192.168.1.1/', 'RFC1918 192.168/16'],
  ['https://[fd00::1]/', 'IPv6 ULA'],
  ['https://2130706433/', 'decimal-encoded 127.0.0.1'],
  ['https://0x7f000001/', 'hex-encoded 127.0.0.1'],
  ['https://metadata.google.internal/', 'GCP metadata host'],
  ['https://example.com:8080/', 'non-443 port'],
  ['http://example.com/', 'plain http'],
];

const allowed = [
  ['https://example.com/', 'normal public host'],
  ['https://relay.paramant.app/v2/sth', 'public host with path'],
  ['https://[2606:4700::1111]/', 'real public IPv6 (Cloudflare)'],
  ['https://1.1.1.1/', 'public IPv4'],
];

test('blocks loopback / RFC1918 / metadata / numeric / IPv4-in-IPv6 embeddings', () => {
  for (const [u, desc] of blocked) assert.equal(isSsrfSafeUrl(u), false, 'should block: ' + desc + '  ' + u);
});

test('allows genuine public HTTPS endpoints', () => {
  for (const [u, desc] of allowed) assert.equal(isSsrfSafeUrl(u), true, 'should allow: ' + desc + '  ' + u);
});

test('garbage input does not throw', () => {
  for (const u of ['', 'not a url', 'ftp://x', null, undefined, '://', 'https://']) {
    assert.equal(isSsrfSafeUrl(u), false);
  }
});

'use strict';
// Cleverbase Signing API client (Cloud Signature Consortium API v1.0.4).
//
// Hosts, per https://cleverbase.com/en/dev-docs/signing/ :
//   pre-production  https://connect.acc.cleverbase.com
//   production      https://connect.cleverbase.com
// Endpoint paths come from POST /csc/v1/info, which is public and unauthenticated.
//
// What this does and does not do:
//   - It only ever sends a 32-byte SHA-256 digest. There is no signDoc in this
//     API and there is no upload path here either. The PDF never leaves.
//   - It cannot identify a signer on its own. authType is "oauth2code" only, so
//     a natural person has to authorise in the Cleverbase app; there is no
//     client_credentials shortcut, in sandbox or in production. The identity in
//     the certificate is Cleverbase's, established with NFC chip reading plus
//     biometrics, not ours.
//   - Credentials come from the environment (CLEVERBASE_*) and nowhere else.
//
// Every secret stays out of the repository. deploy/.env.example carries only the
// client id and secret that Cleverbase itself publishes for its development
// stubs, marked as such.

const crypto = require('node:crypto');

const SANDBOX_BASE_URL = 'https://connect.acc.cleverbase.com';
const PRODUCTION_BASE_URL = 'https://connect.cleverbase.com';

// Both fixed by the API: SHA-256 digests, RSA PKCS#1 v1.5 signatures.
const HASH_ALGO_OID = '2.16.840.1.101.3.4.2.1';
const SIGN_ALGO_OID = '1.2.840.113549.1.1.1';
const MAX_SIGNATURES_PER_AUTHORISATION = 50;

function configFromEnv(env = process.env) {
  return {
    baseUrl: env.CLEVERBASE_BASE_URL || SANDBOX_BASE_URL,
    clientId: env.CLEVERBASE_CLIENT_ID || '',
    clientSecret: env.CLEVERBASE_CLIENT_SECRET || '',
    redirectUri: env.CLEVERBASE_REDIRECT_URI || '',
  };
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

class CleverbaseError extends Error {
  constructor(message, { status = 0, body = null } = {}) {
    super(message);
    this.name = 'CleverbaseError';
    this.status = status;
    this.body = body;
  }
}

class CleverbaseClient {
  constructor(options = {}) {
    const cfg = { ...configFromEnv(options.env), ...options };
    this.baseUrl = String(cfg.baseUrl).replace(/\/+$/, '');
    this.clientId = cfg.clientId;
    this.clientSecret = cfg.clientSecret;
    this.redirectUri = cfg.redirectUri;
    this.timeoutMs = Number(cfg.timeoutMs) || 20000;
    this.fetchImpl = cfg.fetchImpl || fetch;
  }

  get isSandbox() { return this.baseUrl === SANDBOX_BASE_URL; }
  url(path) { return this.baseUrl + '/csc/v1/' + String(path).replace(/^\/+/, ''); }

  async request(path, { body = null, bearer = null, form = null } = {}) {
    const headers = {};
    let payload;
    if (form) {
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      headers['Authorization'] = 'Basic ' + Buffer.from(this.clientId + ':' + this.clientSecret).toString('base64');
      payload = new URLSearchParams(form).toString();
    } else {
      headers['Content-Type'] = 'application/json';
      payload = JSON.stringify(body || {});
    }
    if (bearer) headers['Authorization'] = 'Bearer ' + bearer;

    const res = await this.fetchImpl(this.url(path), {
      method: 'POST', headers, body: payload,
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const text = await res.text();
    let parsed = null;
    try { parsed = text ? JSON.parse(text) : null; } catch { /* keep the raw text below */ }
    if (!res.ok) {
      const detail = (parsed && (parsed.error_description || parsed.error)) || text.slice(0, 300);
      throw new CleverbaseError('Cleverbase ' + path + ' failed: ' + res.status + ' ' + detail,
        { status: res.status, body: parsed || text });
    }
    return parsed;
  }

  // Public discovery document. Needs no credentials, which makes it the one
  // call an integration test can always make against the sandbox.
  info(lang = 'en-US') { return this.request('info', { body: { lang } }); }

  // Step 1: where the signer's browser goes. `scope` is "service" for an API
  // token, "credential" for a Signature Activation Data token bound to exactly
  // the hashes handed in here.
  authorizeUrl({ scope, state, credentialID = null, hashes = null, numSignatures = null,
    redirectUri = this.redirectUri, lang = 'en-US', accountToken = null }) {
    if (scope !== 'service' && scope !== 'credential') throw new Error('scope must be service or credential');
    if (!this.clientId) throw new Error('CLEVERBASE_CLIENT_ID is not set');
    if (!redirectUri) throw new Error('CLEVERBASE_REDIRECT_URI is not set');
    const q = new URLSearchParams({
      response_type: 'code', client_id: this.clientId, redirect_uri: redirectUri, scope, lang,
      state: String(state || ''),
    });
    if (scope === 'credential') {
      if (!credentialID) throw new Error('credential scope needs a credentialID');
      if (!Array.isArray(hashes) || !hashes.length) throw new Error('credential scope needs hashes');
      const count = numSignatures || hashes.length;
      if (count > MAX_SIGNATURES_PER_AUTHORISATION) {
        throw new Error('at most ' + MAX_SIGNATURES_PER_AUTHORISATION + ' signatures per authorisation');
      }
      q.set('credentialID', credentialID);
      q.set('numSignatures', String(count));
      q.set('hash', hashes.map((h) => b64url(h)).join(','));
    }
    if (accountToken) q.set('account_token', accountToken);
    return this.url('oauth2/authorize') + '?' + q.toString();
  }

  // Step 2: authorisation code to token. A "service" scope code yields a Bearer
  // token; a "credential" scope code yields the SAD, which lives 300 seconds.
  async exchangeCode(code, redirectUri = this.redirectUri) {
    if (!this.clientSecret) throw new Error('CLEVERBASE_CLIENT_SECRET is not set');
    return this.request('oauth2/token', {
      form: { grant_type: 'authorization_code', code, client_id: this.clientId, redirect_uri: redirectUri },
    });
  }

  listCredentials(serviceToken, maxResults = 10) {
    return this.request('credentials/list', { bearer: serviceToken, body: { maxResults } });
  }

  // Returns the CSC payload plus the certificate chain as DER buffers, signer
  // certificate first, which is the order CMS wants.
  async credentialInfo(serviceToken, credentialID) {
    const out = await this.request('credentials/info', { bearer: serviceToken, body: { credentialID } });
    const chain = ((out && out.cert && out.cert.certificates) || []).map((b64) => Buffer.from(b64, 'base64'));
    return { ...out, chain };
  }

  // Step 3: the only call that produces a signature. `hashes` are raw digests;
  // they go out base64-encoded and come back as raw signature values.
  async signHash({ serviceToken, credentialID, sad, hashes }) {
    if (!Array.isArray(hashes) || !hashes.length) throw new Error('signHash needs at least one hash');
    for (const h of hashes) {
      if (!Buffer.isBuffer(h) || h.length !== 32) throw new Error('signHash takes 32-byte SHA-256 digests');
    }
    const out = await this.request('signatures/signHash', {
      bearer: serviceToken,
      body: {
        credentialID,
        SAD: sad,
        hash: hashes.map((h) => h.toString('base64')),
        hashAlgo: HASH_ALGO_OID,
        signAlgo: SIGN_ALGO_OID,
      },
    });
    const signatures = (out && out.signatures) || [];
    if (signatures.length !== hashes.length) throw new CleverbaseError('signHash returned ' + signatures.length + ' signatures for ' + hashes.length + ' hashes');
    return signatures.map((b64) => Buffer.from(b64, 'base64'));
  }

  // Cleverbase asks a signature application serving several customers to
  // identify the account it is signing for. HS256 over the client secret's
  // SHA-256, per https://cleverbase.com/en/dev-docs/signing/account-tokens/ .
  accountToken(accountId) {
    if (!this.clientSecret) throw new Error('CLEVERBASE_CLIENT_SECRET is not set');
    const header = b64url(JSON.stringify({ typ: 'JWT', alg: 'HS256' }));
    const payload = b64url(JSON.stringify({
      sub: String(accountId),
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      azp: this.clientId,
    }));
    const key = crypto.createHash('sha256').update(this.clientSecret).digest();
    const mac = crypto.createHmac('sha256', key).update(header + '.' + payload).digest();
    return header + '.' + payload + '.' + b64url(mac);
  }
}

module.exports = {
  CleverbaseClient, CleverbaseError, configFromEnv,
  SANDBOX_BASE_URL, PRODUCTION_BASE_URL,
  HASH_ALGO_OID, SIGN_ALGO_OID, MAX_SIGNATURES_PER_AUTHORISATION,
};

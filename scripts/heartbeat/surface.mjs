// Step (c): the public surface. Liveness, the readiness check, and the six
// entrances that must stay shut.
//
// /health is a sign of life, not a health check. The readiness check that
// aggregates version, loaded keys, free disk and certificate age is
// /v2/health/deep, and until 2026-09-02 it answered "Not available in this
// relay mode" on production: the instrument was off in exactly the mode
// production runs in. c9cec7c put it back behind X-Internal-Auth. This step
// detects from the answer which of those three worlds it is in, and proves
// something in each of them.
//
// The deny check is the more interesting half. On 2026-09-01 the ParaID
// issuance route signed identity credentials for anyone on the internet. It was
// closed the same evening with an nginx rule inserted by hand into all six
// server blocks of paramant-public.conf, and the code fix that would do the
// same with a 401 is in main but not deployed. A hand-inserted nginx rule is
// exactly the kind of guard a config restore, a deploy or a certbot reload
// quietly reverts, and four of the six entrances log nothing at all, so nobody
// would ever see it come back. That is what this checks, hourly, from outside.
import { RELAY, SITE, SLOW_MS, assert, http, proof, timed, DRY_RUN } from './lib.mjs';

// The six server blocks in /etc/nginx/sites-enabled/paramant-public.conf. The
// list is here rather than derived, because deriving it from the live config
// would ask production what it should be and then check it against itself.
export const ENTRANCES = [
  'https://paramant.app',
  'https://relay.paramant.app',
  'https://health.paramant.app',
  'https://legal.paramant.app',
  'https://finance.paramant.app',
  'https://iot.paramant.app',
];

// Both halves of the nginx `location ~ ^/v1/paraid/issue-` rule. The trailing
// hyphen is what closes issue-document and issue-demo without taking the public
// reader list /v1/paraid/issuers with it, so both are checked and neither may
// answer as if it still works.
const DENIED_PATHS = ['/v1/paraid/issue-document', '/v1/paraid/issue-demo'];

// 404 is the deny as it was actually built: an nginx `return 404` in all six
// server blocks, and also what the app itself will answer once b5b7453 (which
// deleted ParaID from the code) reaches production. That is the green answer.
//
// 401, 403, 405 and 410 mean the route is refused but still exists there in
// some form. Not an emergency, so not red, but worth seeing: they are recorded
// as a warning rather than swallowed.
//
// 400 is the failure that started all this. It means the request reached the
// ParaID handler, which parsed the body and rejected it on content, so no auth
// layer ran in front of it. 200 needs no explanation. Both are red.
const DENY_GREEN = 404;
const DENY_AMBER = new Set([401, 403, 405, 410]);

export async function surface(evidence) {
  if (DRY_RUN) {
    proof(evidence, 'dry run: surface wiring exercised, nothing contacted', { entrances: ENTRANCES.length, denied_paths: DENIED_PATHS });
    return;
  }

  // ── liveness ──────────────────────────────────────────────────────────────
  const health = await timed(evidence, 'GET /health', SLOW_MS,
    () => http(evidence, 'GET', `${RELAY}/health`));
  assert(health.status === 200, `/health answered HTTP ${health.status}`,
    'The relay is not answering its liveness probe. Everything below this is likely red too.');
  // A status code alone is not a liveness check. nginx, a maintenance page, a
  // cache or a parked domain will all return 200 with a body that has nothing
  // to do with the relay, and the whole point of this rewrite is that a green
  // tick has to be backed by something observed. So the body is required to be
  // the relay's own answer.
  assert(health.json && typeof health.json === 'object',
    '/health answered 200 but not with JSON',
    `Something is answering on this address that is not the relay: nginx, a cache, a maintenance ` +
    `page or a parked domain. First bytes: ${JSON.stringify((health.text || '').slice(0, 120))}.`);
  const ok = health.json.ok ?? health.json.status;
  assert(ok === true || ok === 'ok' || ok === 'healthy',
    `/health answered 200 with a body that does not say it is healthy (${JSON.stringify(ok)})`,
    `Body: ${JSON.stringify(health.json).slice(0, 300)}.`);
  // The relay names itself and its mode in this answer. Requiring the field to
  // be present is what tells a wrong-service-on-the-right-port apart from a
  // healthy relay; the value is recorded rather than pinned, because the mode
  // is an operational choice and changing it is not an outage.
  assert(health.json.mode !== undefined || health.json.version !== undefined,
    '/health carries neither a mode nor a version',
    `The relay reports at least one of those. A 200 without either is very likely a different ` +
    `service. Body: ${JSON.stringify(health.json).slice(0, 300)}.`);
  proof(evidence, '/health is alive and answers as the relay', {
    status: health.status, ok, mode: health.json.mode ?? null, version: health.json.version ?? null,
    fields: Object.keys(health.json),
  });

  // ── readiness, and which world we are in ──────────────────────────────────
  // Three worlds, told apart from the answer itself:
  //   405 "Not available in this relay mode" -> the pre-c9cec7c deploy, where
  //       the mode allowlist dropped the route before the handler ran
  //   200 -> RELAY_MODE=full, where these numbers are public by design for the
  //       setup wizard
  //   401/403 -> ghost_pipe or iot with the X-Internal-Auth gate shut, which is
  //       the intended production shape
  //
  // The trap this step exists to avoid: the handler answers HTTP 200 even when
  // overall is "red". A check that reads the status code and stops would call a
  // relay with unwritable storage healthy. So the body is what gets asserted.
  const deepOpen = await timed(evidence, 'GET /v2/health/deep (unauthenticated)', SLOW_MS,
    () => http(evidence, 'GET', `${RELAY}/v2/health/deep`));

  const notInThisMode = deepOpen.status === 405 ||
    /not available in this relay mode/i.test(deepOpen.text || '');

  if (notInThisMode) {
    // Not an outage, so not red: the readiness check is simply still switched
    // off and the deploy of c9cec7c has not landed. Recorded as a fact, so the
    // hour it changes is visible in the evidence series.
    proof(evidence, '/v2/health/deep is still dropped by the mode allowlist (c9cec7c has not been deployed)', {
      status: deepOpen.status, mode: deepOpen.json?.mode ?? null, rolled_out: false,
    });
  } else if (deepOpen.status === 200) {
    // Full mode. Public on purpose, so this is not a leak; assert the numbers.
    assertDeepBody(evidence, deepOpen, 'full mode, unauthenticated');
    proof(evidence, '/v2/health/deep is public because the relay runs in full mode', {
      status: 200, rolled_out: true, relay_mode: 'full (inferred from a public 200)',
    });
  } else {
    assert(deepOpen.status === 401 || deepOpen.status === 403,
      `/v2/health/deep answered HTTP ${deepOpen.status} to an unauthenticated caller`,
      'Expected 401 or 403 from the X-Internal-Auth gate, 200 in full mode, or 405 when the mode ' +
      'allowlist still drops the route. Anything else is a shape nobody designed.');
    proof(evidence, '/v2/health/deep is rolled out and its internal-auth gate is shut to the internet', {
      status: deepOpen.status, rolled_out: true,
    });

    // With the token, the numbers themselves. Optional on purpose: the check
    // above already proves the gate holds, so a run without the token still
    // proves something real rather than skipping. When the token IS present and
    // the gate refuses it, that is red: a monitoring credential that no longer
    // works is a broken instrument, not a missing one.
    const token = (process.env.PARAMANT_INTERNAL_AUTH_TOKEN || '').trim();
    if (!token) {
      proof(evidence, 'deep readiness numbers not read: PARAMANT_INTERNAL_AUTH_TOKEN not configured', {
        note: 'Set it to also assert the eight component checks. Without it this step still proves the ' +
              'gate is shut, which is why its absence is not a hard failure here. It is the one ' +
              'optional input in this run, and it is optional only because something is proven either way.',
      });
    } else {
      const deep = await timed(evidence, 'GET /v2/health/deep (internal auth)', SLOW_MS,
        () => http(evidence, 'GET', `${RELAY}/v2/health/deep`, { headers: { 'X-Internal-Auth': token } }));
      assert(deep.status === 200,
        `/v2/health/deep refused the monitoring token: HTTP ${deep.status}`,
        'PARAMANT_INTERNAL_AUTH_TOKEN no longer matches INTERNAL_AUTH_TOKEN on the relay, or the gate ' +
        'is broken. Either way the readiness check cannot be read and has stopped being an instrument.');
      assertDeepBody(evidence, deep, 'internal auth');
    }
  }

  // ── the six entrances that must stay shut ─────────────────────────────────
  const results = [];
  for (const origin of ENTRANCES) {
    for (const p of DENIED_PATHS) {
      // POST, because that is the method the open route accepted. A GET that
      // 404s proves nothing about a POST handler.
      const r = await http(evidence, 'POST', `${origin}${p}`, {
        body: { canary: true, note: 'heartbeat deny check, no credential is wanted' },
        timeoutMs: 20000,
      }).catch((e) => ({ status: 0, text: e.message }));
      results.push({ origin, path: p, status: r.status });
      assert(r.status !== 0, `${origin}${p} could not be reached (${r.text})`,
        'An entrance that does not answer at all cannot be shown to be shut. Treated as red rather ' +
        'than as absence of evidence.');
      assert(r.status !== 400,
        `${origin}${p} answered 400: the handler is reachable again`,
        '400 means the request reached the ParaID handler, which parsed the body and rejected it on ' +
        'content. That is the exact signature of the hole closed on 2026-09-01. The nginx deny in ' +
        'paramant-public.conf has been reverted, or this entrance never had it.');
      assert(r.status === DENY_GREEN || DENY_AMBER.has(r.status),
        `${origin}${p} answered HTTP ${r.status}, which is not a refusal`,
        `Expected ${DENY_GREEN}, or one of ${[...DENY_AMBER].join(', ')} for a route that is refused ` +
        'but still present.');
    }
  }
  const amber = results.filter((r) => r.status !== DENY_GREEN);
  if (amber.length) {
    console.log(`    warning: ${amber.length} entrance(s) refuse with something other than 404: ` +
      amber.map((r) => `${r.origin}${r.path} -> ${r.status}`).join(', '));
  }
  proof(evidence, 'all six entrances still refuse the ParaID issuance routes', {
    entrances: ENTRANCES.length,
    checks: results.length,
    // The distribution is the useful part. All 404 is the nginx deny doing its
    // job (or ParaID fully gone from the code). Anything else means the route
    // still exists behind a gate on that host.
    by_status: results.reduce((a, r) => ({ ...a, [r.status]: (a[r.status] || 0) + 1 }), {}),
    not_404: amber,
    detail: results,
  });

  // The public reader list must survive the deny rule. It is the thing the
  // trailing hyphen in `^/v1/paraid/issue-` exists to spare, and a regex
  // location is a prefix match, so a rule edited without that hyphen would take
  // it down. Not fatal if ParaID is fully removed, so it is recorded, not
  // asserted.
  const issuers = await http(evidence, 'GET', `${SITE}/v1/paraid/issuers`, { timeoutMs: 20000 })
    .catch((e) => ({ status: 0, text: e.message }));
  proof(evidence, 'observed /v1/paraid/issuers (recorded, not asserted)', {
    status: issuers.status,
    note: '200 means the deny rule still spares the public reader list. 404 means ParaID is fully ' +
          'removed from production, which is the intended end state of b5b7453.',
  });
}

// The deep readiness body, asserted rather than glanced at. The handler answers
// HTTP 200 whatever the verdict, so `overall` is the only thing that carries it:
// green, yellow or red, taken as the worst of eight component checks (relay,
// crypto, storage, memory, disk, tls, users, audit). A 200 with overall red is a
// relay that has told you it is broken.
function assertDeepBody(evidence, res, how) {
  const d = res.json || {};
  assert(!!d.overall, 'deep readiness answered 200 without an overall verdict',
    `A readiness check with no verdict is the same lie in a different shape. Body: ${JSON.stringify(d).slice(0, 300)}`);
  const checks = Array.isArray(d.checks) ? d.checks : [];
  assert(checks.length > 0, 'deep readiness carries no component checks',
    'The endpoint aggregates eight named checks. An empty list means it aggregated nothing.');
  const bad = checks.filter((c) => c.status === 'red');
  assert(d.overall !== 'red',
    `deep readiness reports overall red (${bad.map((c) => c.name).join(', ') || 'no component named'})`,
    'The relay answered HTTP 200 and said in the body that it is unhealthy. ' +
    bad.map((c) => `${c.name}: ${c.detail}`).join('; ').slice(0, 400));
  proof(evidence, `deep readiness read via ${how} and its verdict is not red`, {
    overall: d.overall, version: d.version ?? null, sector: d.sector ?? null,
    checks: checks.map((c) => ({ name: c.name, status: c.status })),
    yellow: checks.filter((c) => c.status === 'yellow').map((c) => `${c.name}: ${c.detail}`),
  });
}

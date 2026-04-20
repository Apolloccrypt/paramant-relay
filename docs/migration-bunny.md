# CDN/DNS Migration: Cloudflare to Bunny.net

**Status**: Planned for Q2 2026
**Triggered by**: GitHub Issue #20 (sovereignty claim vs Cloudflare dependency)
**Owner**: Mick Beer

## Rationale

Paramant's core positioning is data sovereignty. The current infrastructure
contradicts this claim at the DNS/CDN layer:

- Cloudflare is a US company subject to CLOUD Act and FISA 702
- paramant.app DNS is hosted on Cloudflare (tia.ns, jim.ns)
- Static assets route through Cloudflare CDN
- Encrypted payloads (ML-KEM-768) cannot be decrypted by Cloudflare,
  but metadata (IPs, request timing, headers) is theoretically observable

Bunny.net addresses the jurisdiction gap:

- Slovenian company, EU law jurisdiction
- Not subject to CLOUD Act
- GDPR compliance by default
- 119 edge PoPs with dense EU coverage
- Comparable latency (24-25ms avg vs Cloudflare 15-20ms)
- Transparent pay-as-you-go pricing
- Established track record (1.5M+ websites)

## Phased Migration

### Phase 1: DNS Only (Low Risk, Q2 Early)

**Goal**: move DNS hosting from Cloudflare to Bunny DNS

Steps:
1. Create Bunny.net account, enable DNS product
2. Import paramant.app zone file from Cloudflare
3. Verify all records replicated: A, AAAA, MX, TXT (SPF, DKIM, DMARC), CNAME
4. Set low TTL on Cloudflare records (300s) 48h before switch
5. Update nameservers at registrar from Cloudflare (tia.ns, jim.ns) to Bunny nameservers (from Bunny dashboard)
6. Monitor DNS propagation for 24h
7. Keep Cloudflare zone active as rollback for 14 days

Risk: low. DNS-only migration, no content path change.
Downtime: zero if TTLs managed correctly.

### Phase 2: Asset CDN (Medium Risk, Q2 Mid)

**Goal**: serve static assets (/design-system.css, /nav.css, /js/, images) through Bunny CDN

Steps:
1. Create Bunny Pull Zone pointing to paramant.app origin
2. Create CNAME cdn.paramant.app -> Bunny zone
3. Update frontend asset references to cdn.paramant.app
4. Keep paramant.app direct-to-origin for all dynamic/API traffic
5. Monitor Bunny CDN hit rates and origin load

Risk: medium. Cache rules must be tested carefully (especially versioned assets).
Downtime: zero (parallel paths during transition).

### Phase 3: Origin Proxying (Higher Risk, Q2 Late)

**Goal**: all traffic via Bunny reverse proxy for DDoS protection and edge caching

Steps:
1. Configure Bunny Pull Zone for paramant.app root
2. Enable Bunny WAF
3. Configure DDoS rules matching Cloudflare's previous ruleset
4. Test full signup/login/drop/relay flow through Bunny proxy
5. Switch A record paramant.app from origin IP to Bunny CDN IP
6. Keep Cloudflare proxy as hot standby for 30 days

Risk: higher. Full path change — all features must be verified end-to-end.
Downtime: minimal (DNS cutover only, ~60s propagation).

## Success Criteria

- p95 latency <= current Cloudflare baseline (~135ms at 500 req/s)
- DDoS protection active and tested against baseline traffic patterns
- TLS 1.3 + HSTS headers preserved
- All file upload/download/relay flows verified through Bunny proxy
- Error rate <= 0.1% during each cutover window
- Post-migration: no US-jurisdiction dependencies in critical path

## Rollback Plan

Each phase has independent rollback:

- **Phase 1**: restore Cloudflare nameservers at registrar (TTL-dependent, up to 5m with 300s TTL)
- **Phase 2**: revert cdn.paramant.app references in frontend, redeploy
- **Phase 3**: switch A record back to origin IP, disable Bunny pull zone

Cloudflare account stays provisioned throughout Q2 as hot standby.

## Open Questions

- Bunny WAF ruleset complexity vs Cloudflare — will rate limiting rules transfer cleanly?
- Bunny Edge Scripting (JS at edge) — do we need it for any current flows?
- Email reputation: moving DNS TTLs might affect DKIM/SPF during transition window
- Cost comparison at current and projected traffic levels (document before Phase 1)

## Timeline

| Week | Work |
|------|------|
| Q2 W1-2 | Bunny.net account setup; staging migration test on a non-production subdomain |
| Q2 W3-4 | Phase 1: DNS migration with 48h monitoring window |
| Q2 W5-8 | Phase 2: static asset CDN, 2-week monitoring |
| Q2 W9-12 | Phase 3: full proxying, final cutover |
| Q3 W1+ | Decommission Cloudflare account if all phases stable for 4 weeks |

## Stakeholders

- **Engineering**: Mick Beer
- **Community credit**: Stensel8 (raised Issue #20 constructively)
- **Public comms**: /sovereignty page updated, Issue #20, possible post-migration blog post

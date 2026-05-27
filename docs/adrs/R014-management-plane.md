# R014. Management plane architecture

Date: 2026-05-27

Status: Draft (specification only)

Relates to: R013 (license-server protocol), R006 (crypto-mode opt-in),
R015 (release channels, forthcoming)

## Context

Per R013, customer-relays check in with a central license-server. The
license-server has data about every customer deployment (which version, which
tier, when last seen, how much usage). That data is operationally valuable for
Paramant to:

- See fleet-wide health at a glance
- Triage support tickets ("what version is this customer on?")
- Bill correctly (usage-based or tier-based)
- Notify customers of available updates
- Issue temporary support-keys for elevated debugging
- Detect anomalies (sudden traffic spike, license-key sharing)

There is currently no central console for any of this: each deployment is
opaque once shipped. This ADR defines the management-plane built on top of the
license-server data. It is a specification only; no implementation is included.

## Decision

### Surface

Web UI on `management.paramant.app` (or `admin.paramant.app/fleet`) accessible
only to the authenticated Paramant team. Two roles:

- **Owner** (Mick): all actions.
- **Support** (delegated team): read + limited actions (issue support-keys,
  extend trial, view usage). No license-revoke, no tier-change, no remote
  actions.

### Data model

Customer entity:

- `customer_id`: UUID, internal
- `email`: contact + billing
- `company`: human-readable name
- `created_at`, `updated_at`
- `payment_status`: active / past_due / cancelled
- `tier`: free / pro / enterprise (drives default capability-set)
- `notes`: support-internal

Relay-instance entity (1 customer can have N relay-instances):

- `relay_id`: ML-DSA-65 pubkey hash (per R013)
- `customer_id`: foreign key
- `first_seen_at`, `last_seen_at`
- `version`: last reported
- `domain`: customer's relay URL (if reported via telemetry opt-in)
- `capabilities_override`: optional per-instance customizations

License-key entity (1 customer can have multiple keys for different envs):

- `license_key`: `plk_<64-hex>`
- `customer_id`: foreign key
- `tier`: overrides `customer.tier` if set
- `expires_at`
- `bound_relay_id`: optional (locks key to a specific relay)
- `revoked_at`: nullable
- `issued_by`: who issued (owner or support)

Audit-event entity (immutable log of all management-plane actions):

- `ts`, `actor`, `action`, `target`, `details`
- Append-only, retained 7 years (per audit requirements)

### API endpoints (Mick's root server)

Authenticated via the existing admin-token + TOTP (same scheme as the relay
`/admin`):

```
GET    /api/fleet/customers            - paginated list
GET    /api/fleet/customers/:id        - single customer detail
POST   /api/fleet/customers            - create customer
PATCH  /api/fleet/customers/:id        - update fields
GET    /api/fleet/instances            - all relay-instances across customers
GET    /api/fleet/instances/:relay_id  - single instance detail incl recent check-ins
POST   /api/fleet/licenses             - issue new license-key
PATCH  /api/fleet/licenses/:key        - extend, change tier, etc
DELETE /api/fleet/licenses/:key        - revoke (sets revoked_at; instance gets 410 on next check-in)
GET    /api/fleet/audit                - paginated audit log
POST   /api/fleet/support-key          - issue 24h support-key for elevated debug access to a customer relay
```

All write actions create an audit-event automatically.

### UI structure

Top-level navigation:

- Fleet (default landing)
- Customers
- Licenses
- Audit
- Settings

Fleet page:

- Summary card: total customers, active licenses, online instances, alerts
- Map / world view (optional): geographic distribution
- Recent activity feed: last 50 audit-events

Customers page:

- Table: company, email, tier, payment_status, instance_count, last_seen
- Filter: by tier, by status, by version
- Click row: customer detail with all related entities

Licenses page:

- Table: license-key (masked), customer, tier, expires, bound_relay, status
- Bulk actions: extend by 30d, change tier, revoke
- Issue new license: form modal

Customer detail page:

- Header: company, email, tier, payment_status, "Edit" button
- Tabs: Instances, Licenses, Activity, Notes
- Each instance shows: relay_id (truncated), domain, version, last_seen, a
  "View dashboard" link (jumps to that relay's `/admin`), and "Issue
  support-key"

### Remote actions

Some management-plane actions require the customer-relay to respond. These are
delivered as flags in the R013 check-in response (the management-plane never
connects inbound to a customer relay):

- **Force-update**: management-plane sets a flag in the next check-in response;
  the customer-relay self-updates within 1h (R015 release channels apply).
- **Issue support-key**: management-plane mints a 24h API-key valid for that
  specific `relay_id`; the customer's admin can revoke it. Used for support
  sessions where Paramant needs read-access without the customer creating and
  sharing their own key.
- **Trigger backup**: management-plane sets a flag; the customer-relay runs
  `paramant-backup.sh` and posts a hash + timestamp on the next check-in.
- **Drain mode**: the customer-relay refuses new uploads and completes
  in-flight transfers; used before an update or maintenance.

Each remote action requires owner-role (not support-role) and creates an
audit-event. The customer is notified by email after the action.

### Telemetry opt-in (privacy-respecting)

The R013 check-in includes telemetry fields. Default off. The customer enables
them via `/admin/settings`:

- `aggregate_counts` (users count, transfer count per 24h)
- `error_rates` (5xx-rate, auth-failures)
- `version` + uptime

Never collected:

- Content
- User identities (emails, names)
- File hashes (would link to specific transfers)
- Source/destination IPs

The customer can see exactly what is sent via
`/admin/settings/telemetry-preview`.

### Self-monitoring

Mick's own `paramant.app` is the first customer in this model: it has its own
license-key, its own `customer_id`, and its own instance-records. The
management-plane shows `paramant.app` alongside all other customers. This
dogfoods the architecture and validates that it works end to end.

### Database

Postgres on Mick's root server. Schema migrations via a standard tool (knex,
prisma, or whichever ecosystem fits the relay code base). Backups daily,
offsite to encrypted S3-compatible storage.

## Consequences

- New service: `paramant-mgmt` (Node.js or similar, hosted on the root server).
- New persistence: a Postgres database (no DB was needed before).
- Increased operational responsibility: Mick must maintain the
  management-plane's uptime and security.
- Audit-trail of all support actions: protects both Paramant and the customer
  in disputes.
- Visibility into customer usage enables tier-pricing optimization.
- Privacy-respecting telemetry maintains Paramant's positioning.

Trade-offs:

- Engineering investment: ~3-4 weeks for an MVP, plus ongoing maintenance.
- GDPR obligations: must document data-processing and sign a DPA with
  customers.
- Single point of failure: management-plane downtime breaks support workflows
  (but NOT customer operations -- relays keep running with cached
  capabilities).

## Alternatives considered

- **No management plane** (current state): does not scale beyond ~20 customers.
- **3rd-party SaaS** (Stripe/Chargebee for billing + Sentry for errors):
  rejected. Multiple subscriptions, less control, brand fragmentation.
- **Self-hosted multi-tenant relay** (give customers tenants on the main
  relay): rejected. Customers want their own infrastructure and jurisdiction.
- **Read-only dashboard** (no remote actions): rejected. Support work requires
  some remote capability (issue support-key at minimum).

## Implementation order

1. Database schema + migrations
2. License-server (R013 implementation) writing to this DB
3. API endpoints (read-first, then write)
4. UI: Fleet + Customers + Licenses pages
5. Audit + Activity feed
6. Remote actions (force-update, support-key, etc)
7. Telemetry opt-in flow on the customer side

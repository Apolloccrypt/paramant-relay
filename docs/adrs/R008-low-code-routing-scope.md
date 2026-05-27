# R008. Low-code routing scope (what may be a flow, what may not)

Date: 2026-05-27

Status: Draft (specification only; implementation in later milestones)

## Context

R005 (plug-and-play onboarding) commits paramant-relay to an
appliance-flow rather than a developer-flow. An appliance owner who can
not write code still needs to express per-blob handling: route a blob to
a webhook, mirror ciphertext to storage, email a team on delivery
failure, enforce a retention window for a sector. Today every one of
those requires editing relay.js or wiring an add-on by hand.

R007 (add-on architecture) gives us containerized integrations with
capability-bounded permissions. But an add-on is a unit of code an
operator installs; it is not a way for the operator to compose behavior
themselves. The seam between "install an add-on" and "describe how my
blobs should flow" is a low-code visual flow editor.

The relay already exposes the primitives a flow would orchestrate:
`/v2/webhook` registration with an SSRF-guarded delivery path
(relay.js:1499-1566), per-sector keys (`/v2/key-sector`), teams
(`/v2/team`), delivery events (`/v2/delivery`, `/v2/stream`), and a NATS
`paramant.>` subject space. A flow is a declarative binding over these,
not new transport.

Reference architectures:

- HomeAssistant: Lovelace dashboards plus YAML/visual automations. The
  automation engine is declarative (trigger -> condition -> action) and
  deliberately not Turing-complete. This is the model to follow.
- Node-RED: a mature flow editor, but a general-purpose one. Flows can
  run arbitrary function nodes (JavaScript). Powerful, but the execution
  surface is unbounded - the wrong fit for a zero-knowledge appliance.
- Proxmox: has no low-code layer at all. Operators script against an
  API. paramant can do better for non-developers.

A flow editor is attractive precisely because it lowers the bar. That
same property makes it dangerous: anything expressible in a flow becomes
operator-reachable without review. The core decision of this ADR is
therefore not "build a flow editor" but "draw the boundary of what a
flow is allowed to express", so that the zero-knowledge and
compliance guarantees of the relay remain structural and are never
weakened by a checkbox.

## Decision

### A flow is declarative, capability-bounded, and not Turing-complete

A flow is a YAML document of the shape `trigger -> (filter) -> actions`,
plus a declared `permissions_required` list. The flow engine evaluates
triggers and filters and dispatches actions. It has no loops, no
arbitrary expression evaluation, and no code-execution node. Templating
is restricted to field interpolation from the trigger event and the
operator-supplied environment (see "Templating" below). This bounds the
execution surface to exactly the documented action set.

### In scope - what MAY be expressed as a low-code flow

- **Routing flows**: "blob received in sector X with label Y -> POST
  webhook Z + email group G + invoke storage-mirror add-on S". Built on
  the existing webhook + delivery + add-on primitives.
- **Compliance toggles**: "all health-sector blobs MUST be ML-DSA-65
  signed, else reject", "sector iot has TTL max 60s". These tighten
  policy; they can only make the relay stricter, never looser than its
  baseline.
- **Retention policies per team/sector**: "finance blobs 24h, iot blobs
  1h". Bounded above by the relay's own configured maximum TTL.
- **Notification triggers**: "on delivery-failure, email admin",
  "on burn, log to SIEM add-on".
- **Add-on configuration**: binding a flow action to an installed
  add-on, within that add-on's R007-granted capabilities.

### Out of scope - what MUST NOT be expressible as a flow

These remain code-only or admin-config-only, never reachable from the
flow editor:

- **Crypto-algorithm switching**: the active algorithm set is governed
  by `CRYPTO_MODE` (R006) and FIPS-compliance claims rest on it. A flow
  must not select, add, or downgrade algorithms.
- **Wire-format alternatives**: the v1 wire format is the interop
  contract. A flow must not introduce framing variants.
- **Key-management overrides**: key generation, rotation, and storage
  are audit-trail-bearing operations. A flow must not touch them.
- **Plaintext access**: no flow action receives plaintext. Flows operate
  on blob metadata and ciphertext only, exactly as R007 add-ons do. The
  zero-knowledge guarantee is structural, not a flow-engine policy.
- **Burn-on-read disabling**: burn-on-read is a core promise. A flow may
  observe a burn event; it may not suppress one.
- **Disk-write enabling**: the relay is RAM-only by design (R004
  blind-store). A flow must not introduce a persistence path for blob
  content.

The asymmetry is deliberate: flows may add observers and tighten
policy, but may never loosen a guarantee or open a data path. A flow
that requests a capability outside the in-scope set fails validation at
save time and never executes.

### Storage

Flow definitions live as YAML files in `addons/flows/`, alongside the
R007 `addons/` tree. One file per flow. This keeps flows reviewable in
version control and inspectable on disk, and reuses the add-on directory
convention rather than inventing a second one.

### Templating

Field interpolation only: `${trigger.<field>}` for event fields
(hash, ts, size, sector, recipient hash) and `${env.<NAME>}` for
operator-supplied environment values (e.g. a webhook URL or notify
address). No expression language, no conditionals inside templates, no
function calls. This keeps the format auditable by reading alone.

### Validation

On save, the flow engine:

1. Validates the YAML against the flow schema (known trigger types,
   known action types, well-formed filters).
2. Checks every `permissions_required` entry against the in-scope
   capability set; rejects any out-of-scope capability.
3. Cross-checks declared permissions against the actions used (an action
   needing `webhook:receive` must declare it).
4. Verifies referenced add-ons are installed and have the matching R007
   capabilities granted.

A flow that fails validation is not persisted and not activated.

### Execution

Flows execute server-side, in the relay process, at two gates:

- the inbound gate at `/v2/webhook` / blob-received, where routing and
  compliance-toggle flows fire; and
- the delivery-event path (`/v2/delivery`, stream/burn events), where
  notification flows fire.

Execution is synchronous for compliance toggles (a reject must block the
blob) and fire-and-forget for notifications and mirrors (a failed
notification must not block delivery). Outbound actions reuse the
existing SSRF-guarded webhook path; flows gain no new egress capability.

## Consequences

- Non-developers can compose per-blob behavior without editing code.
- The boundary is explicit and enforced at save time, so the
  zero-knowledge and RAM-only guarantees cannot be weakened by an
  operator action.
- Flows are plain YAML in version control: reviewable, diffable,
  portable between relays.
- The flow engine's bounded surface keeps the audit story tractable -
  there is a finite, documented set of triggers and actions to review.

Trade-offs:

- The editor must teach operators about capabilities; a too-permissive
  default would erode the guarantee the ADR exists to protect.
- A declarative engine cannot express everything; genuinely custom logic
  still belongs in an R007 add-on, not a flow.
- Maintaining the trigger/action catalog becomes ongoing work as new
  primitives appear.

## Alternatives considered

- **No low-code layer**: rejected. Forces every operator to write code
  or hand-wire add-ons for routine integrations, contradicting the R005
  appliance vision.
- **Code-only flows (Lua/JS sandbox nodes)**: rejected. Turing-complete
  execution inside the relay process is an unbounded audit surface and
  invites exactly the guarantee-weakening this ADR forbids.
- **Node-RED as an R007 add-on**: rejected. Mature, but general-purpose
  and heavy; its function nodes run arbitrary code, so capability
  enforcement could not be structural. A lighter, capability-bounded
  engine of our own keeps the guarantees intact.
- **YAML-only via .env, no UI**: rejected. The files are the right
  storage format, but without a viewer/editor there is no UX for the
  non-developer the layer is meant to serve.

## Implementation roadmap

This ADR is specification only. Implementation in stages:

1. **YAML flow files + admin-CLI validator**: define the schema, parse
   and validate flows in `addons/flows/`, wire execution at the two
   gates. No UI yet.
2. **Read-only web viewer** in the admin panel: render existing flows so
   operators can inspect what is active.
3. **Drag-and-drop editor** in the admin panel: compose flows visually,
   with capability checks surfaced inline at save.
4. **Live preview + test mode**: dry-run a flow against a synthetic
   event without dispatching real actions.

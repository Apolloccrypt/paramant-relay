# Paramant Low-Code Routing

Flows let an operator describe per-blob handling - route to a webhook,
mirror ciphertext to storage, notify a team, enforce a retention window
- without writing code.

See [R008 Low-code routing scope](../adrs/R008-low-code-routing-scope.md)
for the specification and, crucially, the boundary of what a flow may and
may not express.

## What a flow is

A flow is a declarative YAML document:

```
trigger  ->  (filter)  ->  actions
```

plus a `permissions_required` list. It is not Turing-complete: no loops,
no expression language, no code-execution node. Templating is field
interpolation only (`${trigger.<field>}`, `${env.<NAME>}`).

## What flows may do (in scope)

- Routing: blob -> webhook / email / storage-mirror add-on
- Compliance toggles: require ML-DSA-65 signing, cap TTL per sector
- Retention policies per team or sector
- Notification triggers: on delivery-failure, on burn
- Add-on configuration within R007-granted capabilities

Flows may only tighten policy and add observers. They can never loosen a
guarantee or open a data path.

## What flows may NOT do (out of scope)

- Switch crypto algorithms (governed by `CRYPTO_MODE`, R006)
- Introduce wire-format alternatives
- Override key management
- Access plaintext (zero-knowledge is structural)
- Disable burn-on-read
- Enable disk writes (RAM-only, R004)

A flow requesting an out-of-scope capability fails validation at save
time and never executes.

## Storage

Flow files live in `addons/flows/`, one YAML file per flow, alongside
the R007 `addons/` tree. Reviewable in version control, inspectable on
disk.

## Status

The flow engine is specified but not yet implemented. This documentation
is forward-looking. Track progress via the R008 ADR status.

## Examples

- [example-flow-notify-on-health-blob.yaml](./example-flow-notify-on-health-blob.yaml)
  - email/webhook the admin whenever a health-sector blob arrives
- [example-flow-mirror-to-storage.yaml](./example-flow-mirror-to-storage.yaml)
  - mirror finance-sector ciphertext to the R007 storage-mirror add-on

'use strict';

// Whitelist of configuration keys that the admin panel may read and write.
//
// ONLY keys listed here are exposed by /api/admin/config. Anything else in the
// env file is invisible and untouchable through the panel -- no arbitrary
// key/value writes.
//
// Every key documented here is actually read by the relay (relay/relay.js,
// relay/crypto/bootstrap.js) or by the admin service itself. We do not invent
// config that has no effect.
//
// Fields:
//   type        'number' | 'string' | 'boolean' | 'enum'
//   ui          'input' | 'select' | 'slider' | 'toggle'  (frontend hint)
//   group       sidebar grouping
//   default     documented default when the key is unset
//   options     allowed values (enum only)
//   min/max     numeric bounds (number/slider)
//   description short operator-facing explanation
//   class       'relay-restart' (relay reads it at startup) or
//               'admin-restart' (admin service reads it at startup)
//   secret      true  -> value is masked on read; replace-only on write
//   readonly    true  -> shown (masked) but NOT editable via the panel
//               (used for the credentials that protect the panel itself, to
//                avoid an operator locking themselves out)
//
// NOTE on effect: the admin service is a separate process from the relays, so
// any change here takes effect on the next RELAY restart, not immediately. The
// panel surfaces this rather than pretending to hot-reload.

module.exports = {
  // ---- Network / mode -------------------------------------------------------
  RELAY_MODE: {
    type: 'enum', ui: 'select', group: 'Relay', default: 'ghost_pipe',
    options: ['ghost_pipe', 'iot', 'full'], class: 'relay-restart',
    description: 'Which endpoint set the relay exposes.',
  },
  SETUP_MODE: {
    type: 'boolean', ui: 'toggle', group: 'Relay', default: false,
    class: 'relay-restart',
    description: 'Open setup mode (allows first-key bootstrap even with keys present). Turn OFF in production.',
  },
  RELAY_SELF_URL: {
    type: 'string', ui: 'input', group: 'Relay', default: '',
    class: 'relay-restart',
    description: 'Public URL of this relay, e.g. https://relay.paramant.app.',
  },
  RELAY_PRIMARY_URL: {
    type: 'string', ui: 'input', group: 'Relay', default: '',
    class: 'relay-restart',
    description: 'URL of the primary relay this one registers with.',
  },

  // ---- Crypto ---------------------------------------------------------------
  CRYPTO_MODE: {
    type: 'enum', ui: 'select', group: 'Crypto', default: 'core',
    options: ['core', 'extended'], class: 'relay-restart',
    description: 'Algorithms loaded at startup. core = ML-KEM-768 + ML-DSA-65 only; extended = all 18 (ADR R006).',
  },
  PARAMANT_WIRE_VERSION: {
    type: 'enum', ui: 'select', group: 'Crypto', default: '0',
    options: ['0', '1'], class: 'relay-restart',
    description: 'Set 1 to emit the self-describing v1 wire header. Leave 0 unless you know you need it.',
  },

  // ---- Limits ---------------------------------------------------------------
  MAX_BLOB: {
    type: 'number', ui: 'slider', group: 'Limits', default: 5242880,
    min: 65536, max: 1073741824, class: 'relay-restart',
    description: 'Maximum blob size in BYTES (default 5 MiB = 5242880).',
  },
  TTL_MS: {
    type: 'number', ui: 'input', group: 'Limits', default: 300000,
    min: 1000, max: 86400000, class: 'relay-restart',
    description: 'Blob time-to-live in milliseconds (default 300000 = 5 min).',
  },
  ANON_RATE_PER_HOUR: {
    type: 'number', ui: 'input', group: 'Limits', default: 10,
    min: 0, max: 100000, class: 'relay-restart',
    description: 'Anonymous inbound requests allowed per hour per IP.',
  },
  MAX_AUDIT: {
    type: 'number', ui: 'input', group: 'Limits', default: 1000,
    min: 100, max: 100000, class: 'relay-restart',
    description: 'Maximum audit entries retained in the relay CT log.',
  },
  MAX_RELAY_REGISTRY: {
    type: 'number', ui: 'input', group: 'Limits', default: 10000,
    min: 100, max: 1000000, class: 'relay-restart',
    description: 'Maximum peer relays held in the registry.',
  },
  RAM_LIMIT_MB: {
    type: 'number', ui: 'slider', group: 'Limits', default: 512,
    min: 128, max: 16384, class: 'relay-restart',
    description: 'Soft RAM limit per relay process (MB); drives the 503 capacity guard.',
  },
  RAM_RESERVE_MB: {
    type: 'number', ui: 'slider', group: 'Limits', default: 256,
    min: 64, max: 8192, class: 'relay-restart',
    description: 'RAM headroom reserved before the capacity guard trips (MB).',
  },

  // ---- Compliance -----------------------------------------------------------
  ENABLE_USER_TOTP: {
    type: 'boolean', ui: 'toggle', group: 'Compliance', default: false,
    class: 'relay-restart',
    description: 'Require TOTP MFA for end-user logins.',
  },

  // ---- NATS -----------------------------------------------------------------
  NATS_URL: {
    type: 'string', ui: 'input', group: 'NATS', default: '',
    class: 'relay-restart',
    description: 'NATS server URL. Empty = NATS disabled (opt-in only).',
  },
  NATS_USER: {
    type: 'string', ui: 'input', group: 'NATS', default: '',
    class: 'relay-restart',
    description: 'NATS username (non-secret).',
  },
  NATS_PASS: {
    type: 'string', ui: 'input', group: 'NATS', default: '',
    class: 'relay-restart', secret: true,
    description: 'NATS password. Masked; replace-only.',
  },
  NATS_TOKEN: {
    type: 'string', ui: 'input', group: 'NATS', default: '',
    class: 'relay-restart', secret: true,
    description: 'NATS auth token. Masked; replace-only.',
  },

  // ---- Secrets (masked, replace-only) --------------------------------------
  PLK_KEY: {
    type: 'string', ui: 'input', group: 'Secrets', default: '',
    class: 'relay-restart', secret: true,
    description: 'Paramant license key (plk_...). Masked; replace-only.',
  },
  RESEND_API_KEY: {
    type: 'string', ui: 'input', group: 'Secrets', default: '',
    class: 'relay-restart', secret: true,
    description: 'Resend API key for outbound mail. Masked; replace-only.',
  },
  INTERNAL_AUTH_TOKEN: {
    type: 'string', ui: 'input', group: 'Secrets', default: '',
    class: 'relay-restart', secret: true,
    description: 'Shared token for internal relay<->admin calls. Masked; replace-only.',
  },
  STRIPE_SECRET_KEY: {
    type: 'string', ui: 'input', group: 'Secrets', default: '',
    class: 'relay-restart', secret: true,
    description: 'Stripe secret key (SaaS billing only). Masked; replace-only.',
  },
  STRIPE_WEBHOOK_SECRET: {
    type: 'string', ui: 'input', group: 'Secrets', default: '',
    class: 'relay-restart', secret: true,
    description: 'Stripe webhook signing secret. Masked; replace-only.',
  },

  // ---- Panel credentials (masked + READ-ONLY to prevent self-lockout) ------
  ADMIN_TOKEN: {
    type: 'string', ui: 'input', group: 'Secrets', default: '',
    class: 'admin-restart', secret: true, readonly: true,
    description: 'Admin panel token. Read-only here on purpose: rotate it on the host to avoid locking yourself out of this panel.',
  },
  TOTP_SECRET: {
    type: 'string', ui: 'input', group: 'Secrets', default: '',
    class: 'admin-restart', secret: true, readonly: true,
    description: 'Admin TOTP secret. Read-only here on purpose: rotate it on the host and re-enrol your authenticator.',
  },
};

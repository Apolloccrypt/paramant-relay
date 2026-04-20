# PARAMANT Admin Panel

The admin panel runs as a separate Express container on port 4200, proxied by nginx at `/admin/`. It provides a full operator interface for managing users, keys, billing, relay health, and audit logs.

## Access

```
https://paramant.app/admin/
```

Login requires:
- **Admin token** (`ADMIN_TOKEN` env var)
- **TOTP code** (if `ADMIN_TOTP_SECRET` is set — strongly recommended in production)

Sessions are stored in Redis under `paramant:admin:session:{sid}` with a 12-hour TTL. The session token is passed as `X-Session` header on every API request.

---

## Tabs

| Tab | Description |
|-----|-------------|
| **Overview** | Signups today, active sessions, pro upgrades, MRR, recent audit events, plan distribution |
| **Users** | Paginated user list with per-user action menu |
| **Audit** | Full audit log, filterable by user |
| **Billing** | Active subscriptions and MRR breakdown |
| **Relay** | Live health + uptime + metrics for all 5 sector relays, auto-refreshes every 10s |

---

## User action menu

Each row in the Users tab has a `···` menu with grouped actions:

### Email
| Action | What it does | Rate limit |
|--------|-------------|------------|
| Send welcome | Sends onboarding email with API key | 10/user/24h |
| Send TOTP setup link | Resends TOTP setup email | 10/user/24h |
| Send TOTP reset | Sends TOTP reset confirmation email | 5/user/24h |

> Email actions are greyed out when no email address is stored for that user (`paramant:user:meta:{key}` in Redis).

### Account
| Action | What it does | Rate limit |
|--------|-------------|------------|
| Change plan | Updates plan on all sector relays + optional email notification | 20/admin/24h |
| Revoke sessions | Deletes all active user sessions from Redis | — |

### Destructive
| Action | What it does | Rate limit |
|--------|-------------|------------|
| Disable key | Revokes the API key on all sector relays | 10/admin/24h |
| Delete account | Full deletion: revokes key, deletes TOTP, wipes all Redis data, triggers relay reload | 50/admin/24h |

> Delete account requires typing `DELETE` in the confirmation field before the button activates.

---

## API endpoints

All endpoints are mounted at `/admin/api/`. Authentication: `X-Session: <session_token>`.

### Dashboard data

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/admin/overview` | Stats, recent audit events, plan distribution |
| `GET` | `/admin/users` | Paginated user list with TOTP status. Query: `?page=1&page_size=25&status=active&plan=pro` |
| `GET` | `/admin/user-details/:key` | Full user detail: meta, sessions, audit trail |
| `GET` | `/admin/audit` | Global audit log. Query: `?limit=50&user_id=pgp_...` |
| `GET` | `/admin/billing` | Active subscriptions + MRR |
| `GET` | `/admin/relay-detail` | Per-sector health + uptime + metrics |

### User actions

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `POST` | `/admin/send-welcome` | `{ key }` | Send welcome email |
| `POST` | `/admin/reset-totp` | `{ key }` | Send TOTP reset email |
| `POST` | `/admin/change-plan` | `{ key, new_plan, notify }` | Change plan (`community`/`pro`/`enterprise`/`trial`) |
| `POST` | `/admin/revoke-sessions` | `{ key }` | Revoke all sessions |
| `POST` | `/admin/disable-key` | `{ key, reason, notify }` | Disable API key |
| `POST` | `/admin/delete-account` | `{ key, confirm: "DELETE", notify }` | Delete account |
| `POST` | `/admin/preview-email` | `{ type, key }` | Preview email HTML + text before sending. Types: `welcome`, `setup`, `reset-confirm` |

---

## Redis key layout (admin-relevant)

| Key | Type | Content |
|-----|------|---------|
| `paramant:admin:session:{sid}` | string | JSON session object, TTL 12h |
| `paramant:user:meta:{key}` | string | JSON `{ email, created_at, plan, ... }` |
| `paramant:user:totp:{key}` | string | Encrypted TOTP secret (pending setup) |
| `paramant:user:totp_active:{key}` | string | `"true"` when TOTP is active |
| `paramant:user:session:{sid}` | string | User session JSON |
| `paramant:user:audit:{key}` | zset | Per-user audit events (score = timestamp ms) |
| `paramant:audit:global` | zset | Global audit log |
| `paramant:ratelimit:admin_{scope}:{id}` | string | Counter, TTL 24h. Scopes: `welcome`, `reset_totp`, `change_plan`, `disable_key`, `delete_account` |

---

## Email templates

Located in `admin/lib/email-templates.js`. All emails go via Resend (`RESEND_API_KEY`) from `Paramant <hello@paramant.app>`.

| Function | Trigger |
|----------|---------|
| `setupEmail` | New account created |
| `welcomeEmail` | Manual send from admin panel |
| `resetConfirmationEmail` | TOTP reset flow |
| `billingConfirmationEmail` | Plan change (admin or Stripe) |
| `billingCancellationEmail` | Subscription cancelled |
| `accountDeletionEmail` | Account deleted by admin |

---

## Rate limits (admin actions, per 24h)

| Action | Scope | Limit |
|--------|-------|-------|
| Send welcome | per user key | 10 |
| Send TOTP reset | per user key | 5 |
| Change plan | global (admin) | 20 |
| Disable key | global (admin) | 10 |
| Delete account | global (admin) | 50 |

To reset a rate limit manually:
```bash
docker exec paramant-relay-redis redis-cli -u "$REDIS_URL" DEL paramant:ratelimit:admin_delete_account:admin
```

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ADMIN_TOKEN` | Yes | Shared secret for relay auth + admin login |
| `ADMIN_TOTP_SECRET` | Recommended | TOTP secret for admin 2FA (base32) |
| `RESEND_API_KEY` | For email | Resend API key |
| `REDIS_URL` | Yes | `redis://:password@host:port/db` |
| `RELAY_HEALTH` | Yes | `http://relay-health:3000` |
| `RELAY_FINANCE` | Yes | `http://relay-finance:3000` |
| `RELAY_LEGAL` | Yes | `http://relay-legal:3000` |
| `RELAY_IOT` | Yes | `http://relay-iot:3000` |
| `INTERNAL_AUTH_TOKEN` | Yes | Shared secret for internal relay-to-relay calls |
| `SITE_URL` | No | Base URL for email links (default: `https://paramant.app`) |

---

## Deployment

```bash
# Rebuild admin container only
cd /opt/paramant-relay
docker compose up -d --build admin

# View logs
docker logs paramant-relay-admin -f

# Health check
curl http://localhost:4200/admin/
```

The static `admin.html` served at port 8080 by nginx must be kept in sync with the container's `public/index.html`:
```bash
cp /opt/paramant-relay/admin/public/index.html /home/paramant/app/admin.html
```

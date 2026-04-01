# PARAMANT Admin CLI

Key beheer via command-line. Vereist admin API key.

## Gebruik
```bash
# Nieuwe klant toevoegen
python3 paramant-admin.py add \
  --label acme-corp \
  --plan pro \
  --email klant@acme.com
# Genereert key, sync naar alle relays, stuurt welkomstmail

# Alle keys tonen
python3 paramant-admin.py list

# Key revoken
python3 paramant-admin.py revoke acme-corp
python3 paramant-admin.py revoke pgp_xxxx

# Handmatig sync naar alle relays (geen redeploy nodig)
python3 paramant-admin.py sync

# Stripe webhook listener
export STRIPE_WEBHOOK_SECRET=whsec_xxx
export RESEND_API_KEY=re_xxx
python3 paramant-admin.py stripe
```

## Plannen

| Plan | Prijs | Limiet |
|------|-------|--------|
| dev | €9.99/mnd | 50 req/min |
| chat | €24.99/mnd | Chat only |
| pro | €49.99/mnd | 500 req/min |
| enterprise | €499.99/mnd | 1000+ req/min |

## Noodprocedures

### Admin key gecompromitteerd
```bash
python3 paramant-admin.py add --label admin-nieuw --plan enterprise
python3 paramant-admin.py revoke pgp_oude_key
python3 paramant-admin.py sync
```

### TOTP verloren
```bash
ssh root@116.203.86.81
python3 -c "
import base64, os, json
secret = base64.b32encode(os.urandom(20)).decode()
json.dump({'totp_secret': secret}, open('/etc/paramant/admin_mfa.json','w'))
os.chmod('/etc/paramant/admin_mfa.json', 0o600)
print('Nieuw secret:', secret)
"
for s in paramant-relay-health paramant-relay-legal paramant-relay-finance paramant-relay-iot; do
  systemctl restart $s
done
```

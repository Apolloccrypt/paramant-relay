#!/usr/bin/env python3
"""
PARAMANT Admin CLI v1.0
Beheer API keys in users.json bestanden voor alle sector relays.

Gebruik:
  python3 paramant-admin.py list
  python3 paramant-admin.py add  --label "naam" --plan pro --email user@example.com [--sector health]
  python3 paramant-admin.py revoke --key pgp_xxxxx [--sector health]
  python3 paramant-admin.py sync
  python3 paramant-admin.py check --key pgp_xxxxx

Omgeving:
  PARAMANT_SECTORS_DIR   Pad naar sector dirs (default: /home/paramant)
  PARAMANT_RELAY_BASE    Base URL voor /v2/check-key calls (default: https://health.paramant.app)
"""
import os, sys, json, secrets, argparse, urllib.request, urllib.error
from datetime import datetime, timezone

# ── Resend mail ───────────────────────────────────────────────────────────────
def send_welcome_mail(to_email, api_key, plan):
    RESEND_KEY = os.environ.get('RESEND_API_KEY', '')
    if not RESEND_KEY:
        warn('RESEND_API_KEY niet gezet — welkomstmail overgeslagen')
        return False
    html = f'''<div style="font-family:monospace;background:#0c0c0c;color:#ededed;padding:40px;max-width:520px">
  <div style="font-size:16px;font-weight:600;margin-bottom:24px;letter-spacing:.08em">PARAMANT</div>
  <p style="color:#555;margin-bottom:24px">Your API key is ready.</p>
  <div style="background:#111;border:1px solid #1a1a1a;border-radius:6px;padding:20px;margin-bottom:24px">
    <div style="font-size:11px;color:#555;letter-spacing:.08em;text-transform:uppercase;margin-bottom:8px">API KEY &mdash; {plan.upper()}</div>
    <div style="font-size:14px;color:#ededed;word-break:break-all">{api_key}</div>
  </div>
  <p style="color:#555;font-size:13px;margin-bottom:8px">Get started:</p>
  <pre style="background:#111;border:1px solid #1a1a1a;border-radius:4px;padding:16px;font-size:12px;color:#888">pip install paramant-sdk

from paramant_sdk import GhostPipe
gp = GhostPipe(api_key="{api_key}", device="device-001")
hash_ = gp.send(b"hello world")
data  = gp.receive(hash_)</pre>
  <p style="margin-top:24px">
    <a href="https://paramant.app/dashboard" style="color:#ededed">Dashboard</a>
    &nbsp;&middot;&nbsp;
    <a href="https://paramant.app/ct-log" style="color:#555">CT log</a>
    &nbsp;&middot;&nbsp;
    <a href="https://paramant.app/docs" style="color:#555">Docs</a>
  </p>
  <p style="margin-top:32px;font-size:11px;color:#333">ML-KEM-768 &middot; Burn-on-read &middot; EU/DE &middot; BUSL-1.1</p>
</div>'''
    body = json.dumps({
        'from':    'PARAMANT <hello@paramant.app>',
        'to':      [to_email],
        'subject': 'Your PARAMANT API key',
        'html':    html,
    }).encode()
    req = urllib.request.Request(
        'https://api.resend.com/emails',
        data=body, method='POST',
        headers={
            'Authorization':  f'Bearer {RESEND_KEY}',
            'Content-Type':   'application/json',
            'User-Agent':     'paramant-admin/1.0',
        },
    )
    try:
        resp = json.loads(urllib.request.urlopen(req, timeout=10).read())
        if resp.get('id'):
            ok(f'Welkomstmail verstuurd naar {to_email} (id: {resp["id"]})')
            return True
    except Exception as e:
        warn(f'Resend fout: {e}')
    return False

# ── Config ────────────────────────────────────────────────────────────────────
SECTORS_DIR = os.environ.get('PARAMANT_SECTORS_DIR', '/home/paramant')
SECTORS = {
    'health':  os.path.join(SECTORS_DIR, 'relay-health',   'users.json'),
    'legal':   os.path.join(SECTORS_DIR, 'relay-legal',    'users.json'),
    'finance': os.path.join(SECTORS_DIR, 'relay-finance',  'users.json'),
    'iot':     os.path.join(SECTORS_DIR, 'relay-iot',      'users.json'),
}
RELAY_URLS = {
    'health':  'https://health.paramant.app',
    'legal':   'https://legal.paramant.app',
    'finance': 'https://finance.paramant.app',
    'iot':     'https://iot.paramant.app',
}
VALID_PLANS = ('free', 'pro', 'enterprise')

# ── Kleuren ───────────────────────────────────────────────────────────────────
G = '\033[32m'; R = '\033[31m'; Y = '\033[33m'; B = '\033[34m'; E = '\033[0m'; D = '\033[2m'

def ok(msg):  print(f'{G}✓{E} {msg}')
def err(msg): print(f'{R}✗{E} {msg}', file=sys.stderr)
def warn(msg): print(f'{Y}⚠{E} {msg}')
def info(msg): print(f'{B}·{E} {msg}')

# ── JSON helpers ──────────────────────────────────────────────────────────────
def load_users(path):
    if not os.path.exists(path):
        return {'api_keys': []}
    with open(path) as f:
        return json.load(f)

def save_users(path, data):
    data['updated'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2)
        f.write('\n')
    # backup
    if os.path.exists(path):
        import shutil
        shutil.copy2(path, path + '.bak')
    os.replace(tmp, path)

def gen_key():
    return 'pgp_' + secrets.token_hex(16)

def now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

# ── Commando's ────────────────────────────────────────────────────────────────
def cmd_list(args):
    sectors = [args.sector] if args.sector else list(SECTORS.keys())
    total = 0
    for sector in sectors:
        path = SECTORS.get(sector)
        if not path:
            warn(f'Onbekende sector: {sector}'); continue
        data = load_users(path)
        keys = data.get('api_keys', [])
        active = [k for k in keys if k.get('active')]
        revoked = [k for k in keys if not k.get('active')]
        print(f'\n{B}── {sector.upper()} ──{E}  {D}{path}{E}')
        print(f'  {len(active)} actief, {len(revoked)} ingetrokken')
        for k in keys:
            status = f'{G}actief{E}' if k.get('active') else f'{R}ingetrokken{E}'
            print(f'  {status}  {k["key"]}  plan={k.get("plan","?")}  label={k.get("label","")}  email={k.get("email","")}')
        total += len(active)
    print(f'\n{G}Totaal actieve keys: {total}{E}')

def cmd_add(args):
    if args.plan not in VALID_PLANS:
        err(f'Ongeldig plan "{args.plan}". Kies uit: {", ".join(VALID_PLANS)}'); sys.exit(1)
    key = gen_key()
    entry = {
        'key': key,
        'plan': args.plan,
        'limit': 10000 if args.plan == 'pro' else (100000 if args.plan == 'enterprise' else 1000),
        'active': True,
        'label': args.label,
        'email': args.email or '',
        'created': now_iso(),
    }
    sectors = [args.sector] if args.sector else list(SECTORS.keys())
    for sector in sectors:
        path = SECTORS.get(sector)
        if not path:
            warn(f'Onbekende sector: {sector}'); continue
        if not os.path.exists(os.path.dirname(path)):
            warn(f'Sector dir niet gevonden: {os.path.dirname(path)}'); continue
        data = load_users(path)
        data.setdefault('api_keys', []).append(entry)
        save_users(path, data)
        ok(f'{sector}: key toegevoegd')
    print(f'\n  Key: {G}{key}{E}')
    print(f'  Plan: {args.plan}  Label: {args.label}')
    if args.email:
        send_welcome_mail(args.email, key, args.plan)
    print(f'\n{Y}Voer "paramant-admin.py sync" uit om relays te herladen.{E}')

def cmd_revoke(args):
    if not args.key:
        err('Geef --key op'); sys.exit(1)
    sectors = [args.sector] if args.sector else list(SECTORS.keys())
    found = False
    for sector in sectors:
        path = SECTORS.get(sector)
        if not path or not os.path.exists(path):
            continue
        data = load_users(path)
        for k in data.get('api_keys', []):
            if k['key'] == args.key:
                if not k.get('active'):
                    warn(f'{sector}: key was al ingetrokken')
                else:
                    k['active'] = False
                    k['revoked'] = now_iso()
                    save_users(path, data)
                    ok(f'{sector}: key ingetrokken')
                found = True
    if not found:
        warn(f'Key niet gevonden in opgegeven sector(en)')
    else:
        print(f'\n{Y}Voer "paramant-admin.py sync" uit om relays te herladen.{E}')

def cmd_sync(args):
    """Herstart alle sector systemd services zodat de gewijzigde users.json ingeladen wordt."""
    import subprocess
    sectors = [args.sector] if args.sector else list(SECTORS.keys())
    for sector in sectors:
        svc = f'paramant-relay-{sector}'
        try:
            result = subprocess.run(['systemctl', 'restart', svc],
                                    capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                ok(f'{svc} herstart')
            else:
                err(f'{svc}: {result.stderr.strip()}')
        except FileNotFoundError:
            warn(f'systemctl niet beschikbaar (lokaal?) — sla {svc} over')
        except subprocess.TimeoutExpired:
            err(f'{svc}: timeout bij herstarten')

def cmd_check(args):
    if not args.key:
        err('Geef --key op'); sys.exit(1)
    sectors = [args.sector] if args.sector else list(SECTORS.keys())
    for sector in sectors:
        base = RELAY_URLS.get(sector, '')
        if not base:
            continue
        url = f'{base}/v2/check-key?k={args.key}'
        try:
            resp = json.loads(urllib.request.urlopen(url, timeout=6).read())
            valid = resp.get('valid', False)
            plan  = resp.get('plan', '?')
            status = f'{G}geldig{E}' if valid else f'{R}ongeldig{E}'
            print(f'  {sector:10s} {status}  plan={plan}')
        except urllib.error.HTTPError as e:
            print(f'  {sector:10s} {R}HTTP {e.code}{E}')
        except Exception as e:
            print(f'  {sector:10s} {Y}TIMEOUT/ERROR{E}  {e}')

# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description='PARAMANT Admin CLI v1.0')
    sub = p.add_subparsers(dest='cmd', required=True)

    # list
    pl = sub.add_parser('list', help='Toon alle API keys')
    pl.add_argument('--sector', choices=list(SECTORS.keys()), help='Specifieke sector')

    # add
    pa = sub.add_parser('add', help='Voeg een nieuwe API key toe')
    pa.add_argument('--label',  required=True, help='Beschrijving / naam')
    pa.add_argument('--plan',   default='pro', choices=VALID_PLANS)
    pa.add_argument('--email',  default='', help='E-mailadres (optioneel)')
    pa.add_argument('--sector', choices=list(SECTORS.keys()), help='Alleen deze sector (default: alle)')

    # revoke
    pr = sub.add_parser('revoke', help='Trek een API key in')
    pr.add_argument('--key',    required=True, help='Te intrekken key (pgp_...)')
    pr.add_argument('--sector', choices=list(SECTORS.keys()), help='Alleen deze sector (default: alle)')

    # sync
    ps = sub.add_parser('sync', help='Herstart relays zodat users.json opnieuw ingeladen wordt')
    ps.add_argument('--sector', choices=list(SECTORS.keys()), help='Specifieke sector')

    # check
    pc = sub.add_parser('check', help='Verifieer key geldigheid via live relay')
    pc.add_argument('--key',    required=True, help='Te controleren key')
    pc.add_argument('--sector', choices=list(SECTORS.keys()), help='Specifieke sector')

    args = p.parse_args()
    {'list': cmd_list, 'add': cmd_add, 'revoke': cmd_revoke,
     'sync': cmd_sync, 'check': cmd_check}[args.cmd](args)

if __name__ == '__main__':
    main()

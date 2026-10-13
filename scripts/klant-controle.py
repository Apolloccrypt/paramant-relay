#!/usr/bin/env python3
"""klant-controle: zelf nagaan dat een ParaSend-verzending in de transparantielog staat.

Werkt zonder iets van Paramant te importeren: een eigen RFC 6962/9162-boom
(SHA3-256, 0x01 voor binnenknopen), eigen inclusie- en consistentieverifier,
en ML-DSA-65 via OpenSSL 3.5 of nieuwer. Alleen de Python-standaardbibliotheek.

Gebruik
  klant-controle.py ontvangstbewijs.json        receipt als JSON of base64url
  klant-controle.py - < ontvangstbewijs.txt     idem, via stdin
  klant-controle.py --index 777 --relay https://relay.paramant.app
                                                zonder receipt: een openbaar blad

Opties
  --relay URL     waar de log staat (standaard: https://<host uit relay_id>)
  --anchors PAD   de gepinde sleutels (standaard: frontend/js/relay-trust-anchors.js)
  --pubkey B64    een eigen sleutel (zelf gehoste relay); wordt gemeld als niet gepind
  --json          uitslag als JSON

Exitcodes
  0  alles aangetoond
  1  een controle faalt: vertrouw dit niet
  2  gebruik- of netwerkfout
  3  onvolledig: een handtekening kon niet worden gecontroleerd
     (geen OpenSSL met ML-DSA-65, of geen sleutel voor deze relay)

Wat dit WEL aantoont: het blad van uw verzending staat in de boom die de relay
NU ondertekent, en die boom is een aanvulling op de boom uit uw ontvangstbewijs.
Wat dit NIET aantoont: dat anderen dezelfde boom te zien krijgen. Zolang niemand
buiten Paramant de ondertekende boomtoppen bewaart, is een gespleten weergave
(elke klant een eigen boom) hiermee niet te ontdekken.
Voor ParaSign-handtekeningen kan dit nog niet: zie docs/klant-controle.md.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import urllib.error

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DEFAULT_ANCHORS = os.path.join(ROOT, 'frontend', 'js', 'relay-trust-anchors.js')
OPENSSL = os.environ.get('KLANT_CONTROLE_OPENSSL', 'openssl')


# ── Merkle ──────────────────────────────────────────────────────────────────
def sha3(b):
    return hashlib.sha3_256(b).digest()


def node(left, right):
    return sha3(b'\x01' + left + right)


def transfer_leaf(blob_hash_hex, sector, ts):
    """relay/lib/ct-hash.js blobLeafHash: SHA3(0x02 || blob || SHA3(sector) || utf8(ts))."""
    data = bytes.fromhex(blob_hash_hex) + sha3((sector or 'relay').encode()) + str(ts).encode()
    return sha3(b'\x02' + data).hex()


def verify_inclusion(index, size, leaf, path, root):
    """RFC 9162 2.1.3.2. path: 32-byte hashes, diepste eerst."""
    if index < 0 or index >= size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(m, n, old_root, new_root, proof):
    """RFC 9162 2.1.4.2."""
    if m == n:
        return len(proof) == 0 and old_root == new_root
    if m <= 0 or m > n:
        return False
    path = list(proof)
    if m & (m - 1) == 0:
        path = [old_root] + path
    if not path:
        return False
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node(c, fr)
            sr = node(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root


# ── ML-DSA-65 via OpenSSL ───────────────────────────────────────────────────
SPKI_PREFIX = bytes.fromhex('308207b2300b0609608648016503040312038207a100')


def mldsa_available():
    if not shutil.which(OPENSSL):
        return False
    try:
        out = subprocess.run([OPENSSL, 'list', '-signature-algorithms'],
                             capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return False
    return 'ML-DSA-65' in out.upper()


def mldsa65_verify(pk_b64, msg, sig_b64):
    try:
        pk = base64.b64decode(pk_b64)
        sig = base64.b64decode(sig_b64)
    except Exception:
        return False
    if len(pk) != 1952:
        return False
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, 'pk.der'), 'wb') as f:
            f.write(SPKI_PREFIX + pk)
        with open(os.path.join(d, 'm'), 'wb') as f:
            f.write(msg)
        with open(os.path.join(d, 's'), 'wb') as f:
            f.write(sig)
        r = subprocess.run([OPENSSL, 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER',
                            '-inkey', os.path.join(d, 'pk.der'), '-rawin',
                            '-in', os.path.join(d, 'm'), '-sigfile', os.path.join(d, 's')],
                           capture_output=True, text=True)
        return r.returncode == 0 and 'Success' in r.stdout


def sth_message(sth):
    """Canonieke STH-payload, gelijk aan produceSth in relay.js."""
    p = {k: sth.get(k) for k in ('relay_id', 'sha3_root', 'timestamp', 'tree_size', 'version')}
    if p['version'] is None:
        p['version'] = 1
    return json.dumps(dict(sorted(p.items())), separators=(',', ':')).encode()


# ── Pins ────────────────────────────────────────────────────────────────────
def load_pins(path):
    """host -> base64-sleutel, alleen als SHA3(sleutel) gelijk is aan de vingerafdruk."""
    with open(path, encoding='utf-8') as f:
        text = f.read()
    pins = {}
    for block in re.findall(r'\{[^{}]*?host:\s*\'[^\']+\'[^{}]*?\}', text, re.S):
        host = re.search(r"host:\s*'([^']+)'", block)
        fp = re.search(r"fingerprint:\s*'([0-9a-f]{64})'", block)
        key = re.search(r"key:\s*'([^']+)'", block)
        if not (host and fp and key):
            continue
        if sha3(base64.b64decode(key.group(1))).hex() != fp.group(1):
            raise UsageError(f'pin voor {host.group(1)} klopt niet met zijn vingerafdruk')
        pins[host.group(1).lower()] = key.group(1)
    return pins


def host_of(relay_id):
    s = str(relay_id or '').strip()
    if '://' in s:
        return (urllib.parse.urlparse(s).hostname or '').lower()
    return s.split('/')[0].split(':')[0].lower()


# ── Ophalen ─────────────────────────────────────────────────────────────────
class NetError(Exception):
    pass


class UsageError(Exception):
    pass


def get_json(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'paramant-klant-controle/1',
                                               'Accept': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except Exception as e:
        raise NetError(f'{url}: {e}') from e


def get_json_or_none(url):
    """Zelfde als get_json, maar een 404 is een antwoord (niet gevonden), geen netwerkfout."""
    try:
        return get_json(url)
    except NetError as e:
        if isinstance(e.__cause__, urllib.error.HTTPError) and e.__cause__.code == 404:
            return None
        raise


def read_receipt(src):
    text = sys.stdin.read() if src == '-' else open(src, encoding='utf-8').read()
    text = text.strip()
    if not text.startswith('{'):
        compact = re.sub(r'\s+', '', text).replace('-', '+').replace('_', '/')
        text = base64.b64decode(compact + '=' * (-len(compact) % 4)).decode('utf-8')
    obj = json.loads(text)
    if isinstance(obj.get('receipt'), str):
        inner = obj['receipt'].replace('-', '+').replace('_', '/')
        obj = json.loads(base64.b64decode(inner + '=' * (-len(inner) % 4)))
    if not obj.get('blob_hash') or not obj.get('inclusion_proof'):
        raise UsageError('dit is geen ontvangstbewijs van een ParaSend-verzending '
                         '(blob_hash of inclusion_proof ontbreekt). Een ParaSign-bewijs '
                         'kan deze tool nog niet controleren: zie docs/klant-controle.md.')
    return obj


# ── De controle ─────────────────────────────────────────────────────────────
class Report:
    def __init__(self):
        self.steps = []

    def add(self, name, ok, detail=''):
        # ok: True, False, of None (niet te controleren)
        self.steps.append({'stap': len(self.steps) + 1, 'controle': name, 'ok': ok, 'detail': detail})
        return ok


def check_sig(rep, label, sth, key, key_note):
    if key is None:
        return rep.add(label, None, 'geen sleutel voor deze relay; geef --pubkey')
    if not mldsa_available():
        return rep.add(label, None, 'OpenSSL zonder ML-DSA-65 (nodig: 3.5 of nieuwer)')
    ok = mldsa65_verify(key, sth_message(sth), sth.get('signature', ''))
    return rep.add(label, ok, key_note)


def run(args):
    rep = Report()
    pins = load_pins(args.anchors)
    receipt = read_receipt(args.receipt) if args.receipt else None

    if receipt:
        host = host_of(receipt.get('relay_id'))
        base = (args.relay or f'https://{host}').rstrip('/')
        sth = None
    else:
        if args.index is None or not args.relay:
            raise UsageError('geef een ontvangstbewijs, of --index N met --relay URL')
        base = args.relay.rstrip('/')
        # Zonder receipt zegt de relay zelf wie hij is. Dat is geen vertrouwen:
        # de handtekening moet dan kloppen onder de gepinde sleutel van die naam.
        sth = get_json(f'{base}/v2/sth').get('sth') or {}
        host = host_of(sth.get('relay_id'))
    if args.pubkey:
        key, key_note = args.pubkey, 'sleutel door u opgegeven, niet een gepinde Paramant-sleutel'
    elif host in pins:
        key, key_note = pins[host], f'gepinde sleutel van {host}'
    else:
        key, key_note = None, ''

    if receipt:
        ip = receipt['inclusion_proof']
        idx = int(ip.get('leaf_index'))
        size = int(ip.get('tree_size'))
        leaf = transfer_leaf(receipt['blob_hash'], receipt.get('sector'), receipt.get('ts'))
        rep.add('blad herberekend uit het ontvangstbewijs', leaf == ip.get('leaf_hash'),
                f'{leaf[:16]}…' if leaf == ip.get('leaf_hash') else 'het blad hoort bij een ander bestand of tijdstip')
        root = ip.get('root') or ''
        path = [bytes.fromhex(s['hash'] if isinstance(s, dict) else s) for s in ip.get('audit_path') or []]
        rep.add(f'inclusiebewijs uit het ontvangstbewijs (boom van {size})',
                verify_inclusion(idx, size, bytes.fromhex(leaf), path, bytes.fromhex(root)))
        rsth = ip.get('sth')
        if rsth:
            same = rsth.get('sha3_root') == root and int(rsth.get('tree_size', -1)) == size
            rep.add('boomtop in het ontvangstbewijs hoort bij dat bewijs', same)
            check_sig(rep, 'handtekening onder de boomtop van toen', rsth, key, key_note)
    else:
        idx = args.index
        leaf = None

    # Openbare log: staat dat blad op die plek? /v2/ct/proof/<index> komt uit
    # de volledige boom, ook voor een blad dat buiten het venster van de
    # laatste 10.000 valt dat /v2/ct/log toont. Daar zocht deze stap eerst, en
    # een oud bewijs faalde dan vals met "vertrouw dit niet". /v2/ct/log is
    # alleen nog de terugval voor een relay die /v2/ct/proof niet kent.
    p = get_json_or_none(f'{base}/v2/ct/proof/{idx}')
    if p is not None and int(p.get('index', -1)) == idx and p.get('leaf_hash'):
        pub_leaf = p['leaf_hash']
    else:
        p = None
        log = get_json_or_none(f'{base}/v2/ct/log?from={idx}&limit=1') or {}
        entries = log.get('entries') or []
        pub = entries[0] if entries and int(entries[0].get('index', -1)) == idx else None
        pub_leaf = pub.get('leaf_hash') if pub else None
    if not pub_leaf:
        rep.add(f'blad {idx} in de openbare log', False, 'niet gevonden')
        return rep, base
    if leaf is None:
        if p is None:
            rep.add(f'blad {idx} in de openbare log', None, 'deze relay geeft geen inclusiebewijs (/v2/ct/proof)')
            return rep, base
        leaf = pub_leaf
        size = int(p.get('tree_size') or idx + 1)
        root = p.get('tree_hash') or ''
        path = [bytes.fromhex(s['hash'] if isinstance(s, dict) else s) for s in p.get('proof') or []]
        rep.add(f'blad {idx} in de openbare log', True, f'{leaf[:16]}…')
        rep.add(f'inclusiebewijs van de relay (boom van {size})',
                verify_inclusion(idx, size, bytes.fromhex(leaf), path, bytes.fromhex(root)))
    else:
        rep.add(f'blad {idx} in de openbare log is hetzelfde blad', pub_leaf == leaf)

    # Consistentie naar de huidige boomtop, en die boomtop ondertekend.
    if sth is None:
        sth = get_json(f'{base}/v2/sth').get('sth') or {}
    cur = int(sth.get('tree_size', 0))
    if cur < size:
        rep.add('huidige boomtop is minstens zo groot', False,
                f'relay toont nu {cur} bladen, uw bewijs gaat over {size}')
        return rep, base
    if host_of(sth.get('relay_id')) != host and not args.pubkey:
        rep.add('huidige boomtop is van dezelfde relay', False,
                f'{sth.get("relay_id")} in plaats van {host}')
    c = get_json(f'{base}/v2/sth/consistency?from={size}&to={cur}')
    proof = [bytes.fromhex(x) for x in c.get('proof') or []]
    rep.add(f'boom van {size} is ongewijzigd opgenomen in de huidige van {cur}',
            verify_consistency(size, cur, bytes.fromhex(root), bytes.fromhex(sth.get('sha3_root', '')), proof))
    check_sig(rep, 'handtekening onder de huidige boomtop', sth, key, key_note)
    return rep, base


def main(argv=None):
    ap = argparse.ArgumentParser(description='Controleer zelf dat een ParaSend-verzending in de transparantielog staat.')
    ap.add_argument('receipt', nargs='?')
    ap.add_argument('--index', type=int)
    ap.add_argument('--relay')
    ap.add_argument('--anchors', default=DEFAULT_ANCHORS)
    ap.add_argument('--pubkey')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args(argv)
    try:
        rep, base = run(args)
    except NetError as e:
        print(f'netwerkfout: {e}', file=sys.stderr)
        return 2
    except UsageError as e:
        print(str(e), file=sys.stderr)
        return 2
    except (ValueError, KeyError, TypeError) as e:
        print(f'onleesbare invoer: {e}', file=sys.stderr)
        return 2
    oks = [s['ok'] for s in rep.steps]
    code = 1 if False in oks else (3 if None in oks else 0)
    verdict = {0: 'AANGETOOND: het blad staat in de log die deze relay nu ondertekent',
               1: 'NIET AANGETOOND: een controle faalt, vertrouw dit niet',
               3: 'ONVOLLEDIG: de log klopt, maar een handtekening is niet gecontroleerd'}[code]
    if args.json:
        print(json.dumps({'relay': base, 'stappen': rep.steps, 'uitslag': verdict, 'code': code}, indent=2))
    else:
        for s in rep.steps:
            mark = {True: 'OK  ', False: 'FOUT', None: '??  '}[s['ok']]
            print(f"{s['stap']}. {mark} {s['controle']}" + (f"  ({s['detail']})" if s['detail'] else ''))
        print(verdict)
        print('Let op: dit toont niet aan dat anderen dezelfde boom zien. Zie docs/klant-controle.md.')
    return code


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""
PARAMANT Sender v5.0
pip install cryptography

Usage:
  paramant-sender --key pgp_xxx --device my-device --heartbeat 15
  paramant-sender --key pgp_xxx --device my-device --listen 8765
  paramant-sender --key pgp_xxx --device my-device --watch /path/
  paramant-sender --key pgp_xxx --device my-device --file report.pdf
  paramant-sender --key pgp_xxx --device my-device --stdin
"""
import argparse, base64, hashlib, hmac, json, os, sys, time, struct, glob
import urllib.request, urllib.error
from datetime import datetime, timezone

VERSION = '5.0.0'
BLOCK   = 5 * 1024 * 1024
UA      = f'paramant-sender/{VERSION}'
RELAYS  = [
    'https://health.paramant.app',
    'https://iot.paramant.app',
    'https://legal.paramant.app',
    'https://finance.paramant.app',
    'https://paramant-ghost-pipe.fly.dev',
]
STATE = os.path.expanduser('~/.paramant')

def log(msg, level='INFO'):
    t = datetime.now().strftime('%H:%M:%S')
    prefix = {'OK':'✓','WARN':'⚠','ERROR':'✗','SEND':'→','INFO':'·'}.get(level, '·')
    print(f'[{t}] {prefix} {msg}', flush=True)

def blob_hash(key, device, seq):
    """Deterministisch hash zodat stream-next receiver hem kan vinden."""
    secret = key[:24].encode()
    return hmac.new(secret, f'{device}|{seq}'.encode(), hashlib.sha256).hexdigest()

def auto_relay(key):
    # Prefer relays die stream-next ondersteunen
    preferred = ['https://iot.paramant.app', 'https://health.paramant.app',
                 'https://legal.paramant.app', 'https://finance.paramant.app',
                 'https://paramant-ghost-pipe.fly.dev']
    for relay in preferred:
        try:
            r = urllib.request.urlopen(
                urllib.request.Request(f'{relay}/v2/check-key?k={key}',
                headers={'User-Agent': UA}), timeout=4)
            if json.loads(r.read()).get('valid'):
                return relay
        except: pass
    return None

def load_seq(device):
    try: return int(open(os.path.join(STATE, device.replace('/','_')+'.seq')).read())
    except: return 0

def save_seq(device, seq):
    os.makedirs(STATE, exist_ok=True)
    p = os.path.join(STATE, device.replace('/','_')+'.seq')
    open(p+'.tmp','w').write(str(seq))
    os.replace(p+'.tmp', p)

def get_recv_pubkeys(relay, key, device):
    try:
        r = urllib.request.urlopen(
            urllib.request.Request(f'{relay}/v2/pubkey/{device}?k={key}',
            headers={'User-Agent': UA}), timeout=6)
        d = json.loads(r.read())
        if d.get('ok'):
            return d.get('ecdh_pub'), d.get('kyber_pub')
    except Exception as e:
        log(f'Pubkey ophalen mislukt: {e}', 'WARN')
    return None, None

def encrypt_and_send(relay, key, device, data, seq, ttl=300):
    try:
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, ECDH, SECP256R1
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        log('pip install cryptography', 'ERROR'); sys.exit(1)

    be = default_backend()
    ecdh_pub_hex, kyber_pub_hex = get_recv_pubkeys(relay, key, device)
    if not ecdh_pub_hex:
        log('Geen receiver pubkeys — start receiver eerst', 'ERROR')
        return None

    # ECDH
    eph      = generate_private_key(SECP256R1(), be)
    recv_pub = load_der_public_key(bytes.fromhex(ecdh_pub_hex), be)
    ecdh_ss  = eph.exchange(ECDH(), recv_pub)
    eph_pub  = eph.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    # ML-KEM (optioneel)
    kct = b''; kss = b''
    if kyber_pub_hex:
        try:
            from kyber import Kyber768
            kct, kss = Kyber768.enc(bytes.fromhex(kyber_pub_hex))
        except: pass

    # HKDF + AES-GCM
    ikm   = ecdh_ss + kss
    aes_k = HKDF(algorithm=hashes.SHA256(), length=32,
                 salt=b'paramant-gp-v4', info=b'aes-key', backend=be).derive(ikm)
    nonce = os.urandom(12)
    ct    = AESGCM(aes_k).encrypt(nonce, data, None)

    # Packet bouwen
    bundle = struct.pack('>I', len(eph_pub)) + eph_pub + struct.pack('>I', len(kct)) + kct
    packet = struct.pack('>I', len(bundle)) + bundle + nonce + struct.pack('>I', len(ct)) + ct
    if len(packet) > BLOCK:
        log('Data te groot (max 5MB)', 'ERROR'); return None
    blob = packet + os.urandom(BLOCK - len(packet))
    # HMAC-afgeleid hash zodat stream-next receiver de blob kan terugvinden
    h    = blob_hash(key, device, seq)

    body = json.dumps({
        'hash': h,
        'payload': base64.b64encode(blob).decode(),
        'ttl_ms': ttl * 1000,
        'sender_device': device,
        'meta': {'device_id': device, 'seq': seq}
    }).encode()

    for attempt in range(3):
        if attempt > 0:
            wait = 2 ** attempt
            log(f'Retry {attempt}/2 over {wait}s...', 'WARN')
            time.sleep(wait)
        try:
            req  = urllib.request.Request(
                f'{relay}/v2/inbound', data=body, method='POST',
                headers={'Content-Type': 'application/json',
                         'X-Api-Key': key, 'User-Agent': UA})
            resp = json.loads(urllib.request.urlopen(req, timeout=30).read())
            if resp.get('ok'):
                alg = 'ML-KEM+ECDH+AES-GCM' if kct else 'ECDH+AES-GCM'
                log(f'seq={seq} hash={h[:16]}... {len(data)}B [{alg}]', 'SEND')
                return h
        except urllib.error.HTTPError as e:
            log(f'HTTP {e.code} (poging {attempt+1})', 'WARN')
        except Exception as e:
            log(f'Poging {attempt+1}: {str(e)[:60]}', 'WARN')
    return None

def mode_heartbeat(relay, key, device, interval, ttl):
    seq = load_seq(device)
    log(f'Heartbeat elke {interval}s naar {relay}')
    while True:
        seq += 1
        data = json.dumps({
            'device': device, 'seq': seq, 'status': 'ok',
            'ts': datetime.now(timezone.utc).isoformat()
        }).encode()
        h = encrypt_and_send(relay, key, device, data, seq, ttl)
        if h: save_seq(device, seq)
        time.sleep(interval)

def mode_file(relay, key, device, filepath, ttl):
    seq  = load_seq(device) + 1
    data = open(filepath, 'rb').read()
    log(f'Versturen: {filepath} ({len(data)} bytes)')
    h = encrypt_and_send(relay, key, device, data, seq, ttl)
    if h:
        save_seq(device, seq)
        log(f'Verstuurd: {h[:20]}...', 'OK')
    else:
        log('Versturen mislukt', 'ERROR'); sys.exit(1)

def mode_stdin(relay, key, device, ttl):
    seq  = load_seq(device) + 1
    data = sys.stdin.buffer.read()
    log(f'stdin: {len(data)} bytes')
    h = encrypt_and_send(relay, key, device, data, seq, ttl)
    if h:
        save_seq(device, seq)
        print(h)
    else:
        sys.exit(1)

def mode_listen(relay, key, device, port, ttl):
    import http.server, threading
    state = {'seq': load_seq(device)}
    lock  = threading.Lock()

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_POST(self):
            n    = min(int(self.headers.get('Content-Length', 0) or 0), BLOCK)
            body = self.rfile.read(n)
            with lock: state['seq'] += 1; seq = state['seq']
            h = encrypt_and_send(relay, key, device, body, seq, ttl)
            if h:
                save_seq(device, seq)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'ok': True, 'hash': h, 'seq': seq}).encode())
            else:
                self.send_response(502); self.end_headers()
        def do_GET(self):
            if self.path == '/status':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'ok': True, 'seq': state['seq']}).encode())
            else:
                self.send_response(404); self.end_headers()

    log(f'HTTP proxy op :{port} — POST naar http://127.0.0.1:{port}')
    http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()

def mode_watch(relay, key, device, watch_dir, ttl):
    sent = set(); seq = load_seq(device)
    log(f'Bewaakt: {watch_dir}')
    while True:
        for path in sorted(glob.glob(os.path.join(watch_dir, '*'))):
            if path not in sent and os.path.isfile(path):
                try:
                    data = open(path, 'rb').read()
                    seq += 1
                    h = encrypt_and_send(relay, key, device, data, seq, ttl)
                    if h: save_seq(device, seq); sent.add(path)
                except Exception as e:
                    log(str(e)[:60], 'ERROR')
        time.sleep(2)

def main():
    p = argparse.ArgumentParser(
        description=f'PARAMANT Sender v{VERSION}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  paramant-sender --key pgp_xxx --device mri-001 --heartbeat 15
  paramant-sender --key pgp_xxx --device mri-001 --file scan.dcm
  paramant-sender --key pgp_xxx --device mri-001 --listen 8765
  paramant-sender --key pgp_xxx --device mri-001 --watch /exports/
  cat data.json | paramant-sender --key pgp_xxx --device mri-001 --stdin
        """)
    p.add_argument('--key',       required=True,  help='API key (pgp_xxx)')
    p.add_argument('--device',    required=True,  help='Device ID')
    p.add_argument('--relay',     default='',     help='Relay URL (auto-detect als leeg)')
    p.add_argument('--ttl',       type=int, default=300, help='Blob TTL in seconden')
    p.add_argument('--heartbeat', type=int, default=None, metavar='SEC')
    p.add_argument('--listen',    type=int, default=None, metavar='PORT')
    p.add_argument('--watch',     default=None,   metavar='DIR')
    p.add_argument('--file',      default=None,   metavar='FILE')
    p.add_argument('--stdin',     action='store_true')
    a = p.parse_args()

    if not a.key.startswith('pgp_'):
        print('Error: API key moet beginnen met pgp_'); sys.exit(1)

    relay = a.relay or auto_relay(a.key)
    if not relay:
        print('Error: geen relay bereikbaar'); sys.exit(1)

    log(f'PARAMANT Sender v{VERSION}')
    log(f'Device: {a.device}')
    log(f'Relay:  {relay}')

    if a.heartbeat:
        mode_heartbeat(relay, a.key, a.device, a.heartbeat, a.ttl)
    elif a.file:
        mode_file(relay, a.key, a.device, a.file, a.ttl)
    elif a.stdin:
        mode_stdin(relay, a.key, a.device, a.ttl)
    elif a.listen:
        mode_listen(relay, a.key, a.device, a.listen, a.ttl)
    elif a.watch:
        mode_watch(relay, a.key, a.device, a.watch, a.ttl)
    else:
        p.print_help(); sys.exit(1)

if __name__ == '__main__':
    main()

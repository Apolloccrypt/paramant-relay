#!/usr/bin/env python3
"""
PARAMANT Receiver v5.0
pip install cryptography

Usage:
  paramant-receiver --key pgp_xxx --device my-device --output /path/
  paramant-receiver --key pgp_xxx --device my-device --forward https://api/endpoint
  paramant-receiver --key pgp_xxx --device my-device --stdout
"""
import argparse, hashlib, hmac, json, os, sys, time, struct
import urllib.request, urllib.error
from datetime import datetime, timezone

VERSION = '5.0.0'
BLOCK   = 5 * 1024 * 1024
UA      = f'paramant-receiver/{VERSION}'
# Relays met stream-next support eerst
RELAYS  = [
    'https://iot.paramant.app',
    'https://health.paramant.app',
    'https://legal.paramant.app',
    'https://finance.paramant.app',
    'https://paramant-ghost-pipe.fly.dev',
]
STATE = os.path.expanduser('~/.paramant')

def log(msg, level='INFO'):
    t = datetime.now().strftime('%H:%M:%S')
    prefix = {'OK':'✓','WARN':'⚠','ERROR':'✗','RECV':'←','INFO':'·'}.get(level, '·')
    print(f'[{t}] {prefix} {msg}', flush=True)

def auto_relay(key):
    for relay in RELAYS:
        try:
            r = urllib.request.urlopen(
                urllib.request.Request(f'{relay}/v2/check-key?k={key}',
                headers={'User-Agent': UA}), timeout=4)
            if json.loads(r.read()).get('valid'):
                return relay
        except: pass
    return None

def kp_path(device):
    return os.path.join(STATE, device.replace('/','_')+'.keypair.json')

def load_or_gen_keypair(device):
    path = kp_path(device)
    if os.path.exists(path):
        kp = json.load(open(path))
        if time.time() - kp.get('created_ts', 0) > 86400:
            log('Keypair ouder dan 24u — roteren...', 'INFO')
            os.remove(path)
            return load_or_gen_keypair(device)
        return kp

    try:
        from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        log('pip install cryptography', 'ERROR'); sys.exit(1)

    be   = default_backend()
    priv = generate_private_key(SECP256R1(), be)
    pub  = priv.public_key()
    pd   = priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    pubd = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    kpub = b''; kpriv = b''
    try:
        from kyber import Kyber768
        kpub, kpriv = Kyber768.keygen()
        log('ML-KEM-768 keypair gegenereerd', 'OK')
    except:
        log('ML-KEM-768 niet beschikbaar — pip install kyber-py', 'WARN')

    os.makedirs(STATE, exist_ok=True)
    kp = {
        'v': '5.0', 'device': device,
        'ecdh_priv': pd.hex(), 'ecdh_pub': pubd.hex(),
        'kyber_pub':  kpub.hex()  if kpub  else '',
        'kyber_priv': kpriv.hex() if kpriv else '',
        'created_ts': time.time()
    }
    with open(path, 'w') as f: json.dump(kp, f)
    os.chmod(path, 0o600)
    log(f'Nieuw keypair gegenereerd voor {device}', 'OK')
    return kp

def register_pubkeys(relay, key, device, kp):
    body = json.dumps({
        'device_id': device,
        'ecdh_pub':  kp['ecdh_pub'],
        'kyber_pub': kp.get('kyber_pub', '')
    }).encode()
    req = urllib.request.Request(
        f'{relay}/v2/pubkey', data=body, method='POST',
        headers={'Content-Type': 'application/json',
                 'X-Api-Key': key, 'User-Agent': UA})
    try:
        resp = json.loads(urllib.request.urlopen(req, timeout=8).read())
        if resp.get('ok'):
            alg = 'ML-KEM-768+ECDH' if kp.get('kyber_pub') else 'ECDH P-256'
            log(f'Pubkeys geregistreerd ({alg})', 'OK')
            return True
    except Exception as e:
        log(f'Pubkey registratie mislukt: {e}', 'WARN')
    return False

def decrypt_blob(raw_bytes, kp):
    """Decrypteer raw bytes van relay — GEEN base64 decode."""
    try:
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.asymmetric.ec import ECDH
        from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        log('pip install cryptography', 'ERROR'); sys.exit(1)

    be   = default_backend()
    blob = raw_bytes
    o    = 0

    blen   = struct.unpack('>I', blob[o:o+4])[0]; o += 4
    bundle = blob[o:o+blen]; o += blen

    bo    = 0
    eplen = struct.unpack('>I', bundle[bo:bo+4])[0]; bo += 4
    epb   = bundle[bo:bo+eplen]; bo += eplen
    klen  = struct.unpack('>I', bundle[bo:bo+4])[0]; bo += 4
    kct   = bundle[bo:bo+klen]

    nonce = blob[o:o+12]; o += 12
    ctlen = struct.unpack('>I', blob[o:o+4])[0]; o += 4
    ct    = blob[o:o+ctlen]

    priv    = load_der_private_key(bytes.fromhex(kp['ecdh_priv']), None, be)
    epk     = load_der_public_key(epb, be)
    ecdh_ss = priv.exchange(ECDH(), epk)

    kss = b''
    if kct and kp.get('kyber_priv'):
        try:
            from kyber import Kyber768
            kss = Kyber768.dec(bytes.fromhex(kp['kyber_priv']), kct)
        except: pass

    ikm   = ecdh_ss + kss
    aes_k = HKDF(algorithm=hashes.SHA256(), length=32,
                 salt=b'paramant-gp-v4', info=b'aes-key', backend=be).derive(ikm)
    return AESGCM(aes_k).decrypt(nonce, ct, None)

def send_ack(relay, key, blob_hash):
    try:
        req = urllib.request.Request(
            f'{relay}/v2/ack/{blob_hash}',
            data=b'{}', method='POST',
            headers={'Content-Type': 'application/json',
                     'X-Api-Key': key, 'User-Agent': UA})
        resp = json.loads(urllib.request.urlopen(req, timeout=5).read())
        if resp.get('ok'):
            log(f'ACK verstuurd (latency: {resp.get("latency_ms","?")}ms)', 'OK')
    except: pass

def detect_ext(data):
    if data[128:132] == b'DICM' or data[:4] == b'DICM': return '.dcm'
    if data[:1] == b'{': return '.json'
    if data[:5] == b'%PDF-': return '.pdf'
    return '.bin'

def deliver(data, seq, output_dir, forward_url, stdout_mode, blob_hash, relay, key):
    if stdout_mode:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, f'recv_{seq:06d}{detect_ext(data)}')
        with open(path, 'wb') as f: f.write(data)
        log(f'Opgeslagen: {os.path.basename(path)} ({len(data)} bytes)', 'RECV')
    if forward_url:
        try:
            req = urllib.request.Request(
                forward_url, data=data, method='POST',
                headers={'Content-Type': 'application/octet-stream', 'User-Agent': UA})
            urllib.request.urlopen(req, timeout=15)
            log(f'Doorgestuurd naar {forward_url[:50]}', 'OK')
        except Exception as e:
            log(f'Forward mislukt: {e}', 'WARN')
    send_ack(relay, key, blob_hash)

def load_recv_seq(device):
    try: return int(open(os.path.join(STATE, device.replace('/','_')+'.recv_seq')).read())
    except: return 0

def save_recv_seq(device, seq):
    os.makedirs(STATE, exist_ok=True)
    p = os.path.join(STATE, device.replace('/','_')+'.recv_seq')
    open(p+'.tmp','w').write(str(seq))
    os.replace(p+'.tmp', p)

def try_websocket_stream(relay, key, device, kp, output_dir, forward_url, stdout_mode):
    """WebSocket first — sub-100ms delivery. Returns False als WS niet beschikbaar."""
    try:
        import websocket
    except ImportError:
        log('pip install websocket-client voor WebSocket streaming', 'WARN')
        return False

    ws_url = relay.replace('https://','wss://').replace('http://','ws://') + f'/v2/stream?k={key}'
    connected = [False]
    seq = [load_recv_seq(device)]

    def on_open(ws):
        connected[0] = True
        log(f'WebSocket stream actief', 'OK')

    def on_message(ws, msg):
        try:
            d = json.loads(msg)
            if d.get('type') == 'blob_ready':
                h = d.get('hash','')
                if not h: return
                req  = urllib.request.Request(
                    f'{relay}/v2/outbound/{h}',
                    headers={'X-Api-Key': key, 'User-Agent': UA})
                raw  = urllib.request.urlopen(req, timeout=30).read()
                data = decrypt_blob(raw, kp)
                seq[0] += 1
                save_recv_seq(device, seq[0])
                deliver(data, seq[0], output_dir, forward_url, stdout_mode, h, relay, key)
        except Exception as e:
            log(f'WS message fout: {e}', 'WARN')

    def on_error(ws, e):
        log(f'WebSocket fout: {e}', 'WARN')

    def on_close(ws, *a):
        log('WebSocket gesloten', 'WARN')
        connected[0] = False

    ws = websocket.WebSocketApp(ws_url,
        on_open=on_open, on_message=on_message,
        on_error=on_error, on_close=on_close)

    import threading
    t = threading.Thread(target=lambda: ws.run_forever(ping_interval=20), daemon=True)
    t.start()
    time.sleep(2)
    return connected[0]

def poll_loop(relay, key, device, kp, output_dir, forward_url, stdout_mode, interval=3):
    """Polling via status/:hash — werkt op alle relay-modi zonder stream-next."""
    seq = load_recv_seq(device)
    log(f'Polling gestart (interval: {interval}s, vanaf seq={seq})')
    secret = key[:24].encode()

    while True:
        next_seq = seq + 1
        h = hmac.new(secret, f'{device}|{next_seq}'.encode(), hashlib.sha256).hexdigest()
        try:
            req = urllib.request.Request(
                f'{relay}/v2/status/{h}',
                headers={'X-Api-Key': key, 'User-Agent': UA})
            d = json.loads(urllib.request.urlopen(req, timeout=10).read())

            if d.get('available'):
                req2 = urllib.request.Request(
                    f'{relay}/v2/outbound/{h}',
                    headers={'X-Api-Key': key, 'User-Agent': UA})
                raw = urllib.request.urlopen(req2, timeout=30).read()
                try:
                    data = decrypt_blob(raw, kp)
                    seq  = next_seq
                    save_recv_seq(device, seq)
                    deliver(data, seq, output_dir, forward_url, stdout_mode, h, relay, key)
                    continue  # direct volgende seq proberen
                except Exception as e:
                    log(f'Decrypt fout seq={next_seq}: {e}', 'ERROR')
                    seq = next_seq
        except urllib.error.URLError as e:
            log(f'Relay niet bereikbaar: {e}', 'WARN')
        except Exception as e:
            log(f'Poll fout: {e}', 'WARN')
        time.sleep(interval)

def main():
    p = argparse.ArgumentParser(
        description=f'PARAMANT Receiver v{VERSION}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  paramant-receiver --key pgp_xxx --device mri-001 --output /pacs/
  paramant-receiver --key pgp_xxx --device mri-001 --forward https://api/ingest
  paramant-receiver --key pgp_xxx --device mri-001 --stdout | jq .
        """)
    p.add_argument('--key',      required=True,  help='API key (pgp_xxx)')
    p.add_argument('--device',   required=True,  help='Device ID')
    p.add_argument('--relay',    default='',     help='Relay URL (auto-detect als leeg)')
    p.add_argument('--output',   default='',     help='Output directory')
    p.add_argument('--forward',  default='',     help='Forward URL')
    p.add_argument('--stdout',   action='store_true', help='Schrijf naar stdout')
    p.add_argument('--interval', type=int, default=3, help='Poll interval (seconden)')
    p.add_argument('--no-ws',    action='store_true', help='Sla WebSocket over, gebruik polling')
    a = p.parse_args()

    if not a.key.startswith('pgp_'):
        print('Error: API key moet beginnen met pgp_'); sys.exit(1)
    if not a.output and not a.forward and not a.stdout:
        print('Error: geef --output, --forward of --stdout op'); sys.exit(1)

    relay = a.relay or auto_relay(a.key)
    if not relay:
        print('Error: geen relay bereikbaar'); sys.exit(1)

    log(f'PARAMANT Receiver v{VERSION}')
    log(f'Device: {a.device}')
    log(f'Relay:  {relay}')

    kp = load_or_gen_keypair(a.device)
    register_pubkeys(relay, a.key, a.device, kp)

    output_dir  = a.output  or None
    forward_url = a.forward or None
    stdout_mode = a.stdout

    ws_active = False
    if not a.no_ws:
        ws_active = try_websocket_stream(
            relay, a.key, a.device, kp, output_dir, forward_url, stdout_mode)
        if ws_active:
            log('WebSocket actief — polling als fallback')

    poll_loop(relay, a.key, a.device, kp, output_dir, forward_url, stdout_mode,
              interval=1 if ws_active else a.interval)

if __name__ == '__main__':
    main()

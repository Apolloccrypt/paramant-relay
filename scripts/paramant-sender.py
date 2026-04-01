#!/usr/bin/env python3
"""
PARAMANT Ghost Pipe Sender v4.1 — Interactief
pip install cryptography

  python3 paramant-sender.py --key pgp_xxx --device mri-001 --heartbeat 15
  python3 paramant-sender.py --key pgp_xxx --device plc-001 --listen 8765
  python3 paramant-sender.py --key pgp_xxx --device bank    --watch /map/
"""
import argparse, base64, hashlib, json, os, sys, time, struct, glob, signal, threading, termios, tty
import urllib.request, urllib.error
from datetime import datetime, timezone
from collections import deque

VERSION = '4.1.0'
BLOCK   = 5 * 1024 * 1024
UA      = f'Mozilla/5.0 (compatible; paramant-sender/{VERSION})'
RELAYS  = {'health':'https://health.paramant.app','iot':'https://iot.paramant.app',
           'legal':'https://legal.paramant.app','finance':'https://finance.paramant.app',
           'relay':'https://relay.paramant.app'}
STATE   = os.path.expanduser('~/.paramant')

# ── ANSI ──────────────────────────────────────────────────────────────────────
CLS  = '\033[2J\033[H'
G    = '\033[92m'; Y = '\033[93m'; R = '\033[91m'; B = '\033[94m'
C    = '\033[96m'; M = '\033[95m'; D = '\033[2m';  E = '\033[0m'; BOLD = '\033[1m'
HIDE = '\033[?25l'; SHOW = '\033[?25h'

def ts(): return datetime.now().strftime('%H:%M:%S')

# ── Staat ─────────────────────────────────────────────────────────────────────
class State:
    def __init__(self):
        self.running    = True
        self.paused     = False
        self.seq        = 0
        self.sent_ok    = 0
        self.sent_fail  = 0
        self.bytes_sent = 0
        self.relay      = ''
        self.device     = ''
        self.mode       = ''
        self.enc        = ''
        self.interval   = 15
        self.log        = deque(maxlen=12)
        self.last_hash  = ''
        self.last_ts    = ''
        self.connected  = False
        self.pubkey_ok  = False

ST = State()

def slog(lvl, msg):
    c = {'OK':G,'SEND':B,'WARN':Y,'ERROR':R,'INFO':D}.get(lvl, '')
    ST.log.append(f'{D}{ts()}{E} {c}[{lvl}]{E} {msg}')

# ── Display ───────────────────────────────────────────────────────────────────
def draw():
    while ST.running:
        lines = []
        w = 72
        lines.append(f'{CLS}{BOLD}{C}{"─"*w}{E}')
        lines.append(f'{BOLD}{C}  PARAMANT Ghost Pipe Sender v{VERSION}{E}')
        lines.append(f'{C}{"─"*w}{E}')
        status = f'{G}●  VERBONDEN{E}' if ST.connected else f'{R}●  NIET VERBONDEN{E}'
        enc    = f'{G}{ST.enc}{E}' if 'ML-KEM' in ST.enc else f'{Y}{ST.enc}{E}'
        lines.append(f'  Apparaat  {BOLD}{ST.device}{E}   Status {status}')
        lines.append(f'  Relay     {D}{ST.relay}{E}')
        lines.append(f'  Encryptie {enc}')
        lines.append(f'  Modus     {BOLD}{ST.mode}{E}' + (f'  Interval {ST.interval}s' if ST.interval else ''))
        lines.append(f'{C}{"─"*w}{E}')

        # Stats
        lines.append(f'  {BOLD}Seq{E} {B}{ST.seq}{E}   '
                     f'{BOLD}Verzonden{E} {G}{ST.sent_ok}{E}   '
                     f'{BOLD}Mislukt{E} {R if ST.sent_fail else D}{ST.sent_fail}{E}   '
                     f'{BOLD}Data{E} {C}{ST.bytes_sent/1024:.1f}KB{E}')
        if ST.last_hash:
            lines.append(f'  Laatste   {D}{ST.last_hash[:32]}...{E}  {D}{ST.last_ts}{E}')
        lines.append(f'{C}{"─"*w}{E}')

        # Log
        for entry in list(ST.log)[-10:]:
            lines.append(f'  {entry}')
        # Vul aan tot vaste hoogte
        while len(lines) < 22:
            lines.append('')
        lines.append(f'{C}{"─"*w}{E}')
        paused = f'{Y} ⏸ GEPAUZEERD {E}' if ST.paused else ''
        lines.append(f'  {D}[Q]{E} Stoppen  {D}[P]{E} Pauze  {D}[R]{E} Herverbinden  {D}[+/-]{E} Interval{paused}')
        lines.append(f'{C}{"─"*w}{E}')

        sys.stdout.write('\n'.join(lines))
        sys.stdout.flush()
        time.sleep(0.5)

# ── Toetsenbord ───────────────────────────────────────────────────────────────
def keyboard():
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while ST.running:
            ch = sys.stdin.read(1).lower()
            if ch == 'q':
                ST.running = False; break
            elif ch == 'p':
                ST.paused = not ST.paused
                slog('INFO', 'Gepauzeerd' if ST.paused else 'Hervat')
            elif ch == 'r':
                global _cached_keys
                _cached_keys.clear()
                ST.connected = False
                ST.pubkey_ok = False
                slog('INFO', 'Herverbinden...')
            elif ch == '+' and ST.interval < 300:
                ST.interval = min(ST.interval + 5, 300)
                slog('INFO', f'Interval → {ST.interval}s')
            elif ch == '-' and ST.interval > 5:
                ST.interval = max(ST.interval - 5, 5)
                slog('INFO', f'Interval → {ST.interval}s')
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        sys.stdout.write(SHOW)

# ── Crypto ────────────────────────────────────────────────────────────────────
def _cry():
    try:
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, ECDH, SECP256R1
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key
        from cryptography.hazmat.backends import default_backend
        return dict(HKDF=HKDF,hsh=hashes,AES=AESGCM,gen=generate_private_key,
                    ECDH=ECDH,curve=SECP256R1,Enc=Encoding,Pub=PublicFormat,
                    lpub=load_der_public_key,be=default_backend)
    except ImportError:
        print(f'{R}pip install cryptography{E}'); sys.exit(1)

def _kyber():
    try:
        from kyber import Kyber768; return Kyber768
    except: return None

_cached_keys = {}

def get_recv_keys(relay, api_key, device):
    k = f'{relay}:{device}'
    if k in _cached_keys: return _cached_keys[k]
    try:
        url = f'{relay}/v2/pubkey/{device}?k={api_key}'
        r   = urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':UA}),timeout=6)
        d   = json.loads(r.read())
        if d.get('ok'):
            c   = _cry(); be = c['be']()
            pub = c['lpub'](bytes.fromhex(d['ecdh_pub']),be)
            kpub= bytes.fromhex(d['kyber_pub']) if d.get('kyber_pub') else None
            _cached_keys[k] = (pub, kpub)
            return pub, kpub
    except Exception as e:
        slog('WARN', f'Pubkeys: {e}')
    return None, None

def encrypt_send(relay, api_key, device, data, seq, ttl):
    c  = _cry(); K = _kyber(); be = c['be']()
    ecdh_pub, kyber_pub = get_recv_keys(relay, api_key, device)
    if not ecdh_pub:
        slog('ERROR','Geen ontvanger pubkeys — start receiver eerst'); return None

    # ECDH
    eph   = c['gen'](c['curve'](),be)
    ecdh_ss = eph.exchange(c['ECDH'](), ecdh_pub)
    eph_b = eph.public_key().public_bytes(c['Enc'].DER, c['Pub'].SubjectPublicKeyInfo)

    # ML-KEM
    kct = b''; kss = b''
    if K and kyber_pub:
        try: kct, kss = K.enc(kyber_pub)
        except: pass

    # HKDF
    ikm = ecdh_ss + kss
    ss  = c['HKDF'](algorithm=c['hsh'].SHA256(),length=32,
                    salt=b'paramant-gp-v4',info=b'aes-key',backend=be).derive(ikm)

    # AES-256-GCM
    nonce = os.urandom(12)
    ct    = c['AES'](ss).encrypt(nonce, data, None)
    bundle= struct.pack('>I',len(eph_b))+eph_b+struct.pack('>I',len(kct))+kct
    packet= struct.pack('>I',len(bundle))+bundle+nonce+struct.pack('>I',len(ct))+ct
    if len(packet) > BLOCK: slog('ERROR','Data te groot voor 5MB'); return None
    blob  = packet + os.urandom(BLOCK-len(packet))
    h     = hashlib.sha256(blob).hexdigest()

    # Upload
    body = json.dumps({'hash':h,'payload':base64.b64encode(blob).decode(),'ttl_ms':ttl*1000}).encode()
    req  = urllib.request.Request(f'{relay}/v2/inbound',data=body,method='POST',
           headers={'Content-Type':'application/json','X-Api-Key':api_key,'User-Agent':UA})
    try:
        resp = json.loads(urllib.request.urlopen(req,timeout=30).read())
        if resp.get('ok'):
            ST.sent_ok+=1; ST.bytes_sent+=len(data)
            ST.last_hash=h; ST.last_ts=ts(); ST.connected=True
            alg = 'ML-KEM-768+ECDH+AES-GCM' if kct else 'ECDH+AES-GCM'
            ST.enc = alg
            slog('SEND', f'seq={seq}  {D}{h[:20]}...{E}  {len(data)}B  {alg}')
            return h
    except urllib.error.HTTPError as e:
        slog('WARN', f'HTTP {e.code}: {e.read().decode()[:50]}')
    except Exception as e:
        slog('WARN', str(e)[:60])
    ST.sent_fail+=1; ST.connected=False
    return None

# ── State ──────────────────────────────────────────────────────────────────────
def load_seq(dev):
    try: return int(open(os.path.join(STATE,dev.replace('/','_')+'.seq')).read())
    except: return 0
def save_seq(dev,seq):
    os.makedirs(STATE,exist_ok=True)
    p=os.path.join(STATE,dev.replace('/','_')+'.seq')
    open(p+'.tmp','w').write(str(seq)); os.replace(p+'.tmp',p)

def auto_relay(k):
    for relay in RELAYS.values():
        try:
            r=urllib.request.urlopen(urllib.request.Request(f'{relay}/v2/check-key?k={k}',headers={'User-Agent':UA}),timeout=4)
            if json.loads(r.read()).get('valid'): return relay
        except: pass
    return None

# ── Modi ──────────────────────────────────────────────────────────────────────
def mode_heartbeat(relay,key,device,ttl):
    seq=load_seq(device)
    while ST.running:
        if not ST.paused:
            seq+=1; ST.seq=seq
            data=json.dumps({'device':device,'seq':seq,'status':'ok',
                             'ts':datetime.now(timezone.utc).isoformat()}).encode()
            encrypt_send(relay,key,device,data,seq,ttl)
            save_seq(device,seq)
        time.sleep(ST.interval)

def mode_listen(relay,key,device,ttl,port):
    import http.server,threading
    state={'seq':load_seq(device)}; lock=threading.Lock()
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self,*_): pass
        def do_POST(self):
            n=min(int(self.headers.get('Content-Length',0)or 0),50<<20)
            body=self.rfile.read(n)
            with lock: state['seq']+=1; seq=state['seq']
            ST.seq=seq
            h=encrypt_send(relay,key,device,body,seq,ttl)
            if h:
                save_seq(device,seq)
                self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers()
                self.wfile.write(json.dumps({'ok':True,'hash':h,'seq':seq}).encode())
            else: self.send_response(502);self.end_headers()
        def do_GET(self):
            if self.path=='/status':
                self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers()
                self.wfile.write(json.dumps({'ok':True,'seq':state['seq'],'relay':relay}).encode())
            else: self.send_response(404);self.end_headers()
    slog('INFO',f'HTTP proxy :{port}  →  POST naar http://127.0.0.1:{port}')
    http.server.HTTPServer(('127.0.0.1',port),H).serve_forever()

def mode_watch(relay,key,device,ttl,watch_dir):
    sent=set(); seq=load_seq(device)
    slog('INFO',f'Bewaakt: {watch_dir}')
    while ST.running:
        if not ST.paused:
            for path in sorted(glob.glob(os.path.join(watch_dir,'*'))):
                if path not in sent and os.path.isfile(path):
                    try:
                        data=open(path,'rb').read(); seq+=1; ST.seq=seq
                        h=encrypt_send(relay,key,device,data,seq,ttl)
                        if h: save_seq(device,seq); sent.add(path)
                    except Exception as e: slog('ERROR',str(e)[:60])
        time.sleep(2)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    p=argparse.ArgumentParser(description=f'PARAMANT Ghost Pipe Sender v{VERSION}')
    p.add_argument('--key',       required=True)
    p.add_argument('--device',    required=True)
    p.add_argument('--relay',     default='')
    p.add_argument('--ttl',       type=int,default=300)
    p.add_argument('--heartbeat', type=int,default=None,metavar='SEC')
    p.add_argument('--listen',    type=int,default=None,metavar='POORT')
    p.add_argument('--watch',     default=None,metavar='MAP')
    p.add_argument('--stdin',     action='store_true')
    a=p.parse_args()

    if not a.key.startswith('pgp_'): print(f'{R}Fout:{E} API key moet beginnen met pgp_'); sys.exit(1)
    relay=a.relay or auto_relay(a.key)
    if not relay: print(f'{R}Fout:{E} geen relay bereikbaar.'); sys.exit(1)

    ST.relay=relay; ST.device=a.device
    ST.mode='heartbeat' if a.heartbeat else 'listen' if a.listen else 'watch' if a.watch else 'stdin'
    ST.interval=a.heartbeat or 15
    ST.enc='Controleren...'

    sys.stdout.write(HIDE)
    threading.Thread(target=draw, daemon=True).start()
    slog('INFO',f'Gestart — relay={relay}')

    if a.heartbeat:
        t=threading.Thread(target=mode_heartbeat,args=(relay,a.key,a.device,a.ttl),daemon=True); t.start()
    elif a.listen:
        t=threading.Thread(target=mode_listen,args=(relay,a.key,a.device,a.ttl,a.listen),daemon=True); t.start()
    elif a.watch:
        t=threading.Thread(target=mode_watch,args=(relay,a.key,a.device,a.ttl,a.watch),daemon=True); t.start()

    try:
        keyboard()
    except Exception:
        while ST.running: time.sleep(0.1)
    finally:
        ST.running=False
        sys.stdout.write(f'{SHOW}\033[2J\033[H')
        print(f'\n{G}PARAMANT Sender gestopt.{E}  Verzonden: {ST.sent_ok}  Mislukt: {ST.sent_fail}\n')

if __name__=='__main__': main()

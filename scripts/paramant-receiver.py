#!/usr/bin/env python3
"""
PARAMANT Ghost Pipe Receiver v4.1 — Interactief
pip install cryptography

  python3 paramant-receiver.py --key pgp_xxx --device mri-001 --output /pacs/
  python3 paramant-receiver.py --key pgp_xxx --device plc-001 --forward https://scada/api
"""
import argparse, base64, hashlib, json, os, sys, time, struct, signal, threading, termios, tty
import urllib.request, urllib.error
from datetime import datetime, timezone
from collections import deque

VERSION = '4.1.0'
BLOCK   = 5 * 1024 * 1024
UA      = f'Mozilla/5.0 (compatible; paramant-receiver/{VERSION})'
RELAYS  = {'health':'https://health.paramant.app','iot':'https://iot.paramant.app',
           'legal':'https://legal.paramant.app','finance':'https://finance.paramant.app',
           'relay':'https://relay.paramant.app'}
STATE   = os.path.expanduser('~/.paramant')

CLS  = '\033[2J\033[H'
G    = '\033[92m'; Y = '\033[93m'; R = '\033[91m'; B = '\033[94m'
C    = '\033[96m'; D = '\033[2m';  E = '\033[0m';  BOLD = '\033[1m'
HIDE = '\033[?25l'; SHOW = '\033[?25h'

def ts(): return datetime.now().strftime('%H:%M:%S')

class State:
    def __init__(self):
        self.running    = True
        self.paused     = False
        self.seq        = 0
        self.recv_ok    = 0
        self.recv_fail  = 0
        self.bytes_recv = 0
        self.relay      = ''
        self.device     = ''
        self.output     = ''
        self.forward    = ''
        self.enc        = ''
        self.interval   = 3
        self.log        = deque(maxlen=12)
        self.last_file  = ''
        self.last_ts    = ''
        self.connected  = False
        self.fast_mode  = False

ST = State()

def slog(lvl, msg):
    c={'OK':G,'RECV':B,'WARN':Y,'ERROR':R,'INFO':D}.get(lvl,'')
    ST.log.append(f'{D}{ts()}{E} {c}[{lvl}]{E} {msg}')

def draw():
    while ST.running:
        lines = []
        w = 72
        lines.append(f'{CLS}{BOLD}{G}{"─"*w}{E}')
        lines.append(f'{BOLD}{G}  PARAMANT Ghost Pipe Receiver v{VERSION}{E}')
        lines.append(f'{G}{"─"*w}{E}')
        status = f'{G}●  VERBONDEN{E}' if ST.connected else f'{Y}●  WACHTEN{E}'
        enc    = f'{G}{ST.enc}{E}' if 'ML-KEM' in ST.enc else f'{Y}{ST.enc}{E}'
        lines.append(f'  Apparaat  {BOLD}{ST.device}{E}   Status {status}')
        lines.append(f'  Relay     {D}{ST.relay}{E}')
        lines.append(f'  Encryptie {enc}')
        out = ST.output or '—'; fwd = ST.forward[:40] or '—'
        lines.append(f'  Output    {out}   Forward {D}{fwd}{E}')
        lines.append(f'{G}{"─"*w}{E}')

        speed = f'{G}⚡ SNEL{E}' if ST.fast_mode else f'{D}normaal{E}'
        lines.append(f'  {BOLD}Seq{E} {B}{ST.seq}{E}   '
                     f'{BOLD}Ontvangen{E} {G}{ST.recv_ok}{E}   '
                     f'{BOLD}Fout{E} {R if ST.recv_fail else D}{ST.recv_fail}{E}   '
                     f'{BOLD}Data{E} {C}{ST.bytes_recv/1024:.1f}KB{E}   '
                     f'Poll {D}{ST.interval}s{E}  {speed}')
        if ST.last_file:
            lines.append(f'  Laatste   {G}{ST.last_file}{E}  {D}{ST.last_ts}{E}')
        lines.append(f'{G}{"─"*w}{E}')

        for entry in list(ST.log)[-10:]:
            lines.append(f'  {entry}')
        while len(lines) < 22: lines.append('')
        lines.append(f'{G}{"─"*w}{E}')
        paused = f'{Y} ⏸ GEPAUZEERD {E}' if ST.paused else ''
        lines.append(f'  {D}[Q]{E} Stop  {D}[P]{E} Pauze  {D}[R]{E} Herverbinden  {D}[F]{E} Snel inhalen  {D}[+/-]{E} Polling{paused}')
        lines.append(f'{G}{"─"*w}{E}')

        sys.stdout.write('\n'.join(lines))
        sys.stdout.flush()
        time.sleep(0.4)

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
                slog('INFO','Gepauzeerd' if ST.paused else 'Hervat')
            elif ch == 'r':
                ST.connected = False
                slog('INFO','Herverbinden + sequence opnieuw zoeken...')
                ST.seq = 0
            elif ch == 'f':
                ST.fast_mode = not ST.fast_mode
                ST.interval  = 1 if ST.fast_mode else 3
                slog('INFO', f'{"⚡ Snel inhalen: 1s" if ST.fast_mode else "Normaal: 3s"}')
            elif ch == '+' and ST.interval < 60:
                ST.interval = min(ST.interval+1, 60)
                slog('INFO',f'Poll interval → {ST.interval}s')
            elif ch == '-' and ST.interval > 1:
                ST.interval = max(ST.interval-1, 1)
                slog('INFO',f'Poll interval → {ST.interval}s')
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
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, PrivateFormat, NoEncryption,
            load_der_public_key, load_der_private_key)
        from cryptography.hazmat.backends import default_backend
        return dict(HKDF=HKDF,hsh=hashes,AES=AESGCM,gen=generate_private_key,
                    ECDH=ECDH,curve=SECP256R1,Enc=Encoding,Pub=PublicFormat,
                    Priv=PrivateFormat,NoEnc=NoEncryption,
                    lpub=load_der_public_key,lpriv=load_der_private_key,be=default_backend)
    except ImportError:
        print(f'{R}pip install cryptography{E}'); sys.exit(1)

def _kyber():
    try: from kyber import Kyber768; return Kyber768
    except: return None

def kp_path(dev): return os.path.join(STATE, dev.replace('/','_')+'.keypair.json')

def rotate_keypair_if_needed(device, relay, api_key):
    path = kp_path(device)
    if not os.path.exists(path): return load_or_gen_keypair(device)
    kp = json.load(open(path))
    created = kp.get('created_ts', 0)
    if time.time() - created > 86400:  # 24 uur
        slog('INFO', 'Keypair roteren na 24u...')
        os.remove(path)
        kp = load_or_gen_keypair(device)
        kp['created_ts'] = time.time()
        with open(path, 'w') as f: json.dump(kp, f)
        os.chmod(path, 0o600)
        register_pubkeys(relay, api_key, device, kp)
        slog('OK', 'Nieuw keypair actief')
    return kp

def load_or_gen_keypair(device):
    path = kp_path(device)
    if os.path.exists(path):
        return json.load(open(path))
    c=_cry(); K=_kyber(); be=c['be']()
    os.makedirs(STATE, exist_ok=True)
    priv=c['gen'](c['curve'](),be)
    pub =priv.public_key()
    pd  =priv.private_bytes(c['Enc'].DER,c['Priv'].PKCS8,c['NoEnc']())
    pubd=pub.public_bytes(c['Enc'].DER,c['Pub'].SubjectPublicKeyInfo)
    kpub=b''; kpriv=b''
    if K:
        kpub,kpriv=K.keygen()
        slog('INFO','ML-KEM-768 keypair gegenereerd')
    else:
        slog('WARN','ML-KEM-768 niet beschikbaar — pip install kyber-py')
    kp={'v':'4.1','device':device,
        'ecdh_priv':pd.hex(),'ecdh_pub':pubd.hex(),
        'kyber_pub':kpub.hex() if kpub else '',
        'kyber_priv':kpriv.hex() if kpriv else ''}
    kp['created_ts'] = time.time()
    with open(path,'w') as f: json.dump(kp,f)
    os.chmod(path,0o600)
    return kp

def register_pubkeys(relay, api_key, device, kp):
    body=json.dumps({'device_id':device,'ecdh_pub':kp['ecdh_pub'],'kyber_pub':kp.get('kyber_pub','')}).encode()
    req =urllib.request.Request(f'{relay}/v2/pubkey',data=body,method='POST',
         headers={'Content-Type':'application/json','X-Api-Key':api_key,'User-Agent':UA})
    try:
        resp=json.loads(urllib.request.urlopen(req,timeout=8).read())
        if resp.get('ok'):
            alg='ML-KEM-768+ECDH' if kp.get('kyber_pub') else 'ECDH P-256'
            ST.enc=alg; slog('OK',f'Pubkeys geregistreerd  ({alg})')
            return True
    except Exception as e:
        slog('WARN',f'Pubkey registratie: {e}')
    return False

def decrypt_blob(blob, kp):
    c=_cry(); K=_kyber(); be=c['be']()
    o=0
    blen=struct.unpack('>I',blob[o:o+4])[0];o+=4
    bun=blob[o:o+blen];o+=blen
    # Parse bundle
    bo=0
    eplen=struct.unpack('>I',bun[bo:bo+4])[0];bo+=4
    epb=bun[bo:bo+eplen];bo+=eplen
    klen=struct.unpack('>I',bun[bo:bo+4])[0];bo+=4
    kct=bun[bo:bo+klen]
    nonce=blob[o:o+12];o+=12
    ctlen=struct.unpack('>I',blob[o:o+4])[0];o+=4
    ct=blob[o:o+ctlen]
    # ECDH
    priv=c['lpriv'](bytes.fromhex(kp['ecdh_priv']),None,be)
    epk=c['lpub'](epb,be)
    ecdh_ss=priv.exchange(c['ECDH'](),epk)
    # ML-KEM
    kss=b''
    if K and kct and kp.get('kyber_priv'):
        try: kss=K.dec(bytes.fromhex(kp['kyber_priv']),kct)
        except: pass
    # HKDF
    ikm=ecdh_ss+kss
    ss=c['HKDF'](algorithm=c['hsh'].SHA256(),length=32,
                 salt=b'paramant-gp-v4',info=b'aes-key',backend=be).derive(ikm)
    return c['AES'](ss).decrypt(nonce,ct,None)

# ── HTTP ──────────────────────────────────────────────────────────────────────
def _get(url,params=None):
    import urllib.parse
    if params: url+='?'+urllib.parse.urlencode(params)
    try:
        r=urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':UA}),timeout=30)
        return r.status,r.read()
    except urllib.error.HTTPError as e: return e.code,b''
    except: return None,b''

def auto_relay(k):
    for relay in RELAYS.values():
        try:
            r=urllib.request.urlopen(urllib.request.Request(f'{relay}/v2/check-key?k={k}',headers={'User-Agent':UA}),timeout=4)
            if json.loads(r.read()).get('valid'): return relay
        except: pass
    return None

def load_seq(dev):
    try: return int(open(os.path.join(STATE,dev.replace('/','_')+'.recv_seq')).read())
    except: return 0

def save_seq(dev,seq):
    os.makedirs(STATE,exist_ok=True)
    p=os.path.join(STATE,dev.replace('/','_')+'.recv_seq')
    open(p+'.tmp','w').write(str(seq)); os.replace(p+'.tmp',p)

def find_seq(relay,api_key,device):
    saved=load_seq(device)
    slog('INFO',f'Sequence opzoeken vanaf {saved}...')
    for probe in range(saved,saved+5000,50):
        _,body=_get(f'{relay}/v2/stream-next',{'device':device,'seq':probe,'k':api_key})
        try:
            if json.loads(body).get('available'): return probe
        except: pass
    return saved

def deliver(data,seq,output_dir,forward_url):
    if output_dir:
        os.makedirs(output_dir,exist_ok=True)
        path=os.path.join(output_dir,f'block_{seq:06d}.bin')
        with open(path,'wb') as f: f.write(data)
        ST.last_file=os.path.basename(path); ST.last_ts=ts()
        slog('RECV',f'{os.path.basename(path)}  {len(data)}B  seq={seq}  {D}relay vernietigd{E}')
    if forward_url:
        try:
            req=urllib.request.Request(forward_url,data=data,method='POST',
                headers={'Content-Type':'application/octet-stream','User-Agent':UA})
            urllib.request.urlopen(req,timeout=15)
            slog('OK',f'Afgeleverd → {forward_url[:45]}')
        except Exception as e:
            slog('WARN',f'Forward mislukt: {e}')
    ST.recv_ok+=1; ST.bytes_recv+=len(data); ST.connected=True

def _try_ws_stream(relay, api_key, device, kp, output_dir, forward_url):
    try:
        import websocket
        ws_url = relay.replace('https://','wss://').replace('http://','ws://') + f'/v2/stream?k={api_key}'
        def on_message(ws, msg):
            try:
                d = json.loads(msg)
                if d.get('type') == 'blob_ready' and d.get('device') == device:
                    h = d.get('hash')
                    status, raw = _get(f'{relay}/v2/outbound/{h}')
                    if status == 200:
                        import base64
                        blob = base64.b64decode(raw) if isinstance(raw, str) else raw
                        data = decrypt_blob(blob, kp)
                        ST.seq += 1
                        deliver(data, ST.seq, output_dir, forward_url, blob_hash=h, relay=relay, api_key=api_key)
                        save_seq(device, ST.seq)
            except Exception as e:
                slog('WARN', f'WS message fout: {e}')
        def on_error(ws, e): slog('WARN', f'WS fout: {e}')
        def on_close(ws, *a): slog('INFO', 'WS gesloten — terug naar polling')
        def on_open(ws): slog('OK', 'WebSocket stream actief — geen polling nodig')
        ws_app = websocket.WebSocketApp(ws_url, on_message=on_message, on_error=on_error,
                                        on_close=on_close, on_open=on_open)
        ws_app.run_forever(ping_interval=30)
    except ImportError:
        pass  # websocket-client niet geïnstalleerd — fallback naar polling
    except Exception as e:
        slog('WARN', f'WS stream mislukt: {e}')

def poll_loop(relay,api_key,device,kp,output_dir,forward_url):
    if ST.seq==0: ST.seq=find_seq(relay,api_key,device)
    seq=ST.seq
    slog('INFO',f'Polling gestart  seq={seq}')

    while ST.running:
        if ST.paused: time.sleep(0.5); continue

        # Herverbinden als gevraagd
        if ST.seq==0 and seq>0:
            seq=find_seq(relay,api_key,device)
            ST.seq=seq
            register_pubkeys(relay,api_key,device,kp)

        _,body=_get(f'{relay}/v2/stream-next',{'device':device,'seq':seq,'k':api_key})
        try: d=json.loads(body)
        except: d={}

        if d.get('available'):
            nseq=d.get('seq',seq+1); h=d.get('hash','')
            if h:
                status,raw=_get(f'{relay}/v2/outbound/{h}')
                if status==200:
                    try:
                        blob=base64.b64decode(raw) if len(raw)<BLOCK*2 else raw
                        data=decrypt_blob(blob,kp)
                        seq=nseq; ST.seq=seq
                        deliver(data,seq,output_dir,forward_url)
                        save_seq(device,seq)
                        continue  # direct volgende proberen
                    except Exception as e:
                        slog('ERROR',f'Decrypt seq={nseq}: {str(e)[:50]}')
                        ST.recv_fail+=1; seq=nseq
                elif status==404:
                    slog('WARN',f'seq={nseq} al opgehaald'); seq=nseq
                else:
                    ST.connected=False
                    if status: slog('WARN',f'HTTP {status}')
        else:
            ST.connected=bool(d)  # relay bereikbaar maar geen blok

        time.sleep(ST.interval)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    p=argparse.ArgumentParser(description=f'PARAMANT Ghost Pipe Receiver v{VERSION}')
    p.add_argument('--key',      required=True)
    p.add_argument('--device',   required=True)
    p.add_argument('--relay',    default='')
    p.add_argument('--output',   default='')
    p.add_argument('--forward',  default='')
    p.add_argument('--interval', type=int,default=3)
    a=p.parse_args()

    if not a.key.startswith('pgp_'): print(f'{R}Fout:{E} API key moet beginnen met pgp_'); sys.exit(1)
    relay=a.relay or auto_relay(a.key)
    if not relay: print(f'{R}Fout:{E} geen relay bereikbaar.'); sys.exit(1)

    kp=load_or_gen_keypair(a.device)
    ST.relay=relay; ST.device=a.device
    ST.output=a.output; ST.forward=a.forward
    ST.interval=a.interval
    ST.enc='Controleren...'

    sys.stdout.write(HIDE)
    threading.Thread(target=draw,daemon=True).start()

    register_pubkeys(relay,a.key,a.device,kp)
    slog('INFO','Gestart — wachten op Ghost Pipe blokken')

    t=threading.Thread(target=poll_loop,args=(relay,a.key,a.device,kp,a.output or None,a.forward or None),daemon=True)
    t.start()

    try:
        keyboard()
    except Exception:
        while ST.running: time.sleep(0.1)
    finally:
        ST.running=False
        sys.stdout.write(f'{SHOW}\033[2J\033[H')
        print(f'\n{G}PARAMANT Receiver gestopt.{E}  Ontvangen: {ST.recv_ok}  Fout: {ST.recv_fail}\n')

if __name__=='__main__': main()

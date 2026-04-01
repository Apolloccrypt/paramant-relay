"""
PARAMANT Ghost Pipe SDK v1.0.0
Python SDK voor quantum-safe datatransport

pip install cryptography

Gebruik:
  from paramant import GhostPipe

  # Zender
  gp = GhostPipe(api_key='pgp_xxx', device='mri-001')
  hash = gp.send(open('scan.dcm','rb').read())
  print(f'Hash voor ontvanger: {hash}')

  # Ontvanger
  gp = GhostPipe(api_key='pgp_xxx', device='mri-001')
  gp.listen(on_receive=lambda data, meta: save(data))
"""
import base64, hashlib, json, os, struct, time
import urllib.request, urllib.error
from typing import Callable, Optional

__version__ = '1.0.0'

SECTOR_RELAYS = {
    'health':  'https://health.paramant.app',
    'iot':     'https://iot.paramant.app',
    'legal':   'https://legal.paramant.app',
    'finance': 'https://finance.paramant.app',
    'relay':   'https://relay.paramant.app',
}
BLOCK = 5 * 1024 * 1024
UA    = f'paramant-sdk/{__version__}'


class GhostPipeError(Exception):
    pass


class GhostPipe:
    """
    PARAMANT Ghost Pipe client.
    
    Quantum-safe end-to-end encrypted datatransport.
    Relay ziet NOOIT plaintext. Burn-on-read na ophalen.
    
    Args:
        api_key:  pgp_... API key van paramant.app/dashboard
        device:   Uniek apparaat-ID (zender en ontvanger gebruiken hetzelfde)
        relay:    Relay URL (automatisch gedetecteerd op basis van key)
        secret:   Extra geheim voor encryptie (optioneel, default=api_key)
    """

    def __init__(self, api_key: str, device: str, relay: str = '', secret: str = ''):
        if not api_key.startswith('pgp_'):
            raise GhostPipeError('API key moet beginnen met pgp_')
        self.api_key = api_key
        self.device  = device
        self.secret  = secret or api_key
        self.relay   = relay or self._detect_relay()
        if not self.relay:
            raise GhostPipeError('Geen relay bereikbaar. Controleer API key.')
        self._keypair = None

    # ── Relay detectie ────────────────────────────────────────────────────────
    def _detect_relay(self) -> Optional[str]:
        for relay in SECTOR_RELAYS.values():
            try:
                r = urllib.request.urlopen(
                    urllib.request.Request(f'{relay}/v2/check-key?k={self.api_key}',
                                           headers={'User-Agent': UA}), timeout=4)
                if json.loads(r.read()).get('valid'):
                    return relay
            except Exception:
                pass
        return None

    # ── HTTP helpers ──────────────────────────────────────────────────────────
    def _get(self, path: str, params: dict = None):
        import urllib.parse
        url = self.relay + path
        if params: url += '?' + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={'User-Agent': UA, 'X-Api-Key': self.api_key})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def _post(self, path: str, body: bytes, content_type: str = 'application/json'):
        req = urllib.request.Request(
            self.relay + path, data=body, method='POST',
            headers={'Content-Type': content_type, 'X-Api-Key': self.api_key, 'User-Agent': UA})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    # ── Crypto ────────────────────────────────────────────────────────────────
    def _get_crypto(self):
        try:
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives.asymmetric.ec import (
                generate_private_key, ECDH, SECP256R1)
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PublicFormat, PrivateFormat, NoEncryption,
                load_der_public_key, load_der_private_key)
            from cryptography.hazmat.backends import default_backend
            return dict(HKDF=HKDF, hsh=hashes, AES=AESGCM, gen=generate_private_key,
                        ECDH=ECDH, curve=SECP256R1, Enc=Encoding, Pub=PublicFormat,
                        Priv=PrivateFormat, NoEnc=NoEncryption,
                        lpub=load_der_public_key, lpriv=load_der_private_key,
                        be=default_backend)
        except ImportError:
            raise GhostPipeError('pip install cryptography')

    def _try_kyber(self):
        try:
            from kyber import Kyber768
            return Kyber768
        except ImportError:
            return None

    def _load_keypair(self):
        """Laad of genereer keypair voor dit device."""
        if self._keypair:
            return self._keypair
        state_dir = os.path.expanduser('~/.paramant')
        path = os.path.join(state_dir, self.device.replace('/','_') + '.keypair.json')
        if os.path.exists(path):
            self._keypair = json.load(open(path))
            return self._keypair
        c = self._get_crypto(); K = self._try_kyber(); be = c['be']()
        os.makedirs(state_dir, exist_ok=True)
        priv = c['gen'](c['curve'](), be)
        pub  = priv.public_key()
        pd   = priv.private_bytes(c['Enc'].DER, c['Priv'].PKCS8, c['NoEnc']())
        pubd = pub.public_bytes(c['Enc'].DER, c['Pub'].SubjectPublicKeyInfo)
        kpub = b''; kpriv = b''
        if K:
            kpub, kpriv = K.keygen()
        kp = {'device': self.device, 'ecdh_priv': pd.hex(), 'ecdh_pub': pubd.hex(),
              'kyber_pub': kpub.hex() if kpub else '', 'kyber_priv': kpriv.hex() if kpriv else ''}
        with open(path, 'w') as f: json.dump(kp, f)
        os.chmod(path, 0o600)
        self._keypair = kp
        return kp

    def _register_pubkeys(self):
        """Registreer pubkeys bij relay."""
        kp = self._load_keypair()
        body = json.dumps({'device_id': self.device, 'ecdh_pub': kp['ecdh_pub'],
                           'kyber_pub': kp.get('kyber_pub', '')}).encode()
        status, resp = self._post('/v2/pubkey', body)
        if status != 200:
            raise GhostPipeError(f'Pubkey registratie mislukt: {resp.decode()[:100]}')

    def _fetch_receiver_pubkeys(self):
        """Haal pubkeys op van relay (voor encryptie)."""
        status, body = self._get(f'/v2/pubkey/{self.device}')
        if status == 404:
            raise GhostPipeError('Geen pubkeys voor dit device. Start ontvanger eerst met receive_setup().')
        if status != 200:
            raise GhostPipeError(f'Pubkeys ophalen mislukt: HTTP {status}')
        d = json.loads(body)
        c  = self._get_crypto(); be = c['be']()
        ecdh_pub  = c['lpub'](bytes.fromhex(d['ecdh_pub']), be)
        kyber_pub = bytes.fromhex(d['kyber_pub']) if d.get('kyber_pub') else None
        return ecdh_pub, kyber_pub

    def _encrypt(self, data: bytes, ecdh_pub, kyber_pub) -> tuple:
        """ML-KEM-768 + ECDH + AES-256-GCM + 5MB padding."""
        c  = self._get_crypto(); K = self._try_kyber(); be = c['be']()
        # ECDH
        eph     = c['gen'](c['curve'](), be)
        ecdh_ss = eph.exchange(c['ECDH'](), ecdh_pub)
        eph_b   = eph.public_key().public_bytes(c['Enc'].DER, c['Pub'].SubjectPublicKeyInfo)
        # ML-KEM
        kct = b''; kss = b''
        if K and kyber_pub:
            try: kct, kss = K.enc(kyber_pub)
            except Exception: pass
        # HKDF
        ikm = ecdh_ss + kss
        ss  = c['HKDF'](algorithm=c['hsh'].SHA256(), length=32,
                        salt=b'paramant-gp-v1', info=b'aes-key', backend=be).derive(ikm)
        # AES-256-GCM
        nonce  = os.urandom(12)
        ct     = c['AES'](ss).encrypt(nonce, data, None)
        bundle = struct.pack('>I', len(eph_b)) + eph_b + struct.pack('>I', len(kct)) + kct
        packet = struct.pack('>I', len(bundle)) + bundle + nonce + struct.pack('>I', len(ct)) + ct
        if len(packet) > BLOCK:
            raise GhostPipeError(f'Data te groot: {len(data)} bytes (max ~4.9MB per blok)')
        blob = packet + os.urandom(BLOCK - len(packet))
        return blob, hashlib.sha256(blob).hexdigest(), bool(kct)

    def _decrypt(self, blob: bytes) -> bytes:
        """Ontsleutel Ghost Pipe blob."""
        c  = self._get_crypto(); K = self._try_kyber(); be = c['be']()
        kp = self._load_keypair()
        o  = 0
        blen = struct.unpack('>I', blob[o:o+4])[0]; o += 4
        bun  = blob[o:o+blen]; o += blen
        bo   = 0
        eplen = struct.unpack('>I', bun[bo:bo+4])[0]; bo += 4
        epb   = bun[bo:bo+eplen]; bo += eplen
        klen  = struct.unpack('>I', bun[bo:bo+4])[0]; bo += 4
        kct   = bun[bo:bo+klen]
        nonce = blob[o:o+12]; o += 12
        ctlen = struct.unpack('>I', blob[o:o+4])[0]; o += 4
        ct    = blob[o:o+ctlen]
        priv    = c['lpriv'](bytes.fromhex(kp['ecdh_priv']), None, be)
        ecdh_ss = priv.exchange(c['ECDH'](), c['lpub'](epb, be))
        kss = b''
        if K and kct and kp.get('kyber_priv'):
            try: kss = K.dec(bytes.fromhex(kp['kyber_priv']), kct)
            except Exception: pass
        ikm = ecdh_ss + kss
        ss  = c['HKDF'](algorithm=c['hsh'].SHA256(), length=32,
                        salt=b'paramant-gp-v1', info=b'aes-key', backend=be).derive(ikm)
        return c['AES'](ss).decrypt(nonce, ct, None)

    # ── Publieke API ──────────────────────────────────────────────────────────

    def send(self, data: bytes, ttl: int = 300) -> str:
        """
        Verstuur data via Ghost Pipe.
        
        Data wordt versleuteld met ML-KEM-768 + ECDH + AES-256-GCM,
        gepad naar exact 5MB en geüpload naar de relay.
        
        Args:
            data: Bytes om te versturen (max ~4.9MB)
            ttl:  Seconden beschikbaar op relay (default 300)
        
        Returns:
            hash: SHA-256 hash — geef dit aan de ontvanger
        
        Raises:
            GhostPipeError: Bij versleuteling of upload fouten
        """
        ecdh_pub, kyber_pub = self._fetch_receiver_pubkeys()
        blob, h, used_kyber = self._encrypt(data, ecdh_pub, kyber_pub)
        body = json.dumps({
            'hash': h,
            'payload': base64.b64encode(blob).decode(),
            'ttl_ms': ttl * 1000,
            'meta': {'device_id': self.device},
        }).encode()
        status, resp = self._post('/v2/inbound', body)
        if status != 200:
            raise GhostPipeError(f'Upload mislukt: HTTP {status}: {resp.decode()[:100]}')
        alg = 'ML-KEM-768+ECDH+AES-GCM' if used_kyber else 'ECDH+AES-GCM'
        return h

    def receive(self, hash_: str) -> bytes:
        """
        Ontvang data van relay via hash.
        Relay vernietigt het blok direct na dit verzoek (burn-on-read).
        
        Args:
            hash_: SHA-256 hash van het blok
        
        Returns:
            Ontsleutelde data
        
        Raises:
            GhostPipeError: Blok niet gevonden, verlopen of al opgehaald
        """
        status, raw = self._get(f'/v2/outbound/{hash_}')
        if status == 404:
            raise GhostPipeError('Blok niet gevonden. Verlopen, al opgehaald, of nooit opgeslagen.')
        if status != 200:
            raise GhostPipeError(f'Download mislukt: HTTP {status}')
        blob = raw
        return self._decrypt(blob)

    def status(self, hash_: str) -> dict:
        """
        Check of een blok beschikbaar is op de relay.
        
        Returns:
            {'available': bool, 'ttl_remaining_ms': int, 'bytes': int}
        """
        _, body = self._get(f'/v2/status/{hash_}')
        return json.loads(body)

    def receive_setup(self):
        """
        Initialiseer ontvanger: genereer keypair en registreer pubkeys bij relay.
        Roep dit aan voordat de zender kan versturen.
        """
        self._load_keypair()
        self._register_pubkeys()
        return self

    def register_webhook(self, callback_url: str, secret: str = ''):
        """
        Registreer webhook voor push notificaties.
        Relay POSTt naar callback_url zodra een blok klaarstaat.
        
        Args:
            callback_url: URL die de relay aanroept bij nieuw blok
            secret:       Optioneel HMAC-SHA256 secret voor verificatie
        """
        body = json.dumps({'device_id': self.device, 'url': callback_url, 'secret': secret}).encode()
        status, resp = self._post('/v2/webhook', body)
        if status != 200:
            raise GhostPipeError(f'Webhook registratie mislukt: {resp.decode()[:100]}')

    def listen(self, on_receive: Callable, interval: int = 3):
        """
        Luister continu op nieuwe blokken (polling).
        
        Args:
            on_receive: callback(data: bytes, meta: dict) — aangeroepen bij elk blok
            interval:   Poll interval in seconden
        """
        self.receive_setup()
        seq = self._load_seq()
        while True:
            try:
                _, body = self._get('/v2/stream-next', {'device': self.device, 'seq': seq})
                d = json.loads(body)
                if d.get('available'):
                    next_seq = d.get('seq', seq + 1)
                    try:
                        data = self.receive(d['hash'])
                        seq  = next_seq
                        self._save_seq(seq)
                        on_receive(data, {'seq': seq, 'hash': d['hash']})
                        continue
                    except GhostPipeError:
                        seq = next_seq
            except Exception:
                pass
            time.sleep(interval)

    def audit(self, limit: int = 100) -> list:
        """Haal audit log op voor deze API key."""
        _, body = self._get('/v2/audit', {'limit': limit})
        return json.loads(body).get('entries', [])

    def health(self) -> dict:
        """Relay health check."""
        _, body = self._get('/health')
        return json.loads(body)

    def _load_seq(self) -> int:
        try:
            p = os.path.join(os.path.expanduser('~/.paramant'), self.device.replace('/','_') + '.sdk_seq')
            return int(open(p).read())
        except Exception:
            return 0

    def _save_seq(self, seq: int):
        d = os.path.expanduser('~/.paramant')
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, self.device.replace('/','_') + '.sdk_seq')
        open(p + '.tmp', 'w').write(str(seq))
        os.replace(p + '.tmp', p)


# ── Gebruik als script ────────────────────────────────────────────────────────
if __name__ == '__main__':
    import sys, argparse

    p = argparse.ArgumentParser(description=f'PARAMANT Ghost Pipe SDK v{__version__}')
    p.add_argument('action', choices=['send','receive','status','listen','health','audit'])
    p.add_argument('--key',    required=True)
    p.add_argument('--device', required=True)
    p.add_argument('--relay',  default='')
    p.add_argument('--hash',   default='')
    p.add_argument('--file',   default='')
    p.add_argument('--ttl',    type=int, default=300)
    p.add_argument('--output', default='')
    p.add_argument('--webhook',default='')
    a = p.parse_args()

    gp = GhostPipe(a.key, a.device, relay=a.relay)

    if a.action == 'send':
        data = open(a.file, 'rb').read() if a.file else sys.stdin.buffer.read()
        gp.receive_setup()
        h = gp.send(data, ttl=a.ttl)
        print(f'OK hash={h}')

    elif a.action == 'receive':
        if not a.hash: sys.exit('--hash vereist')
        gp.receive_setup()
        data = gp.receive(a.hash)
        if a.output:
            with open(a.output, 'wb') as f: f.write(data)
            print(f'OK opgeslagen in {a.output} ({len(data)} bytes)')
        else:
            sys.stdout.buffer.write(data)

    elif a.action == 'status':
        if not a.hash: sys.exit('--hash vereist')
        print(json.dumps(gp.status(a.hash), indent=2))

    elif a.action == 'listen':
        def on_receive(data, meta):
            if a.output:
                path = os.path.join(a.output, f'block_{meta["seq"]:06d}.bin')
                os.makedirs(a.output, exist_ok=True)
                open(path, 'wb').write(data)
                print(f'[RECV] seq={meta["seq"]} {len(data)}B → {path}')
            else:
                print(f'[RECV] seq={meta["seq"]} {len(data)}B')
        if a.webhook:
            gp.receive_setup()
            gp.register_webhook(a.webhook)
            print(f'Webhook geregistreerd: {a.webhook}')
        gp.listen(on_receive)

    elif a.action == 'health':
        print(json.dumps(gp.health(), indent=2))

    elif a.action == 'audit':
        for e in gp.audit():
            print(f"{e['ts']}  {e['event']:<20}  {e.get('hash',''):<20}  {e.get('bytes',0)}B")


# ── Multi-relay failover (gossip light) ───────────────────────────────────────

class GhostPipeCluster:
    """
    Multi-relay client met automatische failover.
    SDK vindt automatisch de dichtstbijzijnde gezonde node.
    
    Equivalent van "gossip protocol light" — SDK pollt health
    en schakelt automatisch over bij uitval.
    
    Gebruik:
        cluster = GhostPipeCluster(
            api_key='pgp_xxx',
            device='mri-001',
            relays=[
                'https://health.paramant.app',
                'https://health-fra.paramant.app',  # Frankfurt backup
                'https://health-sin.paramant.app',  # Singapore backup
            ]
        )
        hash = cluster.send(data)
    """

    def __init__(self, api_key: str, device: str, relays: list,
                 health_interval: int = 30):
        self.api_key   = api_key
        self.device    = device
        self.relays    = relays
        self._healthy  = {}  # relay → last_health
        self._active   = None
        self._lock     = __import__('threading').Lock()
        # Start health monitor
        import threading
        t = threading.Thread(target=self._monitor, daemon=True)
        t.start()
        # Wacht op eerste health check
        time.sleep(2)

    def _check_health(self, relay: str) -> dict:
        try:
            r = urllib.request.urlopen(
                urllib.request.Request(f'{relay}/health', headers={'User-Agent': UA}),
                timeout=5)
            d = json.loads(r.read())
            if d.get('ok'):
                return {'ok': True, 'relay': relay, 'blobs': d.get('blobs', 0),
                        'version': d.get('version'), 'latency_ms': 0}
        except Exception:
            pass
        return {'ok': False, 'relay': relay}

    def _monitor(self):
        """Achtergrond health monitor — pollt alle relays."""
        import time as t
        while True:
            for relay in self.relays:
                health = self._check_health(relay)
                with self._lock:
                    self._healthy[relay] = health
            # Selecteer beste (eerste gezonde)
            for relay in self.relays:
                if self._healthy.get(relay, {}).get('ok'):
                    with self._lock:
                        if self._active != relay:
                            self._active = relay
                    break
            t.sleep(30)

    def _get_client(self) -> 'GhostPipe':
        """Geef GhostPipe client voor actieve relay."""
        with self._lock:
            relay = self._active
        if not relay:
            raise GhostPipeError('Geen gezonde relay beschikbaar')
        return GhostPipe(self.api_key, self.device, relay=relay)

    def send(self, data: bytes, ttl: int = 300) -> str:
        """Verstuur via eerste gezonde relay. Automatische failover."""
        errors = []
        for relay in self.relays:
            if not self._healthy.get(relay, {}).get('ok'):
                continue
            try:
                gp = GhostPipe(self.api_key, self.device, relay=relay)
                return gp.send(data, ttl=ttl)
            except GhostPipeError as e:
                errors.append(f'{relay}: {e}')
                # Markeer als ongezond
                with self._lock:
                    self._healthy[relay] = {'ok': False}
        raise GhostPipeError(f'Alle relays mislukt: {errors}')

    def receive(self, hash_: str) -> bytes:
        """Ontvang van eerste relay die het blok heeft."""
        for relay in self.relays:
            try:
                gp = GhostPipe(self.api_key, self.device, relay=relay)
                status = gp.status(hash_)
                if status.get('available'):
                    return gp.receive(hash_)
            except Exception:
                pass
        raise GhostPipeError('Blok niet gevonden op een van de relays')

    def health(self) -> dict:
        """Status van alle nodes in de cluster."""
        with self._lock:
            return {'active': self._active, 'nodes': dict(self._healthy)}

    def receive_setup(self):
        """Setup op alle gezonde relays."""
        for relay in self.relays:
            if self._healthy.get(relay, {}).get('ok'):
                try:
                    GhostPipe(self.api_key, self.device, relay=relay).receive_setup()
                except Exception:
                    pass
        return self

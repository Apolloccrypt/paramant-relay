// sweep-api finding 2: paramant-sender.py and paramant-receiver.py derived the
// AES key from the API key, so the relay (which checks that key on every call)
// could read every transfer. The key is a random transfer secret now.
// Needs python3 with the `cryptography` package; without it the suite says so
// and skips, because CI's Node image does not carry it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
let havePy = false;
try { execFileSync('python3', ['-c', 'import cryptography'], { stdio: 'ignore' }); havePy = true; } catch { /* skip below */ }

const PY = `
import importlib.util, sys, os, base64, secrets
def load(name, file):
    spec = importlib.util.spec_from_file_location(name, file); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
s = load('snd', os.path.join(sys.argv[1], 'scripts/paramant-sender.py'))
r = load('rcv', os.path.join(sys.argv[1], 'scripts/paramant-receiver.py'))
api_key = 'pgp_' + 'a'*64
sec = secrets.token_bytes(32)
blob, _ = s.encrypt(b'hello transfer', sec, blob_size=4096)
assert r.unpad(r.decrypt(blob, sec)) == b'hello transfer'
# The API key cannot open it any more.
try:
    r.decrypt(blob, api_key.encode()[:32]); print('API_KEY_OPENS'); sys.exit(1)
except RuntimeError:
    pass
# And a blob made the old way (key derived from the API key) is not what the sender makes.
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
salt = blob[:32]
old = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b'paramant-v6').derive(api_key.encode())
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
try:
    AESGCM(old).decrypt(blob[32:44], blob[44:], None); print('OLD_DERIVATION_OPENS'); sys.exit(1)
except Exception:
    pass
print('OK')
`;

test('a transfer is sealed with a random secret, and the API key cannot open it', { skip: havePy ? false : 'python3 with cryptography not installed' }, () => {
  const out = execFileSync('python3', ['-c', PY, ROOT], { encoding: 'utf8' });
  assert.match(out, /OK/);
});

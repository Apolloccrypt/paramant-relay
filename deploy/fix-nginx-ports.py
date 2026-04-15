#!/usr/bin/env python3
"""
scripts/fix-nginx-ports.py — fix nginx subdomain → relay port mapping.

Run as root on the server:
    sudo python3 /home/paramant/paramant-master/scripts/fix-nginx-ports.py

Correct mapping (v2.4.0 Docker architecture):
    relay.paramant.app   → 3000  (relay-main)
    health.paramant.app  → 3001  (relay-health)
    finance.paramant.app → 3002  (relay-finance)
    legal.paramant.app   → 3003  (relay-legal)
    iot.paramant.app     → 3004  (relay-iot)
"""

import re, subprocess, sys, os

CONF_PATH = '/etc/nginx/sites-enabled/paramant'

# Desired: server_name → port
DESIRED = {
    'relay.paramant.app':   3000,
    'health.paramant.app':  3001,
    'finance.paramant.app': 3002,
    'legal.paramant.app':   3003,
    'iot.paramant.app':     3004,
}

def parse_server_blocks(conf):
    """Split nginx config into server blocks, preserving all content."""
    # Match top-level server { ... } blocks (handles one level of nesting)
    pattern = re.compile(r'(server\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})', re.DOTALL)
    return pattern.findall(conf)

def get_server_name(block):
    m = re.search(r'server_name\s+([\w\.\-]+)', block)
    return m.group(1) if m else None

def fix_block(block, target_port):
    """Replace ALL proxy_pass 127.0.0.1:XXXX with target_port in this block."""
    def replacer(m):
        old_port = m.group(1)
        if old_port == str(target_port):
            return m.group(0)  # already correct
        print(f'  proxy_pass :{old_port} → :{target_port}')
        return m.group(0).replace(f'127.0.0.1:{old_port}', f'127.0.0.1:{target_port}')
    return re.sub(r'proxy_pass\s+http://127\.0\.0\.1:(\d+)', replacer, block)

def main():
    if not os.path.exists(CONF_PATH):
        print(f'ERROR: {CONF_PATH} not found')
        sys.exit(1)

    conf = open(CONF_PATH).read()
    blocks = parse_server_blocks(conf)

    print(f'Found {len(blocks)} server blocks in {CONF_PATH}')
    print()

    changed = False
    new_conf = conf

    for sn, desired_port in DESIRED.items():
        for block in blocks:
            if get_server_name(block) == sn:
                fixed = fix_block(block, desired_port)
                if fixed != block:
                    print(f'{sn}: fixed → port {desired_port}')
                    new_conf = new_conf.replace(block, fixed)
                    changed = True
                else:
                    print(f'{sn}: already correct (port {desired_port})')
                break
        else:
            print(f'{sn}: server block NOT FOUND in config')

    if not changed:
        print('\nNo changes needed.')
        return

    print(f'\nWriting updated config to {CONF_PATH}...')
    # Backup first
    backup = CONF_PATH + '.bak'
    with open(backup, 'w') as f:
        f.write(conf)
    print(f'Backup saved to {backup}')

    with open(CONF_PATH, 'w') as f:
        f.write(new_conf)

    print('\nRunning nginx -t...')
    r = subprocess.run(['nginx', '-t'], capture_output=True, text=True)
    print(r.stdout.strip())
    print(r.stderr.strip())

    if r.returncode != 0:
        print('\nERROR: nginx config test failed. Restoring backup...')
        with open(CONF_PATH, 'w') as f:
            f.write(conf)
        sys.exit(1)

    print('\nReloading nginx...')
    subprocess.run(['nginx', '-s', 'reload'], check=True)
    print('Done. nginx reloaded.')

if __name__ == '__main__':
    main()

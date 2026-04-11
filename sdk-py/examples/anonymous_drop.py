"""
Anonymous drop (BIP39) example.

No API key required. The sender gets a 12-word mnemonic.
The receiver uses the mnemonic to retrieve the file — no account needed.

Use case: whistleblower, journalist source, anonymous tip line.
"""

import sys
from paramant_sdk import GhostPipe


def drop_file(path: str):
    gp = GhostPipe(api_key='', device='')

    with open(path, 'rb') as f:
        data = f.read()

    mnemonic, h = gp.drop(data, ttl=86400)   # burn after 24 hours
    print('=== ANONYMOUS DROP ===')
    print(f'Hash:     {h}')
    print(f'Mnemonic: {mnemonic}')
    print()
    print('Give the mnemonic to your contact via a secure channel.')
    print('They can retrieve the file with:')
    print('  python anonymous_drop.py pickup "<mnemonic>"')


def pickup_file(mnemonic: str):
    gp = GhostPipe(api_key='', device='')
    data = gp.pickup(mnemonic)
    out = 'drop_retrieved.bin'
    with open(out, 'wb') as f:
        f.write(data)
    print(f'Retrieved {len(data)} bytes → saved to {out}')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage:')
        print('  python anonymous_drop.py drop <file>')
        print('  python anonymous_drop.py pickup "<12-word mnemonic>"')
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == 'drop':
        if len(sys.argv) < 3:
            print('Usage: python anonymous_drop.py drop <file>')
            sys.exit(1)
        drop_file(sys.argv[2])
    elif cmd == 'pickup':
        if len(sys.argv) < 3:
            print('Usage: python anonymous_drop.py pickup "<mnemonic>"')
            sys.exit(1)
        pickup_file(' '.join(sys.argv[2:]))
    else:
        print(f'Unknown command: {cmd}')
        sys.exit(1)

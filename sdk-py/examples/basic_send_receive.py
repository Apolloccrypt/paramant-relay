"""
Basic send / receive example.

Run on two machines (or two terminals):
  Terminal 1 (receiver): python basic_send_receive.py receive
  Terminal 2 (sender):   python basic_send_receive.py send <hash-from-receiver-output>
"""

import sys
from paramant_sdk import GhostPipe

API_KEY = 'pgp_xxx'        # replace with your API key
SENDER  = 'laptop-001'
RECEIVER = 'server-001'


def do_receive_setup():
    gp = GhostPipe(api_key=API_KEY, device=RECEIVER)
    result = gp.receive_setup()
    print(f'Receiver registered. Fingerprint: {result["fingerprint"]}')
    print('Waiting for transfer — send a hash to receive it:')
    print('  python basic_send_receive.py receive <hash>')


def do_send():
    gp = GhostPipe(api_key=API_KEY, device=SENDER)
    payload = b'Hello from Ghost Pipe!'
    h = gp.send(payload, recipient=RECEIVER)
    print(f'Transfer hash: {h}')
    print(f'On the receiver, run:')
    print(f'  python basic_send_receive.py receive {h}')


def do_receive(hash_):
    gp = GhostPipe(api_key=API_KEY, device=RECEIVER)
    data = gp.receive(hash_)
    print(f'Received {len(data)} bytes: {data.decode()}')


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'setup'
    if cmd == 'setup':
        do_receive_setup()
    elif cmd == 'send':
        do_send()
    elif cmd == 'receive':
        if len(sys.argv) < 3:
            print('Usage: python basic_send_receive.py receive <hash>')
            sys.exit(1)
        do_receive(sys.argv[2])
    else:
        print('Commands: setup | send | receive <hash>')

"""
Self-hosted relay example.

Shows how to point the SDK at your own relay instance instead of relay.paramant.app.
"""

from paramant_sdk import GhostPipe

MY_RELAY = 'https://relay.example.com'   # your relay URL
API_KEY  = 'pgp_xxx'


def send_via_self_hosted():
    gp = GhostPipe(
        api_key=API_KEY,
        device='sender-001',
        relay=MY_RELAY,
    )

    # Health check
    info = gp.health()
    print(f'Relay version: {info["version"]}  uptime: {info["uptime"]}s')

    # Send
    h = gp.send(b'Confidential payload', recipient='receiver-001')
    print(f'Transfer hash: {h}')
    return h


def receive_via_self_hosted(h: str):
    gp = GhostPipe(
        api_key=API_KEY,
        device='receiver-001',
        relay=MY_RELAY,
    )
    gp.receive_setup()
    data = gp.receive(h)
    print(f'Got: {data.decode()}')


if __name__ == '__main__':
    h = send_via_self_hosted()
    receive_via_self_hosted(h)

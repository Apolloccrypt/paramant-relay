"""
WebSocket streaming example.

Two patterns:
  1. stream()  — async generator, yields all events for this device
  2. listen()  — wait for a specific transfer hash to arrive

Run the listener in one terminal, then send a file from another.
"""

import asyncio
from paramant_sdk import GhostPipe

API_KEY  = 'pgp_xxx'
DEVICE   = 'ws-listener-001'
SENDER   = 'ws-sender-001'


async def stream_all_events():
    """Pattern 1: receive all events for this device."""
    gp = GhostPipe(api_key=API_KEY, device=DEVICE)
    print(f'Streaming events for device: {DEVICE}')
    print('Press Ctrl+C to stop.')
    print()

    async for event in gp.stream():
        event_type = event.get('type', 'unknown')
        print(f'[{event_type}] {event}')
        await gp.ack(event['id'])


async def wait_for_transfer(h: str):
    """Pattern 2: wait for a specific transfer."""
    gp = GhostPipe(api_key=API_KEY, device=DEVICE)
    print(f'Waiting for transfer: {h}')

    async def on_ready(event):
        data = await gp.receive(h)
        print(f'Received {len(data)} bytes: {data[:80]}')

    await gp.listen(h, callback=on_ready)


async def send_file():
    """Send a file to trigger an event on the listener."""
    gp = GhostPipe(api_key=API_KEY, device=SENDER)
    h = gp.send(b'WebSocket test payload', recipient=DEVICE)
    print(f'Sent — hash: {h}')
    return h


if __name__ == '__main__':
    import sys

    cmd = sys.argv[1] if len(sys.argv) > 1 else 'stream'

    if cmd == 'stream':
        asyncio.run(stream_all_events())
    elif cmd == 'send':
        asyncio.run(send_file())
    elif cmd == 'listen':
        if len(sys.argv) < 3:
            print('Usage: python websocket_streaming.py listen <hash>')
            sys.exit(1)
        asyncio.run(wait_for_transfer(sys.argv[2]))
    else:
        print('Commands: stream | send | listen <hash>')

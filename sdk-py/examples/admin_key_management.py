"""
Admin key management example.

Shows how to use the GhostPipeAdmin API to manage API keys,
check license status, and view relay statistics.

Requires admin token (set in relay environment as ADMIN_TOKEN).
"""

from paramant_sdk import GhostPipe

API_KEY      = 'pgp_xxx'
ADMIN_TOKEN  = 'your-admin-token'


def main():
    gp = GhostPipe(api_key=API_KEY, device='admin-console')
    admin = gp.admin(ADMIN_TOKEN)

    # Relay statistics
    print('=== RELAY STATS ===')
    stats = admin.stats()
    print(f'  Active blobs:  {stats.get("blobs", 0)}')
    print(f'  Total keys:    {stats.get("keys", 0)}')
    print(f'  Memory usage:  {stats.get("memory_mb", "?")} MB')
    print()

    # List all API keys
    print('=== API KEYS ===')
    keys = admin.keys()
    for k in keys:
        print(f'  {k["key"][:12]}...  label={k.get("label", "-")}  sectors={k.get("sectors", [])}')
    print()

    # Add a new key for a partner
    print('=== ADD KEY ===')
    result = admin.key_add(
        key='pgp_partner_yyy',
        label='law-firm-b',
        sectors=['legal'],
    )
    print(f'  Added: {result}')
    print()

    # License status
    print('=== LICENSE ===')
    lic = admin.license_status()
    print(f'  Status:  {lic.get("status", "?")}')
    print(f'  Plan:    {lic.get("plan", "?")}')
    print(f'  Expires: {lic.get("expires_at", "?")}')
    print(f'  Keys:    {lic.get("keys_used", "?")}/{lic.get("keys_max", "?")}')
    print()

    # Reload relay config without restart
    print('=== RELOAD ===')
    admin.reload()
    print('  Relay config reloaded.')


if __name__ == '__main__':
    main()

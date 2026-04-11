"""
Pre-Shared Secret (PSS) example.

PSS adds a second factor to HKDF key derivation. Even if the relay is fully
compromised and serves wrong pubkeys, the attacker cannot decrypt the payload
without knowing the PSS.

Use cases:
- Healthcare (DICOM between PACS and MRI scanner)
- Legal documents between law firms
- Any scenario where relay MITM is a realistic threat
"""

from paramant_sdk import GhostPipe, FingerprintMismatchError

API_KEY = 'pgp_xxx'

# PSS agreed out-of-band (phone call, Signal, encrypted email)
# Agree once during device commissioning.
PSS = 'flu-vaccine-2026'


def healthcare_workflow():
    """DICOM transfer from MRI scanner to PACS system."""
    print('=== HEALTHCARE WORKFLOW ===')
    print()

    # --- Device commissioning (one-time, done in person) ---
    gp_pacs = GhostPipe(api_key=API_KEY, device='pacs-001')
    result = gp_pacs.receive_setup()
    fp = gp_pacs.fingerprint()
    print(f'PACS fingerprint: {fp}')
    print('IT team prints this, MRI operator confirms visually → trusted')
    print()

    # --- Daily transfer ---
    gp_mri = GhostPipe(api_key=API_KEY, device='mri-scanner-001')

    dicom_data = b'<fake DICOM bytes for demonstration>'
    try:
        h = gp_mri.send(
            dicom_data,
            recipient='pacs-001',
            pre_shared_secret=PSS,   # relay MITM impossible
        )
        print(f'Transfer hash: {h}')
        print('(Give hash to PACS via hospital MPACS ticket system)')
    except FingerprintMismatchError as e:
        print(f'SECURITY ALERT: Key mismatch for {e.device_id}')
        print(f'  Expected: {e.stored}')
        print(f'  Got:      {e.received}')
        print('Aborting transfer — possible MITM attack.')
        return

    # --- PACS receives ---
    data = gp_pacs.receive(h, pre_shared_secret=PSS)
    print(f'PACS received {len(data)} bytes')
    print()
    print('Security guarantees:')
    print('  1. Relay never sees DICOM plaintext')
    print('  2. PSS ensures relay MITM impossible even on first transfer')
    print('  3. TOFU detects any future key changes')


def legal_workflow():
    """Contract between two law firms."""
    print('=== LEGAL WORKFLOW ===')
    print()

    gp_a = GhostPipe(api_key=API_KEY, device='lawfirm-a-001')

    # Verify receiver fingerprint out-of-band before first transfer
    fp = gp_a.fingerprint('lawfirm-b-001')
    print(f'Law Firm B fingerprint: {fp}')
    print('Call Law Firm B and ask them to read their fingerprint aloud.')
    print('If it matches, trust and send:')
    print()

    gp_a.trust('lawfirm-b-001')

    contract = b'<confidential contract PDF bytes>'
    h = gp_a.send(
        contract,
        recipient='lawfirm-b-001',
        pre_shared_secret=PSS,
    )
    print(f'Transfer hash: {h}')

    gp_b = GhostPipe(api_key=API_KEY, device='lawfirm-b-001')
    data = gp_b.receive(h, pre_shared_secret=PSS)
    print(f'Law Firm B received {len(data)} bytes')


if __name__ == '__main__':
    import sys
    workflow = sys.argv[1] if len(sys.argv) > 1 else 'healthcare'
    if workflow == 'healthcare':
        healthcare_workflow()
    elif workflow == 'legal':
        legal_workflow()
    else:
        print('Workflows: healthcare | legal')

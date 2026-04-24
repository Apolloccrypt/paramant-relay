// Paramant /v2/capabilities negotiation.

export class CapabilitiesError extends Error {
  constructor(msg) { super(msg); this.name = 'CapabilitiesError'; }
}
export class UnsupportedAlgorithmError extends Error {
  constructor(kind, id, supported) {
    super(`${kind}=0x${id.toString(16).padStart(4, '0')} not supported by relay; supported: ${supported.join(', ')}`);
    this.name = 'UnsupportedAlgorithmError';
    this.kind = kind; this.id = id; this.supported = supported;
  }
}
export class UnsupportedWireVersionError extends Error {
  constructor(got, want) {
    super(`relay wire_version=${got}, client supports ${want}`);
    this.name = 'UnsupportedWireVersionError';
  }
}

export async function fetchCapabilities(relayUrl, { fetch: fetchImpl = globalThis.fetch, timeout = 10000 } = {}) {
  if (!fetchImpl) throw new CapabilitiesError('fetch not available in this environment');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetchImpl(relayUrl.replace(/\/+$/, '') + '/v2/capabilities', {
      method: 'GET',
      signal: controller.signal,
    });
    if (!res.ok) throw new CapabilitiesError(`capabilities fetch failed: HTTP ${res.status}`);
    const json = await res.json();
    if (typeof json.wire_version !== 'number') throw new CapabilitiesError('missing wire_version');
    if (!Array.isArray(json.kem)) throw new CapabilitiesError('missing kem list');
    if (!Array.isArray(json.sig)) throw new CapabilitiesError('missing sig list');
    return json;
  } finally {
    clearTimeout(timer);
  }
}

export function assertSupported(capabilities, { wireVersion = 1, kemId, sigId }) {
  if (capabilities.wire_version !== wireVersion) {
    throw new UnsupportedWireVersionError(capabilities.wire_version, wireVersion);
  }
  if (kemId !== undefined) {
    const loaded = capabilities.kem.filter(k => k.loaded).map(k => k.id);
    if (!loaded.includes(kemId)) {
      throw new UnsupportedAlgorithmError('kemId', kemId, loaded.map(i => `0x${i.toString(16).padStart(4, '0')}`));
    }
  }
  if (sigId !== undefined) {
    const loaded = capabilities.sig.filter(s => s.loaded).map(s => s.id);
    if (!loaded.includes(sigId)) {
      throw new UnsupportedAlgorithmError('sigId', sigId, loaded.map(i => `0x${i.toString(16).padStart(4, '0')}`));
    }
  }
}

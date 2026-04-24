const { UnsupportedAlgorithm } = require("./errors");

const KEM_REGISTRY = new Map();
const SIG_REGISTRY = new Map();

function registerKEM(id, impl) {
  if (typeof id !== "number" || id < 0 || id > 0xFFFF) {
    throw new Error(`KEM id must be uint16, got ${id}`);
  }
  const required = ["name", "pubKeySize", "ctSize", "encapsulate", "decapsulate"];
  for (const field of required) {
    if (!(field in impl)) throw new Error(`KEM impl missing required field: ${field}`);
  }
  KEM_REGISTRY.set(id, impl);
}

function registerSig(id, impl) {
  if (typeof id !== "number" || id < 0 || id > 0xFFFF) {
    throw new Error(`Sig id must be uint16, got ${id}`);
  }
  if (id === 0x0000) {
    throw new Error("Cannot register id 0x0000 — it is reserved for no-signature blobs");
  }
  const required = ["name", "pubKeySize", "sigSize", "sign", "verify"];
  for (const field of required) {
    if (!(field in impl)) throw new Error(`Sig impl missing required field: ${field}`);
  }
  SIG_REGISTRY.set(id, impl);
}

function getKEM(id) {
  const impl = KEM_REGISTRY.get(id);
  if (!impl) throw new UnsupportedAlgorithm("KEM", id);
  return impl;
}

function getSig(id) {
  if (id === 0x0000) return null;
  const impl = SIG_REGISTRY.get(id);
  if (!impl) throw new UnsupportedAlgorithm("SIG", id);
  return impl;
}

function hasKEM(id) { return KEM_REGISTRY.has(id); }
function hasSig(id) { return id === 0x0000 || SIG_REGISTRY.has(id); }

function listSupported() {
  const kem = [...KEM_REGISTRY.entries()].map(([id, impl]) => ({
    id, name: impl.name, loaded: true
  }));
  const sig = [
    { id: 0x0000, name: "none", loaded: true },
    ...[...SIG_REGISTRY.entries()].map(([id, impl]) => ({
      id, name: impl.name, loaded: true
    }))
  ];
  return { wire_version: 1, kem, sig };
}

function clearRegistry() {
  KEM_REGISTRY.clear();
  SIG_REGISTRY.clear();
}

module.exports = {
  registerKEM,
  registerSig,
  getKEM,
  getSig,
  hasKEM,
  hasSig,
  listSupported,
  clearRegistry
};

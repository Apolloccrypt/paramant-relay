/* tslint:disable */
/* eslint-disable */

/**
 * Decrypt a blob produced by encrypt_blob.
 *
 * kem_priv  : 2400-byte ML-KEM-768 secret key as returned by noble-post-quantum
 *             ml_kem768.keygen() — NIST FIPS 203: dkPKE ∥ ek ∥ H(ek) ∥ z
 * ecdh_priv : 32-byte P-256 scalar (big-endian, raw private key bytes)
 */
export function decrypt_blob(ciphertext: Uint8Array, kem_priv: Uint8Array, ecdh_priv: Uint8Array): Uint8Array;

/**
 * Encrypt plaintext for a receiver identified by kem_pub (1184 B) and ecdh_pub (65 B).
 * Returns a 5 MB padded blob in wire format:
 *   0x03 | u32be(ctKemLen) | ctKem | u32be(senderPubLen) | senderPub | nonce(12) | u32be(ctLen) | ct
 * All bytes from offset 0 through and including u32be(ctLen) are passed to AES-256-GCM
 * as Associated Data so any tampering with wire metadata fails verification explicitly,
 * rather than relying on cascade failure via HKDF salt = ctKem[..32].
 */
export function encrypt_blob(plaintext: Uint8Array, kem_pub: Uint8Array, ecdh_pub: Uint8Array): Uint8Array;

/**
 * Derive the ML-DSA-65 public key (1952 bytes) from a 32-byte seed (xi).
 * Deterministic: the same seed always yields the same public key; the seed is
 * the private key (mnemonic-derived, ADR-3).
 */
export function ml_dsa_pubkey_from_seed(xi: Uint8Array): Uint8Array;

/**
 * Deterministically sign `message` with the ML-DSA-65 key derived from the
 * 32-byte seed (xi). Empty context. Returns a 3309-byte signature.
 */
export function ml_dsa_sign(xi: Uint8Array, message: Uint8Array): Uint8Array;

/**
 * Verify an ML-DSA-65 signature (empty context). public_key 1952 B, signature
 * 3309 B. Returns false on any decode or verification failure.
 */
export function ml_dsa_verify(public_key: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly decrypt_blob: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly encrypt_blob: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly ml_dsa_pubkey_from_seed: (a: number, b: number) => [number, number, number, number];
    readonly ml_dsa_sign: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly ml_dsa_verify: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;

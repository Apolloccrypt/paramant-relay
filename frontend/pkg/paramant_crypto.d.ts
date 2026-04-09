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
 *   0x02 | u32be(ctKemLen) | ctKem | u32be(senderPubLen) | senderPub | nonce(12) | u32be(ctLen) | ct
 * Matches the JS hybrid-KEM construction in parashare.html exactly.
 */
export function encrypt_blob(plaintext: Uint8Array, kem_pub: Uint8Array, ecdh_pub: Uint8Array): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly decrypt_blob: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly encrypt_blob: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
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

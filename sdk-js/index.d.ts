// Type definitions for paramant-sdk
// Version: 3.0.0
// Wire format: v1 (PQHB). KEM: ML-KEM-768. Sig: ML-DSA-65 or anonymous.

export const VERSION: string;
export const WIRE_VERSION: number;
export const KEM: { readonly ML_KEM_768: 0x0002 };
export const SIG: { readonly NONE: 0x0000; readonly ML_DSA_65: 0x0002 };
export const SECTOR_RELAYS: Record<string, string>;

export interface GhostPipeOptions {
  /** API key (pgp_...). Optional for anonymous-only clients. */
  apiKey?: string;
  /** Stable device identifier */
  device: string;
  /** Relay URL (default: auto-detect via sector relays) */
  relay?: string;
  /** Pre-shared secret mixed into HKDF for relay-MITM protection (Layer 3) */
  preSharedSecret?: string;
  /** Enable TOFU fingerprint verification. Default: true */
  verifyFingerprints?: boolean;
  /** HTTP timeout in milliseconds. Default: 30000 */
  timeout?: number;
  /** KEM algorithm ID. Default: 0x0002 (ML-KEM-768) */
  kemId?: number;
  /** Signature algorithm ID. Default: 0x0002 (ML-DSA-65). Pass 0x0000 for anonymous. */
  sigId?: number;
  /** Query /v2/capabilities before first send. Default: true */
  checkCapabilities?: boolean;
}

export interface SendOptions {
  ttl?: number;
  maxViews?: number;
  padBlock?: number;
  recipient?: string;
  preSharedSecret?: string;
}

export interface ReceiveOptions {
  preSharedSecret?: string;
}

export interface SendAnonymousOptions {
  ttl?: number;
  maxViews?: number;
  padBlock?: number;
}

export interface TransferStatus {
  ok: boolean;
  burned: boolean;
  views: number;
  ttl: number;
  size: number;
  created_at: string;
}

export interface FingerprintInfo {
  deviceId: string;
  fingerprint: string;
  registeredAt: string;
}

export interface CapabilitiesResponse {
  wire_version: number;
  kem: Array<{ id: number; name: string; loaded: boolean }>;
  sig: Array<{ id: number; name: string; loaded: boolean }>;
}

// ── Error classes ─────────────────────────────────────────────────────────────

export class GhostPipeError extends Error {}
export class RelayError extends GhostPipeError {
  status: number;
  body: unknown;
}
export class AuthError extends GhostPipeError {}
export class BurnedError extends GhostPipeError {}
export class FingerprintMismatchError extends GhostPipeError {
  deviceId: string;
  stored: string;
  received: string;
}
export class LicenseError extends GhostPipeError {}
export class RateLimitError extends GhostPipeError {}
export class SignatureError extends GhostPipeError {}

// ── Wire format helpers (re-exported from ./src/wire-format.js) ───────────────

export interface WireEncodeInput {
  kemId: number;
  sigId: number;
  flags?: number;
  ctKem: Uint8Array;
  senderPub: Uint8Array;
  signature?: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}
export interface WireDecodeResult {
  version: number;
  kemId: number;
  sigId: number;
  flags: number;
  ctKem: Uint8Array;
  senderPub: Uint8Array;
  signature: Uint8Array | null;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  aad: Uint8Array;
  consumedBytes: number;
}
export function wireEncode(input: WireEncodeInput): Uint8Array;
export function wireDecode(blob: Uint8Array): WireDecodeResult;
export function buildAAD(input: { kemId: number; sigId: number; flags?: number; chunkIndex?: number }): Uint8Array;
export function isV1(blob: Uint8Array): boolean;

// ── Capabilities ──────────────────────────────────────────────────────────────

export function fetchCapabilities(relayUrl: string, opts?: { fetch?: typeof fetch; timeout?: number }): Promise<CapabilitiesResponse>;

// ── GhostPipeAdmin ────────────────────────────────────────────────────────────

export class GhostPipeAdmin {
  stats(): Promise<Record<string, unknown>>;
  keys(): Promise<Record<string, unknown>>;
  keyAdd(opts: { label?: string; plan?: string; email?: string }): Promise<{ ok: boolean; key: string; plan: string; label: string }>;
  keyRevoke(key: string): Promise<{ ok: boolean }>;
  licenseStatus(): Promise<Record<string, unknown>>;
  reload(): Promise<{ ok: boolean; loaded: number }>;
  sendWelcome(email: string, key: string, opts?: { plan?: string; label?: string }): Promise<{ ok: boolean }>;
}

// ── GhostPipe ─────────────────────────────────────────────────────────────────

export class GhostPipe {
  readonly apiKey: string;
  readonly device: string;
  relay: string;
  readonly kemId: number;
  readonly sigId: number;
  constructor(options: GhostPipeOptions);

  capabilities(): Promise<CapabilitiesResponse>;

  // Core
  send(data: Uint8Array, options?: SendOptions): Promise<string>;
  receive(hash: string, options?: ReceiveOptions): Promise<Uint8Array>;
  status(hash: string): Promise<TransferStatus>;
  cancel(hash: string): Promise<{ ok: boolean }>;

  // Anonymous (v1 sigId=0x0000) inbound
  sendAnonymous(data: Uint8Array, recipientKemPubHex: string, options?: SendAnonymousOptions): Promise<{ hash: string; blob: Uint8Array; response: unknown }>;

  // BIP39 drop
  drop(data: Uint8Array, options?: { ttl?: number }): Promise<string>;
  pickup(mnemonic: string): Promise<Uint8Array>;

  // Pubkey / TOFU
  registerPubkeys(): Promise<{ ok: boolean; fingerprint: string; ct_index: number }>;
  fingerprint(deviceId?: string): Promise<string>;
  verifyFingerprint(deviceId: string, fingerprint: string): Promise<boolean>;
  trust(deviceId: string, fingerprint?: string): Promise<string>;
  untrust(deviceId: string): void;
  knownDevices(): FingerprintInfo[];

  // Sessions
  sessionCreate(pss: string, ttlMs?: number): Promise<{ ok: boolean; session_id: string; expires_ms: number }>;
  sessionJoin(sessionId: string, pss: string): Promise<{ ok: boolean }>;
  sessionPubkey(sessionId: string): Promise<{ kem_pub: string; sig_pub: string } | null>;

  // Events / streaming
  webhookRegister(callbackUrl: string, secret?: string): Promise<{ ok: boolean }>;
  getWsTicket(): Promise<string>;
  stream(onBlob: (hash: string) => void): Promise<WebSocket>;
  ack(hash: string): Promise<{ ok: boolean }>;

  // Health
  health(): Promise<Record<string, unknown>>;
  monitor(): Promise<Record<string, unknown>>;
  checkKey(): Promise<Record<string, unknown>>;
  keySector(): Promise<Record<string, unknown>>;

  // Audit / CT log
  audit(opts?: { limit?: number; format?: 'json' | 'csv' }): Promise<unknown[] | string>;
  ctLog(from?: number, limit?: number): Promise<Record<string, unknown>>;
  ctProof(index: number): Promise<Record<string, unknown>>;
  verifyReceipt(receipt: string | object): Promise<Record<string, unknown>>;

  // DID
  didRegister(dsaPub?: string): Promise<Record<string, unknown>>;
  didResolve(did: string): Promise<Record<string, unknown>>;
  didList(): Promise<unknown[]>;

  // Team
  teamDevices(): Promise<Record<string, unknown>>;
  teamAddDevice(label: string): Promise<Record<string, unknown>>;

  // Admin
  admin(token: string): GhostPipeAdmin;
}

export default GhostPipe;

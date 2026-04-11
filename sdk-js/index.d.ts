// Type definitions for paramant-sdk
// Version: 2.4.1

export interface GhostPipeOptions {
  /** API key (pgp_...) */
  apiKey: string;
  /** Stable device identifier */
  device: string;
  /** Relay URL. Default: https://relay.paramant.app */
  relay?: string;
  /** Pre-shared secret for PSS protection (Layer 3) */
  preSharedSecret?: string;
  /** Enable TOFU fingerprint verification. Default: true */
  verifyFingerprints?: boolean;
  /** HTTP timeout in milliseconds. Default: 30000 */
  timeout?: number;
}

export interface SendOptions {
  /** Time-to-live in seconds. Default: 3600 */
  ttl?: number;
  /** Burn after N downloads. Default: 1 */
  maxViews?: number;
  /** Pad to N MB blocks. Default: 5 */
  padBlock?: number;
  /** Encrypt to a specific recipient device */
  recipient?: string;
  /** Pre-shared secret (overrides constructor PSS) */
  preSharedSecret?: string;
}

export interface ReceiveOptions {
  /** Pre-shared secret (overrides constructor PSS) */
  preSharedSecret?: string;
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
  ctIndex: number;
}

export interface DropResult {
  mnemonic: string;
  hash: string;
}

export interface SessionInfo {
  sessionId: string;
  status: string;
  participants: string[];
  created_at: string;
}

export interface WebhookOptions {
  url: string;
  events: string[];
  secret?: string;
}

export interface CtEntry {
  index: number;
  leaf_hash: string;
  tree_hash: string;
  device_hash: string;
  ts: string;
  proof?: Array<{ hash: string; position: 'left' | 'right' }>;
}

export interface HealthInfo {
  ok: boolean;
  version: string;
  uptime: number;
  blobs: number;
  sectors: string[];
}

export interface DidDocument {
  did: string;
  pubkeyHex: string;
  created_at: string;
}

export interface AdminKeyOptions {
  key: string;
  label?: string;
  sectors?: string[];
}

// ── Error classes ─────────────────────────────────────────────────────────────

export class GhostPipeError extends Error {
  constructor(message: string);
}

export class RelayError extends GhostPipeError {
  statusCode: number;
  constructor(message: string, statusCode?: number);
}

export class AuthError extends GhostPipeError {
  constructor(message?: string);
}

export class BurnedError extends GhostPipeError {
  constructor(message?: string);
}

export class FingerprintMismatchError extends GhostPipeError {
  deviceId: string;
  stored: string;
  received: string;
  constructor(deviceId: string, stored: string, received: string);
}

export class LicenseError extends GhostPipeError {
  constructor(message?: string);
}

export class RateLimitError extends GhostPipeError {
  retryAfter?: number;
  constructor(message?: string, retryAfter?: number);
}

// ── GhostPipeAdmin ────────────────────────────────────────────────────────────

export class GhostPipeAdmin {
  stats(): Promise<Record<string, unknown>>;
  keys(): Promise<Record<string, unknown>[]>;
  keyAdd(options: AdminKeyOptions): Promise<{ ok: boolean }>;
  keyRevoke(key: string): Promise<{ ok: boolean }>;
  licenseStatus(): Promise<Record<string, unknown>>;
  reload(): Promise<{ ok: boolean }>;
  sendWelcome(options: { email: string; name?: string }): Promise<{ ok: boolean }>;
}

// ── GhostPipe ─────────────────────────────────────────────────────────────────

export class GhostPipe {
  constructor(options: GhostPipeOptions);

  // Core
  send(data: Uint8Array | ArrayBuffer, options?: SendOptions): Promise<string>;
  receive(hash: string, options?: ReceiveOptions): Promise<Uint8Array>;
  status(hash: string): Promise<TransferStatus>;
  cancel(hash: string): Promise<{ ok: boolean }>;

  // Drop (anonymous, no API key)
  drop(data: Uint8Array | ArrayBuffer, options?: { ttl?: number }): Promise<DropResult>;
  pickup(mnemonic: string): Promise<Uint8Array>;
  dropStatus(mnemonic: string): Promise<TransferStatus>;

  // Pubkey / TOFU
  registerPubkeys(): Promise<{ ok: boolean; fingerprint: string; ctIndex: number }>;
  /** Alias for registerPubkeys() */
  receiveSetup(): Promise<{ ok: boolean; fingerprint: string; ctIndex: number }>;
  fingerprint(deviceId?: string): Promise<string>;
  verifyFingerprint(deviceId: string, fingerprint: string): Promise<boolean>;
  trust(deviceId: string): Promise<void>;
  untrust(deviceId: string): Promise<void>;
  knownDevices(): Promise<FingerprintInfo[]>;

  // Sessions
  sessionCreate(): Promise<string>;
  sessionJoin(sessionId: string): Promise<{ ok: boolean }>;
  sessionPubkey(sessionId: string): Promise<{ ecdh_pub: string; kyber_pub: string }>;
  sessionStatus(sessionId: string): Promise<SessionInfo>;

  // Events / streaming
  webhookRegister(options: WebhookOptions): Promise<{ ok: boolean }>;
  getWsTicket(): Promise<string>;
  stream(): AsyncGenerator<Record<string, unknown>>;
  listen(hash: string, callback: (event: Record<string, unknown>) => Promise<void>): Promise<void>;
  ack(eventId: string): Promise<{ ok: boolean }>;

  // Health
  health(): Promise<HealthInfo>;
  monitor(): Promise<Record<string, unknown>>;
  checkKey(): Promise<{ ok: boolean; valid: boolean; sectors: string[] }>;
  keySector(): Promise<{ sector: string; features: string[] }>;

  // Audit / CT log
  audit(): Promise<CtEntry[]>;
  ctLog(options?: { from?: number; limit?: number }): Promise<CtEntry[]>;
  ctProof(index: number): Promise<CtEntry>;

  // DID
  didRegister(options: { did: string; pubkeyHex: string }): Promise<{ ok: boolean }>;
  didResolve(did: string): Promise<DidDocument>;
  didList(): Promise<DidDocument[]>;

  // Attestation
  attest(options: Record<string, unknown>): Promise<{ ok: boolean; id: string }>;
  attestationStatus(id: string): Promise<Record<string, unknown>>;

  // Team
  teamDevices(): Promise<{ device: string; label: string }[]>;
  teamAddDevice(options: { device: string; label?: string }): Promise<{ ok: boolean }>;

  // Admin
  admin(token: string): GhostPipeAdmin;
}

// ── GhostPipeCluster ──────────────────────────────────────────────────────────

export interface GhostPipeClusterOptions {
  apiKey: string;
  device: string;
  relays: string[];
  preSharedSecret?: string;
  verifyFingerprints?: boolean;
  timeout?: number;
}

export class GhostPipeCluster {
  constructor(options: GhostPipeClusterOptions);
  send(data: Uint8Array | ArrayBuffer, options?: SendOptions): Promise<string>;
  receive(hash: string, options?: ReceiveOptions): Promise<Uint8Array>;
}

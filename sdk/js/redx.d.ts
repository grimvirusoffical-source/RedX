// TypeScript declarations for the RedX JavaScript client (redx.js). The per-operation methods come from
// operations.d.ts, which scripts/gensdk generates from api/redx-api.json.
import { RedXOperations, CallOptions, Operation, DangerName } from './operations';

export { Operation, DangerName, CallOptions };
export declare const OPERATIONS: Readonly<Record<string, Operation>>;
export declare const DANGER: Readonly<Record<DangerName, number>>;
export declare function dangerOf(opId: string): DangerName;

export declare class RedXError extends Error {
  /** HTTP status; 0 for network, timeout and client-side errors (such as an unconfirmed dangerous call) */
  status: number;
  /** the host's error code, or "confirm_required" */
  code: string | null;
  retryAfter: number | null;
  body: unknown;
  readonly unauthorized: boolean;
  readonly forbidden: boolean;
  readonly notFound: boolean;
  readonly rateLimited: boolean;
}
export declare class BoxTextError extends Error {}
export declare function fromBox(text: string): unknown;
export declare function escapePath(p: string): string;

export interface WriteOptions { ttl?: number; sliding?: boolean; checkpoint?: number }
export interface StreamEvent { path: string; op: 'set' | 'delete' | 'expire' | string; value: string; at: string; data?: unknown; [k: string]: unknown }
export interface StreamOptions {
  onError?: (e: Error) => void;
  onClose?: (c: { code: number; reason: string }) => void;
  /** reconnect after an unexpected close, with exponential backoff; missed events are not replayed */
  reconnect?: boolean | { minMs?: number; maxMs?: number };
  onReconnect?: () => void;
}
export interface Subscription { close(): void; closed: Promise<{ code: number; reason: string }>; ping(): void }

// health, stats, bx, createKey and revokeKey keep their original hand-written signatures (see docs/sdks.md, migration notes)
export interface RedX extends Omit<RedXOperations, 'health' | 'stats' | 'bx' | 'createKey' | 'revokeKey'> {}
export declare class RedX {
  constructor(o: { url: string; key: string; db?: string; timeoutMs?: number });
  readonly baseUrl: string;
  readonly db?: string;
  withDb(db: string): RedX;
  call(opId: string, opts?: CallOptions): Promise<any>;
  stream(opId: 'bxWatch' | 'subscribe' | 'rulesSubscribe', opts: CallOptions, handler: (ev: StreamEvent) => void, o?: StreamOptions): Promise<Subscription>;
  health(): Promise<{ status: string; node: string; role: string; version: string }>;
  databases(): Promise<any>;
  getBox(path: string): Promise<string>;
  get(path: string): Promise<unknown>;
  getOr<T = null>(path: string, fallback?: T): Promise<unknown | T>;
  set(path: string, value: unknown, opts?: WriteOptions): Promise<any>;
  setBox(path: string, boxText: string, opts?: WriteOptions): Promise<any>;
  delete(path: string): Promise<any>;
  query(q: string): Promise<{ count: number; results: string[]; values: unknown[] }>;
  bx(q: string, params?: Record<string, unknown>): Promise<any>;
  stats(): Promise<any>;
  tx(commands: string[], params?: Record<string, unknown>): Promise<any>;
  watch(q: string, handler: (ev: StreamEvent) => void, o?: StreamOptions & { params?: Record<string, unknown> }): Promise<Subscription>;
  subscribe(pathPattern: string, handler: (ev: StreamEvent) => void, o?: StreamOptions): Promise<Subscription>;
  createKey(o: { db?: string; scope: 'read' | 'write' | 'admin'; prefix?: string; label?: string; ttl?: string; rateRps?: number; rateBurst?: number; roles?: string[]; confirm?: boolean }): Promise<{ key: string; id: string; [k: string]: unknown }>;
  revokeKey(id: string, o?: { confirm?: boolean }): Promise<any>;
  uploadFile(pack: string, file: string, data: Uint8Array | string, o?: { db?: string }): Promise<any>;
  downloadFile(pack: string, file: string, o?: { db?: string; range?: [number, number?] }): Promise<Buffer>;
  uploadMedia(lib: string, name: string, data: Uint8Array | string, o?: { db?: string; type?: string }): Promise<any>;
  downloadMedia(lib: string, name: string, o?: { db?: string; range?: [number, number?] }): Promise<Buffer>;
}

export declare function connectRequest(): { state: string; verifier: string; challenge: string };
export declare function connectLink(o: { provider: string; state: string; challenge: string; app?: string; workspace?: string; scope?: string; prefix?: string; label?: string; callback?: string; host?: string; pin?: string; name?: string; consoleUrl?: string }): string;
export declare function parseCallback(url: string, expectedState: string): { code: string; state: string; host: string; pin: string };
export declare function exchangeConnectCode(o: { url: string; code: string; verifier: string; state: string; deviceLabel?: string; providerGrant?: string; timeoutMs?: number }): Promise<any>;
export declare function exchangePairingCode(o: { url: string; code: string; timeoutMs?: number }): Promise<any>;

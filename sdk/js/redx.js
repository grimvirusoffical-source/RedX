'use strict';
// RedX client for Node >= 18 (global fetch). No dependencies.
//
//   const { RedX } = require('./redx');
//   const db = new RedX({ url: 'http://127.0.0.1:7777', key: process.env.REDX_KEY });
//   await db.set('players.red-xai.db:Player[ID=1]', { Name: 'Ann', Level: 5 });
//   const p = await db.get('players.red-xai.db:Player[ID=1]'); // { Level: 5, Name: 'Ann' }
//
// The API key is held in a private field: it is never part of an error
// message, JSON.stringify(client) or util.inspect(client).

const util = require('node:util');
const crypto = require('node:crypto');
const wsClient = require('./ws');
const { fromBox, BoxTextError } = require('./boxtext');
const { OPERATIONS, DANGER, SEGMENT_PARAMS, install } = require('./operations');

const DB_NAME = /^[a-z0-9][a-z0-9_-]{0,62}$/;
const KEY_SHAPE = /rx_live_[A-Za-z0-9]+/g;

class RedXError extends Error {
  /** @param {number} status HTTP status (0 = network/timeout/client-side error) */
  constructor(status, message, { retryAfter = null, body = null, code = null } = {}) {
    super(message);
    this.name = 'RedXError';
    this.status = status;
    // machine-readable code: the host's "code" field, or "confirm_required" when a dangerous call was not confirmed
    this.code = code ?? (body && typeof body.code === 'string' ? body.code : null);
    this.retryAfter = retryAfter; // seconds, for 429
    this.body = body;
  }
  get unauthorized() { return this.status === 401; }
  get forbidden() { return this.status === 403; }
  get notFound() { return this.status === 404; }
  get rateLimited() { return this.status === 429; }
}

function scrub(s) { return String(s).replace(KEY_SHAPE, 'rx_live_[redacted]'); }

/** Escape a RedX path for use inside a URL path ([ ] : = etc. are percent-encoded). */
function escapePath(p) {
  if (typeof p !== 'string' || p === '') throw new TypeError('path must be a non-empty string');
  return encodeURIComponent(p);
}

class RedX {
  #key;
  /**
   * @param {object} o
   * @param {string} o.url      base URL of redxd, e.g. http://127.0.0.1:7777
   * @param {string} o.key      API key (rx_live_...)
   * @param {string} [o.db]     database name; omit for the host's default db
   * @param {number} [o.timeoutMs=30000]
   */
  constructor({ url, key, db, timeoutMs = 30000 } = {}) {
    if (!url) throw new TypeError('url is required');
    if (!key || typeof key !== 'string') throw new TypeError('key is required');
    if (db !== undefined && !DB_NAME.test(db)) throw new TypeError('invalid db name');
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new TypeError('url must be http(s)');
    this.baseUrl = u.origin;
    this.db = db;
    this.timeoutMs = timeoutMs;
    this.#key = key;
  }

  toJSON() { return { baseUrl: this.baseUrl, db: this.db }; }
  [util.inspect.custom]() { return `RedX { baseUrl: '${this.baseUrl}', db: ${JSON.stringify(this.db)} }`; }

  /** A client for another database using the same key. */
  withDb(db) { return new RedX({ url: this.baseUrl, key: this.#key, db, timeoutMs: this.timeoutMs }); }

  #dbPrefix() { return this.db ? `/v1/db/${this.db}` : '/v1'; }

  async #request(method, path, { body, headers = {}, query, accept, raw = false, anonymous = false } = {}) {
    let url = this.baseUrl + path;
    if (query) {
      const q = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== null) q.set(k, String(v));
      const s = q.toString();
      if (s) url += '?' + s;
    }
    const h = anonymous ? { ...headers } : { Authorization: `Bearer ${this.#key}`, ...headers };
    if (accept) h.Accept = accept;
    let res;
    try {
      res = await fetch(url, { method, headers: h, body, signal: AbortSignal.timeout(this.timeoutMs), redirect: 'error' });
    } catch (e) {
      const timedOut = e && (e.name === 'TimeoutError' || e.name === 'AbortError');
      throw new RedXError(0, timedOut ? `request timed out after ${this.timeoutMs}ms` : scrub(`request failed: ${e && e.cause ? e.cause.message || e.cause : e.message}`));
    }
    if (raw && res.ok) return { text: '', buf: Buffer.from(await res.arrayBuffer()), res };
    const text = await res.text();
    if (!res.ok) {
      let msg = `HTTP ${res.status}`;
      let parsed = null;
      try { parsed = JSON.parse(text); if (parsed && parsed.error) msg = String(parsed.error); } catch { /* not JSON */ }
      const ra = res.headers.get('retry-after');
      throw new RedXError(res.status, scrub(msg), { retryAfter: ra ? Number(ra) : null, body: parsed });
    }
    return { text, res };
  }

  async #json(method, path, opts) {
    const { text } = await this.#request(method, path, opts);
    try { return JSON.parse(text); } catch { throw new RedXError(0, 'server sent a non-JSON response'); }
  }

  /** GET /healthz (needs no key). Resolves { status, node, role, version }. */
  async health() {
    let res;
    try { res = await fetch(this.baseUrl + '/healthz', { signal: AbortSignal.timeout(this.timeoutMs) }); }
    catch (e) { throw new RedXError(0, scrub(`request failed: ${e.message}`)); }
    if (!res.ok) throw new RedXError(res.status, `HTTP ${res.status}`);
    return res.json();
  }

  stats() { return this.#json('GET', '/v1/stats'); }

  /** Databases the key can see. Resolves the host's list response. */
  databases() { return this.#json('GET', '/v1/dbs'); }

  /** Raw Box text of the value at `path` (exactly what the host stores/prints). */
  async getBox(path) {
    const { text } = await this.#request('GET', `${this.#dbPrefix()}/path/${escapePath(path)}`, { accept: 'text/x-redx-box' });
    return text;
  }

  /** The value at `path` as a plain JS value (see boxtext.js for the mapping). Throws RedXError(404) if absent. */
  async get(path) {
    const j = await this.#json('GET', `${this.#dbPrefix()}/path/${escapePath(path)}`);
    if (typeof j.value !== 'string') throw new RedXError(0, 'unexpected response shape');
    try { return fromBox(j.value); }
    catch (e) { if (e instanceof BoxTextError) throw new RedXError(0, `cannot decode value: ${e.message}`); throw e; }
  }

  /** Like get(), but resolves `fallback` (default null) when the path does not exist. */
  async getOr(path, fallback = null) {
    try { return await this.get(path); } catch (e) { if (e instanceof RedXError && e.status === 404) return fallback; throw e; }
  }

  /**
   * Write a JSON-compatible value (objects become boxes, null becomes NELL).
   * @param {{ttl?: number, sliding?: boolean, checkpoint?: number}} [opts] seconds
   */
  set(path, value, opts = {}) {
    const body = { value };
    if (opts.ttl !== undefined) body.ttl_seconds = opts.ttl;
    if (opts.sliding !== undefined) body.sliding = !!opts.sliding;
    if (opts.checkpoint !== undefined) body.checkpoint_seconds = opts.checkpoint;
    return this.#json('PUT', `${this.#dbPrefix()}/path/${escapePath(path)}`, {
      body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' },
    });
  }

  /** Write raw Box text (see docs/box-grammar.md) at `path`. Same options as set(). */
  setBox(path, boxText, opts = {}) {
    return this.#json('PUT', `${this.#dbPrefix()}/path/${escapePath(path)}`, {
      body: boxText, headers: { 'Content-Type': 'text/x-redx-box' },
      query: { ttl: opts.ttl, sliding: opts.sliding === undefined ? undefined : !!opts.sliding, checkpoint: opts.checkpoint },
    });
  }

  /** Delete the value at `path`. */
  delete(path) { return this.#json('DELETE', `${this.#dbPrefix()}/path/${escapePath(path)}`); }

  /**
   * Run a RedX path query (POST /v1/query), e.g. `players.red-xai.db:Player[ID=*].Name`.
   * NOTE: this is the host's path-pattern query; use bx() for the BoxQL language (both stay).
   * Resolves { count, results: string[] (Box text), values: any[] (decoded) }.
   */
  async query(q) {
    if (typeof q !== 'string' || q === '') throw new TypeError('query must be a non-empty string');
    const j = await this.#json('POST', `${this.#dbPrefix()}/query`, {
      body: JSON.stringify({ q }), headers: { 'Content-Type': 'application/json' },
    });
    const results = Array.isArray(j.results) ? j.results : [];
    const values = results.map((r) => { try { return fromBox(r); } catch { return r; } });
    return { count: j.count, results, values };
  }

  /**
   * Run one BoxQL command (POST /v1/bx), e.g. `{Get[]} = players:Player[Level >= $min] -> Name`.
   * Values go in `params` ({ name: value }, referenced as $name; never concatenate them into the text).
   * Resolves the host's result: { kind, columns, rows, rows_box, count, affected, paths, access, plan }.
   * Rows hold decoded JSON values; a Tx also carries `results`, one per command. The language is
   * specified in docs/boxql.md.
   */
  async bx(q, params = {}) {
    if (typeof q !== 'string' || q === '') throw new TypeError('bx command must be a non-empty string');
    if (params === null || typeof params !== 'object' || Array.isArray(params)) throw new TypeError('params must be an object');
    return this.#json('POST', `${this.#dbPrefix()}/bx`, {
      body: JSON.stringify({ q, params }), headers: { 'Content-Type': 'application/json' },
    });
  }

  /**
   * Watch a BoxQL `{Watch[]}` command over a WebSocket (Node only), e.g.
   * `{Watch[]} = players:Player[Level > $min]`. The handler receives { path, op, value, at, data }:
   * `value` is the whole changed record as Box text (fields you may not read removed; empty for a
   * removal) and `data` its decoded form. `{Watch[]} = Topic = "player.*"` delivers pulse events.
   * @param {(ev: object) => void} handler
   * @param {{params?: object, onError?: (e: Error) => void, onClose?: (c: {code:number, reason:string}) => void}} [opts]
   */
  async watch(q, handler, { params, onError, onClose } = {}) {
    if (typeof q !== 'string' || q === '') throw new TypeError('watch command must be a non-empty string');
    const sp = { q };
    if (params !== undefined) {
      if (params === null || typeof params !== 'object' || Array.isArray(params)) throw new TypeError('params must be an object');
      sp.params = JSON.stringify(params);
    }
    return this.#stream('/bx/watch', sp, handler, { onError, onClose });
  }

  /** Create an API key (needs an admin key). The returned `key` is shown once; store it. */
  createKey({ db, scope, prefix, label, ttl, rateRps, rateBurst, roles, confirm } = {}) {
    if (confirm !== true) throw new RedXError(0, 'createKey is a dangerous operation and needs confirm: true', { code: 'confirm_required' });
    const body = { db: db ?? this.db ?? 'default', scope };
    if (prefix !== undefined) body.prefix = prefix;
    if (label !== undefined) body.label = label;
    if (ttl !== undefined) body.ttl = ttl;
    if (rateRps !== undefined) body.rate_rps = rateRps;
    if (rateBurst !== undefined) body.rate_burst = rateBurst;
    if (roles !== undefined) body.roles = roles;
    return this.#json('POST', '/v1/keys', { body: JSON.stringify(body), headers: { 'Content-Type': 'application/json', 'X-RedX-Confirm': 'createKey' } });
  }

  /** Revoke a key by id (admin). */
  revokeKey(id, { confirm } = {}) {
    if (confirm !== true) throw new RedXError(0, 'revokeKey is a dangerous operation and needs confirm: true', { code: 'confirm_required' });
    return this.#json('DELETE', `/v1/keys/${encodeURIComponent(id)}`, { headers: { 'X-RedX-Confirm': 'revokeKey' } });
  }

  /**
   * Subscribe to changes under `pathPrefix` (WebSocket, Node only).
   * handler receives { path, op: 'set'|'delete'|'expire', value, at, data }
   * where `value` is Box text and `data` its decoded form (undefined if it
   * could not be decoded). Resolves a Subscription once the upgrade succeeded;
   * rejects with RedXError (401/403/429...) if refused.
   * @param {(ev: object) => void} handler
   * @param {{onError?: (e: Error) => void, onClose?: (c: {code:number, reason:string}) => void}} [opts]
   */
  async subscribe(pathPrefix, handler, { onError, onClose, reconnect, onReconnect } = {}) {
    return this.#stream('/subscribe', { path: pathPrefix }, handler, { onError, onClose, reconnect, onReconnect });
  }

  /**
   * Run any operation of api/redx-api.json by id: call('createDatabase', { body: { name: 'game' } }).
   * opts: { db, <path params by name>, query, body, headers, confirm }. Path params are escaped here.
   * Operations whose danger is "dangerous" are refused without a request unless confirm === true
   * (RedXError with code "confirm_required"). Resolves parsed JSON, a string (Box text) or a Buffer (binary).
   */
  async call(opId, opts = {}) {
    const op = OPERATIONS[opId];
    if (!op) throw new TypeError(`unknown operation ${JSON.stringify(opId)}`);
    if (op.response === 'websocket') throw new TypeError(`${opId} is a WebSocket stream: use stream('${opId}', opts, handler)`);
    checkDanger(op, opts);
    const headers = { ...(opts.headers || {}) };
    if (opts.confirm === true) headers['X-RedX-Confirm'] = op.id;
    let body;
    if (op.request === 'json') {
      body = JSON.stringify(opts.body === undefined ? {} : opts.body);
      headers['Content-Type'] = 'application/json';
    } else if (op.request === 'text') {
      if (typeof opts.body !== 'string') throw new TypeError(`${opId} takes Box text (a string) as body`);
      body = opts.body;
      headers['Content-Type'] = 'text/x-redx-box';
    } else if (op.request === 'binary') {
      if (opts.body === undefined || opts.body === null) throw new TypeError(`${opId} needs a body (Buffer, Uint8Array or string)`);
      body = typeof opts.body === 'string' ? Buffer.from(opts.body) : opts.body;
      headers['Content-Type'] = headers['Content-Type'] || 'application/octet-stream';
      if (!Object.keys(headers).some((k) => k.toLowerCase() === 'x-redx-sha256')) {
        headers['X-Redx-SHA256'] = crypto.createHash('sha256').update(body).digest('hex');
      }
    }
    let query = opts.query;
    if (op.hostConfirm) { // the host's own guard: repeat the name, e.g. DELETE /v1/db/x?confirm=x
      const v = op.hostConfirm === 'db' ? (opts.db ?? this.db ?? 'default') : opts[op.hostConfirm];
      query = { confirm: v, ...(query || {}) };
    }
    const ro = { body, headers, query, anonymous: op.auth === 'none' };
    const path = this.#opPath(op, opts);
    if (op.response === 'binary') return (await this.#request(op.method, path, { ...ro, raw: true })).buf;
    if (op.response === 'text') return (await this.#request(op.method, path, { ...ro, accept: 'text/x-redx-box' })).text;
    const { text } = await this.#request(op.method, path, ro);
    if (text === '') return {};
    try { return JSON.parse(text); } catch { throw new RedXError(0, 'server sent a non-JSON response'); }
  }

  /** Open any WebSocket operation (bxWatch, subscribe, rulesSubscribe) by id; same options as subscribe(). */
  async stream(opId, opts = {}, handler, streamOpts = {}) {
    const op = OPERATIONS[opId];
    if (!op || op.response !== 'websocket') throw new TypeError(`${opId} is not a WebSocket operation`);
    const prefix = this.#opPath(op, opts);
    const sp = {};
    for (const [k, v] of Object.entries(opts.query || {})) if (v !== undefined && v !== null) sp[k] = String(v);
    return this.#stream(prefix, sp, handler, streamOpts, true);
  }

  #opPath(op, opts) {
    let p = op.path;
    if (p.includes('{db}')) {
      const db = opts.db ?? this.db;
      if (db !== undefined && db !== null && !DB_NAME.test(db)) throw new TypeError('invalid db name');
      if (!db && op.shorthand) p = op.shorthand;
      else p = p.replace('{db}', db || 'default');
    }
    return p.replace(/\{([a-z][a-z0-9_]*)\}/g, (_, n) => {
      const v = opts[n];
      if (v === undefined || v === null || v === '') {
        if (n === 'folder') return '';
        throw new TypeError(`${op.id} needs ${n}`);
      }
      return SEGMENT_PARAMS.has(n) ? String(v).split('/').map(encodeURIComponent).join('/') : encodeURIComponent(String(v));
    });
  }

  /** Run several BoxQL commands all-or-nothing: tx(['{Set[]} = ...', '{Add[]} = ...'], params). */
  tx(commands, params = {}) {
    if (!Array.isArray(commands) || commands.length === 0) throw new TypeError('tx needs a non-empty array of commands');
    return this.bx(`{Tx[]} = [\n  ${commands.join(',\n  ')}\n]`, params);
  }

  /** Upload a file into a pack (streamed by the host, verified with its SHA-256). */
  uploadFile(pack, file, data, { db } = {}) { return this.call('packPut', { db, pack, file, body: data }); }

  /** Download a file of a pack; range: [start, end] inclusive byte offsets (end optional). */
  downloadFile(pack, file, { db, range } = {}) {
    return this.call('packGet', { db, pack, file, headers: rangeHeader(range) });
  }

  /** Upload a media item; type declares the media type (e.g. image/png). */
  uploadMedia(lib, name, data, { db, type } = {}) { return this.call('mediaPut', { db, lib, name, body: data, query: { type } }); }

  /** Download a media item; same range option as downloadFile(). */
  downloadMedia(lib, name, { db, range } = {}) { return this.call('mediaGet', { db, lib, name, headers: rangeHeader(range) }); }

  async #stream(subPath, searchParams, handler, { onError, onClose, reconnect, onReconnect } = {}, absolute = false) {
    if (typeof handler !== 'function') throw new TypeError('handler must be a function');
    const wsUrl = new URL(`${this.baseUrl}${absolute ? '' : this.#dbPrefix()}${subPath}`);
    for (const [k, v] of Object.entries(searchParams)) wsUrl.searchParams.set(k, v);
    if (reconnect) return this.#reconnecting(wsUrl.toString(), handler, { onError, onClose, onReconnect, reconnect });
    return this.#open(wsUrl.toString(), handler, { onError, onClose });
  }

  // Keeps a stream open: after an unexpected close it reconnects with exponential backoff (with jitter).
  // Events that happen while disconnected are not replayed; onReconnect is the place to re-read state.
  // It gives up (onError, then closed resolves) when the host refuses the stream (400/401/403/404).
  async #reconnecting(url, handler, { onError, onClose, onReconnect, reconnect }) {
    const minMs = (reconnect && reconnect.minMs) || 250;
    const maxMs = (reconnect && reconnect.maxMs) || 10000;
    let stopped = false;
    let current = await this.#open(url, handler, { onError }); // the first connect reports its error to the caller
    let resolveClosed;
    const closed = new Promise((r) => { resolveClosed = r; });
    const finish = (c) => { if (onClose) onClose(c); resolveClosed(c); };
    let wake = null;
    const sleep = (ms) => new Promise((r) => { const t = setTimeout(r, ms); wake = () => { clearTimeout(t); r(); }; });
    (async () => {
      let delay = minMs;
      for (;;) {
        const c = await current.closed;
        if (stopped) { finish(c); return; }
        for (;;) {
          await sleep(delay / 2 + Math.random() * delay / 2);
          delay = Math.min(delay * 2, maxMs);
          if (stopped) { finish({ code: 1000, reason: 'bye' }); return; }
          try {
            current = await this.#open(url, handler, { onError });
          } catch (e) {
            if (e instanceof RedXError && [400, 401, 403, 404].includes(e.status)) {
              if (onError) onError(e);
              finish({ code: 0, reason: e.message });
              return;
            }
            continue;
          }
          if (stopped) { current.close(); continue; }
          delay = minMs;
          if (onReconnect) { try { onReconnect(); } catch (e) { if (onError) onError(e); } }
          break;
        }
      }
    })();
    return {
      close: () => { stopped = true; if (wake) wake(); current.close(); },
      closed,
      ping: () => current.ping(),
    };
  }

  async #open(url, handler, { onError, onClose } = {}) {
    let ws;
    try {
      ws = await wsClient.connect(url, { Authorization: `Bearer ${this.#key}` }, { timeoutMs: this.timeoutMs });
    } catch (e) {
      let msg = e.message, body = null;
      try { body = JSON.parse(e.body); if (body && body.error) msg = body.error; } catch { /* keep */ }
      const ra = e.headers && e.headers['retry-after'];
      throw new RedXError(e.status || 0, scrub(msg), { retryAfter: ra ? Number(ra) : null, body });
    }
    const closed = new Promise((resolve) => {
      ws.on('close', (c) => { if (onClose) onClose(c); resolve(c); });
    });
    ws.on('error', (e) => { if (onError) onError(e); });
    ws.on('message', (text) => {
      let ev;
      try { ev = JSON.parse(text); } catch (e) { if (onError) onError(new Error('bad event JSON')); return; }
      try { ev.data = typeof ev.value === 'string' && ev.op === 'set' ? fromBox(ev.value) : undefined; } catch { ev.data = undefined; }
      try { handler(ev); } catch (e) { if (onError) onError(e); }
    });
    return { close: () => ws.close(1000, 'bye'), closed, ping: () => ws.ping() };
  }
}

function checkDanger(op, opts) {
  if (op.danger === 'dangerous' && (!opts || opts.confirm !== true)) {
    throw new RedXError(0, `${op.id} is a dangerous operation (${op.summary}) and needs confirm: true`, { code: 'confirm_required' });
  }
}

const warned = new Set();
function unconfirmed(name) {
  if (warned.has(name)) return;
  warned.add(name);
  process.emitWarning(`${name}() without { confirm: true } is deprecated: it is a dangerous operation and will need confirm in a later release`, 'DeprecationWarning');
}

function rangeHeader(range) {
  if (!range) return {};
  const [start, end] = range;
  return { Range: `bytes=${start}-${end === undefined || end === null ? '' : end}` };
}

// ---- app side of the connect handshake (no key needed) ----

const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** A fresh state and PKCE pair: { state, verifier, challenge }. Keep state and verifier secret until the exchange. */
function connectRequest() {
  const verifier = b64url(crypto.randomBytes(32));
  return { state: b64url(crypto.randomBytes(24)), verifier, challenge: b64url(crypto.createHash('sha256').update(verifier).digest()) };
}

const LINK_FIELDS = ['provider', 'app', 'workspace', 'scope', 'prefix', 'label', 'state', 'callback', 'host', 'pin', 'name'];

/**
 * The connect link for the owner to open: redx://connect?... or, with consoleUrl, <consoleUrl>/#/connect?...
 * o: { provider, state, challenge, app?, workspace?, scope?, prefix?, label?, callback?, host?, pin?, name?, consoleUrl? }
 */
function connectLink(o) {
  if (!o || !o.provider || !o.state || !o.challenge) throw new TypeError('connectLink needs provider, state and challenge');
  const q = new URLSearchParams({ v: '1' });
  for (const k of LINK_FIELDS) if (o[k] !== undefined && o[k] !== null && o[k] !== '') q.set(k, String(o[k]));
  q.set('pkce_challenge', o.challenge);
  q.set('pkce_method', 'S256');
  if (o.consoleUrl) return `${new URL(o.consoleUrl).origin}/#/connect?${q}`;
  return `redx://connect?${q}`;
}

/** Read the callback URL the console opened; throws unless its state matches. Resolves { code, state, host, pin }. */
function parseCallback(url, expectedState) {
  const u = new URL(url);
  const g = (k) => u.searchParams.get(k) || '';
  const out = { code: g('code'), state: g('state'), host: g('host'), pin: g('pin') };
  if (!out.code) throw new RedXError(0, 'callback carries no code', { code: 'bad_callback' });
  const a = Buffer.from(out.state), b = Buffer.from(String(expectedState || ''));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new RedXError(0, 'callback state does not match', { code: 'state_mismatch' });
  return out;
}

async function anonymousPost(url, path, body, timeoutMs = 30000) {
  let res;
  try {
    res = await fetch(new URL(url).origin + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs), redirect: 'error' });
  } catch (e) { throw new RedXError(0, scrub(`request failed: ${e && e.cause ? e.cause.message || e.cause : e.message}`)); }
  const text = await res.text();
  let parsed = null;
  try { parsed = JSON.parse(text); } catch { /* not JSON */ }
  if (!res.ok) throw new RedXError(res.status, scrub(parsed && parsed.error ? parsed.error : `HTTP ${res.status}`), { body: parsed });
  return parsed;
}

/** Trade an approved connect code plus the PKCE verifier for the app's key: { key, workspace, scope, ... } (key shown once). */
function exchangeConnectCode({ url, code, verifier, state, deviceLabel, providerGrant, timeoutMs }) {
  const body = { code, pkce_verifier: verifier, state };
  if (deviceLabel) body.device_label = deviceLabel;
  if (providerGrant) body.provider_grant = providerGrant;
  return anonymousPost(url, '/v1/connect/exchange', body, timeoutMs);
}

/** Trade a sign-in (pairing) code for a key. */
function exchangePairingCode({ url, code, timeoutMs }) { return anonymousPost(url, '/v1/pair/exchange', { code }, timeoutMs); }

install(RedX.prototype);

/** The danger level of an operation id ("safe", "write", "admin", "dangerous"). */
function dangerOf(opId) { const op = OPERATIONS[opId]; if (!op) throw new TypeError(`unknown operation ${opId}`); return op.danger; }

module.exports = {
  RedX, RedXError, BoxTextError, fromBox, escapePath,
  OPERATIONS, DANGER, dangerOf,
  connectRequest, connectLink, parseCallback, exchangeConnectCode, exchangePairingCode,
};

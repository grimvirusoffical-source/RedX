// Talks to the redxd HTTP API with a bearer key kept in the browser: sessionStorage by default,
// localStorage only when the user ticks "remember this device". Keys are never logged or sent anywhere else.

const K = 'redx.key';
export const session = {
  get key() { return sessionStorage.getItem(K) || localStorage.getItem(K) || ''; },
  get remembered() { return !!localStorage.getItem(K); },
  set(key, remember) {
    this.clear();
    (remember ? localStorage : sessionStorage).setItem(K, key);
  },
  clear() { sessionStorage.removeItem(K); localStorage.removeItem(K); },
};

export class ApiError extends Error {
  constructor(status, message, body) { super(message); this.status = status; this.body = body; }
}

let onUnauthorized = () => {};
export function setUnauthorizedHandler(fn) { onUnauthorized = fn; }

/**
 * api('GET', '/v1/dbs')                          -> parsed JSON
 * api('PUT', path, {json: {...}})                -> JSON body
 * api('PUT', path, {text: '...', type: 'text/plain'})
 * api('GET', path, {raw: true})                  -> Response (for blobs / headers)
 */
export async function api(method, path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  const key = opts.key !== undefined ? opts.key : session.key;
  if (key) headers.Authorization = 'Bearer ' + key;
  let body;
  if (opts.json !== undefined) { body = JSON.stringify(opts.json); headers['Content-Type'] = 'application/json'; }
  else if (opts.text !== undefined) { body = opts.text; headers['Content-Type'] = opts.type || 'text/plain'; }
  const t0 = performance.now();
  let res;
  try {
    res = await fetch(path, { method, headers, body, cache: 'no-store', signal: opts.signal });
  } catch (e) {
    if (e.name === 'AbortError') throw e;
    throw new ApiError(0, 'Cannot reach the RedX host. Is redxd still running?');
  }
  if (opts.timing) opts.timing.ms = performance.now() - t0;
  if (opts.raw) return res;
  const txt = await res.text();
  let data = null;
  if (txt) { try { data = JSON.parse(txt); } catch { data = txt; } }
  if (!res.ok) {
    const msg = (data && data.error) || (typeof data === 'string' && data) || res.statusText || 'request failed';
    if (res.status === 401 && !opts.noAuthRedirect) onUnauthorized();
    throw new ApiError(res.status, msg, data);
  }
  return data;
}

export function wsURL(path, params = {}) {
  const u = new URL(path, location.href);
  u.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  // browsers cannot set headers on a WebSocket: the API accepts the key as access_token for upgrades only
  u.searchParams.set('access_token', session.key);
  return u.toString();
}

export const enc = encodeURIComponent;
/** Native record path: players.red-xai.db:Player[ID=1] */
export const pathURL = (db, p) => `/v1/db/${enc(db)}/path/${enc(p)}`;
export const baseURL = () => location.origin;

/** Trade a one-time pairing code (typed, or from a QR code) for an API key. No key is needed for this call. */
export async function exchangePairingCode(code) {
  let res;
  try {
    res = await fetch('/v1/pair/exchange', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code }), cache: 'no-store' });
  } catch { throw new ApiError(0, 'Cannot reach the RedX host.'); }
  let body = {};
  try { body = await res.json(); } catch { /* not JSON */ }
  if (!res.ok) throw new ApiError(res.status, body.error || 'The pairing code was not accepted.');
  return body.key;
}
export const looksLikePairingCode = (s) => /^\s*rp[-\s_]?[a-z2-9]{5}[-\s_]?[a-z2-9]{5}\s*$/i.test(s);

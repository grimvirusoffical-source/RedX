// Website mode uses the existing same-origin account cookie. Standalone and
// explicit developer mode retain the existing browser-held bearer credentials.

const K = 'redx.key';
let websiteConfigured = false;
let developerSelected = false;
let requestEpoch = 0;
let websiteLogin = '/signin';
let websiteAccount = '/settings';
export const websiteAuthentication = () => websiteConfigured && !developerSelected;
// Presentation stays a website workspace even after an explicit developer-key
// selection. A credential change must not turn the DB page into a Host panel.
export const websiteDeployment = () => websiteConfigured;
// The return destination is fixed, never copied from a query or fragment.
export const websiteLoginURL = () => websiteLogin + '?next=' + encodeURIComponent('/db');
export const websiteAccountURL = () => websiteAccount;
export function invalidateRequests() { requestEpoch++; }
export function configureAuthentication(config) {
  websiteConfigured = config?.enabled === true && config.mode === 'website';
  developerSelected = false;
  // These are operator-supplied same-site pages, never an arbitrary redirect.
  websiteLogin = config?.website_login === '/signin' ? config.website_login : '/signin';
  websiteAccount = config?.website_account === '/settings' ? config.website_account : '/settings';
  if (websiteConfigured) session.clear();
}
export const session = {
  get key() { return websiteAuthentication() ? '' : sessionStorage.getItem(K) || localStorage.getItem(K) || ''; },
  get remembered() { return !websiteAuthentication() && !!localStorage.getItem(K); },
  set(key, remember) {
    this.clear();
    developerSelected = true; // selected only after the explicit advanced flow succeeds
    (remember ? localStorage : sessionStorage).setItem(K, key);
  },
  clear() { sessionStorage.removeItem(K); localStorage.removeItem(K); developerSelected = false; invalidateRequests(); },
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
  const epoch = requestEpoch;
  const headers = { ...(opts.headers || {}) };
  const key = opts.key !== undefined ? opts.key : session.key;
  if (key) headers.Authorization = 'Bearer ' + key;
  // Dangerous ops need X-RedX-Confirm: <operation-id> (server-enforced since 0.4.5).
  if (opts.confirm) headers['X-RedX-Confirm'] = opts.confirm;
  let body;
  if (opts.json !== undefined) { body = JSON.stringify(opts.json); headers['Content-Type'] = 'application/json'; }
  else if (opts.text !== undefined) { body = opts.text; headers['Content-Type'] = opts.type || 'text/plain'; }
  const t0 = performance.now();
  let res;
  try {
    res = await fetch(path, { method, headers, body, credentials: 'same-origin', cache: 'no-store', signal: opts.signal });
  } catch (e) {
    if (e.name === 'AbortError') throw e;
    throw new ApiError(0, 'Cannot reach the RedX host. Is redxd still running?');
  }
  if (opts.timing) opts.timing.ms = performance.now() - t0;
  if (epoch !== requestEpoch) throw new ApiError(0, 'The account changed while this request was running.');
  if (opts.raw) return res;
  const txt = await res.text();
  if (epoch !== requestEpoch) throw new ApiError(0, 'The account changed while this request was running.');
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
  if (!websiteAuthentication() && session.key) u.searchParams.set('access_token', session.key);
  else u.searchParams.delete('access_token');
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

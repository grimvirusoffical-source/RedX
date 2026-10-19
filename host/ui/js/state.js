import { api } from './api.js';

const ls = (k, d) => { try { return localStorage.getItem(k) ?? d; } catch { return d; } };
const lsSet = (k, v) => { try { localStorage.setItem(k, v); } catch { /* private mode */ } };

export function normTheme(v) { return v === 'light' || v === 'system' ? v : v === 'auto' ? 'system' : 'dark'; } // 'auto' = older builds

export const state = {
  who: null, // {id, scope, db, prefix, roles, host_admin}
  status: null, // /v1/admin/status for host admins
  db: ls('redx.db', 'default'),
  dbs: [],
  mode: ls('redx.mode', 'simple'), // simple | advanced
  consoleMode: 'database', // database | host; per user, applied once whoami is loaded
  theme: normTheme(ls('redx.theme', 'dark')), // dark (default) | system | light
};
const subs = new Set();
export const subscribe = (fn) => { subs.add(fn); return () => subs.delete(fn); };
const emit = () => subs.forEach((f) => f(state));

export function setDb(db) { state.db = db; lsSet('redx.db', db); emit(); }
export function setMode(m) { state.mode = m; lsSet('redx.mode', m); emit(); }

/** Signed-in identity for the remembered console mode. An account uses its id, then its email. */
export function userKey() {
  const w = state.who;
  if (!w) return '';
  const a = w.account;
  if (a) return String(a.sub || a.email || w.id || '');
  return String(w.id || '');
}

function modeKey() {
  const k = userKey();
  return k ? 'redx.consoleMode.' + k : '';
}

/** Stored choice for this user, or Database when nothing valid is stored. */
export function readConsoleMode() {
  const k = modeKey();
  if (!k) return 'database';
  return ls(k, '') === 'host' ? 'host' : 'database';
}

function modeQuery() {
  try {
    const q = new URLSearchParams(location.search).get('mode');
    return q === 'host' || q === 'database' ? q : '';
  } catch { return ''; }
}

function writeModeQuery(mode) {
  try {
    const u = new URL(location.href);
    if (u.searchParams.get('mode') === mode) return;
    u.searchParams.set('mode', mode);
    history.replaceState(null, '', u.pathname + u.search + u.hash);
  } catch { /* ignore */ }
}

/** Drop only ?mode=, leaving the path, any other query, and the hash. */
export function stripModeQuery() {
  try {
    const u = new URL(location.href);
    if (!u.searchParams.has('mode')) return;
    u.searchParams.delete('mode');
    const qs = u.searchParams.toString();
    history.replaceState(null, '', u.pathname + (qs ? '?' + qs : '') + u.hash);
  } catch { /* ignore */ }
}

// ?mode= is read once, on the first apply in this document. A later sign-in in the
// same tab must not inherit the previous user's address.
let deepLinkMode;
function takeDeepLinkMode() {
  if (deepLinkMode === undefined) deepLinkMode = modeQuery();
  const q = deepLinkMode;
  deepLinkMode = '';
  return q;
}

export function setConsoleMode(m) {
  const mode = m === 'host' ? 'host' : 'database';
  state.consoleMode = mode;
  const k = modeKey();
  if (k) lsSet(k, mode);
  writeModeQuery(mode);
  emit();
}

/**
 * forced is 'host' or 'database' when the open page belongs to that mode.
 * Otherwise the one-shot ?mode= from the initial page load wins, then this user's
 * stored choice, then Database. The choice is saved for this user only.
 */
export function applyConsoleModeForRoute(forced) {
  const q = takeDeepLinkMode();
  let mode;
  if (forced === 'host' || forced === 'database') mode = forced;
  else if (q) mode = q;
  else mode = readConsoleMode();
  state.consoleMode = mode;
  const k = modeKey();
  if (k) lsSet(k, mode);
  writeModeQuery(mode);
  emit();
  return mode;
}
export function setTheme(t) {
  state.theme = normTheme(t);
  lsSet('redx.theme', state.theme);
  applyTheme();
  emit();
}
const THEME_COLOR = { dark: '#0f0809', light: '#f7f3f2' };
/** Resolve Dark / System / Light to the shown theme and apply it (keep in sync with js/theme-init.js). */
export function applyTheme() {
  const t = state.theme === 'system' ? (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark') : state.theme;
  const root = document.documentElement;
  root.dataset.theme = t;
  root.dataset.themePref = state.theme;
  const m = document.querySelector('meta[name=theme-color]');
  if (m) m.content = THEME_COLOR[t];
  return t;
}
export const isAdmin = () => !!(state.who && state.who.scope === 'admin');
export const isHostAdmin = () => !!(state.who && state.who.host_admin === true);

/** Owner is a boolean on the account for a console session, and on whoami for an API key. Never a string. */
export function isOwner() {
  const w = state.who;
  if (!w) return false;
  if (w.account) return w.account.owner === true;
  return w.owner === true;
}

/** pageAllowed is the nav and the router. Only whoami.pages[id] === true opens a page. join is public. */
export function pageAllowed(id) {
  if (id === 'join') return true;
  const pages = state.who && state.who.pages;
  return !!(pages && pages[id] === true);
}

export async function loadDbs() {
  try {
    const r = await api('GET', '/v1/dbs');
    state.dbs = r.dbs || [];
    if (!state.dbs.includes(state.db)) state.db = state.dbs[0] || 'default';
  } catch { state.dbs = state.dbs || []; }
  emit();
  return state.dbs;
}
export async function loadWho() {
  state.who = await api('GET', '/v1/ui/whoami', { noAuthRedirect: true });
  return state.who;
}

// "Get started" checklist flags
export const gs = {
  get(k) { return ls('redx.gs.' + k, '') === '1'; },
  set(k) { lsSet('redx.gs.' + k, '1'); emit(); },
  reset() { ['db', 'record', 'query', 'key'].forEach((k) => localStorage.removeItem('redx.gs.' + k)); emit(); },
  dismissed() { return ls('redx.gs.dismissed', '') === '1'; },
  dismiss() { lsSet('redx.gs.dismissed', '1'); emit(); },
};
export const wizard = {
  done() { return ls('redx.wizard', '') === 'done'; },
  finish() { lsSet('redx.wizard', 'done'); },
};

/** BoxQL file stem for a data file name: players.red-xai.db -> players */
export function fileStem(name) {
  return name.replace(/\.red-xai-db-qs-ls$|\.red-xai-db-qs$|\.red-xai\.db$|\.red-xai-db$|\.red-xai-db-link$/, '');
}
export const ID_RE = /^[a-z0-9][a-z0-9_-]{0,62}$/;

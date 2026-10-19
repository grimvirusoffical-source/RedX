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
  theme: normTheme(ls('redx.theme', 'dark')), // dark (default) | system | light
};
const subs = new Set();
export const subscribe = (fn) => { subs.add(fn); return () => subs.delete(fn); };
const emit = () => subs.forEach((f) => f(state));

export function setDb(db) { state.db = db; lsSet('redx.db', db); emit(); }
export function setMode(m) { state.mode = m; lsSet('redx.mode', m); emit(); }
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

import { api, websiteAuthentication, invalidateRequests } from './api.js';
import { accountLocal, setAccountStorageScope } from './account-storage.js';

const ls = (k, d) => { try { return localStorage.getItem(k) ?? d; } catch { return d; } };
const lsSet = (k, v) => { try { localStorage.setItem(k, v); } catch { /* private mode */ } };

export function normTheme(v) { return v === 'light' || v === 'system' ? v : v === 'auto' ? 'system' : 'dark'; } // 'auto' = older builds

export const state = {
  who: null, // {id, scope, db, prefix, roles, host_admin}
  status: null, // /v1/admin/status for host admins
  db: ls('redx.db', 'default'),
  dbs: [],
  dbLogical: {}, // server-provided names for the logged-in account only
  dbAccessIssue: null,
  mode: ls('redx.mode', 'simple'), // simple | advanced
  theme: normTheme(ls('redx.theme', 'dark')), // dark (default) | system | light
};
const subs = new Set();
export const subscribe = (fn) => { subs.add(fn); return () => subs.delete(fn); };
const emit = () => subs.forEach((f) => f(state));

export function setDb(db) { state.db = db; accountLocal.setItem('redx.db', db); emit(); }
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
export const isHostAdmin = () => !!(state.who && state.who.host_admin);
// A regular, signed-in Red-XAI Account has its own hosted tenant; a host
// admin key is a distinct credential. Never use this to access owner routes.
export const isAccountTenant = () => !!(state.who && state.who.account && !state.who.owner && !state.who.host_admin);
export const canManageDatabases = () => isHostAdmin() || isAccountTenant();
export const dbDisplayName = (db) => state.dbLogical[db] || db;
let identityGeneration = 0;
let whoSequence = 0;
export const identityOf = (who) => !who ? '' : JSON.stringify([
  who.account?.sub ? 'account:' + (who.account.storage_subject ?? who.account.sub) : 'key:' + (who.id || ''),
  who.owner === true, who.host_admin === true, who.scope || '', who.roles || [],
]);
function clearAccountState() {
  identityGeneration++;
  invalidateRequests();
  state.who = null;
  state.status = null;
  state.dbs = [];
  state.dbLogical = {};
  state.db = 'default';
  state.dbAccessIssue = null;
}
export function resetAccountState() {
  whoSequence++;
  clearAccountState();
  setAccountStorageScope(websiteAuthentication() ? '' : null);
  emit();
}

export async function loadDbs() {
  const generation = identityGeneration;
  try {
    const r = await api('GET', '/v1/dbs');
    if (generation !== identityGeneration) return state.dbs;
    state.dbs = Array.isArray(r.dbs) ? r.dbs : [];
    // Mapping is returned by the authenticated server, never guessed from a
    // physical database name and never retained across account switches.
    const logical = r.logical && typeof r.logical === 'object' && !Array.isArray(r.logical) ? r.logical : {};
    state.dbLogical = Object.fromEntries(state.dbs.map((d) => [d, typeof logical[d] === 'string' ? logical[d] : d]));
    state.dbAccessIssue = r.suspended ? 'suspended' : r.readonly ? 'readonly' : null;
    if (!state.dbs.includes(state.db)) state.db = state.dbs[0] || 'default';
  } catch (e) {
    if (generation !== identityGeneration) return state.dbs;
    // Never preserve another user's database list after logout or a forbidden
    // response. In particular, do not treat a paid-plan 403 as host admin.
    state.dbs = [];
    state.dbLogical = {};
    state.db = 'default';
    state.dbAccessIssue = e.status === 403 || e.status === 402 ? 'plan_required' : 'unavailable';
  }
  emit();
  return state.dbs;
}
export async function loadWho() {
  const sequence = ++whoSequence;
  let who;
  try { who = await api('GET', '/v1/ui/whoami', { noAuthRedirect: true }); }
  catch (e) { if (sequence === whoSequence && websiteAuthentication()) resetAccountState(); throw e; }
  if (sequence !== whoSequence) throw new Error('The account check was superseded.');
  if (websiteAuthentication() && (!who?.account?.sub || typeof who.account.sub !== 'string')) {
    resetAccountState();
    throw new Error('The website account could not be verified.');
  }
  if (identityOf(who) !== identityOf(state.who)) {
    clearAccountState();
    setAccountStorageScope(who?.account?.storage_subject ?? who?.account?.sub ?? null);
    state.db = accountLocal.getItem('redx.db') || 'default';
  }
  state.who = who;
  emit();
  return state.who;
}

// "Get started" checklist flags
export const gs = {
  get(k) { return accountLocal.getItem('redx.gs.' + k) === '1'; },
  set(k) { accountLocal.setItem('redx.gs.' + k, '1'); emit(); },
  reset() { ['db', 'record', 'query', 'key'].forEach((k) => accountLocal.removeItem('redx.gs.' + k)); emit(); },
  dismissed() { return accountLocal.getItem('redx.gs.dismissed') === '1'; },
  dismiss() { accountLocal.setItem('redx.gs.dismissed', '1'); emit(); },
};
export const wizard = {
  done() { return accountLocal.getItem('redx.wizard') === 'done'; },
  finish() { accountLocal.setItem('redx.wizard', 'done'); },
};

/** BoxQL file stem for a data file name: players.red-xai.db -> players */
export function fileStem(name) {
  return name.replace(/\.red-xai-db-qs-ls$|\.red-xai-db-qs$|\.red-xai\.db$|\.red-xai-db$|\.red-xai-db-link$/, '');
}
export const ID_RE = /^[a-z0-9][a-z0-9_-]{0,62}$/;

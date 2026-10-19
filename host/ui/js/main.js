import { h, icon, mount, toast, $, clear } from './util.js';
import { api, session, setUnauthorizedHandler, exchangePairingCode } from './api.js';
import { state, subscribe, setMode, setTheme, setDb, applyTheme, loadWho, loadDbs, isHostAdmin, wizard } from './state.js';

const NAV = [
  { id: 'dashboard', title: 'Dashboard', icon: 'home' },
  { id: 'databases', title: 'Databases', icon: 'db' },
  { id: 'data', title: 'Data Explorer', icon: 'table' },
  { id: 'studio', title: 'BoxQL Studio', icon: 'terminal' },
  { id: 'keys', title: 'API Keys', icon: 'key' },
  { id: 'devices', title: 'Add a device', icon: 'phone' },
  { id: 'apps', title: 'Connected apps', icon: 'link' },
  { id: 'backups', title: 'Backups', icon: 'backup' },
  { id: 'settings', title: 'Settings', icon: 'gear' },
  { id: 'help', title: 'Help', icon: 'book' },
  { id: 'watch', title: 'Live Watch', icon: 'pulse', adv: true },
  { id: 'raw', title: 'Raw editor', icon: 'file', adv: true },
  { id: 'policy', title: 'Security · Rules · Code', icon: 'shield', adv: true },
  { id: 'cluster', title: 'Cluster & nodes', icon: 'nodes', adv: true },
  { id: 'presets', title: 'Presets', icon: 'compare', adv: true },
];
const PAGES = new Set([...NAV.map((n) => n.id), 'join', 'wizard', 'connect']);

const app = document.getElementById('app');
let current = null; // {destroy}

export function navigate(path) { location.hash = '#/' + path.replace(/^#?\/?/, ''); }
export function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [p, qs] = raw.split('?');
  const [page, ...rest] = p.split('/');
  return { page: page || 'dashboard', args: rest.map(decodeURIComponent), query: Object.fromEntries(new URLSearchParams(qs || '')) };
}

setUnauthorizedHandler(() => {
  if (!state.who) return;
  session.clear();
  state.who = null;
  showLogin('Your key was rejected or has been revoked. Please sign in again.');
});

// ---------- boot ----------
async function boot() {
  applyTheme();
  matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => state.theme === 'system' && applyTheme());
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
  // pairing link:  #/login?code=RP-XXXXX-XXXXX  (from a QR code; the code is single-use, expires in 5 minutes and is not a key.
  // The fragment is never sent to a server and is removed from the address bar before the exchange.)
  const dl = parseHash();
  if (dl.page === 'login' && dl.query.code) {
    history.replaceState(null, '', location.pathname);
    try {
      session.set(await exchangePairingCode(dl.query.code), true);
    } catch (e) {
      return showLogin(e.status === 401 || e.status === 429 || e.status === 409 ? e.message : 'Could not use that pairing code: ' + e.message);
    }
  }
  // a join link does not need a login
  if (dl.page === 'join') {
    const { renderJoin } = await import('./pages/auth.js');
    clear(app);
    app.className = 'plain';
    app.append(renderJoin(dl.query));
    return;
  }
  let needs = false;
  try { needs = (await api('GET', '/v1/ui/bootstrap-status', { noAuthRedirect: true })).needsSetup; } catch { /* host unreachable: login shows the error */ }
  if (needs) return showWelcome();
  if (!session.key) return showLogin();
  try {
    await loadWho();
  } catch (e) {
    session.clear();
    return showLogin(e.status === 401 ? 'That key is not valid (anymore).' : e.message);
  }
  await startShell();
}

export async function showWelcome() {
  const { renderWelcome } = await import('./pages/auth.js');
  clear(app);
  app.className = 'plain';
  app.append(renderWelcome(async () => { await loadWho(); await startShell(true); }));
}
export async function showLogin(msg) {
  const { renderLogin } = await import('./pages/auth.js');
  clear(app);
  app.className = 'plain';
  app.append(renderLogin(msg, async () => { await loadWho(); await startShell(); }));
}

// ---------- shell ----------
let shell;
export async function startShell(firstRun = false) {
  if (isHostAdmin()) { try { state.status = await api('GET', '/v1/admin/status'); } catch { /* ignore */ } }
  await loadDbs();
  clear(app);
  app.className = 'shell';
  shell = buildShell();
  app.append(shell.root);
  window.removeEventListener('hashchange', route);
  window.addEventListener('hashchange', route);
  // a connect link (#/connect?...) must survive the first-run setup and sign-in: never send it to the wizard
  const connecting = parseHash().page === 'connect';
  if (!connecting && (firstRun || (!wizard.done() && isHostAdmin() && state.dbs.length <= 1 && (!location.hash || location.hash === '#/')))) {
    location.hash = '#/wizard';
  }
  route();
}

/** Dark / System / Light switcher (radio group). The choice is stored in localStorage and survives reloads. */
function themeSwitcher() {
  const opts = [['dark', 'moon', 'Dark'], ['system', 'monitor', 'System (follow the device)'], ['light', 'sun', 'Light']];
  const grp = h('div', { class: 'theme-seg', role: 'radiogroup', 'aria-label': 'Colour theme' });
  const btns = opts.map(([v, ic, label]) => h('button', { class: 'theme-opt', role: 'radio', type: 'button', 'data-theme-opt': v, title: label, 'aria-label': label, onclick: () => setTheme(v) }, icon(ic, 16)));
  btns.forEach((b, i) => b.addEventListener('keydown', (e) => {
    const d = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? -1 : 0;
    if (!d) return;
    e.preventDefault();
    const n = btns[(i + d + btns.length) % btns.length];
    n.focus();
    setTheme(n.dataset.themeOpt);
  }));
  grp.append(...btns);
  grp.sync = () => btns.forEach((b) => { const on = b.dataset.themeOpt === state.theme; b.setAttribute('aria-checked', String(on)); b.tabIndex = on ? 0 : -1; });
  grp.sync();
  return grp;
}

function buildShell() {
  const nav = h('nav', { class: 'nav', 'aria-label': 'Main' });
  const side = h('aside', { class: 'side' },
    h('a', { class: 'brand', href: '#/dashboard' }, h('img', { src: '/ui/icons/redx-128.png', width: 34, height: 34, alt: '' }), h('span', null, h('b', null, 'RedX'), h('small', null, 'console'))),
    nav,
    h('div', { class: 'side-foot' }, h('span', { class: 'muted small', id: 'ver' }, 'v' + (state.who && state.who.version || ''))));
  const dbSel = h('select', { class: 'select', 'aria-label': 'Current database', onchange: (e) => setDb(e.target.value) });
  const modeBtn = h('button', { class: 'seg', role: 'group', 'aria-label': 'Mode' },
    h('span', { class: 'seg-opt', 'data-m': 'simple', onclick: () => setMode('simple') }, 'Simple'),
    h('span', { class: 'seg-opt', 'data-m': 'advanced', onclick: () => setMode('advanced') }, 'Advanced'));
  modeBtn.title = 'Simple shows the everyday pages; Advanced adds Live Watch, Raw editor, Security, Cluster and Presets';
  const themeBtn = themeSwitcher();
  const who = h('button', { class: 'chip who', title: 'Sign out', onclick: signOut });
  const menu = h('button', { class: 'icon-btn menu-btn', 'aria-label': 'Menu', onclick: () => root.classList.toggle('open') }, icon('menu'));
  const top = h('header', { class: 'top' }, menu, h('div', { class: 'grow' }), h('label', { class: 'dbpick' }, h('span', { class: 'muted small' }, 'Database'), dbSel), modeBtn, themeBtn, who);
  const main = h('main', { class: 'main', id: 'main', tabindex: '-1' });
  const scrim = h('div', { class: 'scrim', onclick: () => root.classList.remove('open') });
  const root = h('div', { class: 'frame' }, side, scrim, h('div', { class: 'col' }, top, main));
  function refresh() {
    clear(nav);
    const mk = (n) => h('a', { class: 'nav-item', href: '#/' + n.id, 'data-id': n.id, onclick: () => root.classList.remove('open') }, icon(n.icon, 18), h('span', null, n.title));
    NAV.filter((n) => !n.adv).forEach((n) => nav.append(mk(n)));
    nav.append(h('div', { class: 'nav-sep' }, state.mode === 'advanced' ? 'Advanced' : h('a', { href: '#', onclick: (e) => { e.preventDefault(); setMode('advanced'); } }, 'Show advanced pages')));
    if (state.mode === 'advanced') NAV.filter((n) => n.adv).forEach((n) => nav.append(mk(n)));
    clear(dbSel);
    (state.dbs.length ? state.dbs : [state.db]).forEach((d) => dbSel.append(h('option', { value: d, selected: d === state.db }, d)));
    modeBtn.querySelectorAll('.seg-opt').forEach((o) => o.classList.toggle('on', o.dataset.m === state.mode));
    themeBtn.sync();
    mount(who, state.who ? (state.who.label || state.who.id) + ' · ' + state.who.scope : '');
    markActive();
  }
  function markActive() {
    const p = parseHash().page;
    nav.querySelectorAll('.nav-item').forEach((a) => a.classList.toggle('active', a.dataset.id === p));
  }
  subscribe(refresh);
  refresh();
  return { root, main, refresh, markActive };
}

async function signOut() {
  session.clear();
  state.who = null;
  location.hash = '';
  location.reload();
}

let routeSeq = 0;
async function route() {
  if (!shell) return;
  const seq = ++routeSeq;
  const { page, args, query } = parseHash();
  const id = PAGES.has(page) ? page : 'dashboard';
  shell.markActive();
  if (current && current.destroy) { try { current.destroy(); } catch { /* ignore */ } }
  current = null;
  const main = shell.main;
  mount(main, h('div', { class: 'loading' }, h('span', { class: 'spin' }), 'Loading…'));
  document.title = (NAV.find((n) => n.id === id)?.title || (id === 'connect' ? 'Connect an app' : 'RedX')) + ' · RedX Console';
  try {
    const mod = await import('./pages/' + id + '.js');
    if (seq !== routeSeq) return;
    const view = await mod.default({ args, query, state, navigate, refreshShell: () => shell.refresh() });
    if (seq !== routeSeq) { if (view && view.destroy) view.destroy(); return; }
    clear(main);
    if (view instanceof Node) main.append(view);
    else if (view) { main.append(view.el); current = view; }
    main.scrollTop = 0;
    main.focus({ preventScroll: true });
  } catch (e) {
    if (seq !== routeSeq) return;
    console.error(e);
    mount(main, h('div', { class: 'errbox', role: 'alert' }, icon('alert', 18), h('div', null, h('strong', null, 'This page failed to load'), h('div', null, e.message || String(e)))));
  }
}

boot().catch((e) => {
  console.error(e);
  mount(app, h('div', { class: 'plain-card' }, h('h2', null, 'The console could not start'), h('p', null, e.message || String(e))));
});

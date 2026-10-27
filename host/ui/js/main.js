import { h, icon, mount, toast, $, clear } from './util.js';
import { api, session, setUnauthorizedHandler, exchangePairingCode } from './api.js';
import { state, subscribe, setMode, setTheme, setDb, applyTheme, loadWho, loadDbs, isHostAdmin, dbDisplayName, wizard } from './state.js';

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
  // These are customer destinations, not owner routes. The actual Host
  // service independently authenticates each request.
  { id: 'redxai-apps', title: 'All Red-XAI apps', icon: 'link', external: 'https://red-xai.com/store' },
  { id: 'redxai-host', title: 'Red-XAI Host', icon: 'nodes', external: 'https://red-xai.com/hosting' },
  { id: 'watch', title: 'Live Watch', icon: 'pulse', adv: true },
  { id: 'raw', title: 'Raw editor', icon: 'file', adv: true },
  { id: 'policy', title: 'Security · Rules · Code', icon: 'shield', adv: true },
  { id: 'cluster', title: 'Cluster & nodes', icon: 'nodes', adv: true },
  { id: 'presets', title: 'Presets', icon: 'compare', adv: true },
  { id: 'owner', title: 'Owner', icon: 'shield', owner: true },
];
const PAGES = new Set([...NAV.filter((n) => !n.external).map((n) => n.id), 'join', 'wizard', 'connect']);

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
  // back from Red-XAI Accounts: #/signin?handoff=<single-use code> (or ?error=<code>). The code is traded once for a
  // console session and removed from the address bar first.
  if (dl.page === 'signin') {
    history.replaceState(null, '', location.pathname);
    const { SIGNIN_ERRORS } = await import('./pages/account.js');
    if (dl.query.error) return showLogin(SIGNIN_ERRORS[dl.query.error] || 'The sign-in did not work. Please try again.');
    try {
      const r = await api('POST', '/v1/auth/handoff', { key: '', noAuthRedirect: true, json: { code: dl.query.handoff || '' } });
      session.set(r.token, false);
      if (dl.query.return && /^[a-z0-9/-]{1,64}$/.test(dl.query.return)) history.replaceState(null, '', location.pathname + '#/' + dl.query.return);
    } catch (e) {
      return showLogin(e.message);
    }
  }
  if (dl.page === 'signup' && !session.key) {
    const { renderSignup } = await import('./pages/account.js');
    clear(app);
    app.className = 'plain';
    app.append(renderSignup(() => { location.hash = ''; showLogin(); }));
    return;
  }
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
  if (!session.key) {
    // The first visit through the native Red-XAI Hub performs exactly one
    // account OIDC redirect. If the user has an existing site session the
    // provider returns directly, without asking for a DB key or pairing code.
    // The tab-local marker prevents login redirect loops if the provider is
    // unavailable or explicitly denied.
    if (location.pathname.startsWith('/v1/console/')) {
      try {
        const cfg = await api('GET', '/v1/auth/config', { key: '', noAuthRedirect: true });
        if (cfg.enabled && sessionStorage.getItem('redx.hub.autoSSO') !== 'attempted') {
          sessionStorage.setItem('redx.hub.autoSSO', 'attempted');
          location.assign('/v1/auth/login?console=hub&return=dashboard');
          return;
        }
      } catch { /* sign-in screen offers account retry and a helpful error */ }
    }
    return showLogin();
  }
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
  // The Red-XAI workspace is one native console. All pages and actions keep
  // their existing handlers; only navigation, discovery and layout change.
  const nav = h('nav', { class: 'nav hub-navigation', 'aria-label': 'Red-XAI workspace' });
  const navSearch = h('input', {
    class: 'input hub-nav-search', type: 'search', placeholder: 'Find a tool…',
    autocomplete: 'off', 'aria-label': 'Find a Red-XAI workspace tool',
    oninput: () => refreshNav()
  });
  const side = h('aside', { class: 'side' },
    h('a', { class: 'brand', href: '#/dashboard', title: 'Red-XAI Home' },
      h('img', { src: './icons/redx-128.png', width: 44, height: 44, alt: '' }),
      h('span', null, h('b', null, 'RED-XAI'), h('small', null, 'YOUR DEVELOPMENT HUB'))),
    h('div', { class: 'hub-side-search' }, icon('search', 15), navSearch),
    nav,
    h('div', { class: 'side-foot' },
      h('div', { class: 'hub-side-status' }, h('span', { class: 'workspace-pulse', 'aria-hidden': 'true' }), 'Red-XAI workspace'),
      h('span', { class: 'muted small', id: 'ver' }, 'v' + (state.who && state.who.version || ''))));
  const dbSel = h('select', { class: 'select', 'aria-label': 'Active database',
    onchange: e => setDb(e.target.value) });
  const modeBtn = h('button', { class: 'seg', role: 'group', 'aria-label': 'Developer tools mode' },
    h('span', { class: 'seg-opt', 'data-m': 'simple', onclick: () => setMode('simple') }, 'Essentials'),
    h('span', { class: 'seg-opt', 'data-m': 'advanced', onclick: () => setMode('advanced') }, 'All tools'));
  modeBtn.title = 'All tools adds raw records, cluster status, rules, watch and presets';
  const themeBtn = themeSwitcher();
  const who = h('button', { class: 'chip who hub-profile', title: 'Sign out of Red-XAI console',
    onclick: signOut });
  const menu = h('button', { class: 'icon-btn menu-btn', 'aria-label': 'Toggle navigation',
    onclick: () => root.classList.toggle('open') }, icon('menu', 18));
  const workspaceTitle = h('span', { class: 'workspace-topline' },
    h('span', { class: 'workspace-pulse', 'aria-hidden': 'true' }),
    'RED-XAI', h('span', { class: 'workspace-slash' }, '/'), 'WORKSPACE');
  const createDB = h('button', { class: 'btn primary small hub-create',
    title: 'Create your database', onclick: () => navigate('databases') },
    icon('plus', 15), ' New database');
  const top = h('header', { class: 'top hub-toolbar' }, menu, workspaceTitle,
    h('div', { class: 'grow' }),
    h('label', { class: 'dbpick' },
      h('span', { class: 'muted small' }, 'Database'), dbSel),
    createDB, modeBtn, themeBtn, who);
  const main = h('main', { class: 'main', id: 'main', tabindex: '-1' });
  const scrim = h('div', { class: 'scrim', onclick: () => root.classList.remove('open') });
  const root = h('div', { class: 'frame hub-frame' },
    side, scrim, h('div', { class: 'col' }, top, main));

  const groups = [
    ['START HERE', ['dashboard']],
    ['YOUR WORKSPACE', ['databases', 'data', 'studio', 'backups']],
    ['APPS & INTEGRATIONS', ['redxai-apps', 'redxai-host', 'apps', 'devices', 'keys']],
    ['TOOLS', ['settings', 'help']],
  ];
  function itemLink(n) {
    // Red-XAI links always stay on the owned website: no localhost, raw
    // server IP or third-party dashboard entry points in user-facing nav.
    const attrs = {
      class: 'nav-item',
      href: n.external || '#/' + n.id,
      'data-id': n.id,
      onclick: () => root.classList.remove('open')
    };
    if (n.external) attrs.rel = 'noopener noreferrer';
    return h('a', attrs, icon(n.icon, 18), h('span', null, n.title));
  }
  function refreshNav() {
    clear(nav);
    const term = navSearch.value.trim().toLowerCase();
    const byID = id => NAV.find(n => n.id === id);
    for (const [title, ids] of groups) {
      const items = ids.map(byID).filter(n => n && (!n.owner || (state.who && state.who.owner))
        && (!term || n.title.toLowerCase().includes(term)));
      if (!items.length) continue;
      nav.append(h('div', { class: 'nav-sep hub-nav-group' }, title));
      nav.append(...items.map(itemLink));
    }
    if (state.mode === 'advanced' || term) {
      const advanced = NAV.filter(n => n.adv && (!term || n.title.toLowerCase().includes(term)));
      if (advanced.length) {
        nav.append(h('div', { class: 'nav-sep hub-nav-group' }, 'ADVANCED'));
        nav.append(...advanced.map(itemLink));
      }
    } else {
      nav.append(h('button', { class: 'hub-show-advanced',
        onclick: () => setMode('advanced') }, icon('plus', 14), 'Show all developer tools'));
    }
    if (state.who && state.who.owner && (!term || 'owner'.includes(term))) {
      nav.append(h('div', { class: 'nav-sep hub-nav-group' }, 'ACCOUNT ADMINISTRATION'));
      const item = NAV.find(n => n.id === 'owner');
      if (item) nav.append(itemLink(item));
    }
    if (term && !nav.querySelector('.nav-item')) {
      nav.append(h('p', { class: 'muted small hub-nav-empty' }, 'No matching tools'));
    }
    markActive();
  }
  function refresh() {
    refreshNav();
    clear(dbSel);
    (state.dbs.length ? state.dbs : [state.db]).forEach(d =>
      dbSel.append(h('option', { value: d, selected: d === state.db }, dbDisplayName(d))));
    modeBtn.querySelectorAll('.seg-opt').forEach(o => o.classList.toggle('on', o.dataset.m === state.mode));
    themeBtn.sync();
    const acct = state.who && state.who.account;
    mount(who, !state.who ? '' :
      acct ? ((acct.username || acct.email) + (acct.owner ? ' · owner' : '')) :
      (state.who.label || state.who.id) + ' · ' + state.who.scope);
  }
  function markActive() {
    const page = parseHash().page;
    nav.querySelectorAll('.nav-item').forEach(a => {
      const active = a.dataset.id === page;
      a.classList.toggle('active', active);
      if (active) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });
  }
  subscribe(refresh);
  refresh();
  return { root, main, refresh, markActive };
}

async function signOut() {
  // A deliberate sign-out must not trigger immediate automatic sign-in on
  // the same still-authenticated browser session.
  try { sessionStorage.setItem('redx.hub.autoSSO', 'attempted'); } catch {}
  if (session.key.startsWith('rxs_')) { try { await api('POST', '/v1/auth/logout', { noAuthRedirect: true }); } catch { /* the session expires anyway */ } }
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

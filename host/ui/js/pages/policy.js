import { h, icon, terminalPanel, chip, mount, errorBox, spinner, emptyState } from '../util.js';
import { api, enc } from '../api.js';
import { state, isAdmin } from '../state.js';
import { pageHead, page, listFiles } from './shared.js';

const SECTIONS = [
  { id: 'sec', title: 'Security policy', ico: 'shield', url: 'sec', blurb: 'Who may read, write or delete what. Default is deny. Roles and rules apply to API keys that carry roles.', ftype: 'sec' },
  { id: 'pulse', title: 'Pulse rules', ico: 'pulse', url: 'pulse', blurb: 'Live rules and timers: "when Health reaches 0, mark the player dead and announce it".', ftype: 'pulse' },
  { id: 'code', title: 'Code scripts', ico: 'terminal', url: 'code', blurb: 'Small sandboxed scripts that run inside the database. They can only call the host functions they declare.', ftype: 'code' },
  { id: 'idx', title: 'Search indexes', ico: 'search', url: 'idx', blurb: 'Fast lookups and text search on fields you choose.', ftype: 'idx' },
];

export default async function render() {
  const db = state.db;
  const root = page();
  const grid = h('div', { class: 'grid g2' });
  root.append(pageHead('Security, rules and code', 'The rule files of ' + db + '. Summaries come from the running database; edit them in the raw editor.'), grid,
    terminalPanel([{ label: 'Security policy', cmd: 'redx sec show' }, { label: 'Pulse rules', cmd: 'redx pulse get' }, { label: 'Scripts', cmd: 'redx code ls' }, { label: 'Indexes', cmd: 'redx idx list' }]));
  mount(grid, spinner());
  let files = [];
  try { files = (await listFiles(db)).files; } catch { /* non-admin */ }
  const cards = await Promise.all(SECTIONS.map(async (s) => {
    let info = null;
    let err = null;
    try { info = await api('GET', `/v1/db/${enc(db)}/${s.url}`); } catch (e) { err = e; }
    const mine = files.filter((f) => f.type === s.ftype);
    const active = err ? false : summarize(s.id, info);
    return h('div', { class: 'card' }, h('div', { class: 'row gap' }, h('h3', { style: { margin: 0 } }, icon(s.ico, 18), ' ', s.title), h('div', { class: 'grow' }), err ? chip(err.status === 404 || err.status === 501 ? 'not available' : 'no access', 'warn') : active.count > 0 ? chip(active.count + ' active', 'ok') : chip('none set', '')),
      h('p', { class: 'muted' }, s.blurb),
      active && active.names.length ? h('p', null, active.names.slice(0, 10).map((n) => h('code', { class: 'pill' }, n))) : null,
      mine.length ? h('div', null, mine.map((f) => h('div', { class: 'row gap' }, icon('file', 14), f.name, h('div', { class: 'grow' }), isAdmin() ? h('a', { class: 'btn small', href: '#/raw?db=' + enc(db) + '&file=' + enc(f.name) }, 'Edit') : null))) : null,
      isAdmin() ? h('div', { style: { marginTop: '8px' } }, h('a', { class: 'btn small', href: '#/raw?db=' + enc(db) }, mine.length ? 'Open in raw editor' : 'Create one')) : h('p', { class: 'muted small' }, 'Editing needs an admin key.'),
      err && err.status === 501 ? h('p', { class: 'muted small' }, 'This build of the host does not include that engine for this database.') : null);
  }));
  mount(grid, cards);
  return root;
}

function summarize(id, info) {
  const names = [];
  let count = 0;
  const walk = (v) => Array.isArray(v) ? v : v && typeof v === 'object' ? Object.values(v) : [];
  if (!info) return { count, names };
  if (id === 'sec') {
    for (const k of ['roles', 'scopes', 'rules', 'encrypt']) { const a = info[k]; const n = Array.isArray(a) ? a.length : typeof a === 'number' ? a : 0; count += n; if (Array.isArray(a)) a.forEach((x) => names.push(k.replace(/s$/, '') + ': ' + (x.name || x.Name || x.id || ''))); }
    if (info.loaded === true && !count) count = 1;
  } else {
    const list = info.rules || info.scripts || info.sets || info.timers || info.items || (Array.isArray(info) ? info : null);
    const arr = Array.isArray(list) ? list : walk(list);
    count = arr.length;
    arr.forEach((x) => names.push(typeof x === 'string' ? x : x.name || x.Name || x.id || ''));
  }
  return { count, names: names.filter(Boolean) };
}

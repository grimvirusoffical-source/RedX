import { h, icon, terminalPanel, fmtBytes, ago, chip, errorBox, spinner, mount, toast, confirmTyped, emptyState, field, table, dialog } from '../util.js';
import { api, enc } from '../api.js';
import { state, isHostAdmin, loadDbs, setDb, gs, ID_RE } from '../state.js';
import { pageHead, page, listFiles, typeChip } from './shared.js';
import { navigate } from '../main.js';

export default async function render() {
  const root = page();
  const list = h('div');
  const detail = h('div');
  const name = h('input', { class: 'input', placeholder: 'my-app', maxlength: 63, 'aria-label': 'New database name', autocomplete: 'off' });
  const err = h('div', { class: 'form-err', hidden: true });
  const create = async () => {
    const n = name.value.trim();
    err.hidden = true;
    if (!ID_RE.test(n)) { err.textContent = 'Use lower-case letters, digits, "-" and "_" (start with a letter or digit, up to 63 characters).'; err.hidden = false; return; }
    try {
      await api('POST', '/v1/dbs', { json: { name: n } });
      toast('Database "' + n + '" created', 'ok');
      gs.set('db');
      name.value = '';
      await loadDbs();
      setDb(n);
      await load();
      showDetail(n);
    } catch (e) { err.textContent = e.message; err.hidden = false; }
  };
  name.addEventListener('keydown', (e) => { if (e.key === 'Enter') create(); });
  root.append(pageHead('Databases', 'A database is a folder of files. Create one per app or project.'),
    isHostAdmin() ? h('div', { class: 'card', style: { marginBottom: '16px' } }, h('div', { class: 'row gap wrap' }, h('div', { style: { flex: 1, minWidth: '220px' } }, name), h('button', { class: 'btn primary', onclick: create }, icon('plus', 16), ' Create database')), err) : null,
    list, detail,
    terminalPanel([{ label: 'List', cmd: 'redx db list' }, { label: 'Create', cmd: 'redx db create my-app' }, { label: 'Delete (curl; permanent)', cmd: 'curl -X DELETE -H "Authorization: Bearer $REDX_KEY" "' + location.origin + '/v1/db/my-app?confirm=my-app"' }]));

  async function load() {
    mount(list, spinner());
    try {
      const dbs = await loadDbs();
      if (!dbs.length) { mount(list, emptyState('db', 'No databases yet', 'Create your first database above, or use the Setup wizard.', h('button', { class: 'btn primary', onclick: () => navigate('wizard') }, icon('wand', 16), ' Setup wizard'))); return; }
      const sizes = {};
      if (isHostAdmin()) await Promise.all(dbs.map(async (d) => { try { const f = await listFiles(d); sizes[d] = { n: f.files.filter((x) => ['db', 'qs', 'qs-ls', 'pack', 'media'].includes(x.type)).length, bytes: f.files.reduce((a, x) => a + x.size, 0) }; } catch { sizes[d] = null; } }));
      mount(list, table(['Name', 'Files', 'Size', '', ''], dbs.map((d) => h('tr', { class: 'click' + (d === state.db ? ' sel' : ''), onclick: () => showDetail(d) },
        h('td', null, h('b', null, d), d === (state.status && state.status.default_db) ? [' ', chip('default', 'acc')] : null),
        h('td', { class: 'muted' }, sizes[d] ? sizes[d].n + ' data' : '–'),
        h('td', { class: 'muted' }, sizes[d] ? fmtBytes(sizes[d].bytes) : '–'),
        h('td', null, d === state.db ? chip('selected', 'ok') : h('button', { class: 'btn small', onclick: (e) => { e.stopPropagation(); setDb(d); load(); } }, 'Use')),
        h('td', { class: 'num' }, isHostAdmin() && d !== (state.status && state.status.default_db) ? h('button', { class: 'icon-btn', title: 'Delete database', 'aria-label': 'Delete ' + d, onclick: (e) => { e.stopPropagation(); drop(d); } }, icon('trash', 16)) : null)))));
    } catch (e) { mount(list, errorBox(e.message, load)); }
  }
  async function drop(d) {
    if (!(await confirmTyped('Delete database "' + d + '"?', 'Every file in this database is deleted for good, and the deletion is copied to follower nodes. There is no undo. Make a backup first if you might need it.', d, 'Delete forever'))) return;
    try {
      await api('DELETE', `/v1/db/${enc(d)}?confirm=${enc(d)}`);
      toast('Deleted ' + d, 'ok');
      await loadDbs();
      await load();
      mount(detail);
    } catch (e) { toast(e.message, 'error'); }
  }
  async function showDetail(d) {
    if (!isHostAdmin()) { mount(detail, h('p', { class: 'muted' }, 'File details need an admin key.')); return; }
    mount(detail, h('div', { style: { marginTop: '18px' } }, spinner()));
    try {
      const r = await listFiles(d);
      const rows = r.files.filter((f) => !['journal', 'system'].includes(f.type));
      const aux = r.files.filter((f) => ['journal', 'system'].includes(f.type));
      mount(detail, h('div', { style: { marginTop: '22px' } }, h('h2', null, 'Files in ', h('code', null, d)),
        rows.length ? table(['File', 'Type', 'Size', 'Changed', ''], rows.map((f) => h('tr', null,
          h('td', null, h('b', null, f.name), f.dir ? ' /' : '', f.note ? h('div', { class: 'muted small' }, f.note) : null),
          h('td', null, typeChip(f.type)), h('td', { class: 'num' }, fmtBytes(f.size)), h('td', { class: 'muted' }, ago(f.modified)),
          h('td', null, f.records === 'records' ? h('a', { class: 'btn small', href: '#/data?db=' + enc(d) + '&file=' + enc(f.name) }, 'Open records') : f.records === 'raw' || f.records === 'raw-readonly' ? h('a', { class: 'btn small', href: '#/raw?db=' + enc(d) + '&file=' + enc(f.name) }, f.records === 'raw' ? 'Edit' : 'View') : null))))
          : emptyState('file', 'This database has no files yet', 'Files appear when you write the first record. Open the Data Explorer and press New record, or run an {Add[]} command in the BoxQL Studio.', h('a', { class: 'btn primary', href: '#/data' }, 'Add a record')),
        aux.length ? h('p', { class: 'muted small' }, 'Plus ', aux.length, ' engine file', aux.length === 1 ? '' : 's', ' (write-ahead log, lock) totalling ', fmtBytes(aux.reduce((a, x) => a + x.size, 0)), '. Never edit these.') : null));
    } catch (e) { mount(detail, errorBox(e.message, () => showDetail(d))); }
  }
  await load();
  if (state.db) showDetail(state.db);
  return root;
}

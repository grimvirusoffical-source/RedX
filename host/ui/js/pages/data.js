import { h, icon, terminalPanel, chip, errorBox, spinner, mount, toast, confirmDialog, emptyState, table, field, dialog, debounce, copy } from '../util.js';
import { api, enc, pathURL } from '../api.js';
import { state, fileStem, gs, setDb } from '../state.js';
import { pageHead, page, bx, listRecordFiles, parsePath, q, typeChip, getBox } from './shared.js';
import { createEditor } from '../editor.js';
import { parseErrorPos } from '../tokenizers.js';
import { looksSealed, secretsPanel, sealPlaintext, openPlaintext } from '../secrets.js';

const PAGE = 25;
const OPS = ['=', '!=', '<', '<=', '>', '>=', 'starts', 'has'];

function lit(v) {
  v = String(v).trim();
  if (/^-?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(v) || /^(TRUE|FALSE|NELL)$/i.test(v)) return v.toUpperCase() === v || /^-?\d/.test(v) ? v : v.toUpperCase();
  return q(v);
}
function cell(v) {
  const s = v === null ? 'NELL' : typeof v === 'string' ? v : JSON.stringify(v);
  return h('span', { class: 'cellv' + (v === null ? ' muted' : ''), title: s }, s);
}

export default async function render(ctx) {
  const db = ctx.query.db || state.db;
  if (db !== state.db) setDb(db);
  const root = page();
  const treeEl = h('div', { class: 'tree', role: 'tree', 'aria-label': 'Files, boxes and records' });
  const view = h('div');
  const files = [];
  const open = new Map(); // file name -> {boxes: Map(box -> count)} | 'loading'
  const sel = { file: null, box: null, offset: 0, filter: '', filters: [{ field: '', op: '=', value: '' }], cols: [] };
  let editor = null;
  let sig = 0;

  root.append(pageHead('Data Explorer', 'Browse files, boxes and records. Edit with a form or as text.', h('button', { class: 'btn primary', onclick: () => newRecord() }, icon('plus', 16), ' New record')),
    secretsPanel(db),
    h('div', { class: 'split' }, treeEl, view),
    terminalPanel([{ label: 'Read a record', cmd: "redx get 'players.red-xai.db:Player[ID=1]'" }, { label: 'Write a record', cmd: "redx set 'players.red-xai.db:Player[ID=1]' '[ {Name[]} = \"Ann\", {Level[]} = 7 ]'" }, { label: 'Delete', cmd: "redx delete 'players.red-xai.db:Player[ID=1]'" }, { label: 'List records (BoxQL)', cmd: "redx bx '{Get[]} = players:Player[ID=*] -> *, Limit = 25'" }, { label: 'Seal this value (does not write)', cmd: 'curl -sS -H "Authorization: Bearer $REDX_KEY" -H "Content-Type: application/json" -d \'{"password":"$REDX_SECRETS_PASSWORD","plaintext":"<box text>","path":"players.red-xai.db:Player[ID=1]"}\' "$REDX_ADDR/v1/db/default/secrets/seal"' }], 'The console uses the same API. Native paths look like file:Box[ID=n]. $REDX_SECRETS_PASSWORD is a data password, not your account password, and it is not stored.'));

  async function loadFiles() {
    mount(treeEl, spinner());
    try {
      const r = await listRecordFiles(db);
      files.length = 0;
      files.push(...r.files.filter((f) => f.records === 'records'));
      paintTree();
      if (!files.length) mount(view, emptyState('table', 'No data files yet', 'This database has no data files. Add your first record to create one.', h('button', { class: 'btn primary', onclick: () => newRecord() }, icon('plus', 16), ' New record')));
      else if (ctx.query.file) { const f = files.find((x) => x.name === ctx.query.file); if (f) await expand(f); }
      else mount(view, h('div', { class: 'empty' }, h('h3', null, 'Pick a file on the left'), h('p', { class: 'muted' }, 'Expand a file to see its boxes, then pick a box to see its records.')));
    } catch (e) {
      mount(treeEl, errorBox(e.status === 403 ? 'This key cannot list record files in this database.' : e.message, loadFiles));
    }
  }
  function paintTree() {
    mount(treeEl, files.map((f) => {
      const st = open.get(f.name);
      const nodes = [h('div', { class: 'tn' + (st ? ' open' : '') + (sel.file === f.name && !sel.box ? ' sel' : ''), role: 'treeitem', tabindex: 0, onclick: () => (st ? collapse(f) : expand(f)), onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); st ? collapse(f) : expand(f); } } },
        icon('chevron', 14).cloneNode(true) && h('span', { class: 'caret' }, icon('chevron', 14)), icon('table', 15), h('span', null, f.name), typeChip(f.type))];
      if (st === 'loading') nodes.push(h('div', { class: 'tn tl1 muted' }, 'loading…'));
      else if (st) {
        if (!st.boxes.size) nodes.push(h('div', { class: 'tn tl1 muted' }, 'empty'));
        for (const [b, n] of st.boxes) nodes.push(h('div', { class: 'tn tl1' + (sel.file === f.name && sel.box === b ? ' sel' : ''), tabindex: 0, role: 'treeitem', onclick: () => pick(f, b), onkeydown: (e) => { if (e.key === 'Enter') pick(f, b); } }, icon('db', 14), h('span', null, b), h('small', null, n + (st.truncated ? '+' : ''))));
      }
      return nodes;
    }));
  }
  function collapse(f) { open.delete(f.name); paintTree(); }
  async function refreshFilesOnly() {
    const r = await listRecordFiles(db);
    files.length = 0;
    files.push(...r.files.filter((f) => f.records === 'records'));
    paintTree();
  }
  async function expand(f, opts) {
    open.set(f.name, 'loading');
    sel.file = f.name;
    paintTree();
    try {
      const r = await bx(db, `{Get[]} = ${q(f.name)}:*[ID=*] -> [ID], Limit = 2000`);
      const boxes = new Map();
      for (const p of r.paths || []) { const pp = parsePath(p); if (pp) boxes.set(pp.box, (boxes.get(pp.box) || 0) + 1); }
      open.set(f.name, { boxes, truncated: (r.paths || []).length >= 2000 });
    } catch (e) {
      // "ID" may not be a projectable column on every engine build: fall back to all columns
      try {
        const r = await bx(db, `{Get[]} = ${q(f.name)}:*[ID=*] -> *, Limit = 2000`);
        const boxes = new Map();
        for (const p of r.paths || []) { const pp = parsePath(p); if (pp) boxes.set(pp.box, (boxes.get(pp.box) || 0) + 1); }
        open.set(f.name, { boxes, truncated: (r.paths || []).length >= 2000 });
      } catch (e2) { open.delete(f.name); toast(e2.message, 'error'); }
    }
    paintTree();
    if (opts && opts.quiet) return;
    const st = open.get(f.name);
    if (st && st !== 'loading' && st.boxes.size === 1) pick(f, [...st.boxes.keys()][0]);
  }
  function pick(f, box) { sel.file = f.name; sel.box = box; sel.offset = 0; sel.filter = ''; sel.filters = [{ field: '', op: '=', value: '' }]; paintTree(); showBox(); }

  async function showBox() {
    const my = ++sig;
    const stem = q(sel.file);
    const f = files.find((x) => x.name === sel.file);
    const filt = sel.filter ? sel.filter : 'ID=*';
    const bq = `{Get[]} = ${stem}:${sel.box}[${filt}] -> *, Limit = ${PAGE}, Offset = ${sel.offset}`;
    const cq = `{Get[]} = ${stem}:${sel.box}[${filt}] -> [n = Count()]`;
    mount(view, spinner());
    try {
      const [r, c] = await Promise.all([bx(db, bq), bx(db, cq).catch(() => null)]);
      if (my !== sig) return;
      const total = c && c.rows && c.rows[0] ? Number(c.rows[0][0]) : null;
      sel.cols = r.columns || [];
      const fb = filterBuilder();
      const rows = r.rows.map((row, i) => {
        const pp = parsePath(r.paths[i] || '');
        return h('tr', { class: 'click', onclick: () => showRecord(r.paths[i]) }, h('td', { class: 'mono' }, pp ? pp.id : '?'), r.columns.map((_, j) => h('td', null, cell(row[j]))));
      });
      mount(view, h('div', null,
        h('div', { class: 'row gap wrap', style: { marginBottom: '8px' } }, h('h2', { style: { margin: 0 } }, sel.box), typeChip(f ? f.type : ''), h('span', { class: 'muted' }, sel.file), h('div', { class: 'grow' }), total != null ? chip(total + ' record' + (total === 1 ? '' : 's')) : null),
        fb,
        rows.length ? table(['ID', ...r.columns], rows, 'compact') : emptyState('table', sel.filter ? 'No records match this filter' : 'No records in this box', null, sel.filter ? h('button', { class: 'btn', onclick: () => { sel.filter = ''; sel.filters = [{ field: '', op: '=', value: '' }]; showBox(); } }, 'Clear filter') : h('button', { class: 'btn primary', onclick: () => newRecord() }, 'New record')),
        h('div', { class: 'row gap', style: { margin: '10px 0' } },
          h('button', { class: 'btn small', disabled: sel.offset === 0, onclick: () => { sel.offset = Math.max(0, sel.offset - PAGE); showBox(); } }, '← Previous'),
          h('span', { class: 'muted small' }, r.rows.length ? `Showing ${sel.offset + 1}–${sel.offset + r.rows.length}` + (total != null ? ' of ' + total : '') : ''),
          h('button', { class: 'btn small', disabled: total != null ? sel.offset + PAGE >= total : r.rows.length < PAGE, onclick: () => { sel.offset += PAGE; showBox(); } }, 'Next →')),
        h('div', { id: 'recpane' })));
    } catch (e) { if (my === sig) mount(view, errorBox(e.message, showBox)); }
  }

  function filterBuilder() {
    const rowsEl = h('div', { class: 'filters' });
    const gen = h('code', { class: 'cellv', style: { maxWidth: '100%' } });
    const stem = q(sel.file);
    const build = () => {
      const parts = sel.filters.filter((x) => x.field && x.value !== '').map((x) => (x.op === 'starts' || x.op === 'has' ? `${x.field} ${x.op} ${lit(x.value)}` : `${x.field} ${x.op} ${lit(x.value)}`));
      sel.filterNew = parts.join(' & ');
      gen.textContent = `{Get[]} = ${stem}:${sel.box}[${sel.filterNew || 'ID=*'}] -> *`;
    };
    const paint = () => {
      mount(rowsEl, sel.filters.map((f, i) => h('div', { class: 'frow' },
        h('input', { class: 'input', list: 'cols', placeholder: 'field', value: f.field, 'aria-label': 'Field', oninput: (e) => { f.field = e.target.value; build(); } }),
        h('select', { class: 'select', 'aria-label': 'Operator', onchange: (e) => { f.op = e.target.value; build(); } }, OPS.map((o) => h('option', { value: o, selected: o === f.op }, o))),
        h('input', { class: 'input', placeholder: 'value', value: f.value, 'aria-label': 'Value', oninput: (e) => { f.value = e.target.value; build(); }, onkeydown: (e) => { if (e.key === 'Enter') apply(); } }),
        sel.filters.length > 1 ? h('button', { class: 'icon-btn', 'aria-label': 'Remove condition', onclick: () => { sel.filters.splice(i, 1); paint(); build(); } }, icon('x', 14)) : null)));
    };
    const apply = () => { build(); sel.filter = sel.filterNew; sel.offset = 0; showBox(); };
    paint();
    build();
    return h('details', { class: 'card', style: { marginBottom: '12px', padding: '10px 14px' }, open: sel.filter ? true : null },
      h('summary', { style: { cursor: 'pointer', fontWeight: 600 } }, icon('search', 15), ' Filter builder ', sel.filter ? chip('active', 'acc') : null),
      h('datalist', { id: 'cols' }, sel.cols.map((c) => h('option', { value: c }))),
      h('div', { style: { marginTop: '10px' } }, rowsEl,
        h('div', { class: 'row gap wrap', style: { marginTop: '8px' } }, h('button', { class: 'btn small', onclick: () => { sel.filters.push({ field: '', op: '=', value: '' }); paint(); } }, icon('plus', 14), ' Add condition (AND)'), h('button', { class: 'btn small primary', onclick: apply }, 'Apply filter'),
          sel.filter ? h('button', { class: 'btn small', onclick: () => { sel.filter = ''; sel.filters = [{ field: '', op: '=', value: '' }]; sel.offset = 0; showBox(); } }, 'Clear') : null,
          h('button', { class: 'btn small', onclick: () => { build(); sessionStorage.setItem('redx.studio.q', gen.textContent); location.hash = '#/studio'; } }, 'Open in BoxQL Studio')),
        h('div', { style: { marginTop: '8px' } }, h('span', { class: 'muted small' }, 'BoxQL: '), gen)));
  }

  async function showRecord(path, isNew = false, file, box, id) {
    const pane = document.getElementById('recpane') || view;
    const fileName = file || sel.file;
    const stem = q(fileName);
    let mode = 'box';
    let text = '';
    let ttl = '';
    let sliding = false;
    const ft = (files.find((x) => x.name === fileName) || {}).type;
    const needsTTL = ft === 'qs' || ft === 'qs-ls';
    if (!isNew) {
      try { text = await getBox(db, path); }
      catch (e) { return toast(e.message, 'error'); }
    } else {
      path = `${fileName}:${box}[ID=${id}]`;
      text = '[\n    {Name[]} = "",\n    {Value[]} = 0\n]';
      if (needsTTL) ttl = '3600';
    }
    const heading = h('h3', { style: { margin: 0 } }, isNew ? 'New record' : 'Record');
    const msg = h('div', { class: 'form-err', hidden: true });
    const modeSel = h('div', { class: 'seg' }, ['box', 'json'].map((m) => h('span', { class: 'seg-opt' + (m === mode ? ' on' : ''), onclick: () => switchMode(m) }, m === 'box' ? 'Box text' : 'JSON')));
    editor = createEditor({ language: 'box', value: text, height: '260px', onSave: save, onChange: debounce(validate, 450) });
    const ttlIn = h('input', { class: 'input', type: 'number', min: 0, placeholder: 'seconds', value: ttl, 'aria-label': 'Time to live in seconds', style: { width: '140px' } });
    const slide = h('input', { type: 'checkbox', checked: sliding });
    async function validate() {
      if (mode !== 'box') return;
      try {
        const r = await api('POST', '/v1/ui/validate', { json: { kind: 'value', text: editor.getValue() } });
        editor.setDiagnostics(r.ok ? [] : [{ line: r.line || 1, col: r.col || 1, message: r.message || r.error }]);
      } catch { /* ignore */ }
    }
    async function switchMode(m) {
      if (m === mode) return;
      if (editor.getValue() !== text && !isNew && !(await confirmDialog('Discard your changes?', 'Switching the view reloads the record and drops edits you have not saved.', { ok: 'Discard' }))) return;
      try {
        if (m === 'json') {
          const r = await bx(db, `{Get[]} = ${stem}:${box || parsePath(path).box}[ID=${id || parsePath(path).id}] -> *`);
          const o = {};
          (r.columns || []).forEach((c, i) => { o[c] = r.rows[0] ? r.rows[0][i] : null; });
          editor.setValue(JSON.stringify(o, null, 2));
        } else if (!isNew) {
          editor.setValue(await getBox(db, path));
        }
      } catch (e) { return toast(e.message, 'error'); }
      mode = m;
      text = editor.getValue();
      modeSel.querySelectorAll('.seg-opt').forEach((o, i) => o.classList.toggle('on', (i === 0) === (m === 'box')));
      editor.setDiagnostics([]);
    }
    async function save() {
      msg.hidden = true;
      const body = {};
      if (mode === 'box') body.box = editor.getValue();
      else { try { body.value = JSON.parse(editor.getValue()); } catch (e) { msg.textContent = 'Not valid JSON: ' + e.message; msg.hidden = false; return; } }
      const qs = [];
      if (ttlIn.value) qs.push('ttl=' + enc(ttlIn.value));
      if (slide.checked) qs.push('sliding=true');
      try {
        await api('PUT', pathURL(db, path) + (qs.length ? '?' + qs.join('&') : ''), { json: body });
        toast('Saved ' + path, 'ok');
        gs.set('record');
        text = editor.getValue();
        isNew = false;
        heading.textContent = 'Record';
        delBtn.hidden = false;
        await refreshFilesOnly();
        const f = files.find((x) => x.name === fileName);
        if (f) await expand(f, { quiet: true });
      } catch (e) {
        msg.textContent = e.message;
        msg.hidden = false;
        const p = parseErrorPos(e.message);
        if (p && mode === 'box') editor.setDiagnostics([{ line: p.line, col: p.col, message: e.message }]);
      }
    }
    async function seal() {
      if (mode !== 'box') { toast('Switch to Box text to seal this record.', 'info'); return; }
      const boxText = await sealPlaintext(db, path, editor.getValue());
      if (!boxText) return;
      editor.setValue(boxText);
      toast('Sealed in the editor. Nothing was written. Press Save to store this envelope on this record only.', 'ok');
    }
    async function openSeal() {
      if (mode !== 'box') { toast('Switch to Box text to open a seal.', 'info'); return; }
      if (!looksSealed(editor.getValue())) { toast('This record is not a Red-SecretsXAI envelope.', 'info'); return; }
      const pt = await openPlaintext(db, path, editor.getValue());
      if (pt == null) return;
      editor.setValue(pt);
      toast('Opened in the editor. Nothing was written. Save would store this plaintext for this record only. Other sealed data was not modified.', 'ok');
    }
    const delBtn = h('button', { class: 'btn danger', hidden: isNew || undefined, onclick: del }, icon('trash', 15), ' Delete');
    async function del() {
      if (!(await confirmDialog('Delete this record?', path, { danger: true, ok: 'Delete' }))) return;
      try { await api('DELETE', pathURL(db, path)); toast('Deleted', 'ok'); mount(pane); await loadFiles(); const f = files.find((x) => x.name === sel.file); if (f) { open.delete(f.name); await expand(f); if (sel.box) showBox(); } } catch (e) { toast(e.message, 'error'); }
    }
    mount(pane, h('div', { class: 'card', style: { marginTop: '8px' } },
      h('div', { class: 'row gap wrap', style: { marginBottom: '10px' } }, heading, h('code', null, path), h('div', { class: 'grow' }), modeSel),
      editor.el, msg,
      h('div', { class: 'row gap wrap', style: { marginTop: '10px' } },
        h('label', { class: 'row gap' }, h('span', { class: 'muted small' }, 'Expires after'), ttlIn, needsTTL ? chip('required for this file', 'warn') : h('span', { class: 'muted small' }, 'optional')),
        h('label', { class: 'check', style: { margin: 0 } }, slide, ' sliding (reset on read)'),
        h('div', { class: 'grow' }),
        h('button', { class: 'btn', onclick: seal, title: 'Seal the Box text in the editor. Does not write.' }, icon('lock', 15), ' Seal'),
        h('button', { class: 'btn', onclick: openSeal, title: 'Open a Red-SecretsXAI envelope in the editor. Does not write.' }, 'Open'),
        delBtn,
        h('button', { class: 'btn', onclick: () => copy(path, 'Path copied') }, 'Copy path'), h('button', { class: 'btn primary', onclick: save }, 'Save ', h('kbd', null, 'Ctrl+S'))),
      terminalPanel([{ cmd: `redx get '${path}'` }, { cmd: `redx set '${path}' '<box text>'${ttl ? ' --ttl ' + ttl : ''}` }, { cmd: `redx delete '${path}'` }, { label: 'Seal (does not write)', cmd: `curl -sS -H "Authorization: Bearer $REDX_KEY" -H "Content-Type: application/json" -d '{"password":"$REDX_SECRETS_PASSWORD","plaintext":"<box text>","path":"${path}"}' "$REDX_ADDR/v1/db/${db}/secrets/seal"` }], '$REDX_SECRETS_PASSWORD is a placeholder for the data password. It is not your account password and it is not stored.')));
    pane.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    if (!isNew) validate();
  }

  async function newRecord() {
    if (!files.length) {
      const name = h('input', { class: 'input', value: 'players.red-xai.db', 'aria-label': 'File name' });
      const box = h('input', { class: 'input', value: 'Player', 'aria-label': 'Box name' });
      const idIn = h('input', { class: 'input', value: '1', 'aria-label': 'ID' });
      const r = await dialog({ title: 'Create the first record', body: h('div', null, h('p', { class: 'muted' }, 'A file is created when you write its first record. File types: ', h('code', null, '.red-xai.db'), ' (durable), ', h('code', null, '.red-xai-db-qs'), ' (expiring), ', h('code', null, '.red-xai-db-qs-ls'), ' (expiring, journaled).'), field('File', name), field('Box', box), field('ID', idIn)), actions: [{ id: 'cancel', label: 'Cancel' }, { id: 'ok', label: 'Continue', primary: true }] });
      if (r !== 'ok') return;
      if (!files.find((f) => f.name === name.value)) files.push({ name: name.value, type: /qs-ls$/.test(name.value) ? 'qs-ls' : /qs$/.test(name.value) ? 'qs' : 'db', records: 'records' });
      mount(view, h('div', { id: 'recpane' }));
      return showRecord(null, true, name.value, box.value, idIn.value);
    }
    const fsel = h('select', { class: 'select', 'aria-label': 'File' }, files.map((f) => h('option', { value: f.name, selected: f.name === sel.file }, f.name)));
    const known = [...(open.get(sel.file) && open.get(sel.file) !== 'loading' ? open.get(sel.file).boxes.keys() : [])];
    const box = h('input', { class: 'input', value: sel.box || known[0] || 'Item', 'aria-label': 'Box name' });
    const idIn = h('input', { class: 'input', value: '', placeholder: 'auto', 'aria-label': 'ID' });
    const r = await dialog({ title: 'New record', body: h('div', null, field('File', fsel), field('Box', box, 'A box groups records of one kind, for example Player.'), field('ID', idIn, 'Leave empty to use the next free number.')), actions: [{ id: 'cancel', label: 'Cancel' }, { id: 'ok', label: 'Continue', primary: true }] });
    if (r !== 'ok') return;
    let id = idIn.value.trim();
    if (!id) {
      try { const rr = await bx(db, `{Get[]} = ${q(fsel.value)}:${box.value}[ID=*] -> [ID]`); id = String(Math.max(0, ...(rr.paths || []).map((p) => Number((parsePath(p) || {}).id) || 0)) + 1); } catch { id = '1'; }
    }
    if (!document.getElementById('recpane')) mount(view, h('div', { id: 'recpane' }));
    showRecord(null, true, fsel.value, box.value, id);
  }

  await loadFiles();
  return { el: root, destroy() {} };
}

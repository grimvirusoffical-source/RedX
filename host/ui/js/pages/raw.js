import { h, icon, terminalPanel, chip, mount, toast, dialog, field, copy, download, errorBox, spinner, confirmDialog, emptyState, debounce, fmtBytes, ago } from '../util.js';
import { api, enc } from '../api.js';
import { state, setDb } from '../state.js';
import { pageHead, page, listFiles, typeChip, getBox } from './shared.js';
import { createEditor } from '../editor.js';
import { parseErrorPos } from '../tokenizers.js';

const STARTERS = {
  sec: ['policy.red-xai-sec', 'Security policy', '<< Roles, scopes and rules. Default is deny. >>\n{Role[1]}  = [ {Name[]} = "player", {Scopes[]} = ;["game.read"]: ];\n{Scope[1]} = [ {Name[]} = "game.read", {Actions[]} = ;["read"]:, {Resource[]} = "players.red-xai.db" ];\n'],
  pulse: ['rules.red-xai-db-pulse', 'Pulse rules', '<< When Health reaches 0, mark the player dead and announce it. >>\n{PlayerDeath[ON="players.red-xai.db:Player.Health"]} = [\n    {When[]}      = "<= 0",\n    {SetTarget[]} = "Player.IsDead = TRUE",\n    {Emit[]}      = "player.died"\n];\n'],
  code: ['scripts.red-xai-code', 'Code script', '{Script[1]} = [\n    {Name[]}   = "heal",\n    {Params[]} = ;["target", "amount"]:,\n    {Uses[]}   = ;["db_get", "db_set"]:,\n    {Source[]} = "let hp = db_get(target, \\"Health\\"); db_set(target, \\"Health\\", hp + amount); return hp + amount;"\n];\n'],
  idx: ['players.red-xai-db-idx', 'Search index', '{PlayerByName[]} = [\n    {File[]}   = "players.red-xai.db",\n    {Box[]}    = "Player",\n    {Fields[]} = ;["Name"]:,\n    {Kind[]}   = "exact",\n    {Fold[]}   = TRUE\n];\n'],
};
function endpoint(db, name, type) {
  const b = `/v1/db/${enc(db)}`;
  switch (type) {
    case 'sec': return b + '/sec';
    case 'pulse': return b + '/pulse';
    case 'code': return `${b}/code/file/${enc(name.replace(/\.red-xai-code$/, ''))}`;
    case 'idx': return `${b}/idx/${enc(name.replace(/\.red-xai-db-idx$/, ''))}`;
    default: return null;
  }
}
const typeOf = (n) => (/\.red-xai-sec$/.test(n) ? 'sec' : /\.red-xai-db-pulse$/.test(n) ? 'pulse' : /\.red-xai-code$/.test(n) ? 'code' : /\.red-xai-db-idx$/.test(n) ? 'idx' : /\.red-xai-db-link$/.test(n) ? 'link' : 'other');

export default async function render(ctx) {
  const db = ctx.query.db || state.db;
  if (db !== state.db) setDb(db);
  const root = page();
  const side = h('div', { class: 'tree', role: 'list' });
  const main = h('div');
  let files = [];
  let current = null;
  let editor = null;
  root.append(pageHead('Raw file editor', 'Open a database file as Box text, check it, and save it through the API.', h('button', { class: 'btn', onclick: newFile }, icon('plus', 16), ' New file')),
    h('div', { class: 'split' }, side, main),
    terminalPanel([{ label: 'Show a file', cmd: 'redx sec show' }, { label: 'Save a security policy', cmd: 'redx sec put policy.red-xai-sec' }, { label: 'Save pulse rules', cmd: 'redx pulse put rules.red-xai-db-pulse' }, { label: 'Save a code file', cmd: 'redx code define scripts.red-xai-code -' }, { label: 'Define an index set', cmd: 'redx idx define SET FILE' }], 'Data files (records) are edited in the Data Explorer, not here.'));

  async function loadList() {
    mount(side, spinner());
    try {
      const r = await listFiles(db);
      files = r.files.filter((f) => f.records === 'raw' || f.records === 'raw-readonly');
      paintList();
      if (ctx.query.file) { const f = files.find((x) => x.name === ctx.query.file); if (f) return open(f); }
      mount(main, files.length ? h('div', { class: 'empty' }, h('h3', null, 'Pick a file'), h('p', { class: 'muted' }, 'Rules, policies, scripts and indexes live in these files.')) : emptyState('file', 'No definition files yet', 'Create a security policy, pulse rules, a script or an index. Starter text is provided.', h('button', { class: 'btn primary', onclick: newFile }, 'New file')));
    } catch (e) { mount(side, errorBox(e.status === 403 ? 'The raw editor needs an admin key for this database.' : e.message, loadList)); }
  }
  function paintList() {
    mount(side, files.length ? files.map((f) => h('div', { class: 'tn' + (current && current.name === f.name ? ' sel' : ''), tabindex: 0, role: 'listitem', onclick: () => open(f), onkeydown: (e) => { if (e.key === 'Enter') open(f); } }, icon('file', 15), h('span', null, f.name), typeChip(f.type), f.records === 'raw-readonly' ? h('small', null, 'read-only') : null)) : h('p', { class: 'muted small', style: { padding: '8px' } }, 'None yet'));
  }
  async function open(f, startText) {
    if (editor && current && editor.getValue() !== current.orig && !(await confirmDialog('Discard unsaved changes?', 'You changed ' + current.name + ' and have not saved.', { ok: 'Discard', danger: true }))) return;
    mount(main, spinner());
    try {
      let text = startText;
      let meta = { writable: !!endpoint(db, f.name, f.type), write_via: '' };
      if (text == null) {
        const r = await api('GET', `/v1/db/${enc(db)}/files/${enc(f.name)}`);
        text = r.text;
        meta = r;
      }
      current = { name: f.name, type: f.type, orig: startText == null ? text : '', isNew: startText != null };
      paintList();
      const writable = meta.writable && !!endpoint(db, f.name, f.type);
      const msg = h('div', { class: 'form-err', hidden: true });
      const status = h('span', { class: 'muted small' });
      editor = createEditor({ language: 'box', value: text, readOnly: !writable, height: 'min(60vh, 520px)', onSave: save, onChange: debounce(validate, 400) });
      async function validate() {
        try {
          const r = await api('POST', '/v1/ui/validate', { json: { kind: 'document', text: editor.getValue() } });
          editor.setDiagnostics(r.ok ? [] : [{ line: r.line || 1, col: r.col || 1, message: r.message || r.error }]);
          mount(status, r.ok ? [icon('check', 14), ' Valid Box text'] : [icon('alert', 14), ` Line ${r.line || '?'}, column ${r.col || '?'}: ${r.message || r.error}`]);
          status.className = 'small ' + (r.ok ? 'ok-text' : 'err-text');
        } catch { /* ignore */ }
      }
      async function save() {
        if (!writable) return;
        msg.hidden = true;
        const t = editor.getValue();
        try {
          const url = endpoint(db, f.name, f.type);
          const putOpts = { text: t, type: 'text/plain' };
          if (f.type === 'sec') putOpts.confirm = 'putPolicy';
          await api('PUT', url, putOpts);
          current.orig = t;
          current.isNew = false;
          toast('Saved ' + f.name, 'ok');
          await loadList2();
        } catch (e) {
          msg.textContent = e.message;
          msg.hidden = false;
          const p = parseErrorPos(e.message);
          if (p) editor.setDiagnostics([{ line: p.line, col: p.col, message: e.message }]);
        }
      }
      async function loadList2() { const r = await listFiles(db); files = r.files.filter((x) => x.records === 'raw' || x.records === 'raw-readonly'); paintList(); }
      async function del() {
        if (!(await confirmDialog('Remove ' + f.name + '?', 'The ' + (f.type === 'sec' ? 'security policy' : f.type === 'pulse' ? 'rules' : 'definition') + ' stops applying immediately.', { danger: true, ok: 'Remove' }))) return;
        try { const delOpts = f.type === 'sec' ? { confirm: 'deletePolicy' } : {}; await api('DELETE', endpoint(db, f.name, f.type), delOpts); toast('Removed', 'ok'); current = null; editor = null; await loadList(); mount(main); } catch (e) { toast(e.message, 'error'); }
      }
      mount(main, h('div', { class: 'card' },
        h('div', { class: 'row gap wrap', style: { marginBottom: '10px' } }, h('h3', { style: { margin: 0 } }, f.name), typeChip(f.type), h('div', { class: 'grow' }), meta.modified ? h('span', { class: 'muted small' }, 'changed ' + ago(meta.modified)) : null),
        writable ? null : h('div', { class: 'callout info' }, icon('lock'), h('div', null, h('b', null, 'Read-only here. '), f.type === 'link' ? 'The API cannot write link files. Use the Data Explorer, or the CLI link commands.' : 'This file is not the one the API manages (' + (meta.write_via || 'no write endpoint') + '). Edit it on disk or rename it to the standard name.')),
        editor.el, msg,
        h('div', { class: 'row gap wrap', style: { marginTop: '10px' } }, status, h('div', { class: 'grow' }),
          current.isNew ? null : h('button', { class: 'btn danger', disabled: !writable, onclick: del }, icon('trash', 15), ' Remove file'),
          h('button', { class: 'btn', onclick: () => copy(editor.getValue(), 'Copied') }, 'Copy'), h('button', { class: 'btn', onclick: () => download(f.name, editor.getValue(), 'text/plain') }, 'Download'),
          h('button', { class: 'btn primary', disabled: !writable, onclick: save }, 'Save ', h('kbd', null, 'Ctrl+S')))));
      validate();
    } catch (e) { mount(main, errorBox(e.message, () => open(f))); }
  }
  async function newFile() {
    const sel = h('select', { class: 'select' }, Object.entries(STARTERS).map(([k, v]) => h('option', { value: k }, v[1])));
    const name = h('input', { class: 'input', value: STARTERS.sec[0] });
    sel.addEventListener('change', () => { name.value = STARTERS[sel.value][0]; });
    const note = h('p', { class: 'muted small' }, 'Security policy and pulse rules have one standard file each. Code and index files can have any name.');
    const r = await dialog({ title: 'New definition file', body: h('div', null, field('Kind', sel), field('File name', name), note), actions: [{ id: 'cancel', label: 'Cancel' }, { id: 'ok', label: 'Start editing', primary: true }] });
    if (r !== 'ok') return;
    const type = sel.value;
    let nm = name.value.trim();
    if (!nm.endsWith({ sec: '.red-xai-sec', pulse: '.red-xai-db-pulse', code: '.red-xai-code', idx: '.red-xai-db-idx' }[type])) nm += { sec: '.red-xai-sec', pulse: '.red-xai-db-pulse', code: '.red-xai-code', idx: '.red-xai-db-idx' }[type];
    if (type === 'sec') nm = 'policy.red-xai-sec';
    if (type === 'pulse') nm = 'rules.red-xai-db-pulse';
    current = null;
    open({ name: nm, type, records: 'raw' }, STARTERS[type][2]);
  }
  await loadList();
  return { el: root, destroy() {} };
}

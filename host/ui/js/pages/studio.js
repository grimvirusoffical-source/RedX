import { h, icon, terminalPanel, chip, mount, toast, dialog, field, copy, download, table, emptyState } from '../util.js';
import { api, enc } from '../api.js';
import { state, gs } from '../state.js';
import { pageHead, page, bx, listFiles, q as quote, parsePath } from './shared.js';
import { createEditor } from '../editor.js';
import { VERBS, OPTIONS, FUNCTIONS, findParams, parseErrorPos } from '../tokenizers.js';
import { fileStem } from '../state.js';

const SNIPPETS = [
  ['Read everything in a box', '{Get[]} = players:Player[ID=*] -> *, Limit = 50'],
  ['Filter and sort', '{Get[]} = players:Player[Level >= 10, Role = "Admin"] -> [Name, Level], Sort = -Level, Limit = 20'],
  ['Count and group', '{Get[]} = players:Player[ID=*] -> [Role, n = Count()], Group = Role, Sort = -n'],
  ['Search text', '{Get[]} = posts:Post[Body has "dragon"] -> [Title]'],
  ['Use a parameter', '{Get[]} = players:Player[Name = $name] -> *'],
  ['Add a record', '{Add[]} = players:Player[ID=100] = [ {Name[]} = "Ann", {Level[]} = 1 ]'],
  ['Create a file with a record', '{Add[]} = "notes.red-xai.db":Note[ID=1] = [ {Title[]} = "Hello", {Body[]} = "First note" ]'],
  ['Expiring record (60 s)', '{Add[]} = "sessions.red-xai-db-qs":Session[ID=1] = [ {User[]} = "ann" ] (60)'],
  ['Change one field', '{Set[]} = players:Player[ID=1].Level = Level + 1'],
  ['Delete matching records', '{Delete[]} = players:Player[Level < 1]'],
  ['Transfer, all or nothing', '{Tx[]} = [\n    {Require[]} = players:Player[ID=1, Gold >= 5],\n    {Set[]} = players:Player[ID=1].Gold = Gold - 5,\n    {Set[]} = players:Player[ID=2].Gold = Gold + 5\n]'],
  ['Explain the plan', '{Explain[]} = [ {Get[]} = players:Player[Name = "Ann"] -> * ]'],
  ['Follow a link', '{Get[]} = players:Player[ID=*] -> [Name] @> Guild'],
  ['Watch changes (Live Watch page)', '{Watch[]} = players:Player[Level > 10]'],
];
const CHEAT = [
  ['{Get[]} = file:Box[filter] -> [cols], Sort = -Col, Limit = 20', 'Read. Commas inside [ ] mean AND.'],
  ['{Add[]} = file:Box[ID=1] = [ {Name[]} = "x" ]', 'Insert a record (a file is created by its first Add if you quote its full name).'],
  ['{Set[]} = file:Box[ID=1].Field = 5', 'Change one field. Expressions work: Field + 1.'],
  ['{Delete[]} = file:Box[Field < 3]', 'Delete matching records.'],
  ['{Tx[]} = [ {Require[]} = ..., {Set[]} = ... ]', 'All-or-nothing group with guards.'],
  ['[Name starts "A"]  [Tags has "x"]  [Id in ;[1,2,3]:]', 'Operators: = != < <= > >= starts has hasany in'],
  ['$name', 'A parameter. Fill it in below the editor; the value is never spliced into the text.'],
  ['<< comment >>', 'Comments use << >>.'],
  ['(3600)  (~3600)', 'TTL after an Add/Set: fixed, or sliding.'],
  ['TRUE  FALSE  NELL', 'Booleans and "no value".'],
];

const load = (k, d) => { try { return JSON.parse(localStorage.getItem(k)) || d; } catch { return d; } };
const save = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* ignore */ } };

export default async function render(ctx) {
  const db = state.db;
  const root = page();
  let files = [];
  const boxCache = new Map();
  const colCache = new Map();
  try { files = (await listFiles(db)).files.filter((f) => f.records === 'records'); } catch { /* limited key */ }
  let last = null;
  let view = 'table';

  let startQ = sessionStorage.getItem('redx.studio.q') || load('redx.studio.draft', '');
  sessionStorage.removeItem('redx.studio.q');

  async function boxesOf(file) {
    if (boxCache.has(file)) return boxCache.get(file);
    boxCache.set(file, []);
    try {
      const r = await bx(db, `{Get[]} = ${quote(file)}:*[ID=*] -> [ID], Limit = 500`);
      const set = new Set((r.paths || []).map((p) => (parsePath(p) || {}).box).filter(Boolean));
      boxCache.set(file, [...set]);
    } catch { /* ignore */ }
    return boxCache.get(file);
  }
  async function colsOf(file, box) {
    const k = file + ':' + box;
    if (colCache.has(k)) return colCache.get(k);
    colCache.set(k, []);
    try { const r = await bx(db, `{Get[]} = ${quote(file)}:${box}[ID=*] -> *, Limit = 5`); colCache.set(k, r.columns || []); } catch { /* ignore */ }
    return colCache.get(k);
  }
  if (!startQ) {
    startQ = SNIPPETS[0][1];
    if (files[0]) { const bs = await boxesOf(files[0].name); startQ = `{Get[]} = ${fileStem(files[0].name)}:${bs[0] || '*'}[ID=*] -> *, Limit = 50`; }
  }
  function fileByStem(s) { return files.find((f) => fileStem(f.name) === s || f.name === s); }
  // warm caches in the background so autocomplete is instant
  (async () => { for (const f of files.slice(0, 12)) { const bs = await boxesOf(f.name); for (const b of bs.slice(0, 6)) await colsOf(f.name, b); } })();

  function complete(text, pos, force) {
    let s = pos;
    while (s > 0 && /[\w$-]/.test(text[s - 1])) s--;
    const word = text.slice(s, pos);
    const before = text.slice(0, s);
    const lineBefore = before.slice(before.lastIndexOf('\n') + 1);
    const pick = (list) => list.filter((it) => !word || it.label.toLowerCase().startsWith(word.toLowerCase()) && it.label !== word);
    if (/\{$/.test(before)) return { from: s, items: pick(VERBS.map((v) => ({ label: v, detail: 'command', insert: v + '[]} = ', cursor: v.length + 6 }))) };
    if (/:$/.test(before)) {
      const m = /(?:"([^"]+)"|([A-Za-z_][\w-]*)):$/.exec(before);
      const f = m && fileByStem(m[1] || m[2]);
      if (f) { const bs = boxCache.get(f.name) || []; return { from: s, items: pick([{ label: '*', detail: 'any box' }, ...bs.map((b) => ({ label: b, detail: 'box' }))]) }; }
      return null;
    }
    // inside [...] or after ->: fields of the nearest file:Box
    const src = [...before.matchAll(/(?:"([^"]+)"|([A-Za-z_][\w-]*)):([A-Za-z_][\w-]*)/g)].pop();
    const inBracket = (lineBefore.lastIndexOf('[') > lineBefore.lastIndexOf(']')) || /->\s*\[?[^\]]*$/.test(lineBefore);
    if (src && inBracket) {
      const f = fileByStem(src[1] || src[2]);
      const cols = f ? colCache.get(f.name + ':' + src[3]) || [] : [];
      const items = [...cols.map((c) => ({ label: c, detail: 'field' })), ...FUNCTIONS.map((c) => ({ label: c, detail: 'function', insert: c + '(' })), { label: 'ID', detail: 'record id' }];
      return { from: s, items: pick(items) };
    }
    if (/,\s*$/.test(before) && !inBracket) return { from: s, items: pick(OPTIONS.map((o) => ({ label: o, detail: 'option', insert: o + ' = ' }))) };
    if (/}\s*=\s*$/.test(before) || /^\s*$/.test(lineBefore) || /[,[]\s*$/.test(before) && !inBracket) {
      const items = files.map((f) => ({ label: fileStem(f.name), detail: f.name, insert: fileStem(f.name) + ':' }));
      if (word || force) return { from: s, items: pick(items) };
    }
    if (word.length >= 2 || force) {
      const all = [...files.map((f) => ({ label: fileStem(f.name), detail: 'file', insert: fileStem(f.name) + ':' })), ...['TRUE', 'FALSE', 'NELL'].map((l) => ({ label: l, detail: 'value' })), ...FUNCTIONS.map((c) => ({ label: c, detail: 'function', insert: c + '(' }))];
      return { from: s, items: pick(all) };
    }
    return null;
  }

  const editor = createEditor({ language: 'boxql', value: startQ, height: '240px', onRun: run, onChange: (v) => { save('redx.studio.draft', v); schedule(); }, complete });
  let vt;
  const schedule = () => { clearTimeout(vt); vt = setTimeout(() => { paintParams(); checkSyntax(); }, 400); };
  const paramsBox = h('div', { class: 'row gap wrap' });
  const pvals = {};
  function paintParams() {
    const names = findParams(editor.getValue());
    mount(paramsBox, names.length ? [h('span', { class: 'muted small' }, 'Parameters:'), ...names.map((n) => h('label', { class: 'row gap pill' }, h('code', null, '$' + n), h('input', { class: 'input', style: { width: '150px' }, placeholder: 'value', value: pvals[n] || '', 'aria-label': 'Value for ' + n, oninput: (e) => { pvals[n] = e.target.value; }, onkeydown: (e) => { if (e.key === 'Enter') run(); } })))] : null);
  }
  function paramValues() {
    const o = {};
    for (const n of findParams(editor.getValue())) {
      const v = pvals[n] ?? '';
      if (v === '') { o[n] = ''; continue; }
      try { const j = JSON.parse(v); o[n] = j; } catch { o[n] = v; }
    }
    return o;
  }
  async function checkSyntax() {
    try {
      const r = await api('POST', '/v1/ui/validate', { json: { kind: 'boxql', text: editor.getValue() } });
      editor.setDiagnostics(r.ok ? [] : [{ line: r.line || 1, col: r.col || 1, message: r.message || r.error }]);
    } catch { /* validation endpoint optional */ }
  }

  const status = h('div', { class: 'muted small' });
  const out = h('div', { class: 'results' });
  const viewSel = h('div', { class: 'seg' }, [['table', 'Table'], ['json', 'JSON'], ['box', 'Box text']].map(([k, l]) => h('span', { class: 'seg-opt' + (k === view ? ' on' : ''), tabindex: 0, onclick: () => { view = k; viewSel.querySelectorAll('.seg-opt').forEach((o, i) => o.classList.toggle('on', ['table', 'json', 'box'][i] === k)); paintResult(); } }, l)));
  const side = h('div', { class: 'side-pane', hidden: true });

  async function run(explain = false) {
    const text = editor.getValue();
    if (!text.trim()) return toast('Write a command first', 'info');
    if (/^\s*(<<[\s\S]*?>>\s*)*\{\s*Watch\s*\[/.test(text)) { sessionStorage.setItem('redx.watch.q', text); toast('Watch commands stream results. Opening Live Watch.', 'info'); location.hash = '#/watch'; return; }
    mount(status, 'Running…');
    const t0 = performance.now();
    editor.clearDiagnostics();
    try {
      const r = await bx(db, text, paramValues(), explain === true);
      const ms = performance.now() - t0;
      last = { r, explain: explain === true };
      gs.set('query');
      pushHistory(text, true);
      mount(status, chip(r.kind || 'ok', 'ok'), ' ', ms.toFixed(1) + ' ms', r.count != null ? ' · ' + r.count + ' row' + (r.count === 1 ? '' : 's') : '', r.affected ? ' · ' + r.affected + ' changed' : '', r.access ? ' · access: ' + r.access : '', r.scanned ? ' · scanned ' + r.scanned : '');
      paintResult();
    } catch (e) {
      last = null;
      pushHistory(text, false);
      mount(status, chip('error', 'err'));
      const p = parseErrorPos(e.message);
      if (p) editor.setDiagnostics([{ line: p.line, col: p.col, message: e.message }]);
      mount(out, h('div', { class: 'callout err' }, icon('alert'), h('div', null, h('b', null, p ? `Error at line ${p.line}, column ${p.col}` : 'Error'), h('div', { class: 'mono' }, e.message), p ? h('button', { class: 'btn small', onclick: () => editor.goto(p.line, p.col) }, 'Go to error') : null)));
    }
  }
  const planText = (r) => (r.columns && r.columns.length === 1 && r.columns[0] === 'plan' ? r.rows.map((x) => x[0]).join('\n') : r.plan ? (typeof r.plan === 'string' ? r.plan : Array.isArray(r.plan) ? r.plan.join('\n') : JSON.stringify(r.plan, null, 2)) : '');
  function boxText(r) {
    if (planText(r)) return planText(r);
    if (!r.columns || !r.columns.length) return r.plan ? (typeof r.plan === 'string' ? r.plan : JSON.stringify(r.plan, null, 2)) : '';
    return r.rows_box.map((row, i) => (r.paths && r.paths[i] ? '<< ' + r.paths[i] + ' >>\n' : '') + '[\n' + r.columns.map((c, j) => `    {${c}[]} = ${row[j]}`).join(',\n') + '\n]').join('\n\n');
  }
  function paintResult() {
    if (!last) return;
    const r = last.r;
    if (view === 'json') return mount(out, jsonBlock(JSON.stringify(r, null, 2)));
    if (view === 'box') return mount(out, jsonBlock(boxText(r) || '(no rows)'));
    if (planText(r)) return mount(out, h('div', null, h('h3', null, 'Query plan'), jsonBlock(planText(r))));
    if (r.results) return mount(out, jsonBlock(JSON.stringify(r.results, null, 2)));
    if (!r.columns || !r.columns.length) return mount(out, emptyState('check', r.kind === 'get' ? 'No rows matched' : 'Done', r.affected ? r.affected + ' record' + (r.affected === 1 ? '' : 's') + ' changed.' : null));
    const rows = r.rows.map((row) => h('tr', null, row.map((v) => h('td', null, h('span', { class: 'cellv', title: typeof v === 'string' ? v : JSON.stringify(v) }, v === null ? 'NELL' : typeof v === 'string' ? v : JSON.stringify(v))))));
    mount(out, rows.length ? table(r.columns, rows, 'compact') : emptyState('table', 'No rows matched', 'The query ran fine but nothing matched.'));
  }
  function jsonBlock(t) {
    return h('div', { class: 'card', style: { padding: 0 } }, h('div', { class: 'row', style: { padding: '6px 10px', borderBottom: '1px solid var(--line)' } }, h('div', { class: 'grow' }), h('button', { class: 'btn small', onclick: () => copy(t) }, 'Copy'), h('button', { class: 'btn small', onclick: () => download('result.txt', t, 'text/plain') }, 'Download')), h('pre', { class: 'code-block' }, t));
  }

  // history / saved
  function pushHistory(text, ok) {
    const hist = load('redx.hist', []).filter((x) => x.q !== text);
    hist.unshift({ q: text, t: Date.now(), ok });
    save('redx.hist', hist.slice(0, 40));
  }
  async function showHistory() {
    const hist = load('redx.hist', []);
    mount(side, h('div', { class: 'row' }, h('h3', null, 'History'), h('div', { class: 'grow' }), h('button', { class: 'btn small', onclick: () => { save('redx.hist', []); showHistory(); } }, 'Clear'), h('button', { class: 'icon-btn', 'aria-label': 'Close', onclick: () => { side.hidden = true; } }, icon('x', 16))),
      hist.length ? hist.map((x) => h('button', { class: 'list-btn', onclick: () => { editor.setValue(x.q); side.hidden = true; } }, h('code', null, x.q.split('\n')[0].slice(0, 90)), h('span', { class: 'muted small' }, new Date(x.t).toLocaleTimeString(), x.ok ? '' : ' · failed'))) : h('p', { class: 'muted' }, 'Queries you run appear here.'));
    side.hidden = false;
  }
  async function showSaved() {
    const sv = load('redx.saved', []);
    mount(side, h('div', { class: 'row' }, h('h3', null, 'Saved queries'), h('div', { class: 'grow' }), h('button', { class: 'icon-btn', 'aria-label': 'Close', onclick: () => { side.hidden = true; } }, icon('x', 16))),
      sv.length ? sv.map((x, i) => h('div', { class: 'row gap' }, h('button', { class: 'list-btn grow', onclick: () => { editor.setValue(x.q); side.hidden = true; } }, h('b', null, x.name), h('code', null, x.q.split('\n')[0].slice(0, 70))), h('button', { class: 'icon-btn', 'aria-label': 'Delete saved query', onclick: () => { sv.splice(i, 1); save('redx.saved', sv); showSaved(); } }, icon('trash', 15)))) : h('p', { class: 'muted' }, 'Press "Save" to keep a query here. Saved queries stay in this browser.'));
    side.hidden = false;
  }
  async function saveQuery() {
    const name = h('input', { class: 'input', placeholder: 'e.g. Top players' });
    const r = await dialog({ title: 'Save query', body: field('Name', name), actions: [{ id: 'cancel', label: 'Cancel' }, { id: 'ok', label: 'Save', primary: true }] });
    if (r !== 'ok' || !name.value.trim()) return;
    const sv = load('redx.saved', []);
    sv.unshift({ name: name.value.trim(), q: editor.getValue() });
    save('redx.saved', sv);
    toast('Saved', 'ok');
  }
  function showSnippets() {
    mount(side, h('div', { class: 'row' }, h('h3', null, 'Snippets & cheat-sheet'), h('div', { class: 'grow' }), h('button', { class: 'icon-btn', 'aria-label': 'Close', onclick: () => { side.hidden = true; } }, icon('x', 16))),
      h('h4', null, 'Snippets'), SNIPPETS.map(([n, s]) => h('button', { class: 'list-btn', onclick: () => { editor.setValue(s); editor.focus(); } }, h('b', null, n), h('code', null, s.split('\n')[0].slice(0, 80)))),
      h('h4', null, 'Cheat-sheet'), CHEAT.map(([c, d]) => h('div', { class: 'cheat' }, h('code', { onclick: () => editor.insertAtCursor(c) }, c), h('div', { class: 'muted small' }, d))),
      h('p', null, h('a', { href: '#/help/boxql' }, 'Full BoxQL guide →')));
    side.hidden = false;
  }

  root.append(h('div', { class: 'callout info' }, icon('lock'), h('div', null, h('b', null, 'Record seals live on the Data Explorer. '), 'Studio does not encrypt a query, and it does not re-wrap packs or existing Red-SecretsXAI envelopes. Open the record, use Seal or Open, then Save only if you want to keep that one value.')),
    pageHead('BoxQL Studio', 'Write BoxQL, run it against ' + db + '. Ctrl+Enter runs, Ctrl+Space completes.',
    h('button', { class: 'btn', onclick: showSnippets }, icon('book', 16), ' Snippets'), h('button', { class: 'btn', onclick: showHistory }, icon('clock', 16), ' History'), h('button', { class: 'btn', onclick: showSaved }, icon('bookmark', 16), ' Saved')),
    h('div', { class: 'studio' }, h('div', { class: 'studio-main' },
      editor.el, paramsBox,
      h('div', { class: 'row gap wrap', style: { margin: '10px 0' } },
        h('button', { class: 'btn primary', onclick: () => run() }, icon('play', 16), ' Run ', h('kbd', null, 'Ctrl+Enter')),
        h('button', { class: 'btn', onclick: () => run(true) }, icon('search', 16), ' Explain'),
        h('button', { class: 'btn', onclick: saveQuery }, icon('bookmark', 16), ' Save'),
        h('button', { class: 'btn', onclick: () => copy(editor.getValue(), 'Query copied') }, 'Copy'),
        h('div', { class: 'grow' }), status, viewSel), out), side),
    terminalPanel([{ label: 'Run from the terminal', cmd: "redx bx '{Get[]} = players:Player[ID=*] -> *, Limit = 10'" }, { label: 'With a parameter', cmd: "redx bx '{Get[]} = players:Player[Name = $name] -> *' --sparam name=Ann" }, { label: 'curl', cmd: `curl -H "Authorization: Bearer $REDX_KEY" -d '{"q":"{Get[]} = players:Player[ID=*] -> *"}' ${location.origin}/v1/db/${db}/bx` }]));
  mount(out, h('div', { class: 'empty' }, h('p', { class: 'muted' }, 'Results appear here. Try the snippets for ideas.')));
  paintParams();
  checkSyntax();
  setTimeout(() => editor.focus(), 50);
  return { el: root, destroy() { clearTimeout(vt); } };
}

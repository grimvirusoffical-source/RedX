// DOM helpers, toasts, dialogs, formatting. No innerHTML anywhere: text always goes through textContent.

/** h('div', {class:'x', onclick: fn, title:'t'}, 'text', childNode, [more]) */
export function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === 'class') e.className = v;
      else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === 'value') e.value = v;
      else if (k === 'checked') e.checked = !!v;
      else if (k === 'disabled') e.disabled = !!v;
      else if (k === 'hidden') e.hidden = !!v;
      else if (k === 'dataset') Object.assign(e.dataset, v);
      else if (k === 'style' && typeof v === 'object') Object.assign(e.style, v);
      else e.setAttribute(k, v === true ? '' : String(v));
    }
  }
  add(e, kids);
  return e;
}
function add(e, kids) {
  for (const k of kids) {
    if (k == null || k === false) continue;
    if (Array.isArray(k)) add(e, k);
    else if (k instanceof Node) e.append(k);
    else e.append(document.createTextNode(String(k)));
  }
}
export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
export function clear(e) { while (e.firstChild) e.removeChild(e.firstChild); return e; }
export function mount(e, ...kids) { clear(e); add(e, kids); return e; }

// ---- icons (inline SVG paths, 24x24 stroke icons) ----
const ICONS = {
  home: 'M3 11l9-8 9 8M5 10v10h14V10',
  db: 'M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zM4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6',
  table: 'M3 5h18v14H3zM3 10h18M9 5v14',
  terminal: 'M4 5h16v14H4zM7 9l3 3-3 3M12 15h5',
  pulse: 'M3 12h4l3-8 4 16 3-8h4',
  key: 'M14 10a4 4 0 11-3-3.9M11 10l9 9M17 16l3-3M14 19l3-3',
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z',
  nodes: 'M12 5a2 2 0 100-.01M5 19a2 2 0 100-.01M19 19a2 2 0 100-.01M12 7v5M12 12l-6 5M12 12l6 5',
  phone: 'M7 3h10v18H7zM11 18h2',
  backup: 'M12 3v12M7 10l5 5 5-5M4 19h16',
  gear: 'M12 9a3 3 0 100 6 3 3 0 000-6zM19 12l2-1-1-3-2 .5-1.5-1.5.5-2-3-1-1 2h-2l-1-2-3 1 .5 2L6 8.5 4 8l-1 3 2 1v2l-2 1 1 3 2-.5L7.5 19l-.5 2 3 1 1-2h2l1 2 3-1-.5-2 1.5-1.5 2 .5 1-3-2-1z',
  book: 'M5 4h11a3 3 0 013 3v13H8a3 3 0 01-3-3zM5 17a3 3 0 013-3h11',
  file: 'M6 3h8l4 4v14H6zM14 3v4h4',
  compare: 'M4 6h7M4 12h7M4 18h7M15 6h5M15 12h5M15 18h5',
  copy: 'M9 9h11v11H9zM5 15V4h11',
  check: 'M5 12l5 5 9-10',
  user: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21c0-4 4-6 8-6s8 2 8 6',
  plus: 'M12 5v14M5 12h14',
  trash: 'M5 7h14M10 7V4h4v3M7 7l1 13h8l1-13',
  play: 'M7 4l13 8-13 8z',
  stop: 'M6 6h12v12H6z',
  search: 'M11 4a7 7 0 100 14 7 7 0 000-14zM16 16l5 5',
  sun: 'M12 8a4 4 0 100 8 4 4 0 000-8zM12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M5 19l1.5-1.5M17.5 6.5L19 5',
  moon: 'M20 14A8 8 0 0110 4a8 8 0 1010 10z',
  monitor: 'M3 5h18v11H3zM8 20h8M12 16v4',
  menu: 'M4 6h16M4 12h16M4 18h16',
  x: 'M6 6l12 12M18 6L6 18',
  download: 'M12 4v11M7 10l5 5 5-5M5 20h14',
  edit: 'M4 20l4-1 11-11-3-3L5 16zM14 7l3 3',
  alert: 'M12 3l10 18H2zM12 10v5M12 18v.5',
  info: 'M12 3a9 9 0 100 18 9 9 0 000-18zM12 11v6M12 7.5v.5',
  chevron: 'M9 6l6 6-6 6',
  refresh: 'M20 5v5h-5M4 19v-5h5M5.5 9A7 7 0 0118 7.5M18.5 15A7 7 0 016 16.5',
  eye: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zM12 9a3 3 0 100 6 3 3 0 000-6z',
  lock: 'M6 11h12v9H6zM8 11V8a4 4 0 018 0v3',
  rocket: 'M5 19c0-3 1-5 3-7l4-4c3-3 6-4 8-4 0 2-1 5-4 8l-4 4c-2 2-4 3-7 3zM9 15l-2 4 4-2',
  wand: 'M4 20L16 8M14 4l1 2 2 1-2 1-1 2-1-2-2-1 2-1zM19 12l.7 1.3L21 14l-1.3.7L19 16l-.7-1.3L17 14l1.3-.7z',
  pause: 'M7 5h3v14H7zM14 5h3v14h-3z',
  clock: 'M12 3a9 9 0 100 18 9 9 0 000-18zM12 7v5l3 2',
  bookmark: 'M6 3h12v18l-6-4-6 4z',
  upload: 'M12 16V4M7 9l5-5 5 5M5 20h14',
  link: 'M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1M14 10a4 4 0 00-5.7 0l-3 3A4 4 0 0011 18.7l1-1',
  list: 'M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01',
  globe: 'M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18',
  qr: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h3v3h-3zM19 14v6M14 20h3',
};
export function icon(name, size = 18) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.8');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  svg.classList.add('ico');
  const p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  p.setAttribute('d', ICONS[name] || ICONS.info);
  svg.append(p);
  return svg;
}

// ---- toasts ----
let toastBox;
export function toast(msg, kind = 'info', ms = 4200) {
  if (!toastBox) {
    toastBox = h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' });
    document.body.append(toastBox);
  }
  const t = h('div', { class: 'toast ' + kind }, icon(kind === 'error' ? 'alert' : kind === 'ok' ? 'check' : 'info', 16), h('span', null, msg));
  toastBox.append(t);
  const kill = () => { t.classList.add('out'); setTimeout(() => t.remove(), 250); };
  t.addEventListener('click', kill);
  if (ms > 0) setTimeout(kill, kind === 'error' ? Math.max(ms, 7000) : ms);
  return t;
}

// ---- dialogs ----
/** Resolves with the id of the clicked action, or null when dismissed. */
export function dialog({ title, body, actions = [{ id: 'ok', label: 'OK', primary: true }], wide = false, onOpen }) {
  return new Promise((resolve) => {
    const prevFocus = document.activeElement;
    const back = h('div', { class: 'modal-back' });
    const box = h('div', { class: 'modal' + (wide ? ' wide' : ''), role: 'dialog', 'aria-modal': 'true', 'aria-label': title });
    const done = (v) => { back.remove(); document.removeEventListener('keydown', onKey, true); if (prevFocus && prevFocus.focus) prevFocus.focus(); resolve(v); };
    const onKey = (e) => { if (e.key === 'Escape') { e.stopPropagation(); done(null); } };
    document.addEventListener('keydown', onKey, true);
    const btns = actions.map((a) => {
      const b = h('button', { class: 'btn ' + (a.primary ? 'primary' : '') + (a.danger ? ' danger' : ''), type: 'button', onclick: () => { if (a.validate && !a.validate()) return; done(a.id); } }, a.label);
      b.dataset.id = a.id;
      return b;
    });
    box.append(h('div', { class: 'modal-head' }, h('h3', null, title), h('button', { class: 'icon-btn', 'aria-label': 'Close', onclick: () => done(null) }, icon('x'))),
      h('div', { class: 'modal-body' }, body), h('div', { class: 'modal-foot' }, btns));
    back.append(box);
    back.addEventListener('mousedown', (e) => { if (e.target === back) done(null); });
    document.body.append(back);
    const first = box.querySelector('input,textarea,select') || btns[btns.length - 1];
    if (first) first.focus();
    if (onOpen) onOpen({ box, close: done, buttons: btns });
  });
}

export async function confirmDialog(title, message, { danger = false, ok = 'Confirm' } = {}) {
  const r = await dialog({ title, body: h('p', null, message), actions: [{ id: 'cancel', label: 'Cancel' }, { id: 'ok', label: ok, primary: !danger, danger }] });
  return r === 'ok';
}

/** The user must type `word` to proceed. */
export async function confirmTyped(title, message, word, ok = 'Delete') {
  const input = h('input', { class: 'input', placeholder: word, 'aria-label': 'Type ' + word + ' to confirm', autocomplete: 'off' });
  let btn;
  const r = await dialog({
    title,
    body: h('div', null, h('p', null, message), h('p', { class: 'muted' }, 'Type ', h('code', null, word), ' to confirm.'), input),
    actions: [{ id: 'cancel', label: 'Cancel' }, { id: 'ok', label: ok, danger: true }],
    onOpen: ({ buttons }) => {
      btn = buttons[1];
      btn.disabled = true;
      input.addEventListener('input', () => { btn.disabled = input.value !== word; });
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter' && input.value === word) btn.click(); });
    },
  });
  return r === 'ok' && input.value === word;
}

// ---- clipboard / download ----
export async function copy(text, label = 'Copied') {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = h('textarea', { class: 'sr-copy' });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    try { document.execCommand('copy'); } catch { /* ignore */ }
    ta.remove();
  }
  toast(label, 'ok', 1800);
}
export function download(name, data, type = 'application/octet-stream') {
  const blob = data instanceof Blob ? data : new Blob([data], { type });
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

// ---- formatting ----
export function fmtBytes(n) {
  if (n == null || isNaN(n)) return '–';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = Number(n);
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v : v.toFixed(v < 10 ? 2 : 1)) + ' ' + u[i];
}
export function fmtDur(sec) {
  sec = Math.floor(sec);
  const d = Math.floor(sec / 86400);
  const hh = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (d) return `${d}d ${hh}h`;
  if (hh) return `${hh}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}
export function fmtTime(t) {
  if (!t) return '–';
  const d = new Date(t);
  return isNaN(d) ? String(t) : d.toLocaleString();
}
export function ago(t) {
  if (!t) return '–';
  const s = (Date.now() - new Date(t).getTime()) / 1000;
  if (s < 0) return 'in ' + fmtDur(-s);
  if (s < 5) return 'just now';
  return fmtDur(s) + ' ago';
}
export const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

/** Collapsible "Terminal equivalent" panel shown on every page. cmds = [{label?, cmd}] */
export function terminalPanel(cmds, note) {
  const list = (Array.isArray(cmds) ? cmds : [cmds]).map((c) => (typeof c === 'string' ? { cmd: c } : c));
  const body = h('div', { class: 'term-body' },
    note ? h('p', { class: 'muted small' }, note) : null,
    list.map((c) => h('div', { class: 'term-row' },
      c.label ? h('div', { class: 'term-label' }, c.label) : null,
      h('div', { class: 'term-cmd' },
        h('pre', null, c.cmd),
        h('button', { class: 'icon-btn', title: 'Copy command', 'aria-label': 'Copy command', onclick: () => copy(c.cmd, 'Command copied') }, icon('copy', 15)),
      ))));
  return h('details', { class: 'term' }, h('summary', null, icon('terminal', 16), ' Terminal equivalent ', h('span', { class: 'muted small' }, '(optional)')), body);
}

export function emptyState(iconName, title, text, action) {
  return h('div', { class: 'empty' }, h('div', { class: 'empty-ico' }, icon(iconName, 34)), h('h3', null, title), text ? h('p', { class: 'muted' }, text) : null, action || null);
}
export function spinner(label = 'Loading…') { return h('div', { class: 'loading' }, h('span', { class: 'spin' }), label); }
export function errorBox(msg, retry) {
  return h('div', { class: 'errbox', role: 'alert' }, icon('alert', 18), h('div', null, h('strong', null, 'Something went wrong'), h('div', null, msg)), retry ? h('button', { class: 'btn small', onclick: retry }, 'Retry') : null);
}
export function chip(text, kind = '') { return h('span', { class: 'chip ' + kind }, text); }
export function field(label, input, hint) {
  return h('label', { class: 'field' }, h('span', { class: 'field-label' }, label), input, hint ? h('span', { class: 'hint' }, hint) : null);
}
export function table(headers, rows, cls = '') {
  return h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl ' + cls }, h('thead', null, h('tr', null, headers.map((x) => h('th', null, x)))), h('tbody', null, rows)));
}
export function sparkline(values, { width = 220, height = 48, cls = '' } = {}) {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('class', 'spark ' + cls);
  svg.setAttribute('preserveAspectRatio', 'none');
  const max = Math.max(1, ...values);
  const pts = values.map((v, i) => `${(i / Math.max(values.length - 1, 1)) * width},${height - 3 - (v / max) * (height - 8)}`);
  if (pts.length > 1) {
    const area = document.createElementNS(ns, 'polygon');
    area.setAttribute('points', `0,${height} ${pts.join(' ')} ${width},${height}`);
    area.setAttribute('class', 'spark-area');
    const line = document.createElementNS(ns, 'polyline');
    line.setAttribute('points', pts.join(' '));
    line.setAttribute('class', 'spark-line');
    svg.append(area, line);
  }
  return svg;
}
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

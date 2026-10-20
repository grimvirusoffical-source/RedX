import { h } from '../util.js';
import { api, enc } from '../api.js';

export function pageHead(title, desc, ...actions) {
  return h('div', { class: 'page-head' }, h('div', null, h('h1', null, title), desc ? h('p', null, desc) : null), actions.length ? h('div', { class: 'actions' }, actions) : null);
}
export const page = (...kids) => h('div', { class: 'page' }, kids);

export function bx(db, q, params, explain = false) {
  const body = { q };
  if (params && Object.keys(params).length) body.params = params;
  if (explain) body.explain = true;
  return api('POST', `/v1/db/${enc(db)}/bx`, { json: body });
}
export const listFiles = (db) => api('GET', `/v1/db/${enc(db)}/files`);

/** Quote a string as a BoxQL string literal. */
export const q = (s) => JSON.stringify(String(s));
/** "file.red-xai.db:Box[ID=1]" -> {file, box, id} */
export function parsePath(p) {
  const m = /^(.*?):([^[.]+)\[(?:ID=)?([^\]]+)\]/i.exec(p);
  return m ? { file: m[1], box: m[2], id: m[3] } : null;
}
export const KINDS = {
  db: 'Data', qs: 'Quick store', 'qs-ls': 'Quick store + journal', link: 'Links', pulse: 'Pulse rules', idx: 'Index', sec: 'Security', code: 'Code', pack: 'Pack', media: 'Media', journal: 'Journal', system: 'Engine',
};
export function typeChip(t) { return h('span', { class: 'chip ' + (t === 'db' || t === 'qs' || t === 'qs-ls' ? 'acc' : '') }, KINDS[t] || t); }
export function apiMessage(e, fallback = 'Request failed') {
  const b = e && e.body;
  if (b && typeof b.message === 'string' && b.message) return b.message;
  if (b && b.error && typeof b.error === 'object' && typeof b.error.message === 'string') return b.error.message;
  if (b && typeof b.error === 'string' && b.error && !/^[a-z][a-z0-9_]*$/i.test(b.error)) return b.error;
  if (e && typeof e.message === 'string' && e.message && !/^[a-z][a-z0-9_]*$/i.test(e.message)) return e.message;
  if (b && typeof b.error === 'string' && b.error) return b.error;
  if (e && e.message) return e.message;
  return fallback;
}
export function apiCode(e) {
  const b = e && e.body;
  if (!b) return '';
  if (typeof b.code === 'string') return b.code;
  if (typeof b.error === 'string' && /^[a-z][a-z0-9_]*$/i.test(b.error)) return b.error;
  return '';
}

/** Raw Box text of a record path. */
export async function getBox(db, path) {
  const res = await api('GET', `/v1/db/${enc(db)}/path/${enc(path)}`, { headers: { Accept: 'text/x-redx-box' }, raw: true });
  const t = await res.text();
  if (!res.ok) { let m = t; try { m = JSON.parse(t).error || t; } catch { /* plain */ } throw new Error(m); }
  return t;
}

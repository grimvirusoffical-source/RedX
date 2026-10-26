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
/** Record files only. A read or write key can use this. Packs and policy files are not included. */
export const listRecordFiles = (db) => api('GET', `/v1/db/${enc(db)}/files?kind=records`);

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
export function apiMessage(e) { return e && e.message ? e.message : String(e); }

/** Raw Box text of a record path. */
export async function getBox(db, path) {
  const res = await api('GET', `/v1/db/${enc(db)}/path/${enc(path)}`, { headers: { Accept: 'text/x-redx-box' }, raw: true });
  const t = await res.text();
  if (!res.ok) { let m = t; try { m = JSON.parse(t).error || t; } catch { /* plain */ } throw new Error(m); }
  return t;
}

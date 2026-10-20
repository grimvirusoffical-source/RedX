import { h, icon, errorBox, mount, emptyState, spinner, table } from '../util.js';
import { api, enc } from '../api.js';
import { state, isHostAdmin } from '../state.js';
import { navigate } from '../main.js';
import { apiMessage } from './shared.js';

export function planNotice(e) {
  const code = e && e.body && e.body.code;
  const gated = e && (e.status === 402 || (e.status === 403 && (code === 'plan_required' || code === 'plan_readonly' || code === 'quota_exceeded' || !isHostAdmin() && !(state.who && state.who.account && state.who.account.owner))));
  if (!gated) return null;
  const msg = (e.body && (e.body.message || e.body.error)) || e.message || 'This action needs a RedX Hosted plan.';
  return h('div', { class: 'warn-box', role: 'status' }, icon('alert', 16), ' ', msg, ' ',
    h('a', { href: '/ui/billing.html' }, 'Choose a plan'));
}

export function showErr(box, e, retry) {
  const note = planNotice(e);
  if (note) { mount(box, note); return; }
  const status = e && e.status;
  if (status === 404) {
    mount(box, h('div', { class: 'callout info', role: 'status' }, icon('info'), h('div', null, 'This Host feature is not available on this server yet.')));
    return;
  }
  mount(box, errorBox(apiMessage(e, 'Request failed'), retry));
}

export async function loadApps() {
  return api('GET', '/v1/hosted/apps');
}

export function appPicker(apps, id, page) {
  const sel = h('select', { class: 'input', 'aria-label': 'App', onchange: (ev) => navigate(page + '/' + ev.target.value) },
    h('option', { value: '' }, 'Choose an app'));
  for (const a of apps) {
    const opt = h('option', { value: a.id }, (a.name || a.id) + (a.host ? ' · ' + a.host : ''));
    if (a.id === id) opt.selected = true;
    sel.append(opt);
  }
  return sel;
}

export function planBanners(d) {
  const bits = [];
  if (d && d.suspended) bits.push(h('div', { class: 'warn-box' }, icon('alert', 16), ' This plan is suspended. Apps stay listed. Changes wait until the plan is active. ', h('a', { href: '/ui/billing.html' }, 'Billing')));
  if (d && d.readonly) bits.push(h('div', { class: 'warn-box' }, icon('alert', 16), ' This plan is read-only. You can look, not change. ', h('a', { href: '/ui/billing.html' }, 'Billing')));
  return bits;
}

export function noApps() {
  return emptyState('rocket', 'No apps yet', 'Create one on the Apps page. Paying subscribers host sites and containers here.',
    h('a', { class: 'btn primary', href: '#/hostapps' }, 'Apps'));
}

export function busy() { return spinner(); }

export function appTable(apps) {
  return table(['Name', 'Kind', 'Host', 'State', ''], apps.map((a) => h('tr', { class: 'click', onclick: () => navigate('hostapps/' + a.id) },
    h('td', null, h('b', null, a.name || a.id)),
    h('td', null, a.kind || ''),
    h('td', { class: 'muted' }, a.host || '–'),
    h('td', null, a.running ? 'running' : 'stopped'),
    h('td', null, h('a', { class: 'btn small', href: '#/hostapps/' + enc(a.id) }, 'Open')))));
}

export { h, icon, api, enc, navigate, emptyState, table, mount };

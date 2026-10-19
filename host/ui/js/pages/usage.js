// Usage & quotas: meters for this account. An API key has no account, so this page does not call /v1/billing/me.
import { h, fmtBytes } from '../util.js';
import { api } from '../api.js';
import { state } from '../state.js';
import { pageHead, page } from './shared.js';

export default async function render() {
  const root = page();
  root.id = 'usage-page';
  const body = h('div', { id: 'usage-meters' });
  root.append(pageHead('Usage & quotas', 'Storage, monthly traffic, and host on/off switches against this plan.'), body);
  const account = state.who && state.who.account;
  if (!account) {
    body.append(h('p', { class: 'muted' }, 'Sign in with a Red-XAI Account to see usage against your plan.'));
    return root;
  }
  let me = null;
  try { me = await api('GET', '/v1/billing/me', { noAuthRedirect: true }); } catch { me = null; }
  if (!me || !me.usage || !me.quota) {
    body.append(h('p', { class: 'muted' }, 'Usage appears here once a plan is on this account.'));
    return root;
  }
  body.append(meters(me.usage, me.quota));
  return root;
}

function meters(u, q) {
  return h('div', { class: 'card stack' },
    meter('Storage', u.storageBytes || 0, q.storageBytes, fmtBytes),
    meter('Monthly traffic', u.trafficBytes || 0, q.trafficBytes, fmtBytes),
    meter('Host on/off switches', u.hostSwitches || 0, q.hostSwitches, (n) => String(n)));
}

function meter(label, used, cap, fmt) {
  const unlimited = typeof cap !== 'number' || cap < 0;
  const pct = unlimited || !cap ? 0 : Math.max(0, Math.min(100, Math.round((used / cap) * 100)));
  const over = !unlimited && cap > 0 && used >= cap;
  const text = unlimited ? fmt(used) + ' · unlimited' : fmt(used) + ' / ' + fmt(cap);
  return h('div', { class: 'meter-row' },
    h('div', { class: 'row' }, h('span', null, label), h('span', { class: 'muted small' }, text)),
    h('div', { class: 'meter' + (over ? ' err' : ''), role: 'meter', 'aria-label': label, 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(unlimited ? 0 : pct) },
      h('span', { style: { width: pct + '%' } })));
}

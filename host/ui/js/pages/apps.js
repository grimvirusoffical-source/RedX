// Connected apps: keys minted by the connect handshake, with Revoke (docs/connect.md).
import { h, icon, chip, mount, toast, table, errorBox, emptyState, confirmDialog, ago } from '../util.js';
import { api, enc } from '../api.js';
import { isHostAdmin } from '../state.js';
import { pageHead, page } from './shared.js';

export default async function render() {
  const root = page();
  root.append(pageHead('Connected apps', 'Apps that got a workspace on this host through Connect. Revoking takes effect at once.'));
  if (!isHostAdmin()) {
    root.append(h('div', { class: 'callout info' }, icon('info'), h('div', null, 'Connected apps are managed with a host admin key.')));
    return root;
  }
  const pend = h('div');
  const list = h('div');
  root.append(pend, list);
  async function load() {
    let apps, pending;
    try {
      [apps, pending] = await Promise.all([api('GET', '/v1/connect/apps'), api('GET', '/v1/connect/pending')]);
    } catch (e) {
      if (e.body && e.body.code === 'not_leader') return mount(list, h('div', { class: 'callout warn' }, icon('alert'), h('div', null, e.message)));
      return mount(list, errorBox(e.message, load));
    }
    mount(pend, pending.requests.length ? h('div', { class: 'card' }, h('h3', null, 'Waiting for your answer'),
      table(['App', 'Workspace', 'Asks for', 'Expires', ''], pending.requests.map((r) => h('tr', null,
        h('td', null, r.display, ' ', r.verified ? chip('verified', 'ok') : chip('unverified', 'warn'), r.app ? h('div', { class: 'muted small' }, r.app) : null),
        h('td', null, h('code', null, r.workspace)),
        h('td', null, r.scope === 'read' ? 'look at data' : 'read and change data'),
        h('td', null, ago(r.expires_at)),
        h('td', null, h('button', { class: 'btn small', onclick: async () => { try { await api('POST', '/v1/connect/deny', { json: { ref: r.ref } }); toast('Denied', 'ok'); load(); } catch (e) { toast(e.message, 'error'); } } }, 'Deny')))))) : null);
    if (!apps.apps.length) {
      return mount(list, emptyState('link', 'No connected apps', 'When you approve an app (for example Rotten Apple or Gendragoon), it shows up here.'));
    }
    mount(list, table(['App', 'Workspace', 'Access', 'Connected', 'Last used', 'Status', ''], apps.apps.map((c) => h('tr', null,
      h('td', null, c.display, c.app ? h('div', { class: 'muted small' }, c.app) : null, c.device ? h('div', { class: 'muted small' }, c.device) : null),
      h('td', null, h('code', null, c.workspace)),
      h('td', null, chip(c.scope, c.scope === 'write' ? 'acc' : ''), c.prefix ? h('span', { class: 'muted small' }, ' under ' + c.prefix) : null),
      h('td', null, ago(c.created)),
      h('td', { class: 'muted small' }, 'not tracked'),
      h('td', null, c.revoked ? chip('revoked', 'err') : chip('active', 'ok')),
      h('td', null, c.revoked ? null : h('button', { class: 'btn small danger', onclick: () => revoke(c) }, icon('trash', 14), ' Revoke'))))));
  }
  async function revoke(c) {
    if (!await confirmDialog('Revoke ' + c.display, 'The app loses access to ' + c.workspace + ' at once (its key ' + c.key_id + ' stops working). The workspace and its data stay.', { danger: true, ok: 'Revoke' })) return;
    try {
      await api('DELETE', '/v1/connect/apps/' + enc(c.id));
      toast('Revoked', 'ok');
      load();
    } catch (e) { toast(e.message, 'error', 6000); }
  }
  await load();
  return root;
}

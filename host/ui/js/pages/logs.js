// Logs: this account's own database activity. An API key has no account, so this page does not call /v1/hosting/activity.
import { h } from '../util.js';
import { api } from '../api.js';
import { state } from '../state.js';
import { pageHead, page } from './shared.js';

export default async function render() {
  const root = page();
  root.id = 'logs-page';
  root.append(pageHead('Logs', 'Request counts, errors, and recent denied requests for this account\'s databases.'));
  const account = state.who && state.who.account;
  if (!account) {
    root.append(h('p', { class: 'muted' }, 'Sign in with a Red-XAI Account to see this account\'s database activity.'));
    return root;
  }
  root.append(await activityCard());
  return root;
}

async function activityCard() {
  const box = h('div', { class: 'card', id: 'activity-log' }, h('h3', null, 'Database activity'));
  try {
    const r = await api('GET', '/v1/hosting/activity', { noAuthRedirect: true });
    const dbs = r.dbs || [];
    if (!dbs.length) {
      box.append(h('p', { class: 'muted' }, 'No hosted databases on this account yet.'));
      return box;
    }
    box.append(dbs.map((d) => h('div', { 'data-db': d.logical || d.name, style: { marginTop: '12px' } },
      h('p', null, h('b', null, d.logical || d.name), d.name && d.logical ? [' ', h('span', { class: 'muted small' }, 'physical ', h('code', null, d.name))] : null),
      h('p', { class: 'muted small' }, (d.requests || 0) + ' requests · ' + (d.errors || 0) + ' errors'),
      (d.denied || []).length ? h('div', null, h('p', { class: 'muted small' }, 'Recent denied requests'),
        ...d.denied.slice().reverse().map((x) => h('p', { class: 'small' }, String(x.status), ' ', x.method || '', ' ', x.path || '', x.reason ? [' · ', x.reason] : null)))
        : h('p', { class: 'muted small' }, 'No recent denied requests.'))));
  } catch {
    box.append(h('p', { class: 'muted' }, 'Activity is available for this account\'s own databases.'));
  }
  return box;
}

// Owner page: every Red-XAI Account (from the master accounts DB), every hosted database and the owner audit
// trail. Only owner logins (owner email + verified + signed in with 2FA) can open it; every read is audit-logged.
import { h, icon, chip, table, errorBox, spinner, mount, debounce, fmtTime } from '../util.js';
import { api } from '../api.js';
import { state, setDb } from '../state.js';
import { pageHead, page } from './shared.js';

const when = (ms) => (ms ? fmtTime(new Date(ms)) : '–');

export default async function render({ navigate }) {
  const root = page();
  if (!state.who || !state.who.owner) {
    root.append(pageHead('Owner', ''), errorBox('This page is only for owner logins.'));
    return root;
  }
  let ov;
  try { ov = await api('GET', '/v1/owner/overview'); } catch (e) { root.append(pageHead('Owner', ''), errorBox(e.message)); return root; }
  root.append(pageHead('Owner', 'Everything on this host, for moderation. Every view here is written to the audit log with your name.'),
    h('div', { class: 'grid g4', id: 'owner-stats' },
      stat('Red-XAI Accounts', ov.accounts < 0 ? '–' : String(ov.accounts), 'in the master accounts DB'),
      stat('Hosted databases', String(ov.databases), 'on this host'),
      stat('Master DB', ov.master_db, ov.master_exists ? 'protected: owners only' : 'not created yet'),
      stat('Signed in as', state.who.account.username || state.who.account.email, 'owner · 2FA')));

  const tabs = [['accounts', 'Accounts'], ['dbs', 'Databases'], ['audit', 'Owner audit trail']];
  const body = h('div', { id: 'owner-body' });
  const bar = h('div', { class: 'tabs', role: 'tablist' }, tabs.map(([id, label]) => h('button', { class: 'tab', role: 'tab', id: 'owner-tab-' + id, 'data-tab': id, onclick: () => show(id) }, label)));
  root.append(bar, body);
  function show(id) {
    bar.querySelectorAll('.tab').forEach((b) => b.classList.toggle('on', b.dataset.tab === id));
    mount(body, spinner());
    ({ accounts, dbs, audit })[id]().then((v) => mount(body, v)).catch((e) => mount(body, errorBox(e.message)));
  }

  async function accounts() {
    const q = h('input', { class: 'input', id: 'owner-q', placeholder: 'Search username, email or account id', 'aria-label': 'Search accounts' });
    const out = h('div');
    const load = async () => {
      const r = await api('GET', '/v1/owner/accounts?limit=200&q=' + encodeURIComponent(q.value.trim()));
      if (!r.master_exists) return mount(out, h('p', { class: 'muted' }, 'The master accounts DB does not exist on this host yet.'));
      mount(out, h('p', { class: 'muted small' }, `${r.total} account(s)` + (r.unreadable ? `, ${r.unreadable} unreadable record(s)` : '')),
        table(['Username', 'Email', 'Status', 'Age', '2FA', 'Signed up', 'Account id'], r.accounts.map((a) => h('tr', { 'data-account': a.key },
          h('td', null, a.username || '–'), h('td', null, a.email || '–', a.emailVerified ? null : chip('unverified', 'warn')),
          h('td', null, chip(a.status || '–', a.status === 'banned' ? 'err' : 'ok'), a.banReason ? h('div', { class: 'muted small' }, a.banReason) : null),
          h('td', null, a.age != null ? String(a.age) + ' (' + a.ageBand + ')' : '–'),
          h('td', null, (a.twoFactor || 'none') + (a.twoFactorState && a.twoFactorState !== 'active' ? ' · ' + a.twoFactorState : '')),
          h('td', null, when(a.createdMs)), h('td', null, h('code', null, a.key))))));
    };
    q.addEventListener('input', debounce(() => load().catch((e) => mount(out, errorBox(e.message))), 300));
    await load();
    return h('div', null, h('div', { class: 'callout info' }, icon('info'), h('div', null, 'Passwords, 2FA secrets, phone numbers and dates of birth are never shown. Kick, ban and terminate come with the Red-XAI Accounts moderation API.')), q, out);
  }

  async function dbs() {
    const r = await api('GET', '/v1/owner/dbs');
    return table(['Database', '', 'Records', ''], r.dbs.map((d) => h('tr', { 'data-db': d.name },
      h('td', null, h('b', null, d.name)), h('td', null, d.master ? chip('master accounts DB · owners only', 'acc') : null),
      h('td', null, d.stats && d.stats.keys != null ? String(d.stats.keys) : '–'),
      h('td', null, h('button', { class: 'btn small', onclick: () => { setDb(d.name); navigate('data'); } }, 'Open')))));
  }

  async function audit() {
    const r = await api('GET', '/v1/owner/audit?limit=300');
    return table(['Time', 'Event', 'Owner', 'Target', 'Method'], r.events.map((e) => h('tr', null,
      h('td', null, e.time ? fmtTime(new Date(e.time)) : ''), h('td', null, e.event), h('td', null, e.actor || ''), h('td', null, h('code', null, e.target || e.route || '')), h('td', null, e.method || ''))));
  }
  show('accounts');
  return root;
}

function stat(label, value, sub) {
  return h('div', { class: 'card stat' }, h('div', { class: 'k' }, label), h('div', { class: 'v' }, value), h('div', { class: 's' }, sub));
}

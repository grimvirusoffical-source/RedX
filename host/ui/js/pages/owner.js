// Owner page: every Red-XAI Account (from the master accounts DB), every hosted database and the owner audit
// trail. Only owner logins (owner email + verified + signed in with 2FA) can open it; every read is audit-logged.
import { h, icon, chip, table, errorBox, spinner, mount, debounce, fmtTime, dialog, confirmTyped, toast, field } from '../util.js';
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
        table(['Username', 'Email', 'Status', 'Age', '2FA', 'Signed up', 'Account id', ''], r.accounts.map((a) => h('tr', { 'data-account': a.key },
          h('td', null, a.username || '–'), h('td', null, a.email || '–', a.emailVerified ? null : chip('unverified', 'warn')),
          h('td', null, chip(a.status || '–', a.status === 'banned' ? 'err' : 'ok'), a.banReason ? h('div', { class: 'muted small' }, a.banReason) : null),
          h('td', null, a.age != null ? String(a.age) + ' (' + a.ageBand + ')' : '–'),
          h('td', null, (a.twoFactor || 'none') + (a.twoFactorState && a.twoFactorState !== 'active' ? ' · ' + a.twoFactorState : '')),
          h('td', null, when(a.createdMs)), h('td', null, h('code', null, a.key)),
          h('td', { class: 'row-actions' },
            h('button', { class: 'btn small', type: 'button', onclick: () => moderate(a, 'kick') }, 'Kick'),
            h('button', { class: 'btn small', type: 'button', onclick: () => moderate(a, 'ban') }, 'Ban'),
            h('button', { class: 'btn small danger', type: 'button', onclick: () => moderate(a, 'terminate') }, 'Terminate'))))));
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
  async function moderate(a, action) {
    const reason = h('input', { class: 'input', id: 'mod-reason', placeholder: 'Reason the person will see', maxlength: '500' });
    const until = h('input', { class: 'input', id: 'mod-until', type: 'datetime-local' });
    const forever = h('label', { class: 'check' }, h('input', { type: 'checkbox', id: 'mod-forever' }), ' Ban forever');
    const body = h('div', null,
      h('p', null, action === 'kick' ? 'Ends every Red-XAI session for ' + (a.username || a.key) + ' in every app.'
        : action === 'ban' ? 'Bans ' + (a.username || a.key) + ' across every Red-XAI app (and kicks them).'
        : 'Deletes ' + (a.username || a.key) + ' in every Red-XAI app and blocks their email. This cannot be undone.'),
      field('Reason', reason),
      action === 'ban' ? h('div', null, field('Until', until), forever) : null);
    const r = await dialog({ title: action[0].toUpperCase() + action.slice(1) + ' account', body,
      actions: [{ id: 'cancel', label: 'Cancel' }, { id: 'ok', label: action[0].toUpperCase() + action.slice(1), primary: action !== 'terminate', danger: action === 'terminate' }] });
    if (!r || r.id !== 'ok') return;
    if (action === 'terminate' && !(await confirmTyped('Terminate this account?', 'Type TERMINATE to delete the account everywhere.', 'TERMINATE', 'Terminate'))) return;
    const json = { reason: reason.value.trim() };
    if (action === 'terminate') json.confirm = 'TERMINATE';
    if (action === 'ban') {
      if (forever.querySelector('input').checked || !until.value) json.untilMs = 0;
      else json.untilMs = new Date(until.value).getTime();
    }
    try {
      await api('POST', '/v1/owner/accounts/' + encodeURIComponent(a.key) + '/' + action, { json });
      toast(action + ' sent for ' + (a.username || a.key), 'ok');
      show('accounts');
    } catch (e) { toast((e.body && e.body.message) || e.message, 'err'); }
  }
  show('accounts');
  return root;
}

function stat(label, value, sub) {
  return h('div', { class: 'card stat' }, h('div', { class: 'k' }, label), h('div', { class: 'v' }, value), h('div', { class: 's' }, sub));
}

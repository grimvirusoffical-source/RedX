import { h, icon, terminalPanel, fmtBytes, fmtDur, ago, sparkline, chip, errorBox, spinner, copy, mount, confirmDialog } from '../util.js';
import { api, session } from '../api.js';
import { state, isHostAdmin, gs, wizard } from '../state.js';
import { pageHead, page } from './shared.js';
import { navigate } from '../main.js';

export default async function render() {
  const root = page();
  if (!isHostAdmin() && state.who.account) {
    const a = state.who.account;
    root.append(pageHead('Dashboard', 'Signed in with your Red-XAI Account.'),
      a.owner_blocked ? h('div', { class: 'callout warn', id: 'owner-blocked' }, icon('alert'), h('div', null, h('b', null, 'Owner access is not active. '),
        a.owner_blocked === 'owner_2fa_required' ? 'Owner logins must finish signing in with two-factor authentication. Turn on 2FA for this account, then sign out and sign in again.' : 'Verify this account\'s email address, then sign out and sign in again.')) : null,
      h('div', { class: 'card', id: 'account-card' }, h('h3', null, a.username || a.email), h('p', { class: 'muted' }, a.email),
        h('p', null, 'This account has no databases on this host yet. API keys still work for apps and SDKs.')));
    return root;
  }
  if (!isHostAdmin()) {
    root.append(pageHead('Dashboard', 'You are signed in with a limited key.'),
      h('div', { class: 'callout info' }, icon('info'), h('div', null, h('b', null, 'This key is not a host admin key. '), 'You can use the Data Explorer and BoxQL Studio on the databases it allows. Ask an admin for an admin key to see host status, keys, nodes and backups.')),
      h('div', { class: 'card' }, h('h3', null, 'Your key'), h('p', null, 'Scope: ', chip(state.who.scope, 'acc'), ' Database: ', chip(state.who.db), state.who.prefix ? [' Path prefix: ', chip(state.who.prefix)] : null)),
      terminalPanel('curl -H "Authorization: Bearer $REDX_KEY" ' + location.origin + '/v1/dbs'));
    return root;
  }
  const grid = h('div', { class: 'grid g4' });
  const tlsWarn = h('div'); // certificate expired / expiring / not valid yet
  const rates = [];
  const lats = [];
  let last = null;
  let timer;
  const rpsEl = h('div', { class: 'muted small' }, '–');
  const latEl = h('div', { class: 'muted small' }, '–');
  const spark1 = h('div');
  const spark2 = h('div');
  const auditBox = h('div');
  const clusterBox = h('div');
  const gsBox = h('div');
  root.append(pageHead('Dashboard', 'Live status of this RedX host.', h('button', { class: 'btn', onclick: () => navigate('wizard') }, icon('wand', 16), ' Setup wizard')), gsBox, tlsWarn, grid,
    h('div', { class: 'grid g2', style: null }, h('div', { class: 'card' }, h('h3', null, icon('pulse', 18), 'Requests per second'), rpsEl, spark1),
      h('div', { class: 'card' }, h('h3', null, icon('refresh', 18), 'Response time (ms)'), latEl, spark2)),
    h('div', { class: 'grid g2' }, h('div', { class: 'card' }, h('h3', null, icon('nodes', 18), 'Cluster'), clusterBox), h('div', { class: 'card' }, h('h3', null, icon('shield', 18), 'Recent security events'), auditBox)),
    terminalPanel([{ label: 'Status', cmd: 'redx doctor' }, { label: 'Stats as JSON', cmd: 'redx stats --json' }, { label: 'Audit log on disk', cmd: 'tail -n 20 <data-dir>/audit.log' }, { label: 'curl', cmd: 'curl -H "Authorization: Bearer $REDX_KEY" ' + location.origin + '/v1/admin/status' }]));

  function stat(k, v, s) { return h('div', { class: 'card stat' }, h('div', { class: 'k' }, k), h('div', { class: 'v' }, v), s ? h('div', { class: 's' }, s) : null); }
  async function tick() {
    try {
      const t = {};
      const st = await api('GET', '/v1/admin/status', { timing: t });
      state.status = st;
      const now = performance.now();
      if (last) {
        const dt = (now - last.t) / 1000;
        // the status request itself counts as one request
        rates.push(Math.max(0, (st.requests - last.req - 1) / dt));
        if (rates.length > 60) rates.shift();
      }
      last = { t: now, req: st.requests };
      lats.push(t.ms);
      if (lats.length > 60) lats.shift();
      mount(tlsWarn, st.tls_warning ? h('div', { class: 'callout ' + (st.tls_cert && st.tls_cert.state === 'expiring' ? 'warn' : 'err'), role: 'alert' }, icon('alert'), h('div', null, h('b', null, 'TLS certificate: '), st.tls_warning)) : null);
      mount(grid,
        stat('Version', 'v' + st.version, st.os + '/' + st.arch),
        stat('Uptime', fmtDur(st.uptime_seconds), 'since ' + new Date(st.started).toLocaleString()),
        stat('Role', st.role, 'node ' + st.node_id),
        stat('Listening on', st.listen, (st.scheme === 'https' ? 'HTTPS (TLS ' + st.tls + ')' : 'plain HTTP') + (st.tls_fingerprint ? '' : '')),
        stat('Databases', String(st.databases), 'default: ' + st.default_db),
        stat('API keys', String(st.keys), st.auth_failures + ' failed logins'),
        stat('Data on disk', fmtBytes(st.data_bytes), st.data_dir),
        stat('Requests served', st.requests.toLocaleString(), 'preset: ' + (st.preset || 'none')));
      mount(spark1, sparkline(rates.length ? rates : [0]));
      mount(spark2, sparkline(lats));
      rpsEl.textContent = rates.length ? rates[rates.length - 1].toFixed(1) + ' req/s now' : 'measuring…';
      latEl.textContent = t.ms.toFixed(1) + ' ms round trip (includes your browser)';
    } catch (e) { mount(grid, errorBox(e.message, tick)); }
  }
  async function slow() {
    try {
      const [a, c] = await Promise.all([api('GET', '/v1/admin/audit?limit=8'), api('GET', '/v1/cluster/status')]);
      mount(clusterBox,
        h('p', null, 'This node is the ', chip(c.role, c.role === 'leader' ? 'ok' : 'acc'), c.leader_url ? [' following ', h('code', null, c.leader_url)] : null),
        h('p', { class: 'muted' }, 'Replication offset ', h('code', null, String(c.offset)), ' · ', c.members.length, ' node', c.members.length === 1 ? '' : 's'),
        c.last_error ? h('p', { class: 'form-err' }, c.last_error) : null,
        h('a', { class: 'btn small', href: '#/devices' }, icon('phone', 14), ' Add a device'));
      mount(auditBox, a.events.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl compact' }, h('tbody', null, a.events.map((e) => h('tr', null,
        h('td', { class: 'muted' }, ago(e.time)), h('td', null, chip(e.event, /fail|denied|ratelimit/.test(e.event) ? 'err' : /bootstrap|create|join|promote|drop|apply/.test(e.event) ? 'acc' : '')), h('td', { class: 'muted small' }, [e.remote, e.reason || e.detail].filter(Boolean).join(' · '))))))) : h('p', { class: 'muted' }, 'Nothing yet. Failed logins, denied requests, new keys and node joins appear here.'));
      // get started
      const keys = await api('GET', '/v1/keys');
      if (state.dbs.length > 1 || (state.dbs.length === 1 && state.dbs[0] !== 'default')) gs.set('db');
      if (keys.keys.filter((k) => k.status === 'active').length > 1) gs.set('key');
      renderGS();
    } catch (e) { mount(auditBox, errorBox(e.message, slow)); }
  }
  function renderGS() {
    if (gs.dismissed()) { mount(gsBox); return; }
    const items = [
      ['db', 'Create a database', '#/databases', 'You can also use the Setup wizard.'],
      ['record', 'Add a record', '#/data', 'Open the Data Explorer and press New record.'],
      ['query', 'Run a BoxQL query', '#/studio', 'Press Ctrl+Enter in the BoxQL Studio.'],
      ['key', 'Create an app key', '#/keys', 'Give your app its own limited key.'],
    ];
    const doneN = items.filter((i) => gs.get(i[0])).length;
    mount(gsBox, h('div', { class: 'card', style: null }, h('div', { class: 'row' }, h('h3', null, icon('rocket', 18), 'Get started (', doneN, '/4)'), h('div', { class: 'grow' }), h('button', { class: 'btn small', onclick: () => { gs.dismiss(); renderGS(); } }, 'Hide')),
      h('div', { class: 'chk' }, items.map((i, n) => h('a', { class: 'chk-item' + (gs.get(i[0]) ? ' done' : ''), href: i[2] }, h('span', { class: 'dot' }, gs.get(i[0]) ? icon('check', 14) : String(n + 1)), h('div', null, h('b', null, i[1]), h('div', { class: 'muted small' }, i[3])))))));
  }
  await tick();
  slow();
  timer = setInterval(tick, 2000);
  const t2 = setInterval(slow, 8000);
  return { el: root, destroy() { clearInterval(timer); clearInterval(t2); } };
}

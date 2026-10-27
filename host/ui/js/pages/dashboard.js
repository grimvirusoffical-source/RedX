import { h, icon, terminalPanel, fmtBytes, fmtDur, ago, sparkline, chip, errorBox, spinner, copy, mount, confirmDialog } from '../util.js';
import { api, session } from '../api.js';
import { state, isHostAdmin, dbDisplayName, gs, wizard } from '../state.js';
import { pageHead, page } from './shared.js';
import { navigate } from '../main.js';

export default async function render() {
  const root = page();
  if (!isHostAdmin() && state.who.account) {
    const a = state.who.account;
    const tenantDBs = state.dbs.map((d) => ({ id: d, label: dbDisplayName(d) }));
    const needPlan = state.dbAccessIssue === 'plan_required';
    const keysPanel = h('div', { class: 'card', id: 'tenant-key-status' },
      h('h3', null, icon('key', 18), ' API keys'),
      h('p', { class: 'muted small' }, 'Checking keys for your account…'));
    root.append(
      pageHead('Your database workspace',
        'Build on Red-XAI with private, account-scoped databases and application keys.',
        h('a', { class: 'btn primary', href: '#/databases' }, icon('plus', 16), ' New database')),
      a.owner_blocked ? h('div', { class: 'callout warn', id: 'owner-blocked' }, icon('alert'),
        h('div', null, 'Owner administration is separate from your customer databases. Your personal tools remain available.')) : null,
      h('section', { class: 'customer-hero', id: 'account-card' },
        h('div', null,
          h('div', { class: 'customer-eyebrow' }, 'RED-XAI · CONNECTED WORKSPACE'),
          h('h2', null, 'Welcome, ', a.username || a.email || 'developer', '.'),
          h('p', null, 'One account. Private data, powerful tools and scoped app credentials.'),
          h('div', { class: 'row gap wrap' },
            h('a', { class: 'btn primary', href: '#/wizard' }, 'Setup wizard'),
            h('a', { class: 'btn', href: 'https://red-xai.com/hosting' }, 'Hosting & plans'))),
        h('div', { class: 'hero-mark', 'aria-hidden': 'true' }, '×')),
      needPlan ? h('div', { class: 'callout warn', role: 'status' }, icon('alert'),
        h('div', null, 'A hosted database plan is needed to create databases and API keys. ',
          h('a', { href: 'https://red-xai.com/hosting' }, 'View plans'))) : null,
      state.dbAccessIssue === 'readonly' ? h('div', { class: 'callout warn' },
        icon('info'), h('div', null, 'This plan is currently read-only. Your data is preserved.')) : null,
      h('div', { class: 'grid g3 customer-cards' },
        h('a', { class: 'card customer-action', href: '#/databases' },
          h('div', { class: 'card-symbol' }, icon('db', 22)),
          h('h3', null, 'Databases'), h('p', { class: 'muted' }, 'Create and manage private databases.'),
          h('strong', { class: 'customer-count' }, String(tenantDBs.length) + ' database(s)')),
        h('a', { class: 'card customer-action', href: '#/data' },
          h('div', { class: 'card-symbol' }, icon('table', 22)),
          h('h3', null, 'Data Explorer'), h('p', { class: 'muted' }, 'Browse, add and edit records.'),
          h('span', { class: 'customer-link' }, 'Open explorer →')),
        h('a', { class: 'card customer-action', href: '#/studio' },
          h('div', { class: 'card-symbol' }, icon('terminal', 22)),
          h('h3', null, 'BoxQL Studio'), h('p', { class: 'muted' }, 'Query data with BoxQL.'),
          h('span', { class: 'customer-link' }, 'Open studio →'))),
      h('div', { class: 'grid g2 customer-bottom' },
        h('section', { class: 'card' }, h('h3', null, icon('db', 18), ' Your databases'),
          tenantDBs.length ? tenantDBs.map((d) => h('a', {
            href: '#/databases', class: 'tenant-db-row'
          }, h('span', { class: 'tenant-db-dot' }), h('b', null, d.label),
             h('span', { class: 'muted small' }, 'Manage →'))) :
          h('p', { class: 'muted' }, 'No databases visible yet. Create one or activate a hosting plan.'),
          h('a', { class: 'btn small', href: '#/databases' }, 'View databases')),
        keysPanel),
      h('div', { class: 'workspace-resources' },
        h('a', { href: '#/keys' }, 'API credentials'),
        h('a', { href: '#/raw' }, 'Raw editor'),
        h('a', { href: '#/help' }, 'Documentation'),
        h('a', { href: 'https://red-xai.com/store' }, 'All Red-XAI apps')));
    try {
      const res = await api('GET', '/v1/keys');
      const mine = Array.isArray(res.keys) ? res.keys : [];
      mount(keysPanel,
        h('h3', null, icon('key', 18), ' Your API keys'),
        h('div', { class: 'customer-count' },
          String(mine.filter((k) => k.status === 'active').length)),
        h('p', { class: 'muted' }, 'Active keys scoped to databases owned by your account.'),
        h('a', { class: 'btn small', href: '#/keys' }, 'Create, rotate and revoke keys'));
    } catch {
      mount(keysPanel, h('h3', null, icon('key', 18), ' Your API keys'),
        h('p', { class: 'muted' }, needPlan ?
          'Activate a hosted plan before creating keys.' : 'Key listing is currently unavailable.'),
        h('a', { class: 'btn small', href: '#/keys' }, 'Open API keys'));
    }
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

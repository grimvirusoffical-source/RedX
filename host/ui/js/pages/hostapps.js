import { h, icon, fmtBytes, chip, errorBox, spinner, mount, toast, emptyState, table } from '../util.js';
import { api, enc } from '../api.js';
import { state, isHostAdmin } from '../state.js';
import { pageHead, page } from './shared.js';
import { navigate } from '../main.js';

const NAME_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;

function planNotice(e) {
  const code = e && e.body && e.body.code;
  const gated = e && (e.status === 402 || (e.status === 403 && (code === 'plan_required' || code === 'plan_readonly' || code === 'quota_exceeded' || !isHostAdmin() && !(state.who && state.who.account && state.who.account.owner))));
  if (!gated) return null;
  const msg = (e.body && (e.body.message || e.body.error)) || e.message || 'This action needs a RedX Hosted plan.';
  return h('div', { class: 'warn-box', role: 'status' }, icon('alert', 16), ' ', msg, ' ',
    h('a', { href: '/ui/billing.html' }, 'Choose a plan'));
}

function showErr(box, e, retry) {
  const note = planNotice(e);
  mount(box, note || errorBox(e.message || String(e), retry));
}

export default async function render({ args }) {
  const root = page();
  if (args && args[0]) return renderDetail(root, args[0]);
  return renderList(root);
}

async function renderList(root) {
  const list = h('div');
  const name = h('input', { class: 'input', placeholder: 'my-site', maxlength: 40, 'aria-label': 'New app name', autocomplete: 'off' });
  const kind = h('select', { class: 'input', 'aria-label': 'App kind' },
    h('option', { value: 'static' }, 'Static site'),
    h('option', { value: 'container' }, 'Container'),
    h('option', { value: 'process' }, 'Process'));
  const db = h('input', { class: 'input', placeholder: 'database (optional)', 'aria-label': 'Database', autocomplete: 'off' });
  const err = h('div');
  const create = async () => {
    mount(err);
    const n = name.value.trim().toLowerCase();
    if (!NAME_RE.test(n) || n.endsWith('-')) { mount(err, h('div', { class: 'form-err' }, 'Use a DNS name: letters, digits and hyphens, up to 40 characters.')); return; }
    try {
      const body = { name: n, kind: kind.value };
      if (db.value.trim()) body.db = db.value.trim();
      const app = await api('POST', '/v1/hosted/apps', { json: body });
      toast('App "' + n + '" created', 'ok');
      name.value = '';
      navigate('hostapps/' + app.id);
    } catch (e) { showErr(err, e, null); }
  };
  root.append(pageHead('Apps', 'Sites and containers on this RedX host. Each app gets its own hostname.'),
    h('div', { class: 'card', style: { marginBottom: '16px' } },
      h('div', { class: 'row gap wrap' },
        h('div', { style: { flex: 1, minWidth: '180px' } }, name),
        kind, db,
        h('button', { class: 'btn primary', onclick: create }, icon('plus', 16), ' Create app')),
      err),
    list);
  await load();
  return root;

  async function load() {
    mount(list, spinner());
    try {
      const d = await api('GET', '/v1/hosted/apps');
      const apps = d.apps || [];
      const bits = [];
      if (d.suspended) bits.push(h('div', { class: 'warn-box' }, icon('alert', 16), ' This plan is suspended. Apps stay listed. Start, deploy and other changes wait until the plan is active. ', h('a', { href: '/ui/billing.html' }, 'Billing')));
      if (d.readonly) bits.push(h('div', { class: 'warn-box' }, icon('alert', 16), ' This plan is read-only. You can look, not change. ', h('a', { href: '/ui/billing.html' }, 'Billing')));
      if (!apps.length) {
        bits.push(emptyState('rocket', 'No apps yet', 'Create a static site or a container. Paying subscribers host them here, next to their databases.', null));
      } else {
        bits.push(table(['Name', 'Kind', 'Host', 'State', ''], apps.map((a) => h('tr', { class: 'click', onclick: () => navigate('hostapps/' + a.id) },
          h('td', null, h('b', null, a.name || a.id)),
          h('td', null, chip(a.kind || 'app', '')),
          h('td', { class: 'muted' }, a.host || '–'),
          h('td', null, a.running ? chip('running', 'ok') : chip('stopped', '')),
          h('td', { class: 'num' }, h('a', { class: 'btn small', href: '#/hostapps/' + enc(a.id) }, 'Open'))))));
      }
      const u = d.usage || {};
      const lim = d.limits || {};
      bits.push(h('p', { class: 'muted small' }, (u.apps || 0), ' of ', lim.maxApps || '–', ' apps · ', fmtBytes(u.diskBytes || 0), ' on disk · ', u.running || 0, ' running'));
      mount(list, bits);
    } catch (e) { showErr(list, e, load); }
  }
}

function renderDetail(root, id) {
  const body = h('div');
  root.append(pageHead('App', 'Deploys, domains, environment, secrets, logs and usage.'),
    h('a', { class: 'btn small', href: '#/hostapps' }, 'All apps'),
    body);
  load();
  return root;

  async function load() {
    mount(body, spinner());
    try {
      const app = await api('GET', '/v1/hosted/apps/' + enc(id));
      mount(body, detailView(app, id, load));
    } catch (e) { showErr(body, e, load); }
  }
}

function detailView(app, id, reload) {
  const notice = [];
  if (app.suspended) notice.push(h('div', { class: 'warn-box' }, icon('alert', 16), ' This plan is suspended. ', h('a', { href: '/ui/billing.html' }, 'Billing')));
  if (app.readonly) notice.push(h('div', { class: 'warn-box' }, icon('alert', 16), ' This plan is read-only. ', h('a', { href: '/ui/billing.html' }, 'Billing')));
  const err = h('div');
  const act = async (path, opts, ok) => {
    mount(err);
    try { await api('POST', '/v1/hosted/apps/' + enc(id) + path, opts || {}); toast(ok, 'ok'); await reload(); }
    catch (e) { showErr(err, e, null); }
  };
  const deps = app.deploys || [];
  const depRows = deps.map((d) => h('tr', null,
    h('td', null, h('code', null, d.id)),
    h('td', null, d.source || ''),
    h('td', null, chip(d.status || '', d.status === 'active' ? 'ok' : '')),
    h('td', { class: 'num' }, d.id && d.id !== app.current ? h('button', { class: 'btn small', onclick: () => act('/rollback', { json: { deploy: d.id } }, 'Rolled back') }, 'Roll back') : null)));
  const domains = app.domains || [];
  const domRows = domains.map((d) => h('tr', null,
    h('td', null, d.name),
    h('td', null, d.kind || ''),
    h('td', null, d.verified ? chip('verified', 'ok') : chip('pending', '')),
    h('td', null, d.kind === 'custom' && !d.verified ? h('button', { class: 'btn small', onclick: () => act('/domains/' + enc(d.name) + '/verify', {}, 'Checked') }, 'Verify') : null)));
  const secrets = (app.secrets || []).map((s) => h('li', null, h('code', null, s.name), ' ', s.value || '••••••••'));
  const env = app.env || {};
  const envRows = Object.keys(env).sort().map((k) => h('tr', null, h('td', null, h('code', null, k)), h('td', null, env[k])));
  const usage = h('div', { class: 'muted' }, 'Loading usage…');
  api('GET', '/v1/hosted/apps/' + enc(id) + '/usage').then((u) => {
    mount(usage, fmtBytes(u.diskBytes || 0), ' on disk · ', (u.deploys || 0), ' deploys');
  }).catch(() => mount(usage, 'Usage is not available.'));
  const logBox = h('pre', { class: 'muted', style: { whiteSpace: 'pre-wrap', maxHeight: '240px', overflow: 'auto' } }, 'Logs load when you ask for them.');
  const domainName = h('input', { class: 'input', placeholder: 'www.example.com', 'aria-label': 'Custom domain' });
  const envKey = h('input', { class: 'input', placeholder: 'COLOR', 'aria-label': 'Variable name' });
  const envVal = h('input', { class: 'input', placeholder: 'blue', 'aria-label': 'Variable value' });
  const secName = h('input', { class: 'input', placeholder: 'TOKEN', 'aria-label': 'Secret name' });
  const secVal = h('input', { class: 'input', type: 'password', placeholder: 'value (write-only)', 'aria-label': 'Secret value', autocomplete: 'off' });
  return h('div', null,
    notice,
    err,
    h('div', { class: 'card', style: { marginTop: '12px' } },
      h('h2', null, app.name || id),
      h('p', null, 'Default host ', h('code', null, app.host || '–'), app.running ? [' ', chip('running', 'ok')] : [' ', chip('stopped', '')]),
      h('div', { class: 'row gap wrap' },
        h('button', { class: 'btn primary', onclick: () => act('/start', {}, 'Started') }, 'Start'),
        h('button', { class: 'btn', onclick: () => act('/stop', {}, 'Stopped') }, 'Stop'),
        h('button', { class: 'btn', onclick: () => act('/promote', {}, 'Promoted') }, 'Promote canary')),
      h('p', { class: 'muted small' }, usage)),
    h('h2', { style: { marginTop: '22px' } }, 'Deploys'),
    depRows.length ? table(['Deploy', 'Source', 'Status', ''], depRows) : h('p', { class: 'muted' }, 'No deploys yet. Upload an archive or deploy from the CLI.'),
    h('h2', { style: { marginTop: '22px' } }, 'Domains'),
    table(['Name', 'Kind', 'Status', ''], domRows),
    h('div', { class: 'row gap wrap', style: { marginTop: '8px' } }, domainName,
      h('button', { class: 'btn', onclick: async () => { mount(err); try { await api('POST', '/v1/hosted/apps/' + enc(id) + '/domains', { json: { domain: domainName.value.trim(), method: 'txt' } }); toast('Domain added', 'ok'); await reload(); } catch (e) { showErr(err, e, null); } } }, 'Add domain')),
    h('h2', { style: { marginTop: '22px' } }, 'Environment'),
    envRows.length ? table(['Name', 'Value'], envRows) : h('p', { class: 'muted' }, 'No variables yet. REDX_URL is injected when the app runs.'),
    h('div', { class: 'row gap wrap' }, envKey, envVal,
      h('button', { class: 'btn', onclick: async () => {
        mount(err);
        const vars = Object.assign({}, env);
        delete vars.REDX_URL; delete vars.REDX_DB; delete vars.REDX_KEY;
        if (envKey.value.trim()) vars[envKey.value.trim()] = envVal.value;
        try { await api('PUT', '/v1/hosted/apps/' + enc(id) + '/env', { json: { vars } }); toast('Environment saved', 'ok'); await reload(); }
        catch (e) { showErr(err, e, null); }
      } }, 'Save variable')),
    h('h2', { style: { marginTop: '22px' } }, 'Secrets'),
    h('p', { class: 'muted' }, 'Secrets are encrypted at rest and shown masked. The value is not returned after you save it.'),
    secrets.length ? h('ul', null, secrets) : h('p', { class: 'muted' }, 'No secrets.'),
    h('div', { class: 'row gap wrap' }, secName, secVal,
      h('button', { class: 'btn', onclick: async () => {
        mount(err);
        try {
          await api('PUT', '/v1/hosted/apps/' + enc(id) + '/secrets/' + enc(secName.value.trim()), { json: { value: secVal.value } });
          secVal.value = '';
          toast('Secret saved', 'ok');
          await reload();
        } catch (e) { showErr(err, e, null); }
      } }, 'Save secret')),
    h('h2', { style: { marginTop: '22px' } }, 'Logs'),
    h('div', { class: 'row gap wrap' },
      h('button', { class: 'btn small', onclick: () => loadLog('runtime') }, 'Runtime'),
      h('button', { class: 'btn small', onclick: () => loadLog('access') }, 'Requests'),
      h('button', { class: 'btn small', onclick: () => downloadLog('runtime') }, 'Download')),
    logBox);

  async function loadLog(kind) {
    mount(err);
    try {
      const d = await api('GET', '/v1/hosted/apps/' + enc(id) + '/logs?kind=' + kind);
      logBox.textContent = d.log || '(empty)';
    } catch (e) { showErr(err, e, null); }
  }
  async function downloadLog(kind) {
    mount(err);
    try {
      const res = await api('GET', '/v1/hosted/apps/' + enc(id) + '/logs/download?kind=' + kind, { raw: true });
      if (!res.ok) { const t = await res.text(); throw new Error(t || 'download failed'); }
      const blob = await res.blob();
      const a = h('a', { href: URL.createObjectURL(blob), download: kind + '.log' });
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    } catch (e) { showErr(err, e, null); }
  }
}

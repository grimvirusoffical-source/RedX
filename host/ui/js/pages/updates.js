// Updates: manifests, source (Host, GitHub, or Both), plan/apply, rollouts, snapshots, signing keys, live events.
import { h, icon, chip, mount, toast, table, emptyState, field } from '../util.js';
import { api, wsURL, enc } from '../api.js';
import { state } from '../state.js';
import { pageHead, page } from './shared.js';

function updateMessage(e) {
  const err = e && e.body && e.body.error;
  if (err && typeof err === 'object' && err.message) return err.message;
  if (typeof err === 'string') return err;
  return (e && e.message) || String(e);
}

function canMutate() {
  const w = state.who || {};
  return !w.accounts || (w.pages && w.pages.owner === true);
}

export default async function render() {
  const root = page();
  root.id = 'updates-page';
  const live = h('div', { id: 'update-live', 'aria-live': 'polite' }, h('p', { class: 'muted' }, 'Connecting…'));
  const keysBox = h('div', { id: 'update-keys' });
  const appsBox = h('div', { id: 'update-apps' });
  root.append(
    pageHead('Updates', 'Manifests, rollout, and the update source for each app.'),
    h('div', { class: 'card' }, h('h3', null, 'Live status'), live),
    h('div', { class: 'card', style: { marginTop: '16px' } }, h('h3', null, 'Signing keys'), h('p', { class: 'muted small' }, 'Public keys only. The private signing key never leaves the host.'), keysBox),
    h('div', { style: { marginTop: '16px' } }, appsBox));

  let ws = null;
  function destroy() {
    if (!ws) return;
    ws.onclose = null;
    ws.onerror = null;
    ws.onmessage = null;
    try { ws.close(); } catch { /* already closed */ }
    ws = null;
  }
  try {
    ws = new WebSocket(wsURL('/v1/updates/events'));
    ws.onopen = () => mount(live, h('p', { class: 'muted' }, 'Connected. Events appear here.'));
    ws.onmessage = (ev) => {
      let data = {};
      try { data = JSON.parse(ev.data); } catch { data = { type: 'message' }; }
      const line = [data.type || 'event', data.app || '', data.version || '', data.state || '', data.source || ''].filter(Boolean).join(' · ');
      live.append(h('p', { class: 'small' }, line));
    };
    ws.onerror = () => { /* a closed socket is not a page error */ };
    ws.onclose = () => {
      if (ws) live.append(h('p', { class: 'muted small' }, 'Live status disconnected.'));
    };
  } catch { mount(live, h('p', { class: 'muted' }, 'Live status is unavailable.')); }

  loadKeys(keysBox);
  loadApps(appsBox);
  return { el: root, destroy };
}

async function loadKeys(box) {
  try {
    const keys = await api('GET', '/v1/updates/keys', { noAuthRedirect: true });
    const list = Array.isArray(keys) ? keys : [];
    if (!list.length) { mount(box, h('p', { class: 'muted' }, 'No signing key is published.')); return; }
    mount(box, list.map((k) => h('div', { style: { marginTop: '8px' } },
      h('p', null, chip(k.alg || 'ed25519', 'ok'), ' ', h('code', null, k.kid || '')),
      h('p', { class: 'muted small' }, 'Not after ', k.not_after || '–'),
      h('p', { class: 'small mono' }, k.pub || ''))));
  } catch (e) {
    mount(box, h('p', { class: 'muted' }, updateMessage(e)));
  }
}

async function loadApps(box) {
  mount(box, h('p', { class: 'muted' }, 'Loading apps…'));
  let apps = [];
  try {
    const r = await api('GET', '/v1/updates/apps');
    apps = r.apps || [];
  } catch (e) {
    mount(box, h('div', { class: 'callout err', role: 'alert' }, icon('alert'), h('div', null, updateMessage(e))));
    return;
  }
  if (!apps.length) {
    mount(box, emptyState('refresh', 'No apps yet', 'When an app is registered, its installed version, manifests and source appear here.'));
    return;
  }
  apps.sort((a, b) => String(a.app).localeCompare(String(b.app)));
  mount(box, await Promise.all(apps.map(appCard)));
}

async function appCard(app) {
  const id = app.app;
  const installed = app.installed || {};
  const mutate = canMutate();
  const pref = app.source_pref || 'github';
  const sel = h('select', { class: 'select', 'aria-label': 'Update source for ' + id, disabled: !mutate });
  for (const [v, label] of [['host', 'Host'], ['github', 'GitHub'], ['both', 'Both']]) {
    sel.append(h('option', { value: v, selected: pref === v }, label));
  }
  sel.addEventListener('change', async () => {
    try {
      await api('PUT', '/v1/updates/apps/' + enc(id) + '/source', { json: { source: sel.value } });
      toast('Source saved for ' + id, 'ok');
    } catch (e) { toast(updateMessage(e), 'err'); }
  });
  const manifests = h('div');
  const avail = app.available || [];
  if (!avail.length) manifests.append(h('p', { class: 'muted small' }, 'No signed manifests yet.'));
  for (const row of avail) {
    const sources = row.sources || [];
    const bits = [];
    for (const src of sources) {
      bits.push(src + ': ' + await signatureStatus(id, row.version, src));
    }
    manifests.append(h('p', { class: 'small' }, h('b', null, row.version), ' · ', (row.channel || ''), bits.length ? [' · ', bits.join(', ')] : null));
  }
  return h('div', { class: 'card', style: { marginTop: '12px' }, 'data-app': id },
    h('h3', null, id, app.hosted ? chip('hosted', 'ok') : null),
    h('p', null, 'Installed ', installed.version ? h('b', null, installed.version) : h('span', { class: 'muted' }, 'nothing yet'),
      installed.sequence ? [' · sequence ', String(installed.sequence)] : null),
    h('p', { class: 'muted small' }, 'Both accepts a manifest from Host or GitHub. Sequence is one counter across both, and the signature rules are the same.'),
    field('Update source', sel, mutate ? 'Host, GitHub, or Both.' : 'Only an owner can change the update source while Red-XAI Accounts is on.'),
    manifests,
    applyBox(id, avail),
    await snapshotBox(id));
}

async function signatureStatus(app, version, source) {
  try {
    const res = await api('GET', '/v1/updates/apps/' + enc(app) + '/manifests/' + enc(version) + '?source=' + enc(source), { raw: true });
    const sig = res.headers.get('X-RedX-Signature') || '';
    const text = await res.text();
    if (res.ok && sig.startsWith('ed25519:')) return 'signed';
    if (text.indexOf('bad_signature') >= 0) return 'bad_signature';
    return res.ok ? 'unsigned' : 'unavailable';
  } catch { return 'unavailable'; }
}

function applyBox(app, avail) {
  const versions = [];
  const seen = new Set();
  for (const row of avail) {
    if (!seen.has(row.version)) { seen.add(row.version); versions.push(row.version); }
  }
  const ver = h('select', { class: 'select', 'aria-label': 'Version to apply' }, versions.map((v) => h('option', { value: v }, v)));
  if (!versions.length) ver.append(h('option', { value: '' }, 'No version'));
  const source = h('select', { class: 'select', 'aria-label': 'Manifest source' }, ['host', 'github'].map((s) => h('option', { value: s }, s)));
  const strategy = h('select', { class: 'select', 'aria-label': 'Rollout strategy' }, [
    ['direct', 'Direct'], ['canary', 'Canary'], ['blue_green', 'Blue-green'],
  ].map(([v, l]) => h('option', { value: v }, l)));
  const percent = h('input', { class: 'input', type: 'number', value: '10', min: '1', max: '100', 'aria-label': 'Canary percent' });
  const minutes = h('input', { class: 'input', type: 'number', value: '0', min: '0', 'aria-label': 'Canary minimum minutes' });
  const result = h('div');
  let permit = '';
  async function plan() {
    permit = '';
    mount(result, h('p', { class: 'muted' }, 'Planning…'));
    try {
      const r = await api('POST', '/v1/updates/apps/' + enc(app) + '/apply', {
        confirm: 'updateApply',
        json: body(true),
      });
      permit = r.confirm || '';
      mount(result, h('p', null, 'Dry run accepted. Apply with the single-use token before ', r.expires || 'it expires', '.'));
    } catch (e) { mount(result, h('p', null, updateMessage(e))); }
  }
  async function apply() {
    if (!permit) { toast('Plan the update first', 'err'); return; }
    try {
      const r = await api('POST', '/v1/updates/apps/' + enc(app) + '/apply', {
        confirm: 'updateApply',
        headers: { 'X-RedX-Update-Confirm': permit },
        json: body(false),
      });
      permit = '';
      mount(result, h('p', null, 'Rollout ', r.rollout_id || '', r.snapshot_id ? [' · snapshot ', r.snapshot_id] : null));
      if (r.rollout_id) result.append(rolloutActions(r.rollout_id));
    } catch (e) { mount(result, h('p', null, updateMessage(e))); }
  }
  function body(isPlan) {
    const json = { version: ver.value, source: source.value, strategy: strategy.value, plan: isPlan };
    if (!isPlan && strategy.value === 'canary') json.canary = { percent: Number(percent.value) || 10, min_minutes: Number(minutes.value) || 0 };
    if (isPlan) json.dry_run = true;
    return json;
  }
  return h('div', { style: { marginTop: '12px' } },
    h('h4', null, 'Plan and apply'),
    h('div', { class: 'row gap wrap' }, ver, source, strategy, percent, minutes,
      h('button', { class: 'btn', type: 'button', disabled: !canMutate() || !versions.length, onclick: () => plan() }, 'Plan'),
      h('button', { class: 'btn primary', type: 'button', disabled: !canMutate() || !versions.length, onclick: () => apply() }, 'Apply')),
    h('p', { class: 'muted small' }, 'Plan checks the manifest and returns a single-use token. Apply sends that token as X-RedX-Update-Confirm together with X-RedX-Confirm.'),
    result);
}

function rolloutActions(id) {
  const health = h('div');
  async function refresh() {
    try {
      const r = await api('GET', '/v1/updates/rollouts/' + enc(id));
      const hv = r.health || {};
      const status = hv.status || 'unknown';
      const rate = hv.error_rate == null ? '–' : String(hv.error_rate);
      const p95 = hv.p95_ms == null ? '–' : String(hv.p95_ms);
      mount(health, h('p', null, 'State ', r.state || '', ' · health ', status, ' · error rate ', rate, ' · p95 ', p95, ' ms'));
    } catch (e) { mount(health, h('p', null, updateMessage(e))); }
  }
  async function act(kind, confirmId) {
    try {
      const plan = await api('POST', '/v1/updates/rollouts/' + enc(id) + '/' + kind, { confirm: confirmId, json: { plan: true } });
      await api('POST', '/v1/updates/rollouts/' + enc(id) + '/' + kind, {
        confirm: confirmId,
        headers: { 'X-RedX-Update-Confirm': plan.confirm },
        json: {},
      });
      toast(kind + ' sent', 'ok');
      refresh();
    } catch (e) { toast(updateMessage(e), 'err'); }
  }
  refresh();
  return h('div', null, health,
    h('div', { class: 'row gap wrap' },
      h('button', { class: 'btn small', type: 'button', disabled: !canMutate(), onclick: () => refresh() }, 'Refresh health'),
      h('button', { class: 'btn small', type: 'button', disabled: !canMutate(), onclick: () => act('promote', 'updatePromote') }, 'Promote'),
      h('button', { class: 'btn small', type: 'button', disabled: !canMutate(), onclick: () => act('rollback', 'updateRolloutRollback') }, 'Roll back rollout')));
}

async function snapshotBox(app) {
  const box = h('div', { style: { marginTop: '12px' } });
  let snaps = [];
  try {
    const r = await api('GET', '/v1/updates/apps/' + enc(app) + '/snapshots');
    snaps = r.snapshots || [];
  } catch (e) {
    box.append(h('p', { class: 'muted small' }, updateMessage(e)));
    return box;
  }
  box.append(h('h4', null, 'Snapshots'));
  if (!snaps.length) {
    box.append(h('p', { class: 'muted small' }, 'No snapshots yet. Apply takes one before it installs.'));
    return box;
  }
  box.append(table(['Snapshot', 'Version', 'Created', ''], snaps.map((s) => h('tr', null,
    h('td', null, h('code', null, s.id || '')),
    h('td', null, s.version || ''),
    h('td', null, s.created_at || ''),
    h('td', null, h('button', { class: 'btn small', type: 'button', disabled: !canMutate(), 'aria-label': 'Restore snapshot ' + (s.id || ''), onclick: () => restore(app, s.id) }, 'Restore'))))));
  return box;
}

async function restore(app, id) {
  try {
    const plan = await api('POST', '/v1/updates/apps/' + enc(app) + '/rollback', {
      confirm: 'updateAppRollback', json: { snapshot_id: id, plan: true },
    });
    await api('POST', '/v1/updates/apps/' + enc(app) + '/rollback', {
      confirm: 'updateAppRollback',
      headers: { 'X-RedX-Update-Confirm': plan.confirm },
      json: { snapshot_id: id },
    });
    toast('Restore sent', 'ok');
  } catch (e) { toast(updateMessage(e), 'err'); }
}

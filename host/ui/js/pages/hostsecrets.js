import { pageHead, page } from './shared.js';
import { h, api, enc, showErr, planBanners, appPicker, noApps, busy, loadApps, mount } from './hostshared.js';
import { toast, table } from '../util.js';

export default async function render({ args }) {
  const root = page();
  const id = args && args[0];
  const body = h('div');
  root.append(pageHead('Env & Secrets', 'Variables are visible. Secrets are write-only, encrypted at rest, and injected the next time the app starts.'), body);
  mount(body, busy());
  try {
    const d = await loadApps();
    const apps = d.apps || [];
    if (!apps.length) { mount(body, planBanners(d), noApps()); return root; }
    const pick = appPicker(apps, id, 'hostsecrets');
    if (!id) { mount(body, planBanners(d), h('div', { class: 'card' }, h('p', null, 'Choose an app.'), pick)); return root; }
    const app = await api('GET', '/v1/hosted/apps/' + enc(id));
    const env = await api('GET', '/v1/hosted/apps/' + enc(id) + '/env');
    const secrets = await api('GET', '/v1/hosted/apps/' + enc(id) + '/secrets');
    mount(body, planBanners(app), panel(app, env.env || {}, secrets.secrets || [], id, pick));
  } catch (e) { showErr(body, e); }
  return root;
}

function panel(app, env, secrets, id, pick) {
  const err = h('div');
  const key = h('input', { class: 'input', placeholder: 'COLOR', 'aria-label': 'Variable name' });
  const val = h('input', { class: 'input', placeholder: 'blue', 'aria-label': 'Variable value' });
  const secName = h('input', { class: 'input', placeholder: 'TOKEN', 'aria-label': 'Secret name' });
  const secVal = h('input', { class: 'input', type: 'password', placeholder: 'value (write-only)', 'aria-label': 'Secret value', autocomplete: 'off' });
  const rows = Object.keys(env).sort().map((k) => h('tr', null, h('td', null, h('code', null, k)), h('td', null, env[k])));
  const secretRows = secrets.map((s) => h('tr', null,
    h('td', null, h('code', null, s.name)),
    h('td', null, s.value || '••••••••'),
    h('td', null, h('button', { class: 'btn small', onclick: () => remove(s.name) }, 'Delete'))));
  const prompt = app.needsRedeploy ? h('div', { class: 'warn-box', role: 'status' },
    'These values changed after the last deploy. Restart the app so the running process picks them up. A restart counts as a host switch. ',
    h('button', { class: 'btn small primary', onclick: restart }, 'Restart to apply')) : null;
  return h('div', null,
    err, prompt,
    h('div', { class: 'card' }, pick),
    h('h2', { style: { marginTop: '16px' } }, 'Environment'),
    rows.length ? table(['Name', 'Value'], rows) : h('p', { class: 'muted' }, 'No variables yet.'),
    h('div', { class: 'row gap wrap' }, key, val, h('button', { class: 'btn', onclick: saveEnv }, 'Save variable')),
    h('h2', { style: { marginTop: '18px' } }, 'Secrets'),
    h('p', { class: 'muted' }, 'The value is encrypted with the host key and is never shown again. Saving a secret does not put it in the page, the API response, or the audit log.'),
    secretRows.length ? table(['Name', 'Value', ''], secretRows) : h('p', { class: 'muted' }, 'No secrets.'),
    h('div', { class: 'row gap wrap' }, secName, secVal, h('button', { class: 'btn primary', onclick: saveSecret }, 'Save secret')));

  function saveEnv() {
    mount(err);
    const vars = Object.assign({}, env);
    delete vars.REDX_URL; delete vars.REDX_DB; delete vars.REDX_KEY;
    if (!key.value.trim()) { mount(err, h('div', { class: 'form-err' }, 'Name the variable.')); return; }
    vars[key.value.trim()] = val.value;
    api('PUT', '/v1/hosted/apps/' + enc(id) + '/env', { json: { vars } }).then((out) => {
      toast(out.needsRedeploy ? 'Saved. Restart to apply.' : 'Saved', 'ok');
      location.reload();
    }).catch((e) => showErr(err, e));
  }
  function saveSecret() {
    mount(err);
    api('PUT', '/v1/hosted/apps/' + enc(id) + '/secrets/' + enc(secName.value.trim()), { json: { value: secVal.value } }).then((out) => {
      secVal.value = '';
      toast(out.needsRedeploy ? 'Secret stored. Restart to apply.' : 'Secret stored', 'ok');
      location.reload();
    }).catch((e) => showErr(err, e));
  }
  function remove(name) {
    mount(err);
    api('DELETE', '/v1/hosted/apps/' + enc(id) + '/secrets/' + enc(name)).then(() => { toast('Secret removed', 'ok'); location.reload(); }).catch((e) => showErr(err, e));
  }
  function restart() {
    mount(err);
    api('POST', '/v1/hosted/apps/' + enc(id) + '/start', {}).then(() => {
      toast('Restarted. New values are injected.', 'ok');
      location.reload();
    }).catch((e) => showErr(err, e));
  }
}

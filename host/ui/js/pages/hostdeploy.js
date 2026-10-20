import { pageHead, page } from './shared.js';
import { h, icon, api, enc, showErr, planBanners, appPicker, noApps, busy, loadApps, mount } from './hostshared.js';
import { session } from '../api.js';
import { chip, toast, table } from '../util.js';

export default async function render({ args }) {
  const root = page();
  const id = args && args[0];
  const body = h('div');
  root.append(pageHead('Deploy', 'Ship a git repo, a tarball, or an image. A failed health check rolls the previous release back.'), body);
  mount(body, busy());
  try {
    const d = await loadApps();
    const apps = d.apps || [];
    if (!apps.length) { mount(body, planBanners(d), noApps()); return root; }
    const pick = appPicker(apps, id, 'hostdeploy');
    if (!id) { mount(body, planBanners(d), h('div', { class: 'card' }, h('p', null, 'Choose an app to deploy.'), pick)); return root; }
    const app = await api('GET', '/v1/hosted/apps/' + enc(id));
    mount(body, planBanners(app), view(app, id, pick));
  } catch (e) { showErr(body, e); }
  return root;
}

function view(app, id, pick) {
  const err = h('div');
  const strategy = h('select', { class: 'input', 'aria-label': 'Strategy' },
    h('option', { value: 'direct' }, 'Direct'),
    h('option', { value: 'canary' }, 'Canary'),
    h('option', { value: 'blue_green' }, 'Blue-green'));
  const file = h('input', { type: 'file', 'aria-label': 'Archive', accept: '.zip,.tar,.gz,application/gzip,application/zip' });
  const repo = h('input', { class: 'input', placeholder: 'owner/repo', 'aria-label': 'GitHub repository' });
  const ref = h('input', { class: 'input', placeholder: 'ref (tag, branch, commit)', 'aria-label': 'Git ref' });
  const image = h('input', { class: 'input', placeholder: 'image reference', 'aria-label': 'Container image' });
  const reload = () => { location.hash = '#/hostdeploy/' + enc(id); location.reload(); };
  const act = async (path, opts, ok) => {
    mount(err);
    try { await api('POST', '/v1/hosted/apps/' + enc(id) + path, opts || {}); toast(ok, 'ok'); reload(); }
    catch (e) { showErr(err, e); }
  };
  const upload = async () => {
    mount(err);
    if (!file.files || !file.files[0]) { mount(err, h('div', { class: 'form-err' }, 'Choose a zip, tar, or tar.gz.')); return; }
    try {
      const res = await fetch('/v1/hosted/apps/' + enc(id) + '/archive?strategy=' + encodeURIComponent(strategy.value), {
        method: 'POST', headers: { Authorization: 'Bearer ' + session.key }, body: file.files[0],
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw Object.assign(new Error(data.error || 'upload failed'), { status: res.status, body: data });
      toast(data.rolledBack ? 'Health check failed. Previous release restored.' : 'Deployed', data.rolledBack ? 'err' : 'ok');
      reload();
    } catch (e) { showErr(err, e); }
  };
  const deps = (app.deploys || []).map((d) => h('tr', null,
    h('td', null, h('code', null, d.id)),
    h('td', null, d.source || ''),
    h('td', null, chip(d.status || '', d.status === 'active' ? 'ok' : d.status === 'unhealthy' ? 'bad' : '')),
    h('td', null, d.id && d.id !== app.current ? h('button', { class: 'btn small', onclick: () => act('/rollback', { json: { deploy: d.id } }, 'Rolled back') }, 'Roll back') : 'current')));
  return h('div', null,
    err,
    h('div', { class: 'card' },
      pick,
      h('h2', null, app.name || id),
      h('p', null, h('code', null, app.host || '–'), ' ', app.running ? chip('running', 'ok') : chip('stopped', ''), ' ', app.health ? chip(app.health, app.health === 'healthy' ? 'ok' : '') : null),
      h('div', { class: 'row gap wrap' },
        h('button', { class: 'btn primary', onclick: () => act('/start', {}, 'Started') }, 'Start'),
        h('button', { class: 'btn', onclick: () => act('/stop', {}, 'Stopped') }, 'Stop'),
        h('button', { class: 'btn', onclick: () => act('/promote', {}, 'Promoted') }, 'Promote'),
        h('button', { class: 'btn', onclick: async () => {
          mount(err);
          try {
            const health = await api('GET', '/v1/hosted/apps/' + enc(id) + '/health');
            toast('Health: ' + (health.health || 'unknown'), health.health === 'healthy' ? 'ok' : 'err');
          } catch (e) { showErr(err, e); }
        } }, 'Check health'))),
    h('h2', { style: { marginTop: '18px' } }, 'Archive'),
    h('div', { class: 'row gap wrap' }, file, strategy, h('button', { class: 'btn primary', onclick: upload }, icon('upload', 16), ' Upload')),
    h('h2', { style: { marginTop: '18px' } }, 'Git'),
    h('div', { class: 'row gap wrap' }, repo, ref,
      h('button', { class: 'btn', onclick: () => act('/deploy', { json: { source: 'github', repo: repo.value.trim(), ref: ref.value.trim() || 'main', strategy: strategy.value } }, 'Deployed from git') }, 'Deploy git')),
    h('h2', { style: { marginTop: '18px' } }, 'Image'),
    h('div', { class: 'row gap wrap' }, image,
      h('button', { class: 'btn', onclick: () => act('/deploy', { json: { source: 'image', image: image.value.trim(), strategy: strategy.value } }, 'Image deploy recorded') }, 'Deploy image')),
    h('h2', { style: { marginTop: '18px' } }, 'History'),
    deps.length ? table(['Deploy', 'Source', 'Status', ''], deps) : h('p', { class: 'muted' }, 'No deploys yet.'));
}

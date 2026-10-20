import { pageHead, page } from './shared.js';
import { h, icon, api, enc, navigate, showErr, planBanners, appTable, busy, mount } from './hostshared.js';
import { fmtBytes, chip, toast, emptyState } from '../util.js';

const NAME_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;

export default async function render({ args }) {
  const root = page();
  if (args && args[0]) return renderOne(root, args[0]);
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
    if (!NAME_RE.test(n) || n.endsWith('-')) {
      mount(err, h('div', { class: 'form-err' }, 'Use a DNS name: letters, digits and hyphens, up to 40 characters.'));
      return;
    }
    try {
      const body = { name: n, kind: kind.value };
      if (db.value.trim()) body.db = db.value.trim();
      const app = await api('POST', '/v1/hosted/apps', { json: body });
      toast('App "' + n + '" created', 'ok');
      name.value = '';
      navigate('hostapps/' + app.id);
    } catch (e) { showErr(err, e); }
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
    mount(list, busy());
    try {
      const d = await api('GET', '/v1/hosted/apps');
      const apps = d.apps || [];
      const bits = planBanners(d);
      if (!apps.length) bits.push(emptyState('rocket', 'No apps yet', 'Create a static site or a container. Paying subscribers host them here, next to their databases.', null));
      else bits.push(appTable(apps));
      const u = d.usage || {};
      const lim = d.limits || {};
      bits.push(h('p', { class: 'muted small' }, (u.apps || 0), ' of ', lim.maxApps || '–', ' apps · ', fmtBytes(u.diskBytes || 0), ' on disk · ', u.running || 0, ' running'));
      mount(list, bits);
    } catch (e) { showErr(list, e); }
  }
}

async function renderOne(root, id) {
  const body = h('div');
  root.append(pageHead('App', 'Hostname, health, and the pages that change this app.'),
    h('a', { class: 'btn small', href: '#/hostapps' }, 'All apps'), body);
  mount(body, busy());
  try {
    const app = await api('GET', '/v1/hosted/apps/' + enc(id));
    const links = [
      ['hostdeploy/' + enc(id), 'Deploy', 'upload'],
      ['hostdomains/' + enc(id), 'Domains', 'globe'],
      ['hostsecrets/' + enc(id), 'Env & Secrets', 'lock'],
    ];
    mount(body,
      planBanners(app),
      h('div', { class: 'card' },
        h('h2', null, app.name || id),
        h('p', null, 'Default host ', h('code', null, app.host || '–')),
        h('p', null, app.running ? chip('running', 'ok') : chip('stopped', ''), ' ', app.health ? chip(app.health, app.health === 'healthy' ? 'ok' : '') : null, app.uid ? [' ', h('span', { class: 'muted' }, 'uid ' + app.uid)] : null),
        h('p', { class: 'muted' }, fmtBytes(app.diskBytes || 0), ' on disk')),
      h('div', { class: 'row gap wrap', style: { marginTop: '12px' } },
        links.map(([path, title, ico]) => h('a', { class: 'btn', href: '#/' + path }, icon(ico, 16), ' ' + title))));
  } catch (e) { showErr(body, e); }
  return root;
}

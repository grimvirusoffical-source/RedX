import { pageHead, page } from './shared.js';
import { h, api, enc, showErr, planBanners, appPicker, noApps, busy, loadApps, mount } from './hostshared.js';
import { chip, toast, table } from '../util.js';

export default async function render({ args }) {
  const root = page();
  const id = args && args[0];
  const body = h('div');
  root.append(pageHead('Domains', 'Custom domains need a DNS TXT or CNAME check before Caddy will issue a certificate.'), body);
  mount(body, busy());
  try {
    const d = await loadApps();
    const apps = d.apps || [];
    if (!apps.length) { mount(body, planBanners(d), noApps()); return root; }
    const pick = appPicker(apps, id, 'hostdomains');
    if (!id) { mount(body, planBanners(d), h('div', { class: 'card' }, h('p', null, 'Choose an app.'), pick)); return root; }
    const listed = await api('GET', '/v1/hosted/apps/' + enc(id) + '/domains');
    const app = await api('GET', '/v1/hosted/apps/' + enc(id));
    mount(body, planBanners(app), panel(app, listed.domains || [], id, pick));
  } catch (e) { showErr(body, e); }
  return root;
}

function panel(app, domains, id, pick) {
  const err = h('div');
  const name = h('input', { class: 'input', placeholder: 'www.example.com', 'aria-label': 'Custom domain' });
  const method = h('select', { class: 'input', 'aria-label': 'Verification method' },
    h('option', { value: 'txt' }, 'DNS TXT'),
    h('option', { value: 'cname' }, 'DNS CNAME'));
  const lim = (app.limits && app.limits.domains) || '–';
  const reload = () => { location.hash = '#/hostdomains/' + enc(id); location.reload(); };
  const rows = domains.map((d) => {
    const recs = (d.records || []).map((r) => h('div', { class: 'muted small' }, r.type, ' ', r.name, ' → ', r.value));
    return h('tr', null,
      h('td', null, d.name, recs),
      h('td', null, d.kind || ''),
      h('td', null, d.verified ? chip('verified', 'ok') : chip('pending', '')),
      h('td', null, d.kind === 'custom' ? h('div', { class: 'row gap' },
        !d.verified ? h('button', { class: 'btn small', onclick: () => post('/domains/' + enc(d.name) + '/verify', 'Checked') }, 'Verify') : null,
        h('button', { class: 'btn small', onclick: () => del(d.name) }, 'Remove')) : null));
  });
  return h('div', null,
    err,
    h('div', { class: 'card' }, pick, h('p', null, 'Default host ', h('code', null, app.host || '–'), ' · ', lim, ' custom domains on this plan.')),
    h('div', { class: 'row gap wrap', style: { marginTop: '12px' } }, name, method,
      h('button', { class: 'btn primary', onclick: async () => {
        mount(err);
        try {
          await api('POST', '/v1/hosted/apps/' + enc(id) + '/domains', { json: { domain: name.value.trim(), method: method.value } });
          toast('Domain claimed. Publish the DNS record, then verify.', 'ok');
          reload();
        } catch (e) { showErr(err, e); }
      } }, 'Add domain')),
    h('div', { style: { marginTop: '12px' } }, rows.length ? table(['Name', 'Kind', 'Status', ''], rows) : h('p', { class: 'muted' }, 'No names yet. The default hostname is already verified.')));

  function post(path, ok) {
    mount(err);
    api('POST', '/v1/hosted/apps/' + enc(id) + path, {}).then(() => { toast(ok, 'ok'); reload(); }).catch((e) => showErr(err, e));
  }
  function del(domain) {
    mount(err);
    api('DELETE', '/v1/hosted/apps/' + enc(id) + '/domains/' + enc(domain)).then(() => { toast('Removed', 'ok'); reload(); }).catch((e) => showErr(err, e));
  }
}

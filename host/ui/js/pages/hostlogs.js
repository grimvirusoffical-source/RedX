import { pageHead, page } from './shared.js';
import { h, api, enc, showErr, planBanners, appPicker, noApps, busy, loadApps, mount } from './hostshared.js';
import { toast } from '../util.js';

export default async function render({ args }) {
  const root = page();
  const id = args && args[0];
  const body = h('div');
  root.append(pageHead('App logs', 'Runtime stdout and request lines for one app. Search and live tail run when you ask. Retention follows the plan.'), body);
  mount(body, busy());
  try {
    const d = await loadApps();
    const apps = d.apps || [];
    if (!apps.length) { mount(body, planBanners(d), noApps()); return root; }
    const pick = appPicker(apps, id, 'hostlogs');
    if (!id) { mount(body, planBanners(d), h('div', { class: 'card' }, h('p', null, 'Choose an app.'), pick)); return root; }
    const app = await api('GET', '/v1/hosted/apps/' + enc(id));
    mount(body, planBanners(app), panel(app, id, pick));
  } catch (e) { showErr(body, e); }
  return root;
}

function panel(app, id, pick) {
  const err = h('div');
  const kind = h('select', { class: 'input', 'aria-label': 'Log kind' },
    h('option', { value: 'runtime' }, 'Runtime'),
    h('option', { value: 'access' }, 'Requests'));
  const q = h('input', { class: 'input', placeholder: 'Search retained lines', 'aria-label': 'Search logs' });
  const box = h('pre', { class: 'muted', style: { whiteSpace: 'pre-wrap', maxHeight: '360px', overflow: 'auto' } }, 'Search or tail to load logs. This page does not open a stream on its own.');
  let es;
  const stop = () => { if (es) { es.close(); es = null; } };
  const days = (app.limits && app.limits.logDays) || '–';
  return h('div', null,
    err,
    h('div', { class: 'card' }, pick, h('p', { class: 'muted' }, app.name || id, ' · kept ', days, ' day(s). Request bytes count toward the traffic quota.')),
    h('div', { class: 'row gap wrap', style: { marginTop: '12px' } }, kind, q,
      h('button', { class: 'btn primary', onclick: search }, 'Search'),
      h('button', { class: 'btn', onclick: tail }, 'Live tail'),
      h('button', { class: 'btn', onclick: () => { stop(); box.textContent = 'Tail stopped.'; } }, 'Stop'),
      h('button', { class: 'btn', onclick: download }, 'Download')),
    box);

  async function search() {
    stop();
    mount(err);
    try {
      const d = await api('GET', '/v1/hosted/apps/' + enc(id) + '/logs?kind=' + encodeURIComponent(kind.value) + '&q=' + encodeURIComponent(q.value.trim()));
      box.textContent = d.log || '(no matching lines)';
    } catch (e) { showErr(err, e); }
  }
  function tail() {
    stop();
    mount(err);
    box.textContent = '';
    const url = '/v1/hosted/apps/' + enc(id) + '/logs?kind=' + encodeURIComponent(kind.value) + '&stream=1' + (q.value.trim() ? '&q=' + encodeURIComponent(q.value.trim()) : '');
    fetch(url, { headers: { Authorization: 'Bearer ' + (sessionKey()) } }).then(async (res) => {
      if (!res.ok || !res.body) {
        const t = await res.text();
        throw new Error(t || 'tail failed');
      }
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      const pump = () => reader.read().then(({ done, value }) => {
        if (done) return;
        box.textContent += dec.decode(value);
        box.scrollTop = box.scrollHeight;
        return pump();
      });
      return pump();
    }).catch((e) => showErr(err, e));
    toast('Tailing for up to 15 seconds', 'ok');
  }
  async function download() {
    stop();
    mount(err);
    try {
      const res = await api('GET', '/v1/hosted/apps/' + enc(id) + '/logs/download?kind=' + encodeURIComponent(kind.value), { raw: true });
      if (!res.ok) throw new Error(await res.text());
      const blob = await res.blob();
      const a = h('a', { href: URL.createObjectURL(blob), download: kind.value + '.log' });
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    } catch (e) { showErr(err, e); }
  }
}

function sessionKey() {
  return sessionStorage.getItem('redx.key') || localStorage.getItem('redx.key') || '';
}

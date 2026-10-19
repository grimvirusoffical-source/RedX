import { h, icon, terminalPanel, chip, mount, toast, errorBox, spinner, copy, confirmDialog, table } from '../util.js';
import { api, session } from '../api.js';
import { state, setTheme, setMode, isHostAdmin, gs, wizard } from '../state.js';
import { pageHead, page } from './shared.js';

const GROUPS = [
  ['Network', ['listen', 'tls', 'advertise', 'role', 'peers', 'heartbeat_seconds', 'repl_log_max']],
  ['Storage', ['data_dir', 'default_db', 'engine_durability', 'engine_default_ttl', 'argon_memory_kib']],
  ['Security', ['keystore_encrypt', 'bootstrap', 'rate_limit_rps', 'rate_limit_burst', 'audit_success', 'audit_log', 'code_allowed_boxes']],
  ['Limits & logging', ['max_body_mb', 'max_upload_mb', 'log_level']],
];

export default async function render() {
  const root = page();
  const cfgBox = h('div');
  const themeSel = h('div', { class: 'seg' }, [['dark', 'Dark'], ['system', 'System (match the device)'], ['light', 'Light']].map(([k, l]) => h('span', { class: 'seg-opt' + (state.theme === k ? ' on' : ''), tabindex: 0, onclick: () => { setTheme(k); themeSel.querySelectorAll('.seg-opt').forEach((o, i) => o.classList.toggle('on', ['dark', 'system', 'light'][i] === k)); } }, l)));
  const modeSel = h('div', { class: 'seg' }, [['simple', 'Simple'], ['advanced', 'Advanced']].map(([k, l]) => h('span', { class: 'seg-opt' + (state.mode === k ? ' on' : ''), tabindex: 0, onclick: () => { setMode(k); modeSel.querySelectorAll('.seg-opt').forEach((o, i) => o.classList.toggle('on', ['simple', 'advanced'][i] === k)); } }, l)));
  const swState = h('span', { class: 'muted small' }, 'checking…');
  if ('serviceWorker' in navigator) navigator.serviceWorker.getRegistration().then((r) => { swState.textContent = r ? 'Offline shell installed (the console UI opens without a connection; data always comes from the host).' : 'Not installed (service workers need HTTPS or localhost).'; });
  else swState.textContent = 'Not supported by this browser.';

  root.append(pageHead('Settings', 'Console preferences and the running configuration of this host.'),
    h('div', { class: 'grid g2' },
      h('div', { class: 'card' }, h('h3', null, 'This browser'),
        row('Theme', themeSel), row('Mode', modeSel, 'Simple hides the expert pages.'),
        row('Signed in as', h('span', null, chip(state.who.scope, 'acc'), ' ', state.who.label || state.who.id || '', ' ', chip(session.remembered ? 'remembered on this device' : 'this tab only', session.remembered ? 'warn' : 'ok'))),
        row('Offline shell', swState),
        h('div', { class: 'row gap wrap', style: { marginTop: '12px' } },
          h('button', { class: 'btn', onclick: async () => { if (await confirmDialog('Sign out?', 'The key is removed from this browser. It still works elsewhere until you revoke it.', { ok: 'Sign out' })) { session.clear(); location.hash = '#/'; location.reload(); } } }, 'Sign out'),
          h('button', { class: 'btn', onclick: () => { gs.reset(); localStorage.removeItem('redx.gs.dismissed'); localStorage.removeItem('redx.wizard'); toast('Get-started checklist reset', 'ok'); } }, 'Reset Get-started'),
          h('button', { class: 'btn', onclick: () => { ['redx.hist', 'redx.saved', 'redx.studio.draft'].forEach((k) => localStorage.removeItem(k)); toast('Saved queries and history cleared', 'ok'); } }, 'Clear saved queries'))),
      h('div', { class: 'card' }, h('h3', null, 'Documentation'),
        ['box-grammar:Box file grammar', 'boxql:BoxQL guide', 'hosting:Hosting guide', 'clustering:Clustering', 'connect:Connecting apps', 'console:This console'].map((x) => { const [id, t] = x.split(':'); return h('div', null, h('a', { href: '#/help/' + id }, icon('book', 14), ' ', t)); }),
        h('p', { class: 'muted small' }, 'Everything is built into the host, so it works offline.'))),
    cfgBox,
    terminalPanel([{ label: 'Check the configuration', cmd: 'redxd doctor' }, { label: 'Same, with the client', cmd: 'redx doctor' }, { label: 'Config file', cmd: 'redxd run --config /etc/redx/redx.toml' }, { label: 'Show a preset', cmd: 'redx preset show server' }], 'Configuration lives in a TOML file; environment variables and flags override it.'));

  if (!isHostAdmin()) { mount(cfgBox, h('p', { class: 'muted' }, 'Host configuration needs an admin key.')); return root; }
  mount(cfgBox, spinner());
  try {
    const [c, st] = await Promise.all([api('GET', '/v1/admin/config'), api('GET', '/v1/admin/status')]);
    const cfg = c.config;
    const shown = new Set();
    const groups = GROUPS.map(([t, keys]) => {
      const ks = keys.filter((k) => k in cfg);
      ks.forEach((k) => shown.add(k));
      return [t, ks];
    });
    const rest = Object.keys(cfg).filter((k) => !shown.has(k)).sort();
    if (rest.length) groups.push(['Other', rest]);
    const envs = Array.isArray(c.env_overrides) ? c.env_overrides : []; // null-safe: older hosts sent null
    const fmt = (v) => (Array.isArray(v) ? v.join(', ') || '(none)' : v === '' || v == null ? '(not set)' : String(v));
    mount(cfgBox,
      h('h2', null, 'Running configuration'),
      h('p', { class: 'muted' }, 'Secrets are never shown. Config file: ', h('code', null, c.config_file), c.config_file_exists ? '' : ' (not created yet; defaults are in use)', st.preset ? [' · preset ', chip(st.preset, 'acc')] : null),
      envs.length ? h('div', { class: 'callout info' }, icon('info'), h('div', null, 'Set by environment variable (wins over the file): ', envs.map((k) => h('code', { class: 'pill' }, k)))) : null,
      st.tls_warning ? h('div', { class: 'callout ' + (st.tls_cert && st.tls_cert.state === 'expiring' ? 'warn' : 'err'), role: 'alert' }, icon('alert'), h('div', null, h('b', null, 'TLS certificate: '), st.tls_warning)) : null,
      st.tls_fingerprint ? h('div', { class: 'card' }, h('h3', null, icon('lock', 18), 'TLS certificate fingerprint'), h('p', { class: 'muted' }, 'Clients and follower nodes that use this self-signed certificate should pin this value instead of turning verification off.'), h('div', { class: 'term-cmd' }, h('pre', null, st.tls_fingerprint), h('button', { class: 'icon-btn', 'aria-label': 'Copy', onclick: () => copy(st.tls_fingerprint, 'Fingerprint copied') }, icon('copy', 15))), h('p', { class: 'small muted' }, 'Use it with ', h('code', null, 'redx --pin <fingerprint>'), ' or the pin field of a join link.')) : null,
      groups.filter(([, ks]) => ks.length).map(([t, ks]) => h('div', { class: 'card', style: { marginTop: '12px' } }, h('h3', null, t), h('div', { class: 'kv' }, ks.map((k) => [h('div', { class: 'k mono' }, k, envs.includes(k) ? chip('env', 'warn') : null), h('div', { class: 'v' }, h('span', { class: 'mono' }, fmt(cfg[k])))])))),
      h('div', { class: 'row gap wrap', style: { marginTop: '12px' } }, chip('Keystore ' + (c.config.keystore_encrypt ? 'encrypted' : 'not encrypted'), c.config.keystore_encrypt ? 'ok' : 'warn'), chip('Master key ' + (c.master_key_present ? 'present' : 'none')), h('a', { class: 'btn small', href: '#/presets' }, 'Compare presets')));
  } catch (e) { mount(cfgBox, errorBox(e.message)); }
  return root;
}
function row(k, v, hint) { return h('div', { class: 'srow' }, h('div', null, h('b', null, k), hint ? h('div', { class: 'muted small' }, hint) : null), h('div', null, v)); }

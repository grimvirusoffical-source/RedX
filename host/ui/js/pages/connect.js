// Consent page for the app connect handshake (docs/connect.md).
//   #/connect?v=1&provider=..&state=..&pkce_challenge=..&callback=..[&app=..&workspace=..&scope=..&prefix=..&host=..&pin=..&name=..]
// The link carries no secret. The provider's name shown here comes from RedX's own list, never from the link.
import { h, icon, chip, mount, toast, field, copy, errorBox, emptyState } from '../util.js';
import { api } from '../api.js';
import { isHostAdmin } from '../state.js';
import { pageHead, page } from './shared.js';

const LINK_KEYS = ['v', 'provider', 'app', 'workspace', 'scope', 'prefix', 'label', 'engines', 'state', 'pkce_challenge', 'pkce_method', 'callback', 'host', 'pin', 'name'];
const SAVE = 'redx.connect.link';

const scopeWords = (s) => (s === 'read' ? 'look at data' : 'read and change data');

export default async function render({ query, navigate }) {
  const root = page();
  let q = query && query.state ? query : null;
  if (!q) { try { q = JSON.parse(sessionStorage.getItem(SAVE) || 'null'); } catch { q = null; } }
  root.append(pageHead('Connect an app', 'An app asked to use this RedX host. Nothing is shared until you approve.'));
  if (!isHostAdmin()) {
    root.append(h('div', { class: 'callout warn' }, icon('alert'), h('div', null, 'Only a host admin can connect apps. Sign in with an admin key.')));
    return root;
  }
  if (!q) {
    root.append(emptyState('link', 'No connect request open', 'Start the connection from the app (for example Rotten Apple or Gendragoon). It opens this page with its request.',
      h('a', { class: 'btn', href: '#/apps' }, icon('list', 15), ' Connected apps')));
    return root;
  }
  try { sessionStorage.setItem(SAVE, JSON.stringify(q)); } catch { /* private mode */ }
  const body = {};
  for (const k of LINK_KEYS) if (q[k] !== undefined && q[k] !== '') body[k] = k === 'v' ? Number(q[k]) : String(q[k]);
  let s;
  try {
    s = await api('POST', '/v1/connect/start', { json: body });
  } catch (e) {
    sessionStorage.removeItem(SAVE);
    const code = e.body && e.body.code;
    const msg = code === 'expired' || code === 'code_used' || code === 'superseded' || code === 'denied'
      ? 'This request is ' + (code === 'code_used' ? 'already finished' : code) + '. Go back to the app and tap Connect again.'
      : code === 'client_too_old' ? 'The app is too old for this RedX. Update the app and connect again.' : e.message;
    root.append(h('div', { class: 'callout warn' }, icon('alert'), h('div', null, msg)));
    return root;
  }
  const p = s.provider;
  const card = h('div', { class: 'card connect-card' });
  root.append(card);
  const left = h('b');
  const exp = Date.parse(s.expires_at);
  let shown = false; // the countdown stops at 0 and when the page is left (the element leaves the document)
  const update = () => {
    const sec = Math.max(0, Math.round((exp - Date.now()) / 1000));
    left.textContent = Math.floor(sec / 60) + ':' + String(sec % 60).padStart(2, '0');
    if (left.isConnected) shown = true;
    if (!sec || (shown && !left.isConnected)) clearInterval(tick);
  };
  const tick = setInterval(update, 1000);
  update(); // filled at once, not after the first second
  const wsIn = h('input', { class: 'input', value: s.defaults.workspace, 'aria-label': 'Workspace name', readonly: s.defaults.workspace_fixed || undefined, spellcheck: 'false' });
  const replace = h('input', { type: 'checkbox', 'aria-label': 'Replace the existing key' });
  const confirmIn = h('input', { class: 'input', placeholder: p.id, 'aria-label': 'Type the app id to confirm', autocomplete: 'off' });
  const out = h('div');
  const approveBtn = h('button', { class: 'btn primary', onclick: approve }, icon('check', 16), ' Approve');
  const denyBtn = h('button', { class: 'btn danger', onclick: deny }, icon('x', 16), ' Deny');
  mount(card,
    h('div', { class: 'row gap wrap' }, h('h2', null, p.display), p.verified ? chip('verified', 'ok') : chip('unverified', 'warn')),
    h('p', null, h('b', null, p.display), ' wants to connect to this RedX host', s.app ? [' for the app ', h('code', null, s.app)] : null, '. Request expires in ', left, '.'),
    s.name ? h('p', { class: 'muted small' }, 'The link calls itself “' + s.name + '”. That label comes from the link and is not checked.') : null,
    p.wording ? h('p', null, p.wording) : null,
    !p.verified ? h('div', { class: 'callout warn' }, icon('alert'), h('div', null, h('b', null, 'This app is not in RedX\'s list of known apps. '), 'Only continue if you started this yourself. ', field('Type ' + p.id + ' to confirm', confirmIn))) : null,
    field('Workspace name', wsIn, s.defaults.workspace_fixed ? 'Each app gets its own workspace (a new database). The name is fixed.' : 'A new database for this app. It never gets an existing database that was not made for it.'),
    s.workspace.other_owner ? h('div', { class: 'callout warn' }, icon('alert'), h('div', null, 'A database named ', h('code', null, s.defaults.workspace), ' already exists and was not made for this app. Pick another name.')) : null,
    h('h4', null, p.display + ' will be able to:'),
    h('ul', null, h('li', null, scopeWords(s.defaults.scope) + ' in this workspace only' + (s.defaults.prefix ? ' (under ' + s.defaults.prefix + ')' : ''))),
    h('h4', null, 'It will NOT be able to:'),
    h('ul', null, s.cannot.map((c) => h('li', null, c))),
    s.single_key && s.active_key ? h('label', { class: 'row gap' }, replace, h('span', null, p.display + ' already has a key for this workspace. Replace it (the old key is revoked when the new one is issued).')) : null,
    h('details', null, h('summary', null, 'Details'), h('p', { class: 'muted small' }, 'scope: ' + s.defaults.scope + ' · prefix: ' + (s.defaults.prefix || 'none') + ' · key expires: never · storage: on this host · callback: ' + (p.callback_ok ? 'to the app' : 'none (copy the code by hand)'))),
    h('div', { class: 'row gap wrap' }, approveBtn, denyBtn),
    out);

  async function approve() {
    approveBtn.disabled = true;
    try {
      const a = await api('POST', '/v1/connect/approve', { json: { request_id: s.request_id, workspace: wsIn.value.trim(), confirm: confirmIn.value.trim(), replace: replace.checked }, confirm: 'connectApprove' });
      sessionStorage.removeItem(SAVE);
      clearInterval(tick);
      denyBtn.disabled = true;
      const cb = a.callback_template ? a.callback_template.replace('{state}', encodeURIComponent(q.state)) : '';
      mount(out, h('div', { class: 'callout ok' }, icon('check'), h('div', null,
        h('p', null, h('b', null, 'Approved. '), cb ? 'Sending you back to the app…' : 'Copy this into the app to finish:'),
        h('div', { class: 'code-big' }, a.code),
        h('p', { class: 'muted small' }, 'Works once, for 5 minutes, and only together with the secret the app kept. The key is created when the app redeems it.'),
        h('div', { class: 'row gap wrap' },
          cb ? h('a', { class: 'btn primary', href: cb }, icon('link', 15), ' Open the app') : null,
          h('button', { class: 'btn', onclick: () => copy(a.paste, 'Copied') }, icon('copy', 15), ' Copy address and code')))));
      if (cb) setTimeout(() => { location.href = cb; }, 600);
    } catch (e) {
      approveBtn.disabled = false;
      mount(out, errorBox(e.message));
    }
  }
  async function deny() {
    try {
      await api('POST', '/v1/connect/deny', { json: { request_id: s.request_id } });
      sessionStorage.removeItem(SAVE);
      clearInterval(tick);
      toast('Request denied', 'ok');
      navigate('apps');
    } catch (e) { mount(out, errorBox(e.message)); }
  }
  return { el: root, destroy: () => clearInterval(tick) };
}

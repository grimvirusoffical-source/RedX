// Full-screen flows: Welcome (first run), Login, Join link landing page.
import { h, icon, copy, download, toast, field } from '../util.js';
import { api, session, exchangePairingCode, looksLikePairingCode } from '../api.js';

function logo(sub) {
  return h('div', { class: 'auth-logo' }, h('img', { src: '/ui/icons/redx-192.png', width: 84, height: 84, alt: 'RedX' }), h('h1', null, 'RedX'), h('p', { class: 'muted' }, sub));
}

/** First run on this computer: create the admin key, shown once. */
export function renderWelcome(onDone) {
  const card = h('div', { class: 'auth-card' });
  const label = h('input', { class: 'input', value: 'my admin key', maxlength: 64, 'aria-label': 'Key label' });
  const remember = h('input', { type: 'checkbox', id: 'rem' });
  const err = h('div', { class: 'form-err', hidden: true, role: 'alert' });
  const btn = h('button', { class: 'btn primary big', onclick: create }, icon('key', 18), ' Create admin key');
  card.append(logo('Welcome. Your database host is running.'),
    h('p', null, 'RedX needs one ', h('b', null, 'admin key'), ' to protect your data. Create it now: it is shown ', h('b', null, 'once'), ', so keep a copy.'),
    field('Name for this key', label), err, btn,
    h('p', { class: 'muted small' }, 'Only this computer can see this screen. After you create the key it disappears for good. Prefer the terminal? Restart with ', h('code', null, '--bootstrap console'), '.'));
  async function create() {
    btn.disabled = true;
    err.hidden = true;
    try {
      const r = await api('POST', '/v1/ui/bootstrap', { json: { label: label.value }, key: '', noAuthRedirect: true });
      showKey(r.key);
    } catch (e) {
      err.textContent = e.status === 404 ? 'Setup is already finished or is not available from this address. Open the console on the computer running redxd (http://127.0.0.1:7777) and sign in with a key.' : e.message;
      err.hidden = false;
      btn.disabled = false;
    }
  }
  function showKey(key) {
    card.replaceChildren(logo('Your admin key'),
      h('div', { class: 'keybox' }, h('code', { id: 'newkey' }, key)),
      h('div', { class: 'row gap' },
        h('button', { class: 'btn', onclick: () => copy(key, 'Key copied') }, icon('copy', 16), ' Copy'),
        h('button', { class: 'btn', onclick: () => download('redx-admin-key.txt', 'RedX admin key (keep this file private)\n\n' + key + '\n', 'text/plain') }, icon('download', 16), ' Download')),
      h('p', { class: 'warn-text' }, icon('alert', 16), ' This is the only time the key is shown. RedX stores only a hash, so it cannot be recovered.'),
      h('label', { class: 'check' }, remember, ' Remember this device (keeps the key in this browser until you sign out; otherwise it is forgotten when you close the tab)'),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', id: 'saved', onchange: (e) => { go.disabled = !e.target.checked; } }), ' I saved the key somewhere safe'),
    );
    const go = h('button', { class: 'btn primary big', disabled: true, onclick: async () => { session.set(key, remember.checked); await onDone(); } }, 'Continue');
    card.append(go);
  }
  return h('div', { class: 'auth' }, card);
}

export function renderLogin(msg, onDone, opts) {
  const input = h('input', { class: 'input mono', type: 'password', placeholder: 'rx_live_…  or  RP-XXXXX-XXXXX', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'API key or pairing code' });
  const remember = h('input', { type: 'checkbox' });
  const err = h('div', { class: 'form-err', role: 'alert', hidden: !msg }, msg || '');
  const go = async () => {
    let k = input.value.trim();
    if (!k) return;
    err.hidden = true;
    try {
      if (looksLikePairingCode(k)) k = await exchangePairingCode(k); // a one-time code from another signed-in device
      await api('GET', '/v1/ui/whoami', { key: k, noAuthRedirect: true });
      session.set(k, remember.checked);
      await onDone();
    } catch (e) {
      err.textContent = e.status === 401 && !looksLikePairingCode(input.value) ? 'That key was not accepted. Check for missing characters, or ask an admin for a new one.' : e.message;
      err.hidden = false;
    }
  };
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  const card = h('div', { class: 'auth-card' }, logo('Sign in with an API key'),
    field('API key or pairing code', input), err,
    h('label', { class: 'check' }, remember, ' Remember this device'),
    h('button', { class: 'btn primary big', onclick: go }, 'Sign in'),
    h('p', { class: 'muted small' }, 'Keys stay in this browser and are only sent to this RedX host. Lost the admin key? On the host computer run ', h('code', null, 'redx key create --offline --scope admin --db \'*\''), '.'));
  setTimeout(() => input.focus(), 50);
  const wrap = h('div', { class: 'auth' }, card);
  // Red-XAI Accounts sign-in, when this host has it configured
  import('./account.js').then(async ({ accountsConfig, accountButtons, renderSignup, emailResendControl }) => {
    if (opts && Object.prototype.hasOwnProperty.call(opts, 'resendLogin')) {
      card.append(h('div', { class: 'warn-box', id: 'signin-email-unverified' },
        h('p', null, 'Resend the confirmation link, open it, then sign in again.'),
        emailResendControl({ login: opts.resendLogin || '' })));
    }
    const cfg = await accountsConfig();
    if (!cfg.enabled) return;
    card.append(accountButtons(cfg, () => {
      const su = renderSignup(() => su.replaceWith(renderLogin(msg, onDone, opts)));
      wrap.replaceWith(su);
    }));
  }).catch(() => {});
  return wrap;
}

/** Landing page for a join link opened in a browser. */
export function renderJoin(q) {
  const link = location.href;
  return h('div', { class: 'auth' }, h('div', { class: 'auth-card wide' }, logo('Join link'),
    h('p', null, 'This link lets another computer join this RedX host as a ', h('b', null, 'node'), ' (a copy that follows this host). It works once and expires about 10 minutes after it was made.'),
    h('p', null, 'On the new computer, with RedX unpacked, run:'),
    h('div', { class: 'term-cmd' }, h('pre', null, 'redxd join "' + link + '"'), h('button', { class: 'icon-btn', 'aria-label': 'Copy', onclick: () => copy('redxd join "' + link + '"', 'Command copied') }, icon('copy', 15))),
    h('p', { class: 'muted' }, 'On an iPhone or iPad you cannot run a node. Open the console in Safari and tap Share, then Add to Home Screen, and sign in with an API key to use the database from your phone.'),
    h('a', { class: 'btn', href: '#/' }, 'Open the console')));
}

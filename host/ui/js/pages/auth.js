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

export function renderLogin(msg, onDone) {
  // Account sign-in is the normal customer path. An API key is for SDKs,
  // automation, or administrators and must never be required just to browse
  // and edit databases belonging to an authenticated Red-XAI account.
  const input = h('input', { class: 'input mono', type: 'password',
    placeholder: 'rx_live_…  or  RP-XXXXX-XXXXX',
    autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Developer API key or pairing code' });
  const remember = h('input', { type: 'checkbox' });
  const err = h('div', { class: 'form-err', role: 'alert', hidden: !msg }, msg || '');
  const signInWithKey = async () => {
    let key = input.value.trim();
    if (!key) return;
    err.hidden = true;
    try {
      if (looksLikePairingCode(key)) key = await exchangePairingCode(key);
      await api('GET', '/v1/ui/whoami', { key, noAuthRedirect: true });
      session.set(key, remember.checked);
      await onDone();
    } catch (e) {
      err.textContent = e.status === 401 && !looksLikePairingCode(input.value)
        ? 'That developer key was rejected. Check its scope, expiration and characters.' : e.message;
      err.hidden = false;
    }
  };
  input.addEventListener('keydown', e => { if (e.key === 'Enter') signInWithKey(); });
  const advanced = h('details', { class: 'hub-api-key-advanced' },
    h('summary', null, icon('key', 16), 'Developer API key / pairing (advanced)'),
    h('p', { class: 'muted small' }, 'Only use a key for SDKs, automated clients, or an administrator-provided integration. Normal dashboard users sign in with their Red-XAI account.'),
    field('API key or pairing code', input),
    err,
    h('label', { class: 'check' }, remember, ' Remember this device'),
    h('button', { class: 'btn', onclick: signInWithKey }, 'Continue using API key'));
  const primary = h('div', { class: 'hub-auth-primary', id: 'hub-auth-primary' },
    h('p', { class: 'muted' }, 'Checking shared account sign-in…'));
  const card = h('div', { class: 'auth-card hub-auth-card' },
    logo('YOUR RED-XAI DEVELOPMENT HUB'),
    h('h2', null, 'Welcome to your workspace'),
    h('p', { class: 'muted' }, 'One account for your own databases, records, projects, BoxQL Studio, hosting and API credentials. No developer key needed to manage your own data.'),
    primary,
    advanced);
  const wrap = h('div', { class: 'auth' }, card);
  import('./account.js').then(async ({ accountsConfig, accountButtons, renderSignup }) => {
    const cfg = await accountsConfig();
    if (cfg.enabled) {
      primary.replaceChildren(accountButtons(cfg, () => {
        const signup = renderSignup(() => signup.replaceWith(renderLogin(msg, onDone)));
        wrap.replaceWith(signup);
      }));
    } else {
      primary.replaceChildren(h('div', { class: 'callout warn', role: 'status' },
        icon('alert', 19),
        h('div', null,
          h('b', null, 'Shared Red-XAI sign-in is not enabled on this database host yet.'),
          h('p', { class: 'muted small' },
            'Your databases are preserved. An operator must enable the existing account provider for this host. Do not enter an owner or master key into a customer account.'))));
    }
  }).catch(() => {
    primary.replaceChildren(h('p', { class: 'muted' },
      'The Red-XAI account service is temporarily unavailable. Your databases have not changed.'));
  });
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

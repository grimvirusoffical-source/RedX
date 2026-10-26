import { h, icon, mount, toast, dialog, field } from './util.js';
import { api, enc } from './api.js';

const FORMAT = 'red-xai-encrypt/rsxc1';

/** True when the editor text already carries a Red-SecretsXAI envelope. */
export function looksSealed(text) {
  return String(text || '').includes(FORMAT);
}

/**
 * Status card for the Data page. Failures are plain text: this must not use
 * an error box or console.error, and it must not write anything.
 */
export function secretsPanel(db) {
  const status = h('p', { class: 'muted', id: 'secrets-status' }, 'Checking Red-SecretsXAI…');
  const extra = h('div');
  const card = h('div', { class: 'card', id: 'secrets-card', style: { marginBottom: '14px' } },
    h('h3', { style: { marginTop: 0 } }, icon('lock', 16), ' Red-SecretsXAI'),
    status, extra);
  api('GET', `/v1/db/${enc(db)}/secrets`).then((r) => {
    const k = r.kdf || {};
    status.textContent = 'Password seal is available on this host (' + (k.profile || 'interactive') + ' Argon2id, t=' + (k.t ?? '') + ', m=' + (k.m_kib ?? '') + ' KiB, p=' + (k.p ?? '') + '). Seal and Open act on the editor only.';
    const items = (r.notes || []).map((n) => h('li', null, n));
    mount(extra, items.length ? h('ul', { class: 'muted small' }, items) : null,
      h('p', { class: 'muted small' }, 'To hand the sealed text to someone as a red-X PNG, follow the convert steps on the ',
        h('a', { href: '#/help/secrets' }, 'Red-SecretsXAI help page'),
        '. This console stays in password mode and does not convert or rewrite those files.'));
  }).catch((e) => {
    status.textContent = 'Red-SecretsXAI status is unavailable (' + (e && e.message ? e.message : 'request failed') + '). You can still edit records. Nothing was changed.';
  });
  return card;
}

function passwordFields() {
  const pw = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', 'aria-label': 'Red-SecretsXAI password' });
  const pw2 = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', 'aria-label': 'Confirm Red-SecretsXAI password' });
  const err = h('div', { class: 'form-err', hidden: true });
  return { pw, pw2, err };
}

export async function sealPlaintext(db, path, plaintext) {
  if (looksSealed(plaintext)) {
    await dialog({
      title: 'Already sealed',
      body: h('p', null, 'This text already looks like a Red-SecretsXAI envelope (', h('code', null, FORMAT), '). Sealing it again would wrap that ciphertext. Nothing was changed.'),
      actions: [{ id: 'ok', label: 'OK', primary: true }],
    });
    return null;
  }
  const { pw, pw2, err } = passwordFields();
  const r = await dialog({
    title: 'Seal with Red-SecretsXAI',
    body: h('div', null,
      h('p', null, 'This password seals this value. It is not your Red-XAI Account password, and RedX does not store it.'),
      h('p', { class: 'muted' }, 'Nothing is written until you press Save on this record. Existing packs and other sealed data are left as they are.'),
      field('Password (at least 8 characters)', pw),
      field('Confirm password', pw2),
      err),
    actions: [
      { id: 'cancel', label: 'Cancel' },
      {
        id: 'ok', label: 'Seal', primary: true, validate() {
          err.hidden = true;
          if ([...pw.value].length < 8) { err.hidden = false; err.textContent = 'Use at least 8 characters.'; return false; }
          if (pw.value !== pw2.value) { err.hidden = false; err.textContent = 'The two passwords do not match.'; return false; }
          return true;
        },
      },
    ],
  });
  const password = pw.value;
  pw.value = '';
  pw2.value = '';
  if (r !== 'ok') return null;
  try {
    const out = await api('POST', `/v1/db/${enc(db)}/secrets/seal`, { json: { password, plaintext, path: path || '' } });
    return out && out.box ? out.box : null;
  } catch (e) {
    toast(e.message || 'Seal failed', 'error');
    return null;
  }
}

export async function openPlaintext(db, path, box) {
  const pw = h('input', { class: 'input', type: 'password', autocomplete: 'current-password', 'aria-label': 'Red-SecretsXAI password' });
  const err = h('div', { class: 'form-err', hidden: true });
  const r = await dialog({
    title: 'Open a Red-SecretsXAI envelope',
    body: h('div', null,
      h('p', null, 'This is the password that sealed this value, not your Red-XAI Account password.'),
      h('p', { class: 'muted' }, 'Open shows the text in the editor and does not write it. Other sealed records and packs stay untouched.'),
      field('Password', pw),
      err),
    actions: [
      { id: 'cancel', label: 'Cancel' },
      {
        id: 'ok', label: 'Open', primary: true, validate() {
          err.hidden = true;
          if ([...pw.value].length < 8) { err.hidden = false; err.textContent = 'Use at least 8 characters.'; return false; }
          return true;
        },
      },
    ],
  });
  const password = pw.value;
  pw.value = '';
  if (r !== 'ok') return null;
  try {
    const out = await api('POST', `/v1/db/${enc(db)}/secrets/open`, { json: { password, box, path: path || '' } });
    return out && typeof out.plaintext === 'string' ? out.plaintext : null;
  } catch (e) {
    toast(e.message || 'Open failed', 'error');
    return null;
  }
}

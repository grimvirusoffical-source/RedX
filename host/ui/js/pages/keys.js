import { h, icon, terminalPanel, chip, mount, toast, dialog, field, copy, download, table, emptyState, errorBox, spinner, confirmDialog, confirmTyped, ago, fmtTime } from '../util.js';
import { api, enc } from '../api.js';
import { state, isHostAdmin, loadDbs, gs } from '../state.js';
import { pageHead, page } from './shared.js';
import { drawQR } from '../qr.js';

const SCOPES = [
  ['read', 'Read', 'Can read and watch. Cannot change anything.'],
  ['write', 'Read and write', 'Can read, change and delete records. Use this for apps.'],
  ['admin', 'Admin', 'Can also manage keys, rules and files for the database.'],
];
const TTLS = [['', 'Never expires'], ['1h', '1 hour'], ['24h', '1 day'], ['7d', '7 days'], ['30d', '30 days'], ['90d', '90 days'], ['365d', '1 year']];

function curlExample(key, db) {
  return `curl -H "Authorization: Bearer ${key}" ${location.origin}/v1/db/${db === '*' ? state.db : db}/bx \\\n  -d '{"q":"{Get[]} = players:Player[ID=*] -> *, Limit = 5"}'`;
}

export default async function render() {
  const root = page();
  const list = h('div');
  root.append(pageHead('API keys', 'Keys let apps and devices use a database. Each key can be limited to one database, one scope and one path.', h('button', { class: 'btn primary', onclick: createDialog }, icon('plus', 16), ' New key')),
    list,
    terminalPanel([{ label: 'List', cmd: 'redx key list' }, { label: 'Create an app key', cmd: 'redx key create --db default --scope write --label my-app --ttl 90d' }, { label: 'Revoke', cmd: 'redx key revoke KEYID' }, { label: 'Rotate (old key works for 10 more minutes)', cmd: 'redx key rotate KEYID --grace 10m' }], 'The key itself is shown once. Put it in the REDX_KEY environment variable instead of the command line.'));

  async function load() {
    mount(list, spinner());
    try {
      const r = await api('GET', '/v1/keys');
      const keys = r.keys;
      if (!keys.length) return mount(list, emptyState('key', 'No keys yet', 'Create a key for your app.'));
      if (keys.filter((k) => k.status === 'active').length > 1) gs.set('key');
      const rows = keys.map((k) => h('tr', { class: k.status !== 'active' ? 'dim' : '' },
        h('td', null, h('b', null, k.label || '(no label)'), h('div', { class: 'muted small mono' }, k.id)),
        h('td', null, chip(k.scope, k.scope === 'admin' ? 'warn' : k.scope === 'write' ? 'acc' : '')),
        h('td', null, k.db === '*' ? chip('all databases') : h('code', null, k.db)),
        h('td', { class: 'small' }, [k.prefix ? h('div', null, 'path ', h('code', null, k.prefix)) : null, k.roles && k.roles.length ? h('div', null, 'roles ', k.roles.join(', ')) : null, k.rate_rps ? h('div', { class: 'muted' }, k.rate_rps + '/s' + (k.rate_burst ? ' burst ' + k.rate_burst : '')) : null]),
        h('td', { class: 'muted small' }, ago(k.created), k.expires ? h('div', null, 'expires ', fmtTime(k.expires)) : null),
        h('td', null, chip(k.status, k.status === 'active' ? 'ok' : 'err')),
        h('td', { class: 'num nowrap' }, k.status === 'active' ? [
          h('button', { class: 'btn small', title: 'Make a new key and retire this one after a grace period', onclick: () => rotate(k) }, icon('refresh', 13), ' Rotate'), ' ',
          h('button', { class: 'btn small danger', onclick: () => revoke(k) }, 'Revoke')] : null)));
      mount(list, table(['Key', 'Scope', 'Database', 'Limits', 'Created', 'Status', ''], rows));
    } catch (e) { mount(list, errorBox(e.status === 403 ? 'Managing keys needs an admin key.' : e.message, load)); }
  }

  async function revoke(k) {
    const own = state.who && state.who.id === k.id;
    if (!(await confirmDialog('Revoke this key?', (own ? 'This is the key you are signed in with. You will be signed out. ' : '') + 'Anything using "' + (k.label || k.id) + '" stops working immediately. This cannot be undone.', { danger: true, ok: 'Revoke key' }))) return;
    try { await api('DELETE', '/v1/keys/' + enc(k.id)); toast('Key revoked', 'ok'); load(); } catch (e) { toast(e.message, 'error'); }
  }
  async function rotate(k) {
    const grace = h('select', { class: 'select' }, [['10m', '10 minutes'], ['1h', '1 hour'], ['24h', '1 day'], ['0', 'Retire it now']].map(([v, l]) => h('option', { value: v }, l)));
    const r = await dialog({ title: 'Rotate key', body: h('div', null, h('p', null, 'A new key with the same limits is created. The old key keeps working for the grace period, so you can update your app without downtime.'), field('Keep the old key working for', grace)), actions: [{ id: 'cancel', label: 'Cancel' }, { id: 'ok', label: 'Rotate', primary: true }] });
    if (r !== 'ok') return;
    try { const res = await api('POST', `/v1/keys/${enc(k.id)}/rotate`, { json: { grace: grace.value } }); load(); showNewKey(res); } catch (e) { toast(e.message, 'error'); }
  }

  async function createDialog() {
    let dbs = state.dbs;
    if (!dbs.length) dbs = await loadDbs();
    const label = h('input', { class: 'input', placeholder: 'e.g. my-game-server', maxlength: 64 });
    const dbSel = h('select', { class: 'select' }, [...(isHostAdmin() ? [h('option', { value: '*' }, 'All databases')] : []), ...dbs.map((d) => h('option', { value: d, selected: d === state.db }, d))]);
    let scope = 'write';
    const scopeBox = h('div', { class: 'radios' }, SCOPES.map(([v, t, d]) => h('label', { class: 'radio' }, h('input', { type: 'radio', name: 'scope', value: v, checked: v === scope, onchange: () => { scope = v; } }), h('div', null, h('b', null, t), h('div', { class: 'muted small' }, d)))));
    const ttl = h('select', { class: 'select' }, TTLS.map(([v, l]) => h('option', { value: v, selected: v === '90d' }, l)));
    const prefix = h('input', { class: 'input', placeholder: 'e.g. players.red-xai.db:Player (optional)' });
    const roles = h('input', { class: 'input', placeholder: 'e.g. player, moderator (optional)' });
    const rps = h('input', { class: 'input', type: 'number', min: -1, placeholder: 'default' });
    const burst = h('input', { class: 'input', type: 'number', min: 0, placeholder: 'default' });
    const err = h('div', { class: 'form-err', hidden: true });
    const r = await dialog({
      title: 'New API key', wide: true,
      body: h('div', null, field('Label', label, 'A name so you remember what the key is for.'), field('Database', dbSel), field('What may it do?', scopeBox), field('Expires', ttl),
        h('details', { class: 'adv' }, h('summary', null, 'Advanced limits'), field('Limit to a path prefix', prefix, 'The key can only touch records under this path.'), field('Roles', roles, 'Role names from the database security policy.'), h('div', { class: 'row gap' }, field('Requests per second', rps, '-1 = unlimited'), field('Burst', burst))), err),
      actions: [{ id: 'cancel', label: 'Cancel' }, { id: 'ok', label: 'Create key', primary: true }],
    });
    if (r !== 'ok') return;
    const body = { db: dbSel.value, scope, label: label.value.trim(), ttl: ttl.value };
    if (prefix.value.trim()) body.prefix = prefix.value.trim();
    if (roles.value.trim()) body.roles = roles.value.split(',').map((s) => s.trim()).filter(Boolean);
    if (rps.value !== '') body.rate_rps = Number(rps.value);
    if (burst.value !== '') body.rate_burst = Number(burst.value);
    try { const res = await api('POST', '/v1/keys', { json: body }); gs.set('key'); load(); showNewKey(res); } catch (e) { toast(e.message, 'error', 7000); }
  }

  async function showNewKey(res) {
    const k = res.key;
    const db = res.info.db;
    const qrBox = h('div', { hidden: true, class: 'center' });
    const pairOther = async () => {
      qrBox.hidden = false;
      try {
        const r = await api('POST', '/v1/keys/pairing', { json: { db, scope: res.info.scope, prefix: res.info.prefix || '', label: (res.info.label || 'device') + ' (paired)' } });
        const canvas = h('canvas', { class: 'qr-box', 'aria-label': 'QR code of a one-time sign-in link' });
        mount(qrBox, h('p', { class: 'muted small' }, 'Scan with the other device. This is a one-time pairing code (valid 5 minutes), not the key; the other device gets its own new key with the same access.'), canvas, h('div', { class: 'code-big' }, r.code));
        drawQR(canvas, `${location.origin}/#/login?code=${r.code}`, { scale: 5 });
      } catch (e) { mount(qrBox, h('p', { class: 'err-text' }, e.message)); }
    };
    await dialog({
      title: 'Your new key', wide: true,
      body: h('div', null,
        h('div', { class: 'callout warn' }, icon('alert'), h('div', null, h('b', null, 'This is the only time the key is shown. '), 'Copy it now. RedX stores only a hash and cannot show it again.')),
        h('div', { class: 'keybox' }, h('code', { class: 'code-big' }, k), h('button', { class: 'btn', onclick: () => copy(k, 'Key copied') }, icon('copy', 15), ' Copy')),
        h('div', { class: 'row gap wrap', style: { margin: '10px 0' } }, h('button', { class: 'btn', onclick: () => download('redx-key-' + res.id + '.txt', `RedX API key\nlabel: ${res.info.label || ''}\nid: ${res.id}\ndatabase: ${db}\nscope: ${res.info.scope}\nhost: ${location.origin}\n\n${k}\n`, 'text/plain') }, icon('download', 15), ' Download as .txt'),
          h('button', { class: 'btn', onclick: pairOther }, icon('qr', 15), ' Pair another device (one-time code)')),
        qrBox,
        h('h4', null, 'Try it'), h('pre', { class: 'code-block' }, curlExample(k, db)), h('button', { class: 'btn small', onclick: () => copy(curlExample(k, db), 'curl command copied') }, 'Copy curl example'),
        h('p', { class: 'muted small' }, 'In an app, set it as the REDX_KEY environment variable.')),
      actions: [{ id: 'ok', label: 'I have saved the key', primary: true }],
    });
  }
  await load();
  return root;
}

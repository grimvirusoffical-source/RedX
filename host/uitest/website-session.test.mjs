import test from 'node:test';
import assert from 'node:assert/strict';
import { api, session, configureAuthentication, websiteAuthentication, invalidateRequests, wsURL, setUnauthorizedHandler } from '../ui/js/api.js';
import { accountLocal, accountTab, setAccountStorageScope } from '../ui/js/account-storage.js';
import { state, loadWho, loadDbs, resetAccountState, setDb } from '../ui/js/state.js';

function storage() {
  const values = new Map();
  return { getItem: k => values.has(k) ? values.get(k) : null,
    setItem: (k, v) => values.set(k, String(v)), removeItem: k => values.delete(k) };
}
function fixture() {
  globalThis.sessionStorage = storage();
  globalThis.localStorage = storage();
  globalThis.location = { href: 'https://red-xai.com/v1/console/' };
  configureAuthentication({ enabled: false });
  setAccountStorageScope(null);
  resetAccountState();
  setUnauthorizedHandler(() => {});
}
const website = { enabled: true, mode: 'website', website_login: '/signin', website_account: '/settings' };
const who = sub => ({ id: 'acct:' + sub, account: { sub, username: sub }, host_admin: false, owner: false });
const json = body => new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });

test('website requests use cookies and never a previously saved key or WebSocket token', async () => {
  fixture();
  localStorage.setItem('redx.key', 'old-admin-fixture');
  sessionStorage.setItem('redx.key', 'old-session-fixture');
  configureAuthentication(website);
  const requests = [];
  globalThis.fetch = async (path, options) => { requests.push({ path, options }); return json({ ok: true }); };
  await api('POST', '/v1/db/example/bx', { json: { q: 'fixture' }, confirm: 'example' });
  assert.equal(session.key, '');
  assert.equal(localStorage.getItem('redx.key'), null);
  assert.equal(sessionStorage.getItem('redx.key'), null);
  assert.equal(requests[0].options.headers.Authorization, undefined);
  assert.equal(requests[0].options.credentials, 'same-origin');
  assert.equal(requests[0].options.headers['X-RedX-Confirm'], 'example');
  assert.equal(new URL(wsURL('/v1/db/example/bx/watch', { access_token: 'untrusted-fixture' })).searchParams.has('access_token'), false);
});

test('advanced key entry is explicit and standalone credentials retain their original behavior', async () => {
  fixture();
  configureAuthentication(website);
  const headers = [];
  globalThis.fetch = async (path, options) => { headers.push(options.headers); return json({ ok: true }); };
  await api('GET', '/v1/ui/whoami', { key: 'developer-fixture', noAuthRedirect: true });
  assert.equal(websiteAuthentication(), true, 'testing a supplied key must not silently select it');
  session.set('developer-fixture', false);
  assert.equal(websiteAuthentication(), false);
  await api('GET', '/v1/dbs');
  assert.equal(headers[1].Authorization, 'Bearer developer-fixture');
  assert.equal(new URL(wsURL('/v1/db/example/watch')).searchParams.get('access_token'), 'developer-fixture');
  configureAuthentication(website);
  assert.equal(session.key, '', 'website boot must not restore advanced mode automatically');
  localStorage.setItem('redx.key', 'standalone-fixture');
  configureAuthentication({ enabled: false });
  await api('GET', '/v1/dbs');
  assert.equal(headers[2].Authorization, 'Bearer standalone-fixture');
});

test('an old in-flight response is discarded after an account change', async () => {
  fixture();
  configureAuthentication(website);
  let finish;
  globalThis.fetch = () => new Promise(resolve => { finish = resolve; });
  const pending = api('GET', '/v1/dbs');
  invalidateRequests();
  finish(json({ dbs: ['another-account-fixture'] }));
  await assert.rejects(pending, /account changed/);
});

test('canonical account changes clear caches and isolate saved queries, drafts and selected DB', async () => {
  fixture();
  localStorage.setItem('redx.saved', 'legacy-value-is-not-imported');
  configureAuthentication(website);
  let subject = 'alpha';
  globalThis.fetch = async path => path === '/v1/ui/whoami'
    ? json(who(subject)) : json({ dbs: ['physical-' + subject], logical: { ['physical-' + subject]: 'notes' } });
  await loadWho();
  await loadDbs();
  setDb('physical-alpha');
  accountLocal.setItem('redx.saved', 'alpha query');
  accountTab.setItem('redx.studio.q', 'alpha draft');
  state.status = { privateFixture: true };
  subject = 'beta';
  await loadWho();
  assert.deepEqual(state.dbs, []);
  assert.deepEqual(state.dbLogical, {});
  assert.equal(state.status, null);
  assert.equal(state.db, 'default');
  assert.equal(accountLocal.getItem('redx.saved'), null);
  assert.equal(accountTab.getItem('redx.studio.q'), null);
  accountLocal.setItem('redx.saved', 'beta query');
  await loadDbs();
  assert.deepEqual(state.dbs, ['physical-beta']);
  subject = 'alpha';
  await loadWho();
  assert.equal(state.db, 'physical-alpha');
  assert.equal(accountLocal.getItem('redx.saved'), 'alpha query');
  assert.equal(accountTab.getItem('redx.studio.q'), 'alpha draft');
  assert.equal(localStorage.getItem('redx.saved'), 'legacy-value-is-not-imported');
});

test('an old database list cannot repopulate state after a new account is loaded', async () => {
  fixture();
  configureAuthentication(website);
  let subject = 'alpha';
  let finishList;
  globalThis.fetch = async path => {
    if (path === '/v1/ui/whoami') return json(who(subject));
    return new Promise(resolve => { finishList = resolve; });
  };
  await loadWho();
  const oldList = loadDbs();
  subject = 'beta';
  await loadWho();
  finishList(json({ dbs: ['physical-alpha'], logical: { 'physical-alpha': 'alpha-only' } }));
  await oldList;
  assert.equal(state.who.account.sub, 'beta');
  assert.deepEqual(state.dbs, []);
  assert.deepEqual(state.dbLogical, {});
});

test('website identity requires a canonical account and rejection never falls back to a stored key', async () => {
  fixture();
  configureAuthentication(website);
  localStorage.setItem('redx.key', 'unselected-fixture');
  globalThis.fetch = async () => json({ id: 'key-only-fixture', scope: 'admin' });
  await assert.rejects(loadWho(), /website account could not be verified/);
  let rejected = 0;
  setUnauthorizedHandler(() => rejected++);
  globalThis.fetch = async (path, options) => {
    assert.equal(options.headers.Authorization, undefined);
    return new Response('{"error":"unauthorized"}', { status: 401 });
  };
  await assert.rejects(api('GET', '/v1/dbs'), e => e.status === 401);
  assert.equal(rejected, 1);
  assert.equal(websiteAuthentication(), true);
  assert.equal(session.key, '');
});

test('changed privileges discard cached host data even when the canonical subject is unchanged', async () => {
  fixture();
  configureAuthentication(website);
  let owner = true;
  globalThis.fetch = async () => json({ ...who('alpha'), owner, host_admin: owner, scope: owner ? 'admin' : 'none' });
  await loadWho();
  state.status = { ownerFixture: true };
  state.dbs = ['owner-only-fixture'];
  state.dbLogical = { 'owner-only-fixture': 'system' };
  owner = false;
  await loadWho();
  assert.equal(state.who.owner, false);
  assert.equal(state.status, null);
  assert.deepEqual(state.dbs, []);
  assert.deepEqual(state.dbLogical, {});
});

test('a slow superseded identity response cannot restore the previous account', async () => {
  fixture();
  configureAuthentication(website);
  let finishOld;
  let calls = 0;
  globalThis.fetch = async () => ++calls === 1
    ? new Promise(resolve => { finishOld = resolve; }) : json(who('beta'));
  const old = loadWho();
  await loadWho();
  finishOld(json(who('alpha')));
  await assert.rejects(old);
  assert.equal(state.who.account.sub, 'beta');
});

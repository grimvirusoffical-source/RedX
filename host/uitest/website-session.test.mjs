import test from 'node:test';
import assert from 'node:assert/strict';
import { api, session, configureAuthentication, websiteAuthentication, websiteLoginURL, invalidateRequests, wsURL, setUnauthorizedHandler } from '../ui/js/api.js';
import { redirectWebsiteSignIn, resetWebsiteSignIn } from '../ui/js/website-session.js';
import { renderLogin } from '../ui/js/pages/auth.js';
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

test('only confirmed primary website sign-out redirects directly to primary sign-in with a fixed DB return', async () => {
  fixture();
  configureAuthentication({ ...website, website_login: '//untrusted.example/signin' });
  location.href += '?next=https://untrusted.example/#/signin?return=evil';
  const redirects = [];
  location.replace = value => redirects.push(value);
  globalThis.fetch = async (path, options) => {
    assert.equal(path, '/api/accounts/me');
    assert.equal(options.credentials, 'same-origin');
    assert.equal(options.cache, 'no-store');
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers?.Authorization, undefined);
    return new Response('{"error":"signed_out"}', { status: 401 });
  };
  assert.equal(await redirectWebsiteSignIn({ status: 401 }), true);
  assert.equal(websiteLoginURL(), '/signin?next=%2Fdb');
  assert.deepEqual(redirects, ['/signin?next=%2Fdb']);
  assert.equal(session.key, '');
  assert.equal(state.who, null, 'the browser probe must never establish database identity');
});

test('website sign-in does not loop after returning signed out; explicit recovery can retry', async () => {
  fixture();
  configureAuthentication(website);
  let probes = 0;
  const redirects = [];
  location.replace = value => redirects.push(value);
  globalThis.fetch = async () => {
    probes++;
    return new Response('{"error":"signed_out"}', { status: 401 });
  };
  assert.equal(await redirectWebsiteSignIn({ status: 401 }), true);
  configureAuthentication(website); // a new console boot preserves the tab guard
  assert.equal(await redirectWebsiteSignIn({ status: 401 }), false);
  assert.equal(probes, 1);
  resetWebsiteSignIn();
  assert.equal(await redirectWebsiteSignIn({ status: 401 }), true);
  assert.equal(redirects.length, 2);
});

test('authority errors, absent account data and a primary/DB mismatch never start automatic sign-in', async () => {
  fixture();
  configureAuthentication(website);
  location.replace = () => assert.fail('unverified authority must not redirect');
  for (const [status, result] of [[200, {}], [200, { account: { id: 'alpha' } }], [401, { error: 'unavailable' }], [503, { error: 'signed_out' }]]) {
    globalThis.fetch = async () => new Response(JSON.stringify(result), { status });
    assert.equal(await redirectWebsiteSignIn({ status: 401 }), false);
  }
  globalThis.fetch = async () => { throw new Error('offline'); };
  assert.equal(await redirectWebsiteSignIn({ status: 401 }), false);
  globalThis.fetch = async () => new Response('not json', { status: 401 });
  assert.equal(await redirectWebsiteSignIn({ status: 401 }), false);
  globalThis.fetch = async () => assert.fail('a DB service error must not start primary sign-in');
  assert.equal(await redirectWebsiteSignIn({ status: 503 }), false);
});

test('a stale sign-out probe or explicit developer mode cannot redirect an active workspace', async () => {
  fixture();
  configureAuthentication(website);
  let finish;
  location.replace = () => assert.fail('superseded check must not redirect');
  globalThis.fetch = () => new Promise(resolve => { finish = resolve; });
  const stale = redirectWebsiteSignIn({ status: 401 }, () => false);
  finish(new Response('{"error":"signed_out"}', { status: 401 }));
  assert.equal(await stale, false);
  const developer = redirectWebsiteSignIn({ status: 401 });
  session.set('developer-fixture', false);
  finish(new Response('{"error":"signed_out"}', { status: 401 }));
  assert.equal(await developer, false);
  globalThis.fetch = async () => assert.fail('standalone/developer mode must not probe the website');
  assert.equal(await redirectWebsiteSignIn({ status: 401 }), false);
});

test('blocked tab storage prevents automatic redirects and concurrent failures redirect only once', async () => {
  fixture();
  configureAuthentication(website);
  location.replace = () => assert.fail('no guard storage means no automatic redirect');
  sessionStorage = { getItem: () => { throw new Error('blocked'); } };
  assert.equal(await redirectWebsiteSignIn({ status: 401 }), false);
  sessionStorage = storage();
  const redirects = [];
  location.replace = value => redirects.push(value);
  const finishes = [];
  globalThis.fetch = () => new Promise(resolve => finishes.push(resolve));
  const pending = [redirectWebsiteSignIn({ status: 401 }), redirectWebsiteSignIn({ status: 401 })];
  finishes.forEach(finish => finish(new Response('{"error":"signed_out"}', { status: 401 })));
  assert.deepEqual(await Promise.all(pending), [true, false]);
  assert.deepEqual(redirects, ['/signin?next=%2Fdb']);
});

test('website recovery renders no separate DB sign-in landing screen and keeps explicit developer access', async t => {
  fixture();
  configureAuthentication(website);
  class Element {
    constructor(tag, text = '') { this.tag = tag; this.text = text; this.children = []; this.attrs = {}; this.events = {}; this.classList = { add() {} }; }
    setAttribute(key, value) { this.attrs[key] = value; }
    addEventListener(name, fn) { this.events[name] = fn; }
    append(child) { this.children.push(child); }
    get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
    set textContent(value) { this.text = value; this.children = []; }
  }
  const previousNode = globalThis.Node;
  const previousDocument = globalThis.document;
  t.after(() => {
    if (previousNode === undefined) delete globalThis.Node; else globalThis.Node = previousNode;
    if (previousDocument === undefined) delete globalThis.document; else globalThis.document = previousDocument;
  });
  globalThis.Node = Element;
  globalThis.document = {
    createElement: tag => new Element(tag), createElementNS: (_, tag) => new Element(tag),
    createTextNode: text => new Element('#text', text),
  };
  let retried = 0;
  let entered = 0;
  const view = renderLogin('Account service unavailable.', () => entered++, () => retried++);
  const all = node => [node, ...node.children.flatMap(all)];
  const nodes = all(view);
  assert.match(view.textContent, /Database workspace unavailable/);
  assert.doesNotMatch(view.textContent, /Welcome to your workspace|Sign in to Red-XAI|Check website sign-in again/);
  assert.equal(nodes.some(node => node.attrs.id === 'acct-signin' || node.attrs.id === 'hub-auth-primary'), false);
  const advanced = nodes.find(node => node.tag === 'details');
  assert.equal(advanced.attrs.open, undefined, 'developer mode remains collapsed until explicitly chosen');
  nodes.find(node => node.tag === 'button' && node.textContent === 'Retry workspace').events.click();
  assert.equal(retried, 1);
  const input = nodes.find(node => node.attrs['aria-label'] === 'Developer API key or pairing code');
  input.value = 'developer-fixture';
  globalThis.fetch = async (_, options) => {
    assert.equal(options.headers.Authorization, 'Bearer developer-fixture');
    return json({ id: 'key-fixture' });
  };
  await nodes.find(node => node.tag === 'button' && node.textContent === 'Continue using API key').events.click();
  assert.equal(entered, 1);
  assert.equal(websiteAuthentication(), false);
  assert.equal(session.key, 'developer-fixture');
});

test('revocation or an unverifiable website identity removes all previous account state before recovery', async () => {
  for (const status of [401, 503]) {
    fixture();
    configureAuthentication(website);
    globalThis.fetch = async () => json(who('alpha'));
    await loadWho();
    state.dbs = ['physical-alpha'];
    state.dbLogical = { 'physical-alpha': 'private' };
    state.status = { private: true };
    accountTab.setItem('redx.studio.q', 'alpha draft');
    globalThis.fetch = async () => new Response('{"error":"unverified"}', { status });
    await assert.rejects(loadWho(), error => error.status === status);
    assert.equal(state.who, null);
    assert.equal(state.status, null);
    assert.deepEqual(state.dbs, []);
    assert.deepEqual(state.dbLogical, {});
    assert.equal(state.db, 'default');
    assert.equal(accountTab.getItem('redx.studio.q'), null);
  }
});

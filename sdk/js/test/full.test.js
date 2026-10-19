'use strict';
// The generated operations, danger levels, files, media, transactions, reconnecting streams and the
// app side of the connect handshake, all against a real redxd.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const sdk = require('../redx');
const { RedX, RedXError, OPERATIONS } = sdk;
const { startHost } = require('./harness');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(cond, ms = 8000) {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error('timed out waiting');
    await sleep(20);
  }
}

let host, admin;
test.before(async () => {
  host = await startHost();
  admin = new RedX({ url: host.url, key: host.adminKey });
});
test.after(async () => { if (host) await host.stop(); });

test('operation table matches the spec', () => {
  const spec = require('../../../api/redx-api.json');
  assert.equal(Object.keys(OPERATIONS).length, spec.operations.length);
  for (const o of spec.operations) {
    assert.equal(OPERATIONS[o.id].danger, o.danger, o.id);
    assert.equal(OPERATIONS[o.id].path, o.path, o.id);
  }
  for (const id of ['deleteDatabase', 'createKey', 'revokeKey', 'promote', 'repoint', 'connectApprove', 'createJoinToken']) {
    assert.equal(sdk.dangerOf(id), 'dangerous', id);
  }
  assert.equal(sdk.dangerOf('getPath'), 'safe');
  assert.equal(sdk.DANGER.dangerous, 3);
});

test('host and database operations', async () => {
  assert.equal((await admin.health()).status, 'ok');
  const who = await admin.whoami();
  assert.ok(who);
  await admin.createDatabase({ body: { name: 'sdkjs' } });
  const dbs = await admin.listDatabases();
  assert.ok(JSON.stringify(dbs).includes('sdkjs'));
  const c = admin.withDb('sdkjs');
  await c.set('p.red-xai.db:P[ID=1]', { Name: 'Ann', Level: 5 });
  assert.deepEqual(await c.get('p.red-xai.db:P[ID=1]'), { Level: 5, Name: 'Ann' });
  const got = await c.getPath({ path: 'p.red-xai.db:P[ID=1].Name' });
  assert.equal(got.value, '"Ann"');
  assert.match(await c.getPathBox({ path: 'p.red-xai.db:P[ID=1]' }), /Ann/);
  await c.setPath({ path: 's.red-xai-db-qs:S[ID=2]', body: { value: { Name: 'Bo' }, ttl_seconds: 1 } });
  assert.deepEqual(await c.get('s.red-xai-db-qs:S[ID=2]'), { Name: 'Bo' });
  await sleep(2500);
  await assert.rejects(c.get('s.red-xai-db-qs:S[ID=2]'), (e) => e instanceof RedXError && e.status === 404);
  const r = await c.bx('{Get[]} = p:P[Level >= $min] -> Name', { min: 3 });
  assert.equal(r.count, 1);
  const t = await c.tx(['{Set[]} = p:P[ID=1].Level = $l', '{Add[]} = p:P[ID=3] = [ {Name[]} = "Cy" ]'], { l: 9 });
  assert.equal(t.results.length, 2);
  assert.equal(await c.get('p.red-xai.db:P[ID=1].Level'), 9);
  await assert.rejects(c.tx(['{Require[]} = p:P[ID=1, Level > 100]', '{Delete[]} = p:P[ID=3]']), (e) => e.status === 409);
  assert.deepEqual(await c.get('p.red-xai.db:P[ID=3]'), { Name: 'Cy' });
  await c.deletePath({ path: 'p.red-xai.db:P[ID=3]' });
  assert.equal(await c.getOr('p.red-xai.db:P[ID=3]', 'gone'), 'gone');
  const files = await c.listFiles();
  assert.ok(JSON.stringify(files).includes('p.red-xai.db'));
  assert.ok((await c.stats()));
});

test('dangerous operations are refused without confirm, before any request', async () => {
  const c = new RedX({ url: 'http://127.0.0.1:9', key: 'rx_' + 'live_' + 'x'.repeat(43) }); // nothing listens there
  for (const id of ['deleteDatabase', 'promote', 'connectApprove', 'createPairingCode']) {
    await assert.rejects(c.call(id, { db: 'x' }), (e) => e instanceof RedXError && e.code === 'confirm_required' && e.status === 0, id);
  }
  await assert.rejects(admin.deleteDatabase({ db: 'sdkjs' }), (e) => e.code === 'confirm_required');
  assert.ok(JSON.stringify(await admin.listDatabases()).includes('sdkjs'));
});

test('keys: create, rotate, revoke (confirmed) and pairing', async () => {
  const k = await admin.call('createKey', { body: { db: 'sdkjs', scope: 'read', label: 'js-ro' }, confirm: true });
  assert.match(k.key, /^rx_live_/);
  const ro = new RedX({ url: host.url, key: k.key, db: 'sdkjs' });
  assert.equal(await ro.get('p.red-xai.db:P[ID=1].Name'), 'Ann');
  await assert.rejects(ro.set('p.red-xai.db:P[ID=9]', 1), (e) => e.forbidden);
  const info = await admin.getKey({ id: k.id });
  assert.equal(info.id ?? info.key?.id ?? k.id, k.id);
  const rot = await admin.rotateKey({ id: k.id, body: { grace: '0s' }, confirm: true });
  assert.match(rot.key, /^rx_live_/);
  await admin.revokeKey(rot.id, { confirm: true });
  await assert.rejects(new RedX({ url: host.url, key: rot.key }).get('p.red-xai.db:P[ID=1]'), (e) => e.unauthorized);
  const pc = await admin.createPairingCode({ body: { db: 'sdkjs', scope: 'read', label: 'pair' }, confirm: true });
  const paired = await sdk.exchangePairingCode({ url: host.url, code: pc.code });
  assert.match(paired.key, /^rx_live_/);
  assert.ok(!JSON.stringify(Object.keys(await admin.listKeys())).includes('rx_live_'));
});

test('packs and media: upload, range download, checksum mismatch', async () => {
  const c = admin.withDb('sdkjs');
  const data = crypto.randomBytes(300000);
  await c.uploadFile('assets', 'lvl/one.bin', data);
  const st = await c.packStat({ pack: 'assets', file: 'lvl/one.bin' });
  assert.equal(st.size, data.length);
  assert.ok((await c.downloadFile('assets', 'lvl/one.bin')).equals(data));
  assert.ok((await c.downloadFile('assets', 'lvl/one.bin', { range: [10, 19] })).equals(data.subarray(10, 20)));
  const ls = await c.packList({ pack: 'assets', folder: 'lvl' });
  assert.ok(JSON.stringify(ls).includes('one.bin'));
  await assert.rejects(c.call('packPut', { pack: 'assets', file: 'bad.bin', body: Buffer.from('x'), headers: { 'X-Redx-SHA256': '0'.repeat(64) } }), (e) => e.status === 422);
  await c.packDelete({ pack: 'assets', file: 'lvl/one.bin' });
  await assert.rejects(c.packStat({ pack: 'assets', file: 'lvl/one.bin' }), (e) => e.notFound);
  const png = Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'), crypto.randomBytes(64)]);
  await c.uploadMedia('art', 'icon.png', png, { type: 'image/png' });
  assert.ok((await c.downloadMedia('art', 'icon.png')).equals(png));
  assert.ok(JSON.stringify(await c.mediaList({ lib: 'art' })).includes('icon.png'));
  await c.mediaDelete({ lib: 'art', name: 'icon.png' });
});

test('subscribe and watch with reconnect', async () => {
  const c = admin.withDb('sdkjs');
  const got = [];
  const sub = await c.subscribe('w.red-xai.db:*', (ev) => got.push(ev), { reconnect: { minMs: 50, maxMs: 200 } });
  await c.set('w.red-xai.db:W[ID=1]', { A: 1 });
  await waitFor(() => got.length >= 1);
  assert.deepEqual(got[0].data, { A: 1 });
  let reconnects = 0;
  const errors = [];
  sub.close();
  await sub.closed;
  const sub2 = await c.subscribe('w.red-xai.db:*', (ev) => got.push(ev), { reconnect: { minMs: 50, maxMs: 200 }, onReconnect: () => reconnects++, onError: (e) => errors.push(e) });
  await host.restart();
  await waitFor(() => reconnects === 1);
  got.length = 0;
  await c.set('w.red-xai.db:W[ID=3]', { A: 3 });
  await waitFor(() => got.length >= 1);
  assert.deepEqual(got[0].data, { A: 3 });
  sub2.close();
  assert.equal((await sub2.closed).code, 1000);
  const seen = [];
  const w = await c.stream('bxWatch', { query: { q: '{Watch[]} = w:W[A > $min]', params: JSON.stringify({ min: 1 }) } }, (ev) => seen.push(ev));
  await c.set('w.red-xai.db:W[ID=2]', { A: 5 });
  await waitFor(() => seen.length >= 1);
  w.close();
});

test('cluster status and promote on a standalone leader', async () => {
  const st = await admin.clusterStatus();
  assert.ok(st.role);
  await assert.rejects(admin.promote({ confirm: true }), (e) => e instanceof RedXError && e.status >= 400);
});

test('connect handshake: app side against an approved request', async () => {
  const rq = sdk.connectRequest();
  assert.equal(rq.challenge, crypto.createHash('sha256').update(rq.verifier).digest('base64url'));
  const link = sdk.connectLink({ provider: 'gendragoon', state: rq.state, challenge: rq.challenge, callback: 'gendragoon://redx-callback', consoleUrl: host.url });
  assert.ok(link.startsWith(host.url + '/#/connect?v=1&'));
  assert.ok(sdk.connectLink({ provider: 'gendragoon', state: rq.state, challenge: rq.challenge }).startsWith('redx://connect?'));
  const params = Object.fromEntries(new URL(link.replace('/#/', '/')).searchParams);
  params.v = 1;
  const start = await admin.connectStart({ body: params });
  const ap = await admin.connectApprove({ body: { request_id: start.request_id }, confirm: true });
  const cbUrl = ap.callback_template.replace('{state}', rq.state);
  assert.throws(() => sdk.parseCallback(cbUrl, 'x'.repeat(rq.state.length)), (e) => e.code === 'state_mismatch');
  const cb = sdk.parseCallback(cbUrl, rq.state);
  await assert.rejects(sdk.exchangeConnectCode({ url: host.url, code: cb.code, verifier: 'A'.repeat(43), state: rq.state }), (e) => e.code === 'pkce_mismatch');
  const ex = await sdk.exchangeConnectCode({ url: host.url, code: cb.code, verifier: rq.verifier, state: rq.state, deviceLabel: 'js test' });
  assert.match(ex.key, /^rx_live_/);
  const app = new RedX({ url: host.url, key: ex.key, db: ex.workspace.db });
  await app.set('save.red-xai.db:S[ID=1]', { Lvl: 2 });
  assert.ok(JSON.stringify(await admin.connectApps()).includes('gendragoon'));
  await app.connectRevoke();
  await assert.rejects(app.get('save.red-xai.db:S[ID=1]'), (e) => e.unauthorized);
});

test('backup, admin status and delete database (confirmed)', async () => {
  const b = await admin.backup();
  assert.ok(Buffer.isBuffer(b) && b.length > 100);
  assert.ok((await admin.adminStatus()));
  assert.ok((await admin.adminAudit({ query: { limit: 5 } })));
  await admin.deleteDatabase({ db: 'sdkjs', confirm: true });
  assert.ok(!JSON.stringify(await admin.listDatabases()).includes('sdkjs'));
});

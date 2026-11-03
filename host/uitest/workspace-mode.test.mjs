import test from 'node:test';
import assert from 'node:assert/strict';
import { databaseNavigation, databasePageAvailable, databaseAccessLabel, embeddedDatabase, websiteNavigationLocation } from '../ui/js/workspace-mode.js';
import { configureAuthentication, websiteAuthentication, websiteDeployment, session } from '../ui/js/api.js';

const items = [
  { id: 'data', title: 'Data' }, { id: 'studio', title: 'BoxQL' },
  { id: 'keys', title: 'Keys', websiteTitle: 'Database API keys' },
  { id: 'devices' }, { id: 'cluster' }, { id: 'presets' },
  { id: 'backups', websiteAdmin: true }, { id: 'owner', owner: true },
  { id: 'host', external: 'https://red-xai.com/host' },
];

test('website navigation separates database tools from local service and Host destinations for both roles', () => {
  const normal = databaseNavigation(items, { website: true });
  assert.deepEqual(normal.map(n => n.id), ['data', 'studio', 'keys']);
  assert.equal(normal[2].title, 'Database API keys');
  const owner = databaseNavigation(items, { website: true, owner: true, admin: true });
  assert.deepEqual(owner.map(n => n.id), ['data', 'studio', 'keys', 'backups', 'owner']);
  assert.equal(items[2].title, 'Keys', 'presentation must not mutate standalone definitions');
  assert.deepEqual(databaseNavigation(items, { owner: true, admin: true }).map(n => n.id), items.map(n => n.id));
});

test('local administration deep links stay available standalone and cannot open in website DB mode', () => {
  for (const id of ['devices', 'cluster', 'presets', 'join']) {
    assert.equal(databasePageAvailable(id, true), false);
    assert.equal(databasePageAvailable(id, false), true);
  }
  for (const id of ['data', 'studio', 'raw', 'watch', 'policy', 'keys', 'owner']) assert.equal(databasePageAvailable(id, true), true);
});

test('scope labels distinguish private account access from explicit administrative developer keys', () => {
  assert.equal(databaseAccessLabel({ account: { sub: 'fixture-a' }, owner: false }), 'Private account workspace');
  assert.equal(databaseAccessLabel({ account: { sub: 'fixture-owner' }, owner: true }), 'Owner · all databases');
  assert.equal(databaseAccessLabel({ scope: 'admin', host_admin: true }), 'Developer key access');
  assert.equal(databaseAccessLabel({ scope: 'read' }), 'Developer key access');
});

test('embedding needs website mode, an explicit query and a same-origin parent', () => {
  const location = { origin: 'https://red-xai.com', search: '?embed=site' };
  const parent = { location: { origin: location.origin } };
  const view = { parent };
  assert.equal(embeddedDatabase(true, location, view), true);
  assert.equal(websiteNavigationLocation(true, location, view), parent.location);
  assert.equal(embeddedDatabase(false, location, view), false);
  assert.equal(embeddedDatabase(true, { ...location, search: '' }, view), false);
  assert.equal(embeddedDatabase(true, { ...location, search: '?embed=other' }, view), false);
  assert.equal(embeddedDatabase(true, location, { parent: { location: { origin: 'https://other.invalid' } } }), false);
  const top = {}; top.parent = top;
  assert.equal(embeddedDatabase(true, location, top), false);
  const opaque = { parent: {} }; Object.defineProperty(opaque.parent, 'location', { get() { throw new Error('cross origin'); } });
  assert.equal(embeddedDatabase(true, location, opaque), false);
  assert.equal(websiteNavigationLocation(true, location, opaque), location);
});

test('explicit developer credentials do not turn the website DB into a Host deployment', () => {
  const values = new Map();
  globalThis.localStorage = globalThis.sessionStorage = { getItem: k => values.get(k) || null, setItem: (k,v) => values.set(k,v), removeItem: k => values.delete(k) };
  configureAuthentication({ enabled: true, mode: 'website' });
  assert.equal(websiteDeployment(), true);
  assert.equal(websiteAuthentication(), true);
  session.set('synthetic-developer-key', false);
  assert.equal(websiteDeployment(), true);
  assert.equal(websiteAuthentication(), false);
  configureAuthentication({ enabled: false });
  assert.equal(websiteDeployment(), false);
});

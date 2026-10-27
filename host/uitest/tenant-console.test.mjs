import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=join(dirname(fileURLToPath(import.meta.url)),'..','ui');
const file=name=>readFileSync(join(root,name),'utf8');
const main=file('js/main.js');
const state=file('js/state.js');
const databases=file('js/pages/databases.js');
const wizard=file('js/pages/wizard.js');
const keys=file('js/pages/keys.js');
const dashboard=file('js/pages/dashboard.js');
const index=file('index.html');
const css=file('css/forge.css');

test('all old customer tools and both website destinations remain visible in the source navigation',()=>{
 for(const id of ['databases','data','studio','keys','devices','apps','raw','backups','wizard']){
  const pattern=id==='wizard'?"'wizard'":"id: '"+id+"'";
  assert.ok(main.includes(pattern),'missing '+id);
 }
 assert.match(main,/title: 'All Red-XAI apps'/);
 assert.match(main,/title: 'Red-XAI Host'/);
 assert.match(main,/https:\/\/red-xai\.com\/hosting/);
 assert.match(main,/https:\/\/red-xai\.com\/store/);
 assert.match(main,/NAV\.filter\(\(n\) => !n\.adv && \(!n\.owner \|\| isOwner\)\)/);
});

test('tenant auth never grants host administration or owner access',()=>{
 assert.match(state,/export const isAccountTenant/);
 assert.match(state,/!state\.who\.owner && !state\.who\.host_admin/);
 assert.match(state,/export const canManageDatabases = \(\) => isHostAdmin\(\) \|\| isAccountTenant\(\)/);
 assert.match(main,/id: 'owner'.*owner: true/);
 assert.doesNotMatch(main,/\/v1\/owner\//);
 assert.doesNotMatch(keys,/X-RedXAI-Admin/);
});

test('tenant physical database names come from server, not guessed from user input',()=>{
 assert.match(state,/state\.dbLogical/);
 assert.match(state,/r\.logical/);
 assert.match(databases,/const actual = created\.name \|\| n/);
 assert.match(databases,/setDb\(actual\)/);
 assert.match(wizard,/dbName = created\.name \|\| S\.name/);
 assert.match(wizard,/setDb\(dbName\)/);
 assert.match(wizard,/pathURL\(dbName,/);
 assert.match(wizard,/enc\(dbName\)/);
 assert.doesNotMatch(wizard,/setDb\(S\.name\)/);
});

test('name conflict cannot silently reuse reserved or another account database',()=>{
 assert.match(wizard,/state\.dbs\.find\(\(d\) => dbDisplayName\(d\) === S\.name\)/);
 assert.match(wizard,/e\.status === 409 && ours/);
 assert.match(databases,/canManageDatabases\(\)/);
 assert.match(databases,/confirmTyped/);
 assert.match(databases,/confirm: 'deleteDatabase'/);
});

test('database API keys stay scoped and reuse the existing one-time-secret flow',()=>{
 assert.match(keys,/\/v1\/keys/);
 assert.match(keys,/dbDisplayName\(k\.db\)/);
 assert.match(keys,/confirm: 'createKey'/);
 assert.match(keys,/confirm: 'rotateKey'/);
 assert.match(keys,/confirm: 'revokeKey'/);
 assert.match(keys,/only time the key is shown/i);
 assert.match(keys,/!dbs\.length/);
});

test('account switching wipes stale database lists rather than showing another users data',()=>{
 assert.match(state,/state\.dbs = \[\]/);
 assert.match(state,/state\.dbLogical = \{\}/);
 assert.match(state,/state\.dbAccessIssue = e\.status === 403 \|\| e\.status === 402/);
});

test('customer dashboard restores creation, explorer, BoxQL, credentials, and plan status',()=>{
 for(const route of ['#/databases','#/data','#/studio','#/wizard','#/keys']){
  assert.ok(dashboard.includes(route),'missing '+route);
 }
 assert.match(dashboard,/dbDisplayName\(d\)/);
 assert.match(dashboard,/plan_required/);
 assert.match(dashboard,/read-only/);
 assert.match(dashboard,/\/v1\/keys/);
 assert.doesNotMatch(dashboard,/Your own databases on this host yet/);
});

test('unique Red-XAI Forge design supports dark/light, mobile and reduced-motion',()=>{
 assert.match(index,/ui\/css\/forge\.css/);
 assert.match(css,/\.customer-hero/);
 assert.match(css,/\.customer-action/);
 assert.match(css,/\.side-label/);
 assert.match(css,/\.hero-mark/);
 assert.match(css,/\[data-theme=light\]/);
 assert.match(css,/max-width:620px/);
 assert.match(css,/prefers-reduced-motion:reduce/);
 assert.doesNotMatch(css,/@import|url\(https?:/i);
});

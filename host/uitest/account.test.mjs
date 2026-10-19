// Signup live-check copy. Run with the other console unit tests: node --test host/uitest
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ApiError } from '../ui/js/api.js';
import { REMOTE_CHECK_OFFLINE, isUnreachable, retryUnreachable, remoteCheckMessage } from '../ui/js/pages/account.js';

const offline = () => new ApiError(0, 'Cannot reach the RedX host.');

test('signup username/email check retries once, then asks you to check your connection', async () => {
  assert.equal(REMOTE_CHECK_OFFLINE, "Couldn't check — check your connection.");
  assert.equal(remoteCheckMessage(offline()), REMOTE_CHECK_OFFLINE);
  assert.equal(remoteCheckMessage(offline()).includes('redxd'), false);
  assert.equal(remoteCheckMessage(new ApiError(503, 'unavailable')), 'Could not check right now: unavailable');

  let tries = 0;
  const recovered = await retryUnreachable(async () => {
    tries++;
    if (tries === 1) throw offline();
    return { ok: true, checks: [] };
  });
  assert.equal(tries, 2);
  assert.equal(recovered.ok, true);

  let failed = 0;
  await assert.rejects(() => retryUnreachable(async () => {
    failed++;
    throw offline();
  }), (e) => isUnreachable(e));
  assert.equal(failed, 2, 'a browser-side failure is tried twice and then shown');

  let serverHits = 0;
  await assert.rejects(() => retryUnreachable(async () => {
    serverHits++;
    throw new ApiError(400, 'username_invalid');
  }), /username_invalid/);
  assert.equal(serverHits, 1, 'an answer from the server is not retried');
});

test('the redxd-down hint is not used for a failed fetch', () => {
  const api = fs.readFileSync(new URL('../ui/js/api.js', import.meta.url), 'utf8');
  const account = fs.readFileSync(new URL('../ui/js/pages/account.js', import.meta.url), 'utf8');
  assert.equal(api.includes('Is redxd still running'), false);
  assert.equal(account.includes('Is redxd still running'), false);
  assert.equal(account.includes(REMOTE_CHECK_OFFLINE), true);
  assert.match(account, /retryUnreachable\(post\)/);
});

// Signup live-check copy. Run with the other console unit tests: node --test host/uitest
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ApiError } from '../ui/js/api.js';
import { REMOTE_CHECK_OFFLINE, SIGNIN_ERRORS, isUnreachable, retryUnreachable, remoteCheckMessage, nameChecks, pendingUntilText, resendErrorText } from '../ui/js/pages/account.js';

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

test('sign-up names follow the Accounts v1.2 rules', () => {
  const ok = (checks) => checks.every((c) => c.ok);
  for (const good of ['Josh', 'Mary Ann', "O'Brien", 'O\u2019Brien', 'José', '李', 'Анна-Мария', 'A.']) {
    assert.equal(ok(nameChecks(good, true)), true, good);
  }
  for (const bad of ['', ' ', 'Josh2', '---', 'a'.repeat(51)]) {
    assert.equal(ok(nameChecks(bad, true)), false, bad);
  }
  assert.equal(ok(nameChecks('', false)), true, 'middle name is optional');
  assert.equal(ok(nameChecks('   ', false)), true);
  assert.equal(nameChecks('Josh2', true).find((c) => c.id === 'chars').ok, false);
  assert.equal(nameChecks('a'.repeat(51), true).find((c) => c.id === 'length').ok, false);
});

test('an unverified account can resend the confirmation email', () => {
  assert.match(SIGNIN_ERRORS.email_unverified, /not confirmed/);
  assert.match(SIGNIN_ERRORS.email_unverified, /resend/i);
  const held = pendingUntilText(Date.UTC(2026, 9, 20, 15, 0, 0));
  assert.match(held, /held until/);
  assert.match(held, /2026/);
  assert.equal(pendingUntilText(0), '');
  assert.equal(pendingUntilText('nope'), '');
  const limited = resendErrorText({ status: 429, message: 'rate_limited', body: { error: 'rate_limited', message: 'Too many verification emails. Try again later.', retryAfter: 120 } });
  assert.match(limited, /Too many verification emails/);
  assert.match(limited, /120 seconds/);
  assert.equal(resendErrorText({ status: 503, message: 'unavailable', body: { message: 'Red-XAI Accounts cannot be reached right now.' } }), 'Red-XAI Accounts cannot be reached right now.');
  const account = fs.readFileSync(new URL('../ui/js/pages/account.js', import.meta.url), 'utf8');
  const main = fs.readFileSync(new URL('../ui/js/main.js', import.meta.url), 'utf8');
  assert.match(account, /Check your email/);
  assert.match(account, /\/v1\/auth\/email\/resend/);
  assert.match(account, /r\.step === 'verify_email' && !r\.handle/);
  assert.match(account, /!r\.resumed && r\.totp/);
  assert.match(account, /su-2fa-reenroll/);
  assert.equal(account.includes('email_pending'), false);
  assert.match(main, /email_unverified/);
  assert.match(main, /renderUnverified/);
  assert.equal(main.includes('resendLogin'), false);
});

test('the redxd-down hint is not used for a failed fetch', () => {
  const api = fs.readFileSync(new URL('../ui/js/api.js', import.meta.url), 'utf8');
  const account = fs.readFileSync(new URL('../ui/js/pages/account.js', import.meta.url), 'utf8');
  assert.equal(api.includes('Is redxd still running'), false);
  assert.equal(account.includes('Is redxd still running'), false);
  assert.equal(account.includes(REMOTE_CHECK_OFFLINE), true);
  assert.match(account, /retryUnreachable\(post\)/);
});

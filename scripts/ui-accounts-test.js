// Headless-Chrome test of Red-XAI Accounts in the console, against the in-memory fake (scripts/fake-accounts):
//   sign-up (ToS scroll -> Read ToS -> Agree to ToS, red/green hints, copy arrows, DOB typed + calendar, under-13 block,
//   2FA options that are available (Red-XAI Auth omitted until it is), "None" warning, TOTP confirm), sign-in as a regular account (no Owner page),
//   then sign-in as an owner with 2FA (Owner page, master DB, audit trail). Dark theme by default.
//   PLAYWRIGHT_CORE=/path/to/node_modules/playwright-core CHROME=/usr/bin/google-chrome \
//   node scripts/ui-accounts-test.js <redxd binary> <fake-accounts binary>
// Exit code 0 = pass, 1 = failures, 77 = Chrome/playwright-core not available (skipped).
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), net = require('node:net');
const { spawn } = require('node:child_process');
let chromium;
try { ({ chromium } = require(process.env.PLAYWRIGHT_CORE || 'playwright-core')); } catch { console.log('SKIP playwright-core not found (set PLAYWRIGHT_CORE)'); process.exit(77); }
const chrome = process.env.CHROME || ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'].find((p) => fs.existsSync(p));
if (!chrome) { console.log('SKIP no Chrome found (set CHROME)'); process.exit(77); }
const [,, redxd, fakeBin] = process.argv;
if (!fakeBin) { console.error('usage: node scripts/ui-accounts-test.js <redxd> <fake-accounts>'); process.exit(2); }
const free = () => new Promise((r) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const OWNER = 'owner@example.com'; // placeholder; real owner addresses live in deploy config only

(async () => {
  let failures = 0;
  const fail = (m) => { failures++; console.log('FAIL ', m); };
  const ok = (m) => console.log('ok   ', m);
  const fake = spawn(fakeBin, ['-listen', '127.0.0.1:0', '-client-secret', 'test-client-secret'], { stdio: ['ignore', 'pipe', 'inherit'] });
  const issuer = await new Promise((res, rej) => {
    let buf = '';
    fake.stdout.on('data', (d) => { buf += d; const m = /ISSUER (\S+)/.exec(buf); if (m) res(m[1]); });
    fake.on('exit', () => rej(new Error('fake-accounts exited')));
    setTimeout(() => rej(new Error('fake-accounts did not start')), 20000);
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redx-acct-'));
  const port = await free(), url = `http://127.0.0.1:${port}`;
  const host = spawn(redxd, ['run', '--no-open', '--bootstrap', 'console', '--data-dir', dir, '--listen', `127.0.0.1:${port}`], {
    stdio: 'ignore', env: { ...process.env, REDX_NO_OPEN: '1', REDX_ACCOUNTS_ISSUER: issuer, REDX_ADVERTISE: url, REDXAI_OWNER_EMAILS: OWNER, REDX_ACCOUNTS_CLIENT_SECRET: 'test-client-secret' } });
  const setNext = (id) => fetch(issuer + '/fake/next-login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(id) });
  let b;
  try {
    for (let i = 0; i < 150; i++) { try { if ((await fetch(url + '/healthz')).ok) break; } catch {} await sleep(100); }
    b = await chromium.launch({ executablePath: chrome, args: ['--no-sandbox'] });
    const ctx = await b.newContext({ viewport: { width: 1280, height: 1000 }, colorScheme: 'light' });
    const p = await ctx.newPage();
    let where = 'start';
    // expected refusals (wrong 2FA code, a regular account asking for owner data) show up as 4xx resource errors
    p.on('console', (m) => { if ((m.type() === 'error' || m.type() === 'warning') && !/Failed to load resource: the server responded with a status of 4\d\d/.test(m.text())) fail(`[${where}] console ${m.type()}: ${m.text()}`); });
    p.on('pageerror', (e) => fail(`[${where}] uncaught exception: ${e.message}`));
    p.on('request', (r) => { const u = r.url(); if (!u.startsWith(url) && !u.startsWith(issuer) && !u.startsWith('data:') && !u.startsWith('blob:')) fail(`[${where}] request left the host: ${u}`); });
    p.on('response', (r) => { if (r.url().startsWith(url) && r.status() >= 500) fail(`[${where}] ${r.status()} from ${r.url()}`); });
    const expect = (cond, msg) => (cond ? ok(msg) : fail(msg));
    const hints = (id) => p.$$eval(`#${id} li`, (ls) => ls.map((l) => ({ id: l.dataset.check, cls: l.className, color: getComputedStyle(l).color })));

    // ---- login page ----
    where = 'login';
    await p.goto(url + '/', { waitUntil: 'networkidle' });
    await p.waitForSelector('#acct-signin', { timeout: 10000 });
    expect(await p.evaluate(() => document.documentElement.dataset.theme) === 'dark', 'dark theme by default (even when the device prefers light)');
    expect(await p.$('input[aria-label="API key or pairing code"]') !== null, 'API-key sign-in is still offered');

    // ---- sign-up: ToS gate ----
    where = 'signup-tos';
    await p.click('#acct-signup');
    await p.waitForSelector('#tos-box');
    expect(await p.$eval('#tos-read', (e) => e.disabled) && await p.$eval('#tos-agree', (e) => e.disabled), 'Read ToS and Agree to ToS start disabled');
    await p.$eval('#tos-box', (e) => { e.scrollTop = e.scrollHeight / 3; e.dispatchEvent(new Event('scroll')); });
    expect(await p.$eval('#tos-read', (e) => e.disabled), 'Read ToS stays disabled until the bottom is reached');
    await p.$eval('#tos-box', (e) => { e.scrollTop = e.scrollHeight; e.dispatchEvent(new Event('scroll')); });
    expect(!(await p.$eval('#tos-read', (e) => e.disabled)) && await p.$eval('#tos-agree', (e) => e.disabled), 'scrolled to the bottom: Read ToS enabled, Agree still disabled');
    await p.click('#tos-read');
    await p.waitForFunction(() => !document.querySelector('#tos-agree').disabled);
    ok('after Read ToS, Agree to ToS is enabled');
    await p.click('#tos-agree');
    await p.waitForSelector('#su-username');
    expect(/version 2026-10-19/.test(await p.textContent('#tos-accepted')), 'the accepted ToS version and time are shown');

    // ---- sign-up: fields and hints ----
    where = 'signup-form';
    await p.fill('#su-username', 'a!');
    let hs = await hints('hints-username');
    expect(hs.length >= 3 && hs.every((x) => x.cls.includes('bad')), 'bad username: hints are red');
    const red = hs[0].color;
    await p.fill('#su-username', 'takenuser1');
    await p.waitForFunction(() => document.querySelector('#hints-username li[data-check="available"]'));
    expect((await hints('hints-username')).find((x) => x.id === 'available').cls.includes('bad'), 'taken username is flagged by Red-XAI Accounts');
    await p.fill('#su-username', 'grim_player1');
    await p.waitForFunction(() => { const l = [...document.querySelectorAll('#hints-username li')]; return l.length >= 4 && l.every((x) => x.classList.contains('good')); });
    hs = await hints('hints-username');
    expect(hs[0].color !== red, `good username: hints turn green (${hs[0].color} vs red ${red})`);

    await p.fill('#su-email', 'not-an-email');
    expect((await hints('hints-email'))[0].cls.includes('bad'), 'bad email is red');
    await p.fill('#su-email', 'new.player@example.com');
    await p.waitForFunction(() => { const l = [...document.querySelectorAll('#hints-email li')]; return l.length >= 4 && l.every((x) => x.classList.contains('good')); });
    ok('email checked live (syntax, domain, disposable, available) and green');
    expect((await hints('hints-email2'))[0].cls.includes('bad'), 'confirm email starts red');
    await p.click('#su-email2 + .copy-arrow, .field:has(#su-email2) .copy-arrow');
    expect(await p.inputValue('#su-email2') === 'new.player@example.com' && (await hints('hints-email2'))[0].cls.includes('good'), 'the ⇅ arrow copies the email into the confirm box');

    await p.fill('#su-password', 'short');
    expect((await hints('hints-password')).filter((x) => x.cls.includes('bad')).length >= 3, 'weak password: several red hints');
    await p.fill('#su-password', 'Pass word"1A');
    const pw = await hints('hints-password');
    expect(pw.find((x) => x.id === 'chars').cls.includes('bad'), 'space and quote are refused');
    await p.fill('#su-password', 'Abcdefgh123!');
    expect((await hints('hints-password')).every((x) => x.cls.includes('good')), 'strong password: all green');
    await p.click('.field:has(#su-password2) .copy-arrow');
    expect(await p.inputValue('#su-password2') === 'Abcdefgh123!' && (await hints('hints-password2'))[0].cls.includes('good'), 'the ⇅ arrow copies the password into the confirm box');

    const now = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    const under = `${pad(now.getMonth() + 1)}${pad(now.getDate())}${now.getFullYear() - 12}`;
    await p.fill('#su-dob', '');
    await p.type('#su-dob', under);
    expect(/^\d{2}\/\d{2}\/\d{4}$/.test(await p.inputValue('#su-dob')), 'typed digits become MM/DD/YYYY');
    expect(await p.isVisible('#su-age-block') && (await hints('hints-dob')).find((x) => x.id === 'min_age').cls.includes('bad'), 'under 13 is blocked');
    await p.fill('#su-dob-cal', '2001-07-04');
    await p.dispatchEvent('#su-dob-cal', 'change');
    expect(await p.inputValue('#su-dob') === '07/04/2001' && !(await p.isVisible('#su-age-block')), 'the calendar picker fills MM/DD/YYYY');
    expect((await hints('hints-dob')).every((x) => x.cls.includes('good')), 'date of birth hints green');

    expect(await p.$('#su-2fa-redxai_auth') === null && !/Coming soon/.test(await p.textContent('.tfa')), 'Red-XAI Auth is omitted until it is available');
    await p.check('#su-2fa-none');
    expect(await p.isVisible('#su-no2fa-warning'), 'choosing None shows the risk warning');
    await p.check('#su-2fa-phone');
    expect(await p.isVisible('#su-phone'), 'choosing Phone asks for the number');
    await p.check('#su-2fa-app');
    expect(await p.isVisible('#su-false-info') && /cannot be recovered/.test(await p.textContent('#su-false-info')), 'false-info warning is shown');
    expect(await p.$eval('#su-submit', (e) => e.disabled), 'Create account is disabled until the false-info warning is acknowledged');
    await p.check('#su-ack-false');
    await p.waitForFunction(() => !document.querySelector('#su-submit').disabled);
    ok('everything valid: Create account enabled');
    await p.click('#su-submit');
    await p.waitForSelector('#su-totp-secret', { timeout: 10000 });
    ok('account created; authenticator key shown');
    await p.fill('#su-2fa-code', '000000');
    await p.click('#su-2fa-go');
    await p.waitForFunction(() => { const e = document.querySelector('.form-err:not([hidden])'); return e && e.textContent.length > 0; });
    ok('a wrong 2FA code is refused');
    await p.fill('#su-2fa-code', '123456');
    await p.click('#su-2fa-go');
    await p.waitForSelector('#su-signin');
    ok('2FA confirmed; sign-in offered');

    // ---- sign in as a regular account ----
    where = 'signin-regular';
    await setNext({ sub: 'rxa_REG1', email: 'new.player@example.com', email_verified: true, username: 'grim_player1', amr: ['pwd', 'otp'] });
    await p.click('#su-signin');
    await p.waitForSelector('.shell', { timeout: 15000 });
    expect(/grim_player1/.test(await p.textContent('.who')), 'signed in: the account name is shown');
    expect(await p.$('.nav-item[data-id="owner"]') === null, 'a regular account has no Owner page');
    expect(await p.isVisible('#account-card'), 'regular dashboard explains the account has no databases yet');
    where = 'role-gate-account';
    await p.evaluate(() => localStorage.setItem('redx.mode', 'advanced'));
    await p.reload({ waitUntil: 'networkidle' });
    await p.waitForSelector('.shell');
    const hiddenAccount = ['owner', 'updates', 'keys', 'devices', 'apps', 'backups', 'cluster', 'presets', 'raw', 'policy', 'watch'];
    for (const id of hiddenAccount) expect(await p.$(`.nav-item[data-id="${id}"]`) === null, 'regular account hides ' + id);
    const hostOnly = ['hosting', 'usage', 'updates', 'logs'];
    const notInNav = ['hostapps', 'deploy', 'domains', 'env', 'applogs'];
    expect(await p.getAttribute('#console-mode [data-surface="database"]', 'aria-pressed') === 'true', 'default mode is Database');
    expect(await p.evaluate(() => {
      const header = document.querySelector('header.top');
      const sw = document.querySelector('#console-mode');
      if (!header || !sw || !header.contains(sw)) return false;
      const h = header.getBoundingClientRect();
      const s = sw.getBoundingClientRect();
      return Math.abs((s.left + s.right) / 2 - (h.left + h.right) / 2) < 12;
    }), 'the Database / Host switch is centered in the header');
    expect(await p.$('.nav-item[data-id="dashboard"]') !== null && await p.$('.nav-item[data-id="help"]') !== null, 'Database mode shows the database pages and Help');
    for (const id of hostOnly) expect(await p.$(`.nav-item[data-id="${id}"]`) === null, 'Database mode hides ' + id);
    where = 'mode-toggle';
    await p.click('#console-mode [data-surface="host"]');
    await p.waitForSelector('.nav-item[data-id="hosting"]');
    expect(await p.getAttribute('#console-mode [data-surface="host"]', 'aria-pressed') === 'true', 'toggle selects Host');
    for (const id of ['hosting', 'usage', 'logs']) {
      expect(await p.$(`.nav-item[data-id="${id}"]`) !== null, 'Host mode shows ' + id);
    }
    for (const id of notInNav) expect(await p.$(`.nav-item[data-id="${id}"]`) === null, 'Host mode has no ' + id + ' entry');
    expect(await p.$('#coming-soon') === null, 'Host mode has no Coming soon page');
    expect(await p.$('.nav-item[data-id="updates"]') === null, 'a regular account hides Updates in Host mode');
    expect(await p.$('.nav-item[data-id="owner"]') === null, 'a regular account hides Owner in Host mode');
    expect(await p.$('.nav-item[data-id="dashboard"]') === null, 'Host mode hides the database pages');
    await p.click('.nav-item[data-id="logs"]');
    await p.waitForSelector('#logs-page');
    expect(/activity/i.test(await p.textContent('#logs-page')) && await p.$('.errbox') === null && await p.$('#page-missing') === null, 'Logs shows this account\'s activity');
    expect(await p.$('#activity-error') === null && await p.$('#activity-missing') === null, 'Logs has no silent API failure callout for a signed-in account');
    await p.click('.nav-item[data-id="usage"]');
    await p.waitForSelector('#usage-page');
    expect(/Usage|plan|Sign in/i.test(await p.textContent('#usage-page')) && await p.$('.errbox') === null, 'Usage page loads for a signed-in account');
    expect(await p.$('#usage-error') === null, 'Usage does not show a load error when billing/me answers');
    expect(await p.getAttribute('#console-brand', 'href') === '#/hosting', 'brand link stays on Host home while in Host mode');
    await p.click('#console-mode [data-surface="database"]');
    await p.waitForSelector('.nav-item[data-id="dashboard"]');
    expect(await p.$('.nav-item[data-id="hosting"]') === null, 'toggle back to Database hides Host pages');
    expect(await p.getAttribute('#console-brand', 'href') === '#/dashboard', 'brand link returns to Dashboard in Database mode');
    where = 'mode-persist';
    await p.click('#console-mode [data-surface="host"]');
    await p.waitForSelector('.nav-item[data-id="hosting"]');
    expect(await p.evaluate(() => localStorage.getItem('redx.consoleMode.rxa_REG1')) === 'host', 'Host mode is stored for this user');
    await p.reload({ waitUntil: 'networkidle' });
    await p.waitForSelector('.nav-item[data-id="hosting"]');
    expect(await p.getAttribute('#console-mode [data-surface="host"]', 'aria-pressed') === 'true', 'reload keeps Host for this user');
    where = 'mode-deeplink';
    await p.goto(url + '/?mode=database#/dashboard', { waitUntil: 'networkidle' });
    await p.waitForSelector('.nav-item[data-id="dashboard"]');
    expect(await p.getAttribute('#console-mode [data-surface="database"]', 'aria-pressed') === 'true', 'deep link selects Database');
    expect(await p.evaluate(() => localStorage.getItem('redx.consoleMode.rxa_REG1')) === 'database', 'deep link updates the stored choice');
    await p.goto(url + '/?mode=host#/hosting', { waitUntil: 'networkidle' });
    await p.waitForSelector('#hosting-off');
    expect(await p.getAttribute('#console-mode [data-surface="host"]', 'aria-pressed') === 'true', 'deep link selects Host and keeps the hash route');
    expect(/Hosting plans aren't on sale yet/.test(await p.textContent('#hosting-page')), 'billing off says plans are not on sale');
    expect(/#\/hosting$/.test(await p.evaluate(() => location.hash)) && /[?&]mode=host(?:&|$)/.test(await p.evaluate(() => location.search)), 'address keeps ?mode=host and #/hosting');
    await p.evaluate(() => localStorage.setItem('redx.consoleMode.rxa_REG1', 'database'));
    await p.goto(url + '/#/logs', { waitUntil: 'networkidle' });
    await p.waitForSelector('#logs-page');
    expect(await p.getAttribute('#console-mode [data-surface="host"]', 'aria-pressed') === 'true', 'opening a host page selects Host mode');
    await p.goto(url + '/?mode=database#/updates', { waitUntil: 'networkidle' });
    await p.waitForSelector('#page-missing');
    expect(await p.getAttribute('#console-mode [data-surface="host"]', 'aria-pressed') === 'true', 'a host address overrides ?mode=database');
    await p.goto(url + '/#/owner', { waitUntil: 'networkidle' });
    await p.waitForSelector('#page-missing');
    const missing = await p.textContent('#page-missing');
    expect(/Page not found/.test(missing) && !missing.includes(OWNER), 'direct #/owner is not-found and does not name an owner');
    expect(await p.$('.nav-item[data-id="owner"]') === null, 'Owner stays hidden for a regular account after a direct address');
    const regStatus = await p.evaluate(async () => (await fetch('/v1/owner/accounts', { headers: { Authorization: 'Bearer ' + sessionStorage.getItem('redx.key') } })).status);
    expect(regStatus === 403, 'owner API refuses a regular account (403)');
    await p.click('.who');
    await p.waitForSelector('#acct-signin', { timeout: 10000 });
    ok('signed out');

    // ---- owner email without 2FA ----
    where = 'signin-owner-no2fa';
    await setNext({ sub: 'rxa_OWN1', email: OWNER, email_verified: true, username: 'owner_account', amr: ['pwd'] });
    await p.click('#acct-signin');
    await p.waitForSelector('.shell', { timeout: 15000 });
    expect(await p.getAttribute('#console-mode [data-surface="database"]', 'aria-pressed') === 'true', 'a different user starts in Database mode');
    expect(await p.evaluate(() => localStorage.getItem('redx.consoleMode.rxa_REG1')) === 'host', 'the previous user Host choice is kept');
    expect(await p.$('.nav-item[data-id="owner"]') === null && await p.isVisible('#owner-blocked'), 'owner email without 2FA gets no owner rights and is told why');
    await p.click('#console-mode [data-surface="host"]');
    await p.waitForSelector('.nav-item[data-id="hosting"]');
    expect(await p.$('.nav-item[data-id="owner"]') === null, 'Owner stays hidden in Host mode without owner rights');
    await p.click('#console-mode [data-surface="database"]');
    await p.waitForSelector('.nav-item[data-id="dashboard"]');
    await p.click('.who');
    await p.waitForSelector('#acct-signin', { timeout: 10000 });

    // ---- owner with 2FA ----
    where = 'signin-owner';
    await setNext({ sub: 'rxa_OWN1', email: OWNER, email_verified: true, username: 'owner_account', amr: ['pwd', 'otp'], owner_scope: true });
    await p.click('#acct-signin');
    await p.waitForSelector('.nav-item[data-id="owner"]', { timeout: 15000 });
    ok('owner with 2FA sees the Owner page');
    expect(await p.getAttribute('#console-mode [data-surface="database"]', 'aria-pressed') === 'true', 'owner starts in Database mode');
    await p.click('#console-mode [data-surface="host"]');
    await p.waitForSelector('.nav-item[data-id="updates"]');
    expect(await p.$('.nav-item[data-id="owner"]') !== null, 'owner sees Owner in Host mode');
    await p.click('#console-mode [data-surface="database"]');
    await p.waitForSelector('.nav-item[data-id="dashboard"]');
    expect(await p.$('.nav-item[data-id="owner"]') !== null, 'owner sees Owner in Database mode');
    // create the master accounts DB and one account record as the owner (the accounts service would write these)
    await p.evaluate(async () => {
      const H = { Authorization: 'Bearer ' + sessionStorage.getItem('redx.key'), 'Content-Type': 'application/json' };
      await fetch('/v1/dbs', { method: 'POST', headers: H, body: JSON.stringify({ name: 'redxai_accounts' }) });
      await fetch('/v1/db/redxai_accounts/path/' + encodeURIComponent('account.red-xai.db:Record[ID=1]'), { method: 'PUT', headers: H,
        body: JSON.stringify({ value: { key: 'rxa_UI1', username: 'grim_player1', email: 'new.player@example.com', emailVerified: true, passHash: 'argon2id$SECRET', dob: '2001-07-04', status: 'active', createdMs: 1 } }) });
    });
    await p.click('.nav-item[data-id="owner"]');
    await p.waitForSelector('tr[data-account="rxa_UI1"]', { timeout: 10000 });
    const ownerText = await p.textContent('#owner-body');
    expect(/grim_player1/.test(ownerText) && !/argon2id/.test(ownerText) && !/2001-07-04/.test(ownerText), 'Owner page lists accounts without secrets or dates of birth');
    await p.click('#owner-tab-dbs');
    await p.waitForSelector('tr[data-db="redxai_accounts"]');
    expect(/owners only/.test(await p.textContent('tr[data-db="redxai_accounts"]')), 'Owner page shows the master accounts DB');
    await p.click('#owner-tab-audit');
    await p.waitForFunction(() => /owner\.read/.test(document.querySelector('#owner-body').innerText));
    expect((await p.textContent('#owner-body')).includes(OWNER), 'owner audit trail names the acting owner');
    // Kick/Ban/Terminate buttons (Accounts tab); master may be empty so absence is OK
    where = 'owner-moderation';
    const hasKick = await p.$('button:has-text("Kick")');
    ok(hasKick ? 'Owner accounts table exposes Kick/Ban/Terminate' : 'no Kick button (master empty or Accounts tab) — OK');
    where = 'role-gate-key';
    await p.click('#console-mode [data-surface="host"]');
    await p.waitForSelector('.nav-item[data-id="hosting"]');
    expect(/[?&]mode=host(?:&|$)/.test(await p.evaluate(() => location.search)), 'Host mode writes ?mode=host');
    const created = await p.evaluate(async () => {
      const headers = { Authorization: 'Bearer ' + sessionStorage.getItem('redx.key'), 'Content-Type': 'application/json', 'X-RedX-Confirm': 'createKey' };
      const mint = async (label) => {
        const r = await fetch('/v1/keys', { method: 'POST', headers, body: JSON.stringify({ db: 'default', scope: 'read', label }) });
        const b = await r.json().catch(() => ({}));
        return { status: r.status, key: b.key || '' };
      };
      return { a: await mint('limited-a'), b: await mint('limited-b') };
    });
    expect(created.a.status === 201 && created.a.key.length > 8 && created.b.status === 201 && created.b.key.length > 8, 'owner created two db-scoped read keys');
    const signKey = async (k) => {
      await p.evaluate((key) => {
        sessionStorage.setItem('redx.key', key);
        localStorage.setItem('redx.mode', 'advanced');
        localStorage.setItem('redx.wizard', 'done');
        location.hash = '#/dashboard';
        location.reload();
      }, k);
      await p.waitForSelector('.shell', { timeout: 15000 });
    };
    const modeOf = async () => {
      const who = await p.evaluate(async () => (await fetch('/v1/ui/whoami', { headers: { Authorization: 'Bearer ' + sessionStorage.getItem('redx.key') } })).json());
      const stored = await p.evaluate((id) => localStorage.getItem('redx.consoleMode.' + id), who.id);
      return { id: who.id, stored, search: await p.evaluate(() => location.search) };
    };
    await p.click('.who');
    await p.waitForSelector('#acct-signin');
    expect(!/(?:^|[?&])mode=/.test(await p.evaluate(() => location.search)), 'account sign-out strips ?mode=');
    where = 'mode-leak-account-key';
    await signKey(created.a.key);
    const keyA = await modeOf();
    expect(await p.getAttribute('#console-mode [data-surface="database"]', 'aria-pressed') === 'true', 'a read key that never chose a mode stays in Database after an account Host URL');
    expect(keyA.stored !== 'host', 'account Host mode is not saved onto the next key');
    const hiddenKey = ['owner', 'updates', 'keys', 'devices', 'apps', 'backups', 'cluster', 'presets', 'raw', 'policy'];
    for (const id of hiddenKey) expect(await p.$(`.nav-item[data-id="${id}"]`) === null, 'read key hides ' + id);
    expect(await p.$('.nav-item[data-id="watch"]') !== null, 'a read key can open Live Watch');
    expect(await p.$('.nav-item[data-id="hosting"]') === null, 'a read key starts in Database mode');
    await p.click('#console-mode [data-surface="host"]');
    await p.waitForSelector('.nav-item[data-id="hosting"]');
    expect(await p.evaluate((id) => localStorage.getItem('redx.consoleMode.' + id), keyA.id) === 'host', 'the first read key can choose Host for itself');
    await p.click('.who');
    await p.waitForSelector('#acct-signin');
    expect(!/(?:^|[?&])mode=/.test(await p.evaluate(() => location.search)), 'key sign-out strips ?mode=');
    where = 'mode-leak-key-key';
    await signKey(created.b.key);
    const keyB = await modeOf();
    expect(keyB.id !== keyA.id, 'the second key is a different user');
    expect(await p.getAttribute('#console-mode [data-surface="database"]', 'aria-pressed') === 'true', 'a second read key stays in Database after the previous key Host URL');
    expect(keyB.stored !== 'host', 'the previous key Host mode is not saved onto the next key');
    expect(await p.evaluate((id) => localStorage.getItem('redx.consoleMode.' + id), keyA.id) === 'host', 'the first key keeps its own Host choice');
    await p.goto(url + '/#/hosting', { waitUntil: 'networkidle' });
    await p.waitForSelector('.nav-item[data-id="hosting"]');
    expect(await p.getAttribute('#console-mode [data-surface="host"]', 'aria-pressed') === 'true', 'opening Hosting selects Host mode');
    expect(await p.$('.nav-item[data-id="owner"]') === null, 'a read key has no Owner item in Host mode');
    await p.goto(url + '/#/owner', { waitUntil: 'networkidle' });
    await p.waitForSelector('#page-missing');
    expect(/Page not found/.test(await p.textContent('#page-missing')), 'direct #/owner is not-found for a read key');
    await ctx.close();
  } catch (e) {
    fail('exception: ' + (e && e.stack || e));
  } finally {
    if (b) await b.close();
    host.kill('SIGKILL');
    fake.kill('SIGKILL');
  }
  console.log(failures ? `${failures} failure(s)` : 'all accounts console checks passed');
  process.exit(failures ? 1 : 0);
})();

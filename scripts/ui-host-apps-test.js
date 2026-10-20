// Headless Chrome E2E for Host tab apps against a real redxd (no mocked API).
//   PLAYWRIGHT_CORE=... CHROME=... node scripts/ui-host-apps-test.js <redxd>
// Exit 0 = pass, 1 = fail, 77 = skip (no Chrome).
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), net = require('node:net');
const { spawn, execFileSync } = require('node:child_process');
let chromium;
try { ({ chromium } = require(process.env.PLAYWRIGHT_CORE || 'playwright-core')); } catch { console.log('SKIP playwright-core not found'); process.exit(77); }
const chrome = process.env.CHROME || ['/usr/bin/google-chrome', '/usr/bin/chromium'].find((p) => fs.existsSync(p));
if (!chrome) { console.log('SKIP no Chrome'); process.exit(77); }
const [,, redxd] = process.argv;
if (!redxd) { console.error('usage: node scripts/ui-host-apps-test.js <redxd>'); process.exit(2); }
const free = () => new Promise((r) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  let failures = 0;
  const fail = (m) => { failures++; console.log('FAIL ', m); };
  const ok = (m) => console.log('ok   ', m);
  const expect = (c, m) => { if (c) ok(m); else fail(m); };

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redx-hostapps-'));
  const port = await free(), url = `http://127.0.0.1:${port}`;
  const log = path.join(dir, 'redxd.log');
  const host = spawn(redxd, ['run', '--no-open', '--bootstrap', 'console', '--data-dir', dir, '--listen', `127.0.0.1:${port}`], {
    stdio: ['ignore', fs.openSync(log, 'w'), fs.openSync(log, 'a')],
    env: { ...process.env, REDX_NO_OPEN: '1' },
  });
  try {
    for (let i = 0; i < 150; i++) { try { if ((await fetch(url + '/healthz')).ok) break; } catch {} await sleep(100); }
    const key = fs.readFileSync(log, 'utf8').match(/rx_live_[A-Za-z0-9]+/)?.[0];
    if (!key) { fail('bootstrap key printed'); throw new Error('no key'); }
    ok('redxd up with bootstrap key');

    const b = await chromium.launch({ executablePath: chrome, args: ['--no-sandbox'] });
    const p = await (await b.newContext({ viewport: { width: 1280, height: 900 }, colorScheme: 'dark' })).newPage();
    const pageErrors = [];
    p.on('pageerror', (e) => pageErrors.push(e.message));

    await p.goto(url + '/', { waitUntil: 'networkidle' });
    await p.fill('input[type="password"]', key);
    await p.click('button');
    await p.waitForSelector('.shell', { timeout: 15000 });
    ok('signed in as bootstrap-admin');

    // Skip wizard if present
    if (await p.$('a[href="#/wizard"], #wizard-page')) {
      await p.evaluate(() => localStorage.setItem('redx.wizard', 'done'));
      await p.goto(url + '/#/dashboard', { waitUntil: 'networkidle' });
      await p.waitForSelector('.shell');
    }

    await p.click('#console-mode [data-surface="host"]');
    await p.waitForSelector('.nav-item[data-id="hostapps"]', { timeout: 10000 });
    expect(await p.getAttribute('#console-mode [data-surface="host"]', 'aria-pressed') === 'true', 'Host mode selected');
    for (const id of ['hosting', 'usage', 'hostapps', 'hostdeploy', 'hostdomains', 'hostsecrets', 'hostlogs', 'logs']) {
      expect(await p.$(`.nav-item[data-id="${id}"]`) !== null, 'Host nav has ' + id);
    }
    expect(await p.$('.nav-item[data-id="dashboard"]') === null, 'Host mode hides Database pages');
    expect(await p.getAttribute('#console-brand', 'href') === '#/hosting', 'brand stays on Host home');

    await p.click('.nav-item[data-id="hostapps"]');
    await p.waitForSelector('#hostapps-page, .page', { timeout: 10000 });
    // Wait for empty state or list
    await p.waitForTimeout(800);
    const appsText = await p.textContent('.main');
    expect(/No apps yet|Create app|Apps/i.test(appsText) && !(await p.$('.errbox')), 'Apps page loads without error box');

    // Create an app through the UI
    const nameInput = await p.$('input[aria-label="New app name"], input[placeholder="my-site"]');
    if (!nameInput) { fail('create form missing'); }
    else {
      await nameInput.fill('e2e-site');
      await p.click('button:has-text("Create app")');
      await p.waitForTimeout(1500);
      const after = await p.textContent('.main');
      const onDetail = /#\/hostapps\//.test(await p.evaluate(() => location.hash)) || /e2e-site|Start|Stop|Deploys|Domains/i.test(after);
      expect(onDetail || /e2e-site/.test(after), 'created app appears (detail or list)');
      // If still on list, open it
      if (!/#\/hostapps\//.test(await p.evaluate(() => location.hash))) {
        const link = await p.$('a[href*="#/hostapps/"]');
        if (link) { await link.click(); await p.waitForTimeout(800); }
      }
      if (/#\/hostapps\//.test(await p.evaluate(() => location.hash))) {
        expect(/Start|Stop|Domains|Environment|Secrets|Logs/i.test(await p.textContent('.main')), 'app detail shows start/stop/domains/env/secrets/logs');
        // Load runtime logs (may be empty)
        const logBtn = await p.$('button:has-text("Runtime")');
        if (logBtn) {
          await logBtn.click();
          await p.waitForTimeout(500);
          expect(!(await p.$('.errbox')), 'runtime logs load without error box');
          ok('runtime logs requested');
        }
        // Open Deploy page for this app
        await p.click('.nav-item[data-id="hostdeploy"]');
        await p.waitForTimeout(800);
        expect(/Deploy|Choose an app|Ship|Archive|git/i.test(await p.textContent('.main')) && !(await p.$('.errbox')), 'Deploy page loads');
        await p.click('.nav-item[data-id="hostdomains"]');
        await p.waitForTimeout(600);
        expect(/Domain|Apps|Choose/i.test(await p.textContent('.main')) && !(await p.$('.errbox')), 'Domains page loads');
        await p.click('.nav-item[data-id="hostsecrets"]');
        await p.waitForTimeout(600);
        expect(/Secret|Environment|Env|Choose/i.test(await p.textContent('.main')) && !(await p.$('.errbox')), 'Env & Secrets page loads');
        await p.click('.nav-item[data-id="hostlogs"]');
        await p.waitForTimeout(600);
        expect(/log|App|Choose|Runtime|Request/i.test(await p.textContent('.main')) && !(await p.$('.errbox')), 'App logs page loads');
      }
    }

    // Verify via real API
    const listed = await (await fetch(url + '/v1/hosted/apps', { headers: { Authorization: 'Bearer ' + key } })).json();
    expect((listed.apps || []).some((a) => a.name === 'e2e-site'), 'API lists the UI-created app');

    expect(pageErrors.length === 0, 'no page exceptions (' + pageErrors.join('; ') + ')');
    await b.close();
  } finally {
    host.kill();
  }
  if (failures) { console.log(failures + ' failures'); process.exit(1); }
  console.log('all host-apps console checks passed');
})().catch((e) => { console.error(e); process.exit(1); });

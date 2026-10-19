// Headless-Chrome test: sign in, visit EVERY console page in both themes, and fail on
//   * any console error/warning or uncaught exception,
//   * any failed request, or any request that leaves the host's own origin,
//   * a page that renders an in-page error box ("Something went wrong"), or an empty page,
//   * the wrong theme being applied.
//   PLAYWRIGHT_CORE=/path/to/node_modules/playwright-core CHROME=/usr/bin/google-chrome \
//   node scripts/ui-pages-test.js <redxd binary> <redx binary>
// Exit code 0 = pass, 1 = failures, 77 = Chrome/playwright-core not available (skipped).
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), net = require('node:net');
const { spawn, execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
let chromium;
try { ({ chromium } = require(process.env.PLAYWRIGHT_CORE || 'playwright-core')); } catch { console.log('SKIP playwright-core not found (set PLAYWRIGHT_CORE)'); process.exit(77); }
const chrome = process.env.CHROME || ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'].find((p) => fs.existsSync(p));
if (!chrome) { console.log('SKIP no Chrome found (set CHROME)'); process.exit(77); }
const [,, redxd, redx] = process.argv;
if (!redx) { console.error('usage: node scripts/ui-pages-test.js <redxd> <redx>'); process.exit(2); }
const free = () => new Promise((r) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const ABOUT = 'RedX is developed and maintained by Red-XAI LLC. Red-XAI LLC is wholly owned by GRIM-VIRUS, an independent recording artist who leads development under the alias MainDirectory. © Red-XAI LLC. All rights reserved.';
const PAGES = ['dashboard', 'databases', 'data', 'studio', 'keys', 'devices', 'backups', 'settings', 'hosting', 'usage', 'logs', 'hostapps', 'deploy', 'domains', 'env', 'applogs', 'updates', 'help', 'watch', 'raw', 'policy', 'cluster', 'presets', 'wizard', 'apps', 'connect'];
(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redx-pages-'));
  const port = await free(), url = `http://127.0.0.1:${port}`;
  const key = JSON.parse(execFileSync(redx, ['key', 'create', '--offline', '--data-dir', dir, '--scope', 'admin', '--db', '*', '--label', 'pages', '--json'], { stdio: ['ignore', 'pipe', 'ignore'] }).toString()).key;
  const host = spawn(redxd, ['run', '--no-open', '--bootstrap', 'console', '--data-dir', dir, '--listen', `127.0.0.1:${port}`], { stdio: 'ignore', env: { ...process.env, REDX_NO_OPEN: '1' } });
  let failures = 0;
  const fail = (m) => { failures++; console.log('FAIL ', m); };
  try {
    for (let i = 0; i < 100; i++) { try { if ((await fetch(url + '/healthz')).ok) break; } catch {} await sleep(100); }
    const cli = (...a) => execFileSync(redx, a, { env: { ...process.env, REDX_ADDR: url, REDX_KEY: key }, stdio: 'ignore' });
    cli('set', 'players.red-xai.db:Player[ID=1]', '[ {Name[]} = "Ann", {Level[]} = 7 ]');
    cli('set', 'sessions.red-xai-db-qs:Session[ID=1].Token', '"abc"', '--ttl', '600');
    const b = await chromium.launch({ executablePath: chrome, args: ['--no-sandbox'] });
    for (const theme of ['dark', 'light']) {
      const ctx = await b.newContext({ viewport: { width: 1280, height: 800 }, colorScheme: theme });
      await ctx.addInitScript(([k, t]) => { try { localStorage.setItem('redx.key', k); localStorage.setItem('redx.theme', t); localStorage.setItem('redx.mode', 'advanced'); localStorage.setItem('redx.wizard.done', '1'); } catch {} }, [key, theme]);
      const p = await ctx.newPage();
      let where = 'start';
      p.on('console', (m) => { if (m.type() === 'error' || m.type() === 'warning') fail(`[${theme}/${where}] console ${m.type()}: ${m.text()}`); });
      p.on('pageerror', (e) => fail(`[${theme}/${where}] uncaught exception: ${e.message}`));
      p.on('requestfailed', (r) => fail(`[${theme}/${where}] request failed: ${r.url()} ${r.failure() && r.failure().errorText}`));
      p.on('request', (r) => { if (!r.url().startsWith(url) && !r.url().startsWith('data:') && !r.url().startsWith('blob:')) fail(`[${theme}/${where}] request left the host: ${r.url()}`); });
      p.on('response', (r) => { if (r.url().startsWith(url) && r.status() >= 500) fail(`[${theme}/${where}] ${r.status()} from ${r.url()}`); });
      for (const pg of PAGES) {
        where = pg;
        await p.goto(`${url}/#/${pg}`, { waitUntil: 'networkidle' });
        await p.waitForTimeout(400);
        const info = await p.evaluate(() => ({
          theme: document.documentElement.dataset.theme,
          errbox: [...document.querySelectorAll('.errbox')].map((e) => e.textContent.trim().slice(0, 160)),
          text: (document.querySelector('main, #app') || document.body).innerText.trim().length,
          shell: !!document.querySelector('.shell'),
        }));
        if (info.theme !== theme) fail(`[${theme}/${pg}] theme is ${info.theme}`);
        if (!info.shell) fail(`[${theme}/${pg}] console shell did not render`);
        if (info.errbox.length) fail(`[${theme}/${pg}] error box on the page: ${info.errbox.join(' | ')}`);
        if (info.text < 20) fail(`[${theme}/${pg}] page is empty`);
        if (pg === 'help') {
          const about = await p.evaluate(() => { const e = document.querySelector('#about .about-copy'); return e ? e.textContent : ''; });
          if (about !== ABOUT) fail(`[${theme}/help] About text differs: ${JSON.stringify(about)}`);
        }
      }
      await ctx.close();
    }
    // Connect consent flow (docs/connect.md): link -> consent page -> Approve -> code; the app redeems it; Connected apps -> Revoke.
    {
      const ctx = await b.newContext({ viewport: { width: 1280, height: 900 } });
      await ctx.addInitScript((k) => { try { localStorage.setItem('redx.key', k); localStorage.setItem('redx.wizard.done', '1'); } catch {} }, key);
      const p = await ctx.newPage();
      let where = 'connect-flow';
      p.on('console', (m) => { if (m.type() === 'error' || m.type() === 'warning') fail(`[${where}] console ${m.type()}: ${m.text()}`); });
      p.on('pageerror', (e) => fail(`[${where}] uncaught exception: ${e.message}`));
      const verifier = crypto.randomBytes(40).toString('base64url');
      const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
      const st = crypto.randomBytes(24).toString('base64url');
      const qs = new URLSearchParams({ v: '1', provider: 'gendragoon', state: st, pkce_challenge: challenge, workspace: 'gd-ui', name: 'Gendragoon on a test phone' });
      await p.goto(`${url}/#/connect?${qs}`, { waitUntil: 'networkidle' });
      await p.waitForTimeout(300);
      const txt = await p.evaluate(() => document.querySelector('main').innerText);
      if (!/expires in \d+:\d\d/.test(txt)) fail(`[${where}] the expiry countdown is not filled at once`);
      for (const want of ['Gendragoon', 'verified', 'Workspace name', 'read and change data in this workspace only', 'see your other databases', 'manage keys', 'Approve', 'Deny']) {
        if (!txt.toLowerCase().includes(want.toLowerCase())) fail(`[${where}] consent page lacks "${want}"`);
      }
      await p.click('button.btn.primary:has-text("Approve")');
      await p.waitForSelector('.code-big', { timeout: 5000 }).catch(() => fail(`[${where}] no code after Approve`));
      const code = (await p.textContent('.code-big') || '').trim();
      if (!/^RX-[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(code)) fail(`[${where}] approve did not show a pairing code`);
      const ex = await fetch(url + '/v1/connect/exchange', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code, pkce_verifier: verifier, state: st, device_label: 'ui-test' }) });
      const exb = await ex.json();
      if (ex.status !== 200 || !exb.key || exb.workspace.db !== 'gd-ui') fail(`[${where}] exchange ${ex.status} ${exb.code || ''}`);
      where = 'apps';
      await p.goto(`${url}/#/apps`, { waitUntil: 'networkidle' });
      await p.waitForTimeout(300);
      if (!(await p.evaluate(() => document.querySelector('main').innerText)).includes('gd-ui')) fail(`[${where}] Connected apps does not list the new connection`);
      await p.click('button:has-text("Revoke")');
      await p.click('.modal button[data-id="ok"]');
      await p.waitForTimeout(500);
      if (!(await p.evaluate(() => document.querySelector('main').innerText)).includes('revoked')) fail(`[${where}] revoke not shown`);
      const after = await fetch(url + '/v1/db/gd-ui/stats', { headers: { Authorization: 'Bearer ' + exb.key } });
      if (after.status !== 401) fail(`[${where}] revoked app key still works (${after.status})`);
      await ctx.close();
    }
    await b.close();
  } finally {
    host.kill();
    await new Promise((r) => { host.once('exit', r); setTimeout(r, 3000); });
    try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }); } catch {}
  }
  console.log(failures ? `${failures} failure(s)` : `PASS: ${PAGES.length} pages x 2 themes + connect consent/revoke flow, no console errors, no exceptions, no error boxes, no external requests`);
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });

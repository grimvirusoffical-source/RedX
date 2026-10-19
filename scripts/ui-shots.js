// Take screenshots of the console in dark and light (and a phone width) against a throw-away redxd.
//   PLAYWRIGHT_CORE=/path/to/node_modules/playwright-core CHROME=/usr/bin/google-chrome \
//   node scripts/ui-shots.js <redxd binary> <redx binary> <out dir>
// Needs Node 18+, playwright-core and a Chrome/Chromium. Nothing leaves the machine; the key is a test key.
const { chromium } = require(process.env.PLAYWRIGHT_CORE || 'playwright-core');
const { spawn, execFileSync } = require('node:child_process');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), net = require('node:net');
const [,, redxd, redx, out] = process.argv;
if (!out) { console.error('usage: node scripts/ui-shots.js <redxd> <redx> <outdir>'); process.exit(2); }
fs.mkdirSync(out, { recursive: true });
const free = () => new Promise((r) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redx-shots-'));
  const port = await free(), url = `http://127.0.0.1:${port}`;
  const key = JSON.parse(execFileSync(redx, ['key', 'create', '--offline', '--data-dir', dir, '--scope', 'admin', '--db', '*', '--label', 'shots', '--json'], { stdio: ['ignore', 'pipe', 'ignore'] }).toString()).key;
  const host = spawn(redxd, ['run', '--no-open', '--data-dir', dir, '--listen', `127.0.0.1:${port}`], { stdio: ['ignore', 'ignore', process.env.SHOTS_DEBUG ? 'inherit' : 'ignore'], env: { ...process.env, REDX_NO_OPEN: '1' } });
  for (let i = 0; i < 100; i++) { try { if ((await fetch(url + '/healthz')).ok) break; } catch {} await sleep(100); }
  const env = { ...process.env, REDX_ADDR: url, REDX_KEY: key };
  const cli = (...a) => execFileSync(redx, a, { env, stdio: 'ignore' });
  cli('set', 'players.red-xai.db:Player[ID=1]', '[ {Name[]} = "Ann", {Level[]} = 7, {Class[]} = "Reaper" ]');
  cli('set', 'players.red-xai.db:Player[ID=2]', '[ {Name[]} = "Bob", {Level[]} = 30, {Class[]} = "Scythe" ]');
  cli('set', 'sessions.red-xai-db-qs:Session[ID=1].Token', '"abc"', '--ttl', '600');
  cli('key', 'create', '--db', 'default', '--scope', 'write', '--label', 'game-server');
  const b = await chromium.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', args: ['--no-sandbox'] });
  const pages = ['dashboard', 'databases', 'data', 'studio', 'keys', 'devices', 'presets', 'settings', 'help'];
  for (const theme of ['dark', 'light']) {
    for (const [tag, vp] of [['', { width: 1366, height: 860 }], ['-mobile', { width: 390, height: 844 }]]) {
      if (tag && theme === 'light' && false) continue;
      const ctx = await b.newContext({ viewport: vp, colorScheme: theme });
      await ctx.addInitScript(([k, t]) => { try { localStorage.setItem('redx.key', k); localStorage.setItem('redx.theme', t); localStorage.setItem('redx.mode', 'advanced'); localStorage.setItem('redx.wizard.done', '1'); } catch {} }, [key, theme]);
      const p = await ctx.newPage();
      for (const pg of tag ? ['dashboard', 'data', 'studio'] : pages) {
        await p.goto(`${url}/#/${pg}`, { waitUntil: 'networkidle' });
        await p.waitForTimeout(500);
        await p.screenshot({ path: path.join(out, `${pg}-${theme}${tag}.png`) });
      }
      await ctx.close();
    }
  }
  // signed-out login page, and the System option following the device colour scheme
  for (const [name, scheme, pref] of [['login-dark', 'dark', 'dark'], ['login-light', 'light', 'light'], ['system-follows-light', 'light', 'system'], ['system-follows-dark', 'dark', 'system']]) {
    const ctx = await b.newContext({ viewport: { width: 1100, height: 760 }, colorScheme: scheme });
    await ctx.addInitScript((t) => { try { localStorage.setItem('redx.theme', t); } catch {} }, pref);
    const p = await ctx.newPage();
    await p.goto(url + '/', { waitUntil: 'networkidle' });
    await p.waitForTimeout(400);
    await p.screenshot({ path: path.join(out, `${name}.png`) });
    console.log(name, 'data-theme =', await p.evaluate(() => document.documentElement.dataset.theme), 'pref =', await p.evaluate(() => document.documentElement.dataset.themePref));
    await ctx.close();
  }
  // pairing: a one-time code from a QR link signs a fresh browser in; the link cannot be reused and holds no key
  {
    const r = await fetch(url + '/v1/keys/pairing', { method: 'POST', headers: { Authorization: 'Bearer ' + key, 'X-RedX-Confirm': 'createPairingCode' }, body: JSON.stringify({ db: 'default', scope: 'write', label: 'shots-phone' }) });
    const { code } = await r.json();
    const ctx = await b.newContext({ viewport: { width: 390, height: 844 }, colorScheme: 'dark' });
    const p = await ctx.newPage();
    await p.goto(`${url}/#/login?code=${code}`, { waitUntil: 'networkidle' });
    await p.waitForTimeout(800);
    const signedIn = await p.evaluate(() => !!document.querySelector('.shell'));
    const hash = await p.evaluate(() => location.hash + location.search);
    await p.screenshot({ path: path.join(out, 'paired-phone-dark.png') });
    const ctx2 = await b.newContext({ viewport: { width: 390, height: 844 } });
    const p2 = await ctx2.newPage();
    await p2.goto(`${url}/#/login?code=${code}`, { waitUntil: 'networkidle' });
    await p2.waitForTimeout(500);
    const reused = await p2.evaluate(() => !!document.querySelector('.shell'));
    console.log('pairing: signed in =', signedIn, '| code left in URL =', JSON.stringify(hash), '| reuse signed in =', reused);
    if (!signedIn || reused) process.exitCode = 1;
  }
  await b.close();
  host.kill();
  await new Promise((r) => { host.once('exit', r); setTimeout(r, 3000); });
  try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }); } catch {}
  console.log('screenshots in', out);
})().catch((e) => { console.error(e); process.exit(1); });

'use strict';
// Starts a real redxd on a free local port with a throwaway data dir.
// The bootstrap admin key is captured from redxd's stdout and never printed;
// every other key is created through the API during the run.

const { spawn, execFileSync } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const REPO = path.resolve(__dirname, '..', '..', '..');

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
    s.on('error', reject);
  });
}

async function startHost() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'redx-sdk-js-'));
  let bin = process.env.REDXD_BIN;
  if (!bin) {
    bin = path.join(tmp, 'redxd');
    execFileSync('go', ['build', '-o', bin, './cmd/redxd'], { cwd: REPO, stdio: 'inherit' });
  }
  const port = await freePort();
  const dataDir = path.join(tmp, 'data');
  // minimal environment: no inherited REDX_* settings or keys
  const env = { PATH: process.env.PATH, HOME: tmp };
  let child;
  let out = '';
  let adminKey = null;
  const url = `http://127.0.0.1:${port}`;
  const spawnHost = () => {
    child = spawn(bin, ['run', '--no-open', '--bootstrap', 'console', '--data-dir', dataDir, '--listen', `127.0.0.1:${port}`], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', (d) => {
      out += d;
      if (!adminKey) { const m = /rx_live_[A-Za-z0-9]{43}/.exec(out); if (m) adminKey = m[0]; }
      if (out.length > 20000) out = out.slice(-5000);
    });
    child.stderr.on('data', () => {});
  };
  const kill = async () => {
    if (child.exitCode === null) {
      child.kill('SIGKILL');
      await new Promise((r) => child.once('exit', r));
    }
  };
  const stop = async () => { await kill(); fs.rmSync(tmp, { recursive: true, force: true }); };
  const ready = async () => {
    for (let i = 0; ; i++) {
      if (child.exitCode !== null) throw new Error('redxd exited early');
      try { const r = await fetch(url + '/healthz'); if (r.ok && adminKey) break; } catch { /* not up yet */ }
      if (i > 200) throw new Error('redxd did not become ready');
      await new Promise((r) => setTimeout(r, 50));
    }
  };
  spawnHost();
  try { await ready(); } catch (e) { await stop(); throw e; }
  // restart: kill the host, wait downMs, start it again on the same port and data (to test reconnects)
  const restart = async (downMs = 300) => { await kill(); await new Promise((r) => setTimeout(r, downMs)); spawnHost(); await ready(); };
  return { url, adminKey, stop, restart, dataDir };
}

module.exports = { startHost };

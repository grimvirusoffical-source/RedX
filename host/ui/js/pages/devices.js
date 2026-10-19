import { h, icon, terminalPanel, chip, mount, toast, dialog, field, copy, download, errorBox, spinner, emptyState } from '../util.js';
import { api, enc } from '../api.js';
import { state, isHostAdmin, loadDbs } from '../state.js';
import { pageHead, page } from './shared.js';
import { drawQR } from '../qr.js';
import { makeZip } from '../zip.js';

const isLocalName = (u) => { try { return /^(localhost|127\.|\[?::1)/.test(new URL(u).hostname); } catch { return false; } };

export default async function render() {
  const root = page();
  if (!isHostAdmin()) {
    root.append(pageHead('Add a device'), h('div', { class: 'callout info' }, icon('info'), h('div', null, 'Adding devices needs a host admin key.')));
    return root;
  }
  let status = null;
  let cluster = null;
  try { [status, cluster] = await Promise.all([api('GET', '/v1/admin/status'), api('GET', '/v1/cluster/status')]); } catch (e) { root.append(errorBox(e.message)); return root; }
  const leader = cluster.role === 'leader';
  let tab = 'node';
  const tabs = h('div', { class: 'tabs', role: 'tablist' });
  const body = h('div');
  const TABS = [['node', 'Add a node'], ['phone', 'Phone or browser'], ['install', 'Install commands'], ['ios', 'iPhone & iPad']];
  const paintTabs = () => mount(tabs, TABS.map(([k, l]) => h('button', { class: 'tab' + (tab === k ? ' on' : ''), role: 'tab', 'aria-selected': String(tab === k), onclick: () => { tab = k; paintTabs(); paintBody(); } }, l)));
  root.append(pageHead('Add a device', 'Connect another computer, a Raspberry Pi or a phone. No terminal needed on this side.'), tabs, body,
    terminalPanel([{ label: 'On the new computer', cmd: 'redxd join "https://<this-host>:7777/#/join?c=RX-XXXXX-XXXXX&pin=<fingerprint>"' }, { label: 'Make a token on this host', cmd: 'redx node token' }, { label: 'Join with a token', cmd: 'redx node join http://leader:7777 --token rxj_...' }]));

  let addr = location.origin;
  let code = null; // {code, expires}
  let tick;
  const link = () => `${addr.replace(/\/$/, '')}/#/join?c=${code.code}${status.tls_fingerprint ? '&pin=' + status.tls_fingerprint : ''}`;

  function nodeTab() {
    const addrIn = h('input', { class: 'input', value: addr, 'aria-label': 'Address of this host', oninput: (e) => { addr = e.target.value; if (code) paintCode(); warn(); } });
    const warnEl = h('div');
    const out = h('div');
    const warn = () => mount(warnEl, isLocalName(addr) ? h('div', { class: 'callout warn' }, icon('alert'), h('div', null, h('b', null, 'Other devices cannot reach ' + addr + '. '), 'That address only works on this computer. Enter this machine\'s LAN address (for example ', h('code', null, 'http://192.168.1.20:7777'), '). Also start RedX listening on the network, for example with the Server preset or ', h('code', null, 'listen = "0.0.0.0:7777"'), '.')) : status.scheme === 'http' && !/^http:\/\/(localhost|127|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(addr) ? h('div', { class: 'callout warn' }, icon('alert'), h('div', null, 'This address is not private and uses plain HTTP. Turn on TLS (', h('code', null, 'tls = "auto"'), ') before pairing over the internet.')) : null);
    warn();
    const make = async () => {
      try {
        const r = await api('POST', '/v1/cluster/join-token', { json: { kind: 'code', ttl_seconds: 600 }, confirm: 'createJoinToken' });
        code = { code: r.code, expires: Date.now() + r.expires_in_seconds * 1000 };
        paintCode();
      } catch (e) { toast(e.status === 409 ? 'Only the leader can create join codes. Open the console on the leader.' : e.message, 'error', 6000); }
    };
    function paintCode() {
      clearInterval(tick);
      if (!code) return mount(out);
      const canvas = h('canvas', { class: 'qr-box', 'aria-label': 'QR code of the join link' });
      const left = h('b');
      const L = link();
      mount(out, h('div', { class: 'card', style: { marginTop: '14px' } }, h('div', { class: 'grid g2' },
        h('div', { class: 'center' }, canvas, h('p', { class: 'muted small' }, 'Scan with the camera of a phone, or paste the link on the new computer.')),
        h('div', null, h('div', { class: 'muted small' }, 'Pairing code'), h('div', { class: 'code-big' }, code.code),
          h('p', null, 'Valid for ', left, '. Works once, and only to join this cluster (it cannot read your data or make keys).'),
          h('div', { class: 'row gap wrap' }, h('button', { class: 'btn', onclick: () => copy(code.code, 'Code copied') }, icon('copy', 15), ' Copy code'), h('button', { class: 'btn', onclick: () => copy(L, 'Link copied') }, icon('link', 15), ' Copy link'), h('button', { class: 'btn', onclick: make }, icon('refresh', 15), ' New code')),
          h('h4', null, 'On the new computer'), h('div', { class: 'term-cmd' }, h('pre', null, `redxd join "${L}"`), h('button', { class: 'icon-btn', 'aria-label': 'Copy command', onclick: () => copy(`redxd join "${L}"`, 'Command copied') }, icon('copy', 15))),
          h('p', { class: 'muted small' }, status.tls_fingerprint ? 'The link includes this host\'s certificate fingerprint, so the new node trusts exactly this host.' : 'This host uses plain HTTP, so no certificate is pinned.'))),
        h('hr'), h('div', { class: 'row gap wrap' }, h('button', { class: 'btn', onclick: bundle }, icon('download', 15), ' Download config bundle (.zip)'), h('span', { class: 'muted small' }, 'A ready redx.toml with the join link, plus a README. The code inside expires with the pairing code.'))));
      drawQR(canvas, L, { scale: 5, level: 'M' });
      const upd = () => {
        const s = Math.max(0, Math.round((code.expires - Date.now()) / 1000));
        left.textContent = Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
        if (s === 0) { clearInterval(tick); left.textContent = 'expired'; left.className = 'err-text'; }
      };
      upd();
      tick = setInterval(upd, 1000);
    }
    function bundle() {
      const L = link();
      const toml = `# RedX node config created by the Add a device page.\n# Put this file next to redxd, then run:  redxd run --config redx.toml\n# The join link works once and expires; after the node has joined it is ignored.\nrole = "follower"\nlisten = "0.0.0.0:7777"\ndata_dir = "./redx-data"\njoin = "${L}"\n# advertise = "http://THIS-DEVICE-LAN-IP:7777"   # how other nodes reach this one\n`;
      const readme = `RedX node bundle\n================\n\n1. Unpack the RedX release for this computer (redxd and redx).\n2. Put redx.toml from this bundle in the same folder.\n3. Run:  redxd run --config redx.toml\n   (or:  redxd join "${L}" )\n\nThe join code is single-use and expires about 10 minutes after it was made. If it has expired,\nopen "Add a device" on the leader and make a new one.\nLeader: ${addr}\n`;
      download('redx-node-bundle.zip', makeZip([{ name: 'redx.toml', text: toml }, { name: 'README.txt', text: readme }]), 'application/zip');
    }
    return h('div', null,
      !leader ? h('div', { class: 'callout warn' }, icon('alert'), h('div', null, 'This node is a follower. Join codes are issued by the leader (', h('code', null, cluster.leader_url || 'unknown'), '). Open the console there.')) : null,
      h('p', null, 'A ', h('b', null, 'node'), ' is another computer that keeps a live copy of this database and can take over if this one goes away. Pair it with a one-time code.'),
      field('Address other devices use to reach this host', addrIn, 'Listening on ' + status.listen + ' (' + status.scheme + ').'), warnEl,
      h('button', { class: 'btn primary', disabled: !leader, onclick: make }, icon('qr', 16), code ? ' Make a new pairing code' : ' Make a pairing code'), out);
  }

  function phoneTab() {
    const label = h('input', { class: 'input', value: 'my-phone', maxlength: 40 });
    const scope = h('select', { class: 'select' }, [['read', 'Read only'], ['write', 'Read and write'], ['admin', 'Admin']].map(([v, l]) => h('option', { value: v, selected: v === 'write' }, l)));
    const db = h('select', { class: 'select' }, state.dbs.map((d) => h('option', { value: d, selected: d === state.db }, d)));
    const ttl = h('select', { class: 'select' }, [['24h', '1 day'], ['7d', '7 days'], ['30d', '30 days'], ['', 'Never']].map(([v, l]) => h('option', { value: v, selected: v === '7d' }, l)));
    const out = h('div');
    let tick2;
    const make = async () => {
      clearInterval(tick2);
      try {
        const r = await api('POST', '/v1/keys/pairing', { json: { db: db.value, scope: scope.value, label: label.value || 'device', ttl: ttl.value }, confirm: 'createPairingCode' });
        const L = `${addr.replace(/\/$/, '')}/#/login?code=${r.code}`;
        const expires = Date.now() + r.expires_in_seconds * 1000;
        const canvas = h('canvas', { class: 'qr-box', 'aria-label': 'QR code of the one-time sign-in link' });
        const left = h('b');
        mount(out, h('div', { class: 'card', style: { marginTop: '14px' } },
          h('div', { class: 'callout info' }, icon('info'), h('div', null, 'This QR code holds a ', h('b', null, 'one-time pairing code'), ', not your key. It works once and expires in 5 minutes; the key is created on the new device when it is used.')),
          h('div', { class: 'grid g2' },
            h('div', { class: 'center' }, canvas, h('p', { class: 'muted small' }, 'Scan with the phone camera.')),
            h('div', null, h('div', { class: 'muted small' }, 'Or type this code on the sign-in page'), h('div', { class: 'code-big' }, r.code),
              h('p', null, 'Valid for ', left, '.'),
              h('div', { class: 'row gap wrap' }, h('button', { class: 'btn', onclick: () => copy(r.code, 'Code copied') }, icon('copy', 15), ' Copy code'), h('button', { class: 'btn', onclick: () => copy(L, 'Link copied') }, icon('link', 15), ' Copy link'), h('button', { class: 'btn', onclick: make }, icon('refresh', 15), ' New code'))))));
        drawQR(canvas, L, { scale: 5 });
        const upd = () => {
          const s = Math.max(0, Math.round((expires - Date.now()) / 1000));
          left.textContent = s === 0 ? 'expired' : Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
          if (s === 0) { clearInterval(tick2); left.className = 'err-text'; }
        };
        upd();
        tick2 = setInterval(upd, 1000);
      } catch (e) { toast(e.status === 409 ? 'Pairing codes are made on the leader. Open the console there.' : e.message, 'error', 6000); }
    };
    return h('div', null, h('p', null, 'Sign in to this console from a phone or another computer\'s browser with its own limited key, using a one-time pairing code. The key can be revoked any time on the API Keys page.'),
      isLocalName(addr) ? h('div', { class: 'callout warn' }, icon('alert'), h('div', null, 'The phone cannot open ', h('code', null, addr), '. Set the LAN address on the "Add a node" tab first.')) : null,
      h('div', { class: 'grid g2' }, field('Name', label), field('Database', db), field('Access', scope), field('Expires', ttl)),
      h('button', { class: 'btn primary', onclick: make }, icon('qr', 16), ' Make a sign-in QR (one-time code)'), out);
  }

  function installTab() {
    const ver = status.version;
    const L = code ? link() : 'https://<this-host>:7777/#/join?c=RX-XXXXX-XXXXX';
    const mk = (os, arch, ext) => `redx-${ver}-${os}-${arch}.${ext}`;
    const rows = [
      ['Windows (PowerShell)', `Expand-Archive .\\${mk('windows', 'amd64', 'zip')} -DestinationPath .; cd .\\redx-${ver}-windows-amd64; .\\redxd.exe join "${L}"`, 'Use windows-arm64 on ARM laptops.'],
      ['macOS (Terminal)', `tar xzf ${mk('darwin', 'arm64', 'tar.gz')} && cd redx-${ver}-darwin-arm64 && ./redxd join '${L}'`, 'Intel Macs: darwin-amd64. The first run may need right-click → Open in Finder, or: xattr -dr com.apple.quarantine .'],
      ['Linux', `tar xzf ${mk('linux', 'amd64', 'tar.gz')} && cd redx-${ver}-linux-amd64 && ./redxd join '${L}'`, 'ARM servers: linux-arm64.'],
      ['Raspberry Pi', `tar xzf ${mk('linux', 'arm64', 'tar.gz')} && cd redx-${ver}-linux-arm64 && ./redxd join '${L}'`, 'Pi 3, 4, 5 with 64-bit Raspberry Pi OS use linux-arm64. A 32-bit OS needs linux-armv7.'],
      ['Docker', `docker run -d --name redx-node -p 7777:7777 -v redx-data:/data -e REDX_LISTEN=0.0.0.0:7777 -e REDX_JOIN='${L}' redx:${ver}`, 'Build the image once from the release: docker build -f deploy/docker/Dockerfile -t redx:' + ver + ' .'],
    ];
    return h('div', null,
      h('div', { class: 'callout info' }, icon('info'), h('div', null, 'These commands are optional shortcuts. RedX is not downloaded from the internet by this console: the archives are the release files (', h('code', null, 'redx-' + ver + '-<os>-<arch>'), ') you built or received. Copy the right archive to the new device first.')),
      !code ? h('div', { class: 'callout warn' }, icon('alert'), h('div', null, 'Make a pairing code on the "Add a node" tab first and these commands fill in the real link.')) : null,
      rows.map(([t, c, note]) => h('div', { class: 'card', style: { marginTop: '12px' } }, h('h4', { style: { margin: 0 } }, t), h('div', { class: 'term-cmd' }, h('pre', null, c), h('button', { class: 'icon-btn', 'aria-label': 'Copy command', onclick: () => copy(c, 'Command copied') }, icon('copy', 15))), h('p', { class: 'muted small' }, note))));
  }

  function iosTab() {
    const url = location.origin;
    return h('div', null,
      h('p', null, 'An iPhone or iPad cannot run a RedX node (there is no iOS build of redxd). It can use this console as an app on the home screen:'),
      h('ol', { class: 'olsteps' },
        h('li', null, 'Open ', h('code', null, url), ' in ', h('b', null, 'Safari'), ' on the device. (Make sure it is the LAN address of this host, not 127.0.0.1.)'),
        h('li', null, 'Tap the ', h('b', null, 'Share'), ' button, then ', h('b', null, 'Add to Home Screen'), '.'),
        h('li', null, 'Open the new RedX icon and sign in with a key (use the "Phone or browser" tab to make a one-time pairing code).')),
      h('div', { class: 'callout warn' }, icon('alert'), h('div', null, 'Safari only installs web apps and allows service workers on ', h('b', null, 'HTTPS'), ' (or localhost). Over plain HTTP you can still use the console in the browser, but "Add to Home Screen" gives a plain bookmark and the offline shell will not work. Turn on TLS (', h('code', null, 'tls = "auto"'), ') and trust the certificate on the device.')));
  }
  function paintBody() { clearInterval(tick); mount(body, tab === 'node' ? nodeTab() : tab === 'phone' ? phoneTab() : tab === 'install' ? installTab() : iosTab()); }
  paintTabs();
  paintBody();
  await loadDbs();
  return { el: root, destroy() { clearInterval(tick); } };
}

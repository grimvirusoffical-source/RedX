import { h, icon, terminalPanel, chip, mount, toast, errorBox, spinner, fmtBytes, copy } from '../util.js';
import { api, session } from '../api.js';
import { state, isHostAdmin } from '../state.js';
import { pageHead, page, listFiles } from './shared.js';

export default async function render() {
  const root = page();
  if (!isHostAdmin()) { root.append(pageHead('Backups'), h('div', { class: 'callout info' }, icon('info'), h('div', null, 'Backups need a host admin key.'))); return root; }
  const st = await api('GET', '/v1/admin/status').catch(() => null);
  const out = h('div');
  const btn = h('button', { class: 'btn primary', onclick: backup }, icon('download', 16), ' Download a backup now');
  async function backup() {
    btn.disabled = true;
    mount(out, spinner('Making a consistent snapshot…'));
    try {
      const res = await api('GET', '/v1/admin/backup', { raw: true });
      if (!res.ok) throw new Error((await res.text()) || res.statusText);
      const blob = await res.blob();
      const cd = res.headers.get('Content-Disposition') || '';
      const name = (/filename="?([^";]+)/.exec(cd) || [])[1] || 'redx-backup-' + new Date().toISOString().replace(/[:.]/g, '-') + '.tgz';
      const a = h('a', { href: URL.createObjectURL(blob), download: name });
      document.body.append(a);
      a.click();
      setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 2000);
      mount(out, h('div', { class: 'callout ok' }, icon('check'), h('div', null, h('b', null, 'Backup downloaded: '), name, ' (' + fmtBytes(blob.size) + ')')));
      toast('Backup downloaded', 'ok');
    } catch (e) { mount(out, errorBox(e.message, backup)); } finally { btn.disabled = false; }
  }
  root.append(pageHead('Backups', 'A backup is one file with every database and the API keys. Keep it somewhere safe.', btn), out,
    h('div', { class: 'grid g2', style: { marginTop: '16px' } },
      h('div', { class: 'card' }, h('h3', null, 'What is in a backup'), h('ul', null, h('li', null, 'All databases and their files'), h('li', null, 'API key records (hashed, never the keys themselves)'), h('li', null, 'Record expiry (TTL) timers'), h('li', null, 'Not included: the config file, TLS certificates, and the keystore passphrase or master key. Store those separately.'))),
      h('div', { class: 'card' }, h('h3', null, 'Data on this host'), st ? h('div', null, h('p', null, h('b', null, fmtBytes(st.data_bytes)), ' in ', h('code', null, st.data_dir)), h('p', { class: 'muted small' }, 'Free disk space is not shown (the host does not report it). Check it before large backups.')) : null)),
    h('div', { class: 'card', style: { marginTop: '16px' } }, h('h3', null, 'Restoring'), h('p', null, 'Restoring replaces a data directory, so it is done on the machine, with the host stopped. This console does not restore for you.'),
      h('ol', { class: 'olsteps' }, h('li', null, 'Stop redxd.'), h('li', null, 'Run the restore command below (add ', h('code', null, '--force'), ' if databases already exist: they are moved aside, not deleted).'), h('li', null, 'Start redxd again and check the Dashboard.'))),
    terminalPanel([{ label: 'Online backup (host running)', cmd: 'redx backup --out redx-backup.tgz' }, { label: 'Offline backup (host stopped)', cmd: 'redx backup --out redx-backup.tgz --offline' }, { label: 'Restore (host stopped)', cmd: 'redx restore redx-backup.tgz' }, { label: 'curl', cmd: 'curl -H "Authorization: Bearer $REDX_KEY" -o redx-backup.tgz ' + location.origin + '/v1/admin/backup' }]));
  return root;
}

import { h, icon, terminalPanel, chip, mount, toast, dialog, field, copy, errorBox, spinner, confirmTyped, ago, table, fmtTime } from '../util.js';
import { api } from '../api.js';
import { isHostAdmin } from '../state.js';
import { pageHead, page } from './shared.js';

export default async function render() {
  const root = page();
  if (!isHostAdmin()) { root.append(pageHead('Cluster & nodes'), h('div', { class: 'callout info' }, icon('info'), h('div', null, 'This page needs a host admin key.'))); return root; }
  const box = h('div');
  root.append(pageHead('Cluster & nodes', 'One leader takes writes; followers keep an async copy and can be promoted.', h('a', { class: 'btn primary', href: '#/devices' }, icon('plus', 16), ' Add a node')), box,
    terminalPanel([{ label: 'Status', cmd: 'redx node status' }, { label: 'Make a join token', cmd: 'redx node token' }, { label: 'Promote this follower', cmd: 'redx node promote' }, { label: 'Point this follower at a new leader', cmd: 'redx node repoint http://new-leader:7777 --token rxj_...' }]));
  let timer;
  async function load(first) {
    try {
      const c = await api('GET', '/v1/cluster/status');
      const leader = c.role === 'leader';
      mount(box,
        h('div', { class: 'grid g4' }, stat('This node', c.node_id), stat('Role', c.role, leader ? 'accepts writes' : 'read-only copy'), stat('Offset', String(c.offset), 'oldest kept: ' + c.first_offset), stat('Last sync', c.last_sync ? ago(c.last_sync) : leader ? 'n/a' : 'never', c.snapshots_installed ? c.snapshots_installed + ' snapshot(s) installed' : '')),
        c.last_error ? h('div', { class: 'callout err' }, icon('alert'), h('div', null, h('b', null, 'Last replication error: '), c.last_error)) : null,
        !leader ? h('div', { class: 'card', style: { marginTop: '14px' } }, h('p', null, 'Following ', h('code', null, c.leader_url || '(unknown)'), '.'), h('button', { class: 'btn danger', onclick: () => promote(c) }, icon('alert', 15), ' Promote this node to leader…')) : null,
        h('h2', null, leader ? 'Followers' : 'Known members'),
        c.members && c.members.length ? table(['Node', 'Address', 'Health', 'Lag', 'Acked', 'Last seen'], c.members.map((m) => h('tr', null, h('td', null, h('b', null, m.id), ' ', chip(m.role)), h('td', { class: 'mono small' }, m.addr || '–'), h('td', null, chip(m.healthy ? 'healthy' : 'behind', m.healthy ? 'ok' : 'warn')), h('td', { class: 'num' }, String(m.lag)), h('td', { class: 'num' }, String(m.acked)), h('td', { class: 'muted' }, ago(m.last_seen))))) : h('div', { class: 'empty' }, h('p', { class: 'muted' }, leader ? 'No followers yet. Use "Add a node" to pair one.' : 'No members known.')),
        h('div', { class: 'callout info', style: { marginTop: '14px' } }, icon('info'), h('div', null, 'Replication is asynchronous: a write is acknowledged before every follower has it. Promoting a follower can lose writes the old leader had not yet sent.')));
    } catch (e) { if (first) mount(box, errorBox(e.message, () => load(true))); }
  }
  function stat(k, v, s) { return h('div', { class: 'card stat' }, h('div', { class: 'k' }, k), h('div', { class: 'v' }, v), s ? h('div', { class: 's' }, s) : null); }
  async function promote(c) {
    const ok = await confirmTyped('Promote this node to leader?', 'The old leader may still be running. If it is, two leaders will accept writes and their data will diverge. Writes the old leader acknowledged but had not yet replicated are lost. Only promote after you are sure the old leader is down or cut off. Other followers must then be pointed at this node.', 'promote', 'Promote to leader');
    if (!ok) return;
    try { const r = await api('POST', '/v1/cluster/promote'); toast('Promoted. ' + (r.note || ''), 'ok', 9000); load(); } catch (e) { toast(e.message, 'error', 7000); }
  }
  await load(true);
  timer = setInterval(load, 4000);
  return { el: root, destroy() { clearInterval(timer); } };
}

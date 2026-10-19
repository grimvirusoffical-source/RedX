import { h, icon, terminalPanel, chip, mount, toast, emptyState, copy, download } from '../util.js';
import { wsURL, enc } from '../api.js';
import { state } from '../state.js';
import { pageHead, page, listFiles } from './shared.js';
import { createEditor } from '../editor.js';
import { fileStem } from '../state.js';

const MAX = 500;

export default async function render() {
  const db = state.db;
  const root = page();
  let ws = null;
  let paused = false;
  let missed = 0;
  let shouldRun = false;
  let retry = 0;
  let timer;
  const events = [];
  let files = [];
  try { files = (await listFiles(db)).files.filter((f) => f.records === 'records'); } catch { /* limited key */ }
  const pre = sessionStorage.getItem('redx.watch.q');
  sessionStorage.removeItem('redx.watch.q');
  const first = files[0];
  const init = pre || (first ? `{Watch[]} = ${fileStem(first.name)}:*[ID=*]` : '{Watch[]} = players:Player[ID=*]');
  const editor = createEditor({ language: 'boxql', value: init, height: '96px', onRun: start });
  const stat = h('span');
  const list = h('div', { class: 'events', role: 'log', 'aria-live': 'polite' });
  const pauseBtn = h('button', { class: 'btn', onclick: togglePause }, icon('pause', 16), ' Pause');
  const startBtn = h('button', { class: 'btn primary', onclick: () => (shouldRun ? stop() : start()) }, icon('play', 16), ' Start');

  const setStat = (txt, kind) => mount(stat, chip(txt, kind));
  function togglePause() {
    paused = !paused;
    mount(pauseBtn, paused ? icon('play', 16) : icon('pause', 16), paused ? ' Resume' : ' Pause');
    if (!paused && missed) { toast(missed + ' event(s) arrived while paused (not shown)', 'info'); missed = 0; }
  }
  function start() {
    stop(true);
    const text = editor.getValue().trim();
    if (!text) return;
    let qtext = text;
    if (!/^\s*(<<[\s\S]*?>>\s*)*\{/.test(text)) qtext = `{Watch[]} = Topic = ${JSON.stringify(text)}`; // a bare topic name
    shouldRun = true;
    mount(startBtn, icon('stop', 16), ' Stop');
    connect(qtext);
  }
  function connect(qtext) {
    setStat('connecting…', 'warn');
    let opened = false;
    ws = new WebSocket(wsURL(`/v1/db/${enc(db)}/bx/watch`, { q: qtext }));
    ws.onopen = () => { opened = true; retry = 0; setStat('live', 'ok'); };
    ws.onmessage = (m) => {
      if (paused) { missed++; return; }
      let v;
      try { v = JSON.parse(m.data); } catch { v = { raw: m.data }; }
      events.unshift({ t: new Date(), v });
      if (events.length > MAX) events.pop();
      paint();
    };
    ws.onclose = () => {
      if (!shouldRun) { setStat('stopped', ''); return; }
      if (!opened && retry >= 2) { shouldRun = false; mount(startBtn, icon('play', 16), ' Start'); setStat('could not connect', 'err'); toast('Could not start the watch. Check the command and that your key may read ' + db + '.', 'error', 7000); return; }
      retry++;
      setStat('reconnecting…', 'warn');
      timer = setTimeout(() => shouldRun && connect(qtext), Math.min(8000, 800 * retry));
    };
    ws.onerror = () => { /* onclose follows */ };
  }
  function stop(quiet) {
    shouldRun = false;
    clearTimeout(timer);
    if (ws) { ws.onclose = null; ws.close(); ws = null; }
    mount(startBtn, icon('play', 16), ' Start');
    if (!quiet) setStat('stopped', '');
  }
  function paint() {
    if (!events.length) return mount(list, emptyState('pulse', shouldRun ? 'Waiting for changes…' : 'Not watching yet', shouldRun ? 'Change a record in another tab or from your app. It shows up here instantly.' : 'Press Start. Events appear here as records change.'));
    mount(list, events.slice(0, 200).map((e) => {
      const v = e.v;
      const op = v.op || v.event || v.kind || 'event';
      const where = v.path || v.topic || '';
      return h('details', { class: 'ev' }, h('summary', null, h('span', { class: 'muted mono' }, e.t.toLocaleTimeString()), chip(String(op), op === 'del' || op === 'delete' ? 'err' : op === 'set' ? 'acc' : ''), h('code', null, where)), h('pre', { class: 'code-block' }, JSON.stringify(v, null, 2)));
    }));
  }
  root.append(pageHead('Live Watch', 'See changes as they happen, over a WebSocket.', stat),
    h('div', { class: 'card' }, editor.el, h('div', { class: 'row gap wrap', style: { marginTop: '10px' } }, startBtn, pauseBtn,
      h('button', { class: 'btn', onclick: () => { events.length = 0; missed = 0; paint(); } }, icon('trash', 16), ' Clear'),
      h('button', { class: 'btn', onclick: () => download('watch-events.json', JSON.stringify(events.map((e) => ({ at: e.t, ...e.v })), null, 2), 'application/json') }, 'Download'),
      h('div', { class: 'grow' }), h('span', { class: 'muted small' }, 'Database: ', h('b', null, db), '. A bare name (no braces) watches a pulse topic.'))),
    h('div', { style: { marginTop: '14px' } }, list),
    terminalPanel([{ label: 'Watch from the terminal', cmd: "redx bx '{Watch[]} = players:Player[ID=*]'" }, { label: 'Any WebSocket client', cmd: `websocat "${location.origin.replace(/^http/, 'ws')}/v1/db/${db}/bx/watch?q=..." -H "Authorization: Bearer $REDX_KEY"` }]));
  paint();
  return { el: root, destroy: () => stop(true) };
}

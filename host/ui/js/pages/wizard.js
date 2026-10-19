import { h, icon, chip, mount, toast, field, copy, spinner, emptyState } from '../util.js';
import { api, enc, pathURL } from '../api.js';
import { state, loadDbs, setDb, gs, wizard, ID_RE, isHostAdmin, setMode } from '../state.js';
import { page } from './shared.js';
import { loadPresets, applyPreset } from './presets.js';
import { navigate } from '../main.js';

const TEMPLATES = [
  { id: 'game', title: 'Game saves', ico: 'rocket', file: 'saves.red-xai.db', box: 'Save', blurb: 'Player progress that must never be lost.', ttl: 0,
    seeds: [['[ {Player[]} = "ann", {Level[]} = 3, {Gold[]} = 120 ]', 1], ['[ {Player[]} = "bob", {Level[]} = 7, {Gold[]} = 940 ]', 2]],
    query: '{Get[]} = "saves.red-xai.db":Save[Level >= 3] -> *, Sort = -Level', what: 'A durable file. Each record is one save. Fast to read and safe on disk.' },
  { id: 'sessions', title: 'Sessions cache', ico: 'clock', file: 'sessions.red-xai-db-qs', box: 'Session', blurb: 'Logins and temporary data that clean themselves up.', ttl: 3600,
    seeds: [['[ {User[]} = "ann", {Device[]} = "laptop" ]', 1]],
    query: '{Get[]} = "sessions.red-xai-db-qs":Session[ID=*] -> *', what: 'A quick store kept in memory. Every record expires on its own (1 hour here).' },
  { id: 'notes', title: 'Notes', ico: 'edit', file: 'notes.red-xai.db', box: 'Note', blurb: 'Documents, posts, anything with text.', ttl: 0,
    seeds: [['[ {Title[]} = "Welcome", {Body[]} = "Your first note." ]', 1], ['[ {Title[]} = "Ideas", {Body[]} = "Try a BoxQL search with has." ]', 2]],
    query: '{Get[]} = "notes.red-xai.db":Note[Body has "note"] -> [Title]', what: 'A durable file with text fields you can search.' },
  { id: 'empty', title: 'Empty', ico: 'file', file: '', box: '', blurb: 'Start from nothing and add your own files.', ttl: 0, seeds: [], query: '', what: 'Just the database folder. Files appear when you write records.' },
];
const PROFILES = [['', 'Skip: keep the current settings'], ['dev', 'Dev / laptop: just me, on this computer'], ['server', 'Server: other computers will use it'], ['app', 'App: back end for an app'], ['website', 'Website'], ['game', 'Game'], ['edge', 'Edge / Pi / IoT (follower)']];

export default async function render() {
  const root = page();
  const S = { step: 0, name: '', tpl: 'game', seed: true, profile: '', adv: state.mode === 'advanced' };
  if (!isHostAdmin()) {
    root.append(h('div', { class: 'callout info' }, icon('info'), h('div', null, 'The setup wizard needs a host admin key. You can still use the ', h('a', { href: '#/data' }, 'Data Explorer'), ' and the ', h('a', { href: '#/studio' }, 'BoxQL Studio'), '.')));
    return root;
  }
  const body = h('div');
  const steps = h('div', { class: 'wsteps', role: 'list' });
  const nav = h('div', { class: 'row gap', style: { marginTop: '18px' } });
  const NAMES = ['Name', 'Template', 'Where it runs', 'Review'];
  root.append(h('div', { class: 'wizard' }, h('h1', null, 'Set up your first database'), h('p', { class: 'muted' }, 'Four quick steps. You can change everything later.'), steps, h('div', { class: 'card wcard' }, body, nav)));

  const paintSteps = () => mount(steps, NAMES.map((n, i) => h('div', { class: 'wstep' + (i === S.step ? ' on' : i < S.step ? ' done' : ''), role: 'listitem' }, h('span', { class: 'n' }, i < S.step ? icon('check', 13) : String(i + 1)), n)));
  const tpl = () => TEMPLATES.find((t) => t.id === S.tpl);

  function paint() {
    paintSteps();
    if (S.step === 0) {
      const input = h('input', { class: 'input big', value: S.name, placeholder: 'my-app', maxlength: 63, autocomplete: 'off', 'aria-label': 'Database name', oninput: (e) => { S.name = e.target.value.trim(); err.hidden = true; } });
      const err = h('div', { class: 'form-err', hidden: true });
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter') next(); });
      mount(body, h('h2', null, 'Name your database'), h('p', { class: 'muted' }, 'One database per app or project. Use lower-case letters, digits, "-" and "_".'), input, err, h('p', { class: 'muted small' }, state.dbs.length ? 'You already have: ' + state.dbs.join(', ') + '.' : ''));
      S.err = err;
      setTimeout(() => input.focus(), 30);
    } else if (S.step === 1) {
      mount(body, h('h2', null, 'What are you making?'), h('p', { class: 'muted' }, 'This picks the right kind of file and adds example data so you can try things right away.'),
        h('div', { class: 'grid g2 tcards' }, TEMPLATES.map((t) => h('button', { class: 'card pcard' + (t.id === S.tpl ? ' on' : ''), onclick: () => { S.tpl = t.id; paint(); } }, h('h3', null, icon(t.ico, 18), ' ', t.title), h('p', { class: 'muted' }, t.blurb), S.adv && t.file ? h('div', { class: 'small' }, h('code', null, t.file), ' · box ', h('code', null, t.box)) : h('div', { class: 'small muted' }, t.what)))),
        tpl().seeds.length ? h('label', { class: 'check', style: { marginTop: '12px' } }, h('input', { type: 'checkbox', checked: S.seed, onchange: (e) => { S.seed = e.target.checked; } }), ' Add ' + tpl().seeds.length + ' example record' + (tpl().seeds.length === 1 ? '' : 's')) : null);
    } else if (S.step === 2) {
      const profiles = S.adv ? PROFILES : PROFILES.filter((p) => ['', 'dev', 'server'].includes(p[0]));
      mount(body, h('h2', null, 'Where will it run?'), h('p', { class: 'muted' }, 'Optional. A profile sets sensible defaults for network access, security and speed. It only changes the settings file; you will restart redxd to use it.'),
        h('div', { class: 'radios' }, profiles.map(([v, l]) => h('label', { class: 'radio' }, h('input', { type: 'radio', name: 'prof', checked: S.profile === v, onchange: () => { S.profile = v; } }), h('div', null, h('b', null, l))))),
        h('label', { class: 'check', style: { marginTop: '12px' } }, h('input', { type: 'checkbox', checked: S.adv, onchange: (e) => { S.adv = e.target.checked; setMode(S.adv ? 'advanced' : 'simple'); paint(); } }), ' Advanced: show every profile and technical details'),
        h('p', { class: 'small' }, h('a', { href: '#/presets' }, 'Compare all profiles →')));
    } else if (S.step === 3) {
      const t = tpl();
      mount(body, h('h2', null, 'Ready'), h('div', { class: 'review' },
        rev('Database', h('b', null, S.name)),
        rev('Template', t.title + (S.adv && t.file ? ' (' + t.file + ')' : '')),
        rev('Example records', S.seed && t.seeds.length ? t.seeds.length + ' will be added' : 'none'),
        rev('Profile', S.profile ? PROFILES.find((p) => p[0] === S.profile)[1] : 'unchanged')),
        S.profile === 'edge' ? h('div', { class: 'callout warn' }, icon('alert'), h('div', null, 'The Edge profile makes this host a follower of another host and needs a join link. Use ', h('a', { href: '#/presets' }, 'Presets'), ' to apply it, or pick another profile.')) : null,
        S.profile ? h('div', { class: 'callout info' }, icon('info'), h('div', null, 'The profile is written to the config file. It takes effect after you restart redxd.')) : null);
    }
    mount(nav, S.step > 0 && S.step < 4 ? h('button', { class: 'btn', onclick: () => { S.step--; paint(); } }, 'Back') : null, h('div', { class: 'grow' }),
      S.step < 3 ? h('button', { class: 'btn primary', onclick: next }, 'Next') : S.step === 3 ? h('button', { class: 'btn primary', onclick: finish }, icon('rocket', 16), ' Create everything') : null,
      S.step < 3 ? h('a', { class: 'btn ghost', href: '#/', onclick: () => wizard.finish() }, 'Skip setup') : null);
  }
  const rev = (k, v) => h('div', { class: 'rrow' }, h('div', { class: 'muted' }, k), h('div', null, v));
  function next() {
    if (S.step === 0) {
      if (!ID_RE.test(S.name)) { S.err.textContent = 'Use lower-case letters, digits, "-" and "_", starting with a letter or digit (up to 63 characters).'; S.err.hidden = false; return; }
    }
    if (S.step === 2 && S.profile === 'edge') { /* allowed, explained in review */ }
    S.step++;
    paint();
  }
  async function finish() {
    mount(body, spinner('Creating…'));
    mount(nav);
    const log = [];
    try {
      try { await api('POST', '/v1/dbs', { json: { name: S.name } }); log.push(['ok', 'Created database ' + S.name]); gs.set('db'); } catch (e) { if (/exist/i.test(e.message) || e.status === 409) log.push(['info', 'Database ' + S.name + ' already existed; using it']); else throw e; }
      await loadDbs();
      setDb(S.name);
      const t = tpl();
      if (S.seed && t.seeds.length) {
        for (const [box, id] of t.seeds) {
          const qs = t.ttl ? '?ttl=' + t.ttl : '';
          await api('PUT', pathURL(S.name, `${t.file}:${t.box}[ID=${id}]`) + qs, { json: { box } });
        }
        gs.set('record');
        log.push(['ok', 'Added ' + t.seeds.length + ' example record' + (t.seeds.length === 1 ? '' : 's')]);
      }
      if (S.profile && S.profile !== 'edge') {
        try { const r = await applyPreset(S.profile, {}, '', false); log.push(['ok', 'Saved profile "' + S.profile + '" (' + r.changes.filter((c) => c.changed).length + ' settings changed). Restart redxd to use it.']); if (r.skipped && r.skipped.length) log.push(['info', r.skipped.map((s) => s.key + ': ' + s.reason).join(' ')]); } catch (e) { log.push(['err', 'Profile not applied: ' + e.message]); }
      }
      wizard.finish();
      S.step = 4;
      paintSteps();
      const t2 = tpl();
      mount(body, h('div', { class: 'center' }, h('div', { class: 'big-ico ok' }, icon('check', 40)), h('h2', null, 'You are set up')),
        h('div', { class: 'log' }, log.map(([k, m]) => h('div', { class: 'logrow ' + k }, icon(k === 'err' ? 'alert' : k === 'ok' ? 'check' : 'info', 15), m))),
        h('h3', null, 'Next'),
        h('div', { class: 'grid g2' },
          h('a', { class: 'card linkcard', href: '#/data' + (t2.file ? '?db=' + enc(S.name) + '&file=' + enc(t2.file) : '') }, h('b', null, icon('table', 16), ' Look at your data'), h('p', { class: 'muted small' }, 'Browse and edit records.')),
          h('a', { class: 'card linkcard', href: '#/studio', onclick: () => { if (t2.query) sessionStorage.setItem('redx.studio.q', t2.query); } }, h('b', null, icon('terminal', 16), ' Run a query'), h('p', { class: 'muted small' }, 'Try BoxQL on your data.')),
          h('a', { class: 'card linkcard', href: '#/keys' }, h('b', null, icon('key', 16), ' Make a key for your app'), h('p', { class: 'muted small' }, 'Give your app its own limited key.')),
          h('a', { class: 'card linkcard', href: '#/' }, h('b', null, icon('home', 16), ' Go to the dashboard'), h('p', { class: 'muted small' }, 'Status and the Get-started list.'))));
      mount(nav);
    } catch (e) {
      mount(body, h('div', { class: 'callout err' }, icon('alert'), h('div', null, h('b', null, 'Something went wrong. '), e.message)), h('div', { class: 'log' }, log.map(([k, m]) => h('div', { class: 'logrow ' + k }, m))));
      mount(nav, h('button', { class: 'btn', onclick: () => { S.step = 3; paint(); } }, 'Back'), h('button', { class: 'btn primary', onclick: finish }, 'Try again'));
    }
  }
  paint();
  return root;
}

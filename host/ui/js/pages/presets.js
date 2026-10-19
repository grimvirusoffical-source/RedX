import { h, icon, terminalPanel, chip, mount, toast, dialog, field, copy, errorBox, spinner, table, confirmDialog } from '../util.js';
import { api, enc } from '../api.js';
import { isHostAdmin } from '../state.js';
import { pageHead, page } from './shared.js';

export const applyPreset = (name, overrides, join, dry) => api('POST', `/v1/admin/presets/${enc(name)}/apply`, { json: { overrides: overrides || {}, join: join || '', dry_run: !!dry } });
export const loadPresets = () => api('GET', '/v1/admin/presets');

const ENUMS = { role: ['leader', 'follower'], tls: ['off', 'auto', 'files'], engine_durability: ['sync', 'group', 'async'], log_level: ['debug', 'info', 'warn', 'error'], bootstrap: ['auto', 'web', 'console', 'off'] };
const show = (v) => (Array.isArray(v) ? v.join(', ') || '(none)' : v === '' || v == null ? '(not set)' : typeof v === 'boolean' ? (v ? 'on' : 'off') : String(v));

export function settingInput(key, val, onChange) {
  if (typeof val === 'boolean') return h('input', { type: 'checkbox', checked: val, 'aria-label': key, onchange: (e) => onChange(e.target.checked) });
  if (ENUMS[key]) return h('select', { class: 'select', 'aria-label': key, onchange: (e) => onChange(e.target.value) }, ENUMS[key].map((o) => h('option', { value: o, selected: o === val }, o)));
  if (typeof val === 'number') return h('input', { class: 'input', type: 'number', value: val, 'aria-label': key, style: { maxWidth: '160px' }, oninput: (e) => onChange(e.target.value === '' ? val : Number(e.target.value)) });
  if (Array.isArray(val)) return h('input', { class: 'input', value: val.join(', '), 'aria-label': key, oninput: (e) => onChange(e.target.value.split(',').map((s) => s.trim()).filter(Boolean)) });
  return h('input', { class: 'input', value: val ?? '', 'aria-label': key, oninput: (e) => onChange(e.target.value) });
}

export default async function render() {
  const root = page();
  if (!isHostAdmin()) { root.append(pageHead('Presets'), h('div', { class: 'callout info' }, icon('info'), h('div', null, 'Presets change the host configuration and need a host admin key.'))); return root; }
  const box = h('div');
  root.append(pageHead('Presets', 'Ready-made profiles for common jobs. Compare them, read why each setting is chosen, edit anything, then apply.'), box,
    terminalPanel([{ label: 'List', cmd: 'redx preset ls' }, { label: 'Show one with reasons', cmd: 'redx preset show game' }, { label: 'See what would change', cmd: 'redx preset show game --diff' }, { label: 'Apply', cmd: 'redx preset apply game' }, { label: 'Start redxd with a preset', cmd: 'redxd run --preset game' }], 'A preset is a plain file in the binary. Applying it writes ordinary settings into redx.toml; nothing is hidden.'));
  mount(box, spinner());
  let data;
  let cfg;
  try { [data, cfg] = await Promise.all([loadPresets(), api('GET', '/v1/admin/config')]); } catch (e) { mount(box, errorBox(e.message)); return root; }
  const presets = data.presets;
  let selected = data.active || null;
  const detail = h('div', { style: { marginTop: '18px' } });

  const keys = data.keys.filter((k) => presets.some((p) => k in p.settings));
  const cmp = table(['Setting', 'This host', ...presets.map((p) => p.title)], keys.map((k) => h('tr', null, h('td', { class: 'mono' }, k), h('td', { class: 'mono muted' }, show(cfg.config[k])), presets.map((p) => h('td', { class: 'mono' + (p.name === selected ? ' hi' : '') + (k in p.settings && String(p.settings[k]) !== String(cfg.config[k]) ? ' chg' : '') }, k in p.settings ? show(p.settings[k]) : '–')))), 'compare');
  mount(box,
    data.active ? h('div', { class: 'callout info' }, icon('info'), h('div', null, 'The config file names the preset ', chip(data.active, 'acc'), '. Settings may have been edited since.')) : null,
    h('div', { class: 'grid g3 pcards' }, presets.map((p) => h('button', { class: 'card pcard' + (p.name === selected ? ' on' : ''), onclick: () => select(p.name), 'aria-pressed': String(p.name === selected) }, h('h3', null, p.title, p.name === data.active ? chip('active', 'ok') : null), h('p', { class: 'muted' }, p.summary), h('div', { class: 'small muted' }, p.audience)))),
    detail,
    h('h2', { style: { marginTop: '26px' } }, 'Comparison'), h('p', { class: 'muted small' }, 'Highlighted cells differ from how this host is set up now.'), h('div', { class: 'cmp' }, cmp));

  async function select(name) {
    selected = name;
    box.querySelectorAll('.pcard').forEach((c, i) => { const on = presets[i].name === name; c.classList.toggle('on', on); c.setAttribute('aria-pressed', String(on)); });
    const p = presets.find((x) => x.name === name);
    let full;
    try { full = await api('GET', `/v1/admin/presets/${enc(name)}`); } catch (e) { return mount(detail, errorBox(e.message)); }
    const values = { ...p.settings };
    const edited = {};
    const join = h('input', { class: 'input', placeholder: 'https://leader:7777/#/join?c=RX-XXXXX-XXXXX&pin=…', 'aria-label': 'Join link' });
    const result = h('div');
    const needsJoin = p.settings.role === 'follower';
    const rows = Object.keys(p.settings).map((k) => {
      const d = full.diff.find((x) => x.key === k);
      return h('div', { class: 'prow' }, h('div', { class: 'pk' }, h('code', null, k), d && d.changed ? h('div', { class: 'muted small' }, 'now: ', show(d.from)) : h('div', { class: 'muted small' }, 'already set')), h('div', null, settingInput(k, p.settings[k], (v) => { values[k] = v; if (JSON.stringify(v) !== JSON.stringify(p.settings[k])) edited[k] = v; else delete edited[k]; })), h('div', { class: 'why' }, full.why[k] || ''));
    });
    const run = async (dry) => {
      mount(result, spinner());
      try {
        const r = await applyPreset(name, edited, join.value, dry);
        mount(result, h('div', { class: 'card' }, h('h3', null, dry ? 'Preview: what would change' : 'Applied to ' + r.path),
          table(['Setting', 'Now', 'After'], r.changes.map((c) => h('tr', { class: c.changed ? '' : 'dim' }, h('td', { class: 'mono' }, c.key), h('td', { class: 'mono' }, show(c.from)), h('td', { class: 'mono' }, show(c.to), c.changed ? '' : h('span', { class: 'muted' }, '  (unchanged)'))))),
          r.skipped && r.skipped.length ? h('div', { class: 'callout warn' }, icon('alert'), h('div', null, r.skipped.map((s) => h('div', null, h('b', null, s.key + ' not applied: '), s.reason)))) : null,
          r.env_overrides && r.env_overrides.length ? h('div', { class: 'callout info' }, icon('info'), h('div', null, 'These are also set by environment variables, which win over the file: ', r.env_overrides.join(', '))) : null,
          dry ? h('details', null, h('summary', null, 'Config file text'), h('pre', { class: 'code-block' }, r.text)) : h('div', { class: 'callout ok' }, icon('check'), h('div', null, h('b', null, 'Saved. Restart redxd for it to take effect. '), r.backup ? 'Your previous file was kept as ' + r.backup + '. ' : '', 'Restart with ', h('code', null, 'redxd restart'), ' (service) or stop and start redxd.'))));
        if (!dry) toast('Preset ' + p.title + ' saved. Restart to apply.', 'ok', 6000);
      } catch (e) { mount(result, h('div', { class: 'callout err' }, icon('alert'), h('div', null, e.message))); }
    };
    mount(detail, h('div', { class: 'card' },
      h('div', { class: 'row gap wrap' }, h('h2', { style: { margin: 0 } }, p.title), h('div', { class: 'grow' }), h('span', { class: 'muted small' }, p.audience)),
      h('p', null, p.summary),
      p.needs && p.needs.length ? h('div', { class: 'callout warn' }, icon('alert'), h('div', null, h('b', null, 'Needs: '), p.needs.join('; '))) : null,
      p.warnings.map((w) => h('div', { class: 'callout warn' }, icon('alert'), h('div', null, w))),
      h('h3', null, 'Settings, and why'), h('div', { class: 'ptable' }, rows),
      p.guidance.length ? [h('h3', null, 'Good to know'), h('ul', null, p.guidance.map((g) => h('li', null, g)))] : null,
      p.files.length ? [h('h3', null, 'Suggested files'), h('ul', null, p.files.map((f) => h('li', null, h('code', null, f.name), f.box ? [' · box ', h('code', null, f.box)] : null, f.ttl_seconds ? ' · expires after ' + f.ttl_seconds + ' s' : null, ' — ', f.note)))] : null,
      needsJoin ? field('Join link of the leader', join, 'This profile makes the host a follower. Get the link from the leader\'s Add a device page.') : null,
      h('div', { class: 'row gap wrap', style: { marginTop: '14px' } }, h('button', { class: 'btn', onclick: () => run(true) }, icon('search', 15), ' Preview what changes'), h('button', { class: 'btn primary', onclick: async () => { if (await confirmDialog('Apply "' + p.title + '"?', 'This rewrites redx.toml (the old file is kept as a .bak copy). The host keeps running with its current settings until you restart it.', { ok: 'Apply' })) run(false); } }, 'Apply to this host')),
      result));
    detail.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
  if (selected) select(selected);
  return root;
}

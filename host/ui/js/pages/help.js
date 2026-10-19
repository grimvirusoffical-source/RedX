import { h, icon, mount, errorBox, spinner, terminalPanel } from '../util.js';
import { renderMarkdown } from '../md.js';
import { pageHead, page } from './shared.js';

export const ABOUT = 'RedX is developed and maintained by Red-XAI LLC. Red-XAI LLC is wholly owned by GRIM-VIRUS, an independent recording artist who leads development under the alias MainDirectory. © Red-XAI LLC. All rights reserved.';

export const DOCS = [
  ['console', 'Using the console', 'Every page, the security model, presets and the terminal equivalents.'],
  ['boxql', 'BoxQL guide', 'The query and command language: read, add, set, delete, transactions, watch.'],
  ['box-grammar', 'Box file grammar', 'The text format of data files, rules, policies and queries.'],
  ['hosting', 'Hosting guide', 'Install, run as a service, TLS, troubleshooting.'],
  ['clustering', 'Clustering', 'Adding nodes, pairing codes, failover, fencing and repoint.'],
  ['connect', 'Connecting apps', 'How apps such as Rotten Apple get their own workspace and key.'],
];

export default async function render(ctx) {
  const id = ctx.args[0];
  const root = page();
  if (!id) {
    root.append(pageHead('Help', 'Everything here is built into the host and works offline.'),
      h('div', { class: 'grid g2' }, DOCS.map(([k, t, d]) => h('a', { class: 'card linkcard', href: '#/help/' + k }, h('h3', null, icon('book', 18), ' ', t), h('p', { class: 'muted' }, d)))),
      h('div', { class: 'card', style: { marginTop: '16px' } }, h('h3', null, 'Quick answers'),
        h('dl', { class: 'faq' },
          h('dt', null, 'Where is my admin key?'), h('dd', null, 'It was shown once when you created it. If it is lost, an admin on the host can make a new one with ', h('code', null, 'redx key create --offline --db "*" --scope admin'), '.'),
          h('dt', null, 'What is BoxQL?'), h('dd', null, 'RedX\'s own query language. ', h('a', { href: '#/help/boxql' }, 'Read the guide'), ' or open the ', h('a', { href: '#/studio' }, 'BoxQL Studio'), ' and try the snippets.'),
          h('dt', null, 'Do I need a terminal?'), h('dd', null, 'No. Every page shows the terminal equivalent in a collapsible panel if you want it.'),
          h('dt', null, 'Is my data sent anywhere?'), h('dd', null, 'No. The console talks only to this host. It loads no fonts, scripts or images from the internet.'))),
      h('div', { class: 'card', id: 'about', style: { marginTop: '16px' } }, h('h3', null, 'About RedX'), h('p', { class: 'about-copy' }, ABOUT)),
      terminalPanel([{ label: 'Open this console', cmd: 'redxd open' }, { label: 'Check your setup', cmd: 'redxd doctor' }]));
    return root;
  }
  const meta = DOCS.find((d) => d[0] === id);
  if (!meta) { root.append(errorBox('There is no help page called "' + id + '".')); return root; }
  const body = h('div');
  const side = h('nav', { class: 'toc', 'aria-label': 'On this page' });
  root.append(pageHead(meta[1], meta[2], h('a', { class: 'btn', href: '#/help' }, '← All help')), h('div', { class: 'doc' }, body, side));
  mount(body, spinner());
  try {
    const res = await fetch('/ui/docs/' + id + '.md', { cache: 'no-cache' });
    if (!res.ok) throw new Error('Could not load the document (' + res.status + ').');
    const { el, toc } = renderMarkdown(await res.text());
    mount(body, el);
    mount(side, h('div', { class: 'muted small' }, 'On this page'), toc.filter((t) => t.lvl <= 2).map((t) => h('a', { class: 'lvl' + t.lvl, href: '#/help/' + id, onclick: (e) => { e.preventDefault(); const n = document.getElementById(t.id); if (n) n.scrollIntoView({ behavior: 'smooth', block: 'start' }); } }, t.text)));
  } catch (e) { mount(body, errorBox(e.message)); }
  return root;
}

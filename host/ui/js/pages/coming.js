// Placeholder pages for the Host nav. Each one is a real route with a Coming soon state.
import { h, icon } from '../util.js';
import { pageHead, page } from './shared.js';

const TITLES = {
  hostapps: 'Apps',
  deploy: 'Deploy',
  domains: 'Domains & SSL',
  env: 'Env & Secrets',
  applogs: 'App logs',
};

export default async function render({ page: id } = {}) {
  const root = page();
  root.id = 'coming-soon';
  root.dataset.page = id || '';
  const title = TITLES[id] || 'Coming soon';
  root.append(
    pageHead(title, 'This part of Host is not available yet.'),
    h('div', { class: 'callout info', role: 'status' }, icon('info'), h('div', null, 'Coming soon')));
  return root;
}

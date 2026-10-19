// Hosting: plans, access, quotas, and this account's databases. Prices come from /v1/billing/plans.
import { h, icon, chip, mount, toast, field, fmtBytes, fmtTime } from '../util.js';
import { api } from '../api.js';
import { state } from '../state.js';
import { pageHead, page } from './shared.js';

const ACCESS = {
  full: 'Full access: you can create, read, write and drop databases and keys, within this tier\'s quotas.',
  readonly: 'Read-only: reads work. Writes and new keys answer plan_readonly. Your data is kept.',
  suspended: 'Suspended: the host answers plan_required. Your data is kept.',
  none: 'No plan: creating a database answers plan_required.',
};

const TIER_ORDER = ['basic', 'bronze', 'silver', 'gold', 'platinum', 'emerald'];

export default async function render() {
  const root = page();
  root.id = 'hosting-page';
  const body = h('div');
  root.append(pageHead('Plans & billing', 'RedX Hosted plans, the current plan, and a new database on this account.'), body);

  let plans = null;
  let plansFailed = false;
  try {
    plans = await api('GET', '/v1/billing/plans', { noAuthRedirect: true });
  } catch { plansFailed = true; }

  if (plansFailed) {
    body.append(h('div', { class: 'callout info', id: 'hosting-plans-error', role: 'status' }, icon('info'),
      h('div', null, "Couldn't load plans, try again")));
  } else if (!plans || !plans.enabled) {
    body.append(h('div', { class: 'callout info', id: 'hosting-off', role: 'status' }, icon('info'),
      h('div', null, "Hosting plans aren't on sale yet")));
  }

  const account = state.who && state.who.account;
  let me = null;
  if (account) {
    try { me = await api('GET', '/v1/billing/me', { noAuthRedirect: true }); } catch { me = null; }
  } else {
    body.append(h('div', { class: 'callout info' }, icon('info'), h('div', null, 'Sign in with a Red-XAI Account to choose a plan and see usage.')));
  }

  if (me) body.append(accountCard(me, plans));
  if (plans && plans.enabled) body.append(planGrid(plans, me));
  if (account) body.append(createCard());
  return root;
}

function accountCard(me, plans) {
  const access = me.access || 'none';
  const tier = ((plans && plans.plans) || []).find((p) => p.key === me.plan && (p.interval || 'month') === (me.interval || 'month'));
  const name = me.plan ? (tier && tier.name ? tier.name : me.plan) : 'None';
  const bits = [h('div', { id: 'current-plan' }, h('b', null, 'Current plan: '), name, me.interval ? [' · ', me.interval === 'year' ? 'annual' : 'monthly'] : null)];
  if (me.periodEnd) {
    bits.push(h('p', { id: 'period-end', class: 'muted' }, (me.cancelAtPeriodEnd ? 'Ends ' : 'Period ends '), fmtTime(new Date(me.periodEnd))));
  }
  const notices = [];
  if (plans && plans.enabled) {
    if (access === 'readonly') notices.push(notice('plan_readonly', 'warn', 'plan_readonly: this plan is read-only. Reads work. Writes and new keys are refused. Your data is kept.'));
    if (access === 'suspended' || access === 'none') notices.push(notice('plan_required', 'warn', 'plan_required: choose a plan to create databases and write. Existing data is kept.'));
    if (overQuota(me)) notices.push(notice('quota_exceeded', 'err', 'quota_exceeded: usage is at this tier\'s limit. Upgrade the plan or wait for the next period.'));
  }
  const card = h('div', { class: 'card', id: 'access-state' },
    h('h3', null, 'This account'),
    ...bits,
    h('p', null, chip(access, access === 'full' ? 'ok' : access === 'readonly' ? 'warn' : 'err'), ' ', ACCESS[access] || ACCESS.none),
    ...notices);
  if (me.portal || me.active) card.append(h('button', { class: 'btn', type: 'button', style: { marginTop: '12px' }, onclick: () => portal() }, 'Manage billing'));
  return card;
}

function notice(id, kind, text) {
  return h('div', { class: 'callout ' + kind, id: 'notice-' + id, role: 'status' }, icon(kind === 'err' ? 'alert' : 'info'), h('div', null, text));
}

function overQuota(me) {
  const u = me.usage, q = me.quota;
  if (!u || !q) return false;
  const hit = (used, cap) => typeof cap === 'number' && cap >= 0 && used >= cap;
  return hit(u.trafficBytes || 0, q.trafficBytes) || hit(u.storageBytes || 0, q.storageBytes) || hit(u.hostSwitches || 0, q.hostSwitches);
}

function planGrid(plans, me) {
  let interval = (me && me.interval) || 'month';
  const box = h('div', { class: 'card', id: 'plan-grid', style: { marginTop: '16px' } });
  const grid = h('div', { class: 'grid g3' });
  function draw() {
    mount(grid, TIER_ORDER.map((key) => {
      const p = (plans.plans || []).find((row) => row.key === key && (row.interval || 'month') === interval);
      if (!p) return null;
      return h('div', { class: 'card', 'data-plan': key },
        h('h3', null, p.name || key),
        h('p', { class: 'price' }, p.available && p.amount != null ? money(p.amount, p.currency) : 'Price unavailable',
          h('span', { class: 'muted small' }, interval === 'year' ? ' / year' : ' / month')),
        quotaLine(p.quota),
        p.available ? h('a', { class: 'btn primary', href: '/ui/billing.html?plan=' + encodeURIComponent(key) + '&interval=' + encodeURIComponent(interval) }, 'Choose a plan')
          : h('p', { class: 'muted small' }, 'Not available'));
    }));
  }
  const month = h('button', { class: 'seg-opt', type: 'button', 'aria-pressed': String(interval === 'month'), onclick: () => pick('month') }, 'Monthly');
  const year = h('button', { class: 'seg-opt', type: 'button', 'aria-pressed': String(interval === 'year'), onclick: () => pick('year') }, 'Annual');
  function pick(v) {
    interval = v;
    month.setAttribute('aria-pressed', String(v === 'month'));
    year.setAttribute('aria-pressed', String(v === 'year'));
    month.classList.toggle('on', v === 'month');
    year.classList.toggle('on', v === 'year');
    draw();
  }
  month.classList.toggle('on', interval === 'month');
  year.classList.toggle('on', interval === 'year');
  box.append(
    h('h3', null, 'Plans'),
    h('div', { class: 'seg', role: 'group', 'aria-label': 'Billing interval' }, month, year),
    h('p', { class: 'muted small' }, 'Annual is 10× the monthly price (2 months free). Choose a plan opens checkout.'),
    grid);
  draw();
  return box;
}

function quotaLine(q) {
  if (!q) return null;
  const sw = q.hostSwitches < 0 ? 'unlimited switches' : q.hostSwitches + ' switches';
  return h('p', { class: 'muted small' }, fmtBytes(q.trafficBytes) + ' traffic · ' + fmtBytes(q.storageBytes) + ' storage · ' + sw);
}

function money(amount, currency) {
  const cur = (currency || 'usd').toUpperCase();
  try { return new Intl.NumberFormat(undefined, { style: 'currency', currency: cur }).format(amount / 100); }
  catch { return (amount / 100).toFixed(2) + ' ' + cur; }
}

function createCard() {
  const name = h('input', { class: 'input', id: 'hosted-logical', 'aria-label': 'Logical database name', placeholder: 'game', maxlength: '50' });
  const out = h('div', { id: 'hosted-names' });
  async function create() {
    const logical = name.value.trim();
    if (!logical) { toast('Type a logical name', 'err'); return; }
    try {
      const r = await api('POST', '/v1/dbs', { json: { name: logical } });
      mount(out, h('p', null, 'Logical name: ', h('code', null, r.logical || logical), ' · physical name: ', h('code', null, r.name || '')));
      toast('Database created', 'ok');
    } catch (e) {
      const code = e.body && (e.body.code || e.body.error);
      mount(out, h('p', { class: 'muted' }, typeof code === 'string' ? code : (e.message || 'Could not create the database')));
    }
  }
  return h('div', { class: 'card', id: 'hosted-create', style: { marginTop: '16px' } },
    h('h3', null, 'Create a hosted database'),
    h('p', { class: 'muted' }, 'You choose the logical name. The host stores it under a physical name that is unique to this account, so two accounts can both use the same logical name.'),
    field('Logical name', name),
    h('button', { class: 'btn primary', type: 'button', onclick: () => create() }, 'Create hosted database'),
    out);
}

async function portal() {
  try {
    const r = await api('POST', '/v1/billing/portal', { json: {} });
    if (r && r.url) location.href = r.url;
  } catch (e) { toast(e.message || String(e), 'err'); }
}

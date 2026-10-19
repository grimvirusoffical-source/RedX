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
  root.append(pageHead('Hosting', 'RedX Hosted plans, usage, and the databases on your account.'), body);

  let plans = { enabled: false, plans: [] };
  try {
    plans = await api('GET', '/v1/billing/plans', { noAuthRedirect: true });
  } catch { /* a missing price list is the same as plans not being on sale */ }

  if (!plans || !plans.enabled) {
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
  if (account) {
    body.append(createCard());
    body.append(await activityCard());
  }
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
  if (me.usage && me.quota) card.append(h('div', { id: 'usage-meters' }, meters(me.usage, me.quota)));
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

function meters(u, q) {
  return h('div', { class: 'stack' },
    meter('Storage', u.storageBytes || 0, q.storageBytes, fmtBytes),
    meter('Monthly traffic', u.trafficBytes || 0, q.trafficBytes, fmtBytes),
    meter('Host on/off switches', u.hostSwitches || 0, q.hostSwitches, (n) => String(n)));
}

function meter(label, used, cap, fmt) {
  const unlimited = typeof cap !== 'number' || cap < 0;
  const pct = unlimited || !cap ? 0 : Math.max(0, Math.min(100, Math.round((used / cap) * 100)));
  const over = !unlimited && cap > 0 && used >= cap;
  const text = unlimited ? fmt(used) + ' · unlimited' : fmt(used) + ' / ' + fmt(cap);
  return h('div', { class: 'meter-row' },
    h('div', { class: 'row' }, h('span', null, label), h('span', { class: 'muted small' }, text)),
    h('div', { class: 'meter' + (over ? ' err' : ''), role: 'meter', 'aria-label': label, 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(unlimited ? 0 : pct) },
      h('span', { style: { width: pct + '%' } })));
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

async function activityCard() {
  const box = h('div', { class: 'card', id: 'activity-log', style: { marginTop: '16px' } }, h('h3', null, 'Database activity'));
  try {
    const r = await api('GET', '/v1/hosting/activity', { noAuthRedirect: true });
    const dbs = r.dbs || [];
    if (!dbs.length) {
      box.append(h('p', { class: 'muted' }, 'No hosted databases on this account yet.'));
      return box;
    }
    box.append(dbs.map((d) => h('div', { 'data-db': d.logical || d.name, style: { marginTop: '12px' } },
      h('p', null, h('b', null, d.logical || d.name), d.name && d.logical ? [' ', h('span', { class: 'muted small' }, 'physical ', h('code', null, d.name))] : null),
      h('p', { class: 'muted small' }, (d.requests || 0) + ' requests · ' + (d.errors || 0) + ' errors'),
      (d.denied || []).length ? h('div', null, h('p', { class: 'muted small' }, 'Recent denied requests'),
        ...d.denied.slice().reverse().map((x) => h('p', { class: 'small' }, String(x.status), ' ', x.method || '', ' ', x.path || '', x.reason ? [' · ', x.reason] : null)))
        : h('p', { class: 'muted small' }, 'No recent denied requests.'))));
  } catch {
    box.append(h('p', { class: 'muted' }, 'Activity is available for this account\'s own databases.'));
  }
  return box;
}

async function portal() {
  try {
    const r = await api('POST', '/v1/billing/portal', { json: {} });
    if (r && r.url) location.href = r.url;
  } catch (e) { toast(e.message || String(e), 'err'); }
}

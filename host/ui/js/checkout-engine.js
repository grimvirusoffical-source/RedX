// Themed Stripe checkout (shared by Rotten Apple, QuickLaunch, RedX and Gendragoon; copied per app so
// each page stays dependency-free and same-origin). It renders the app's own plan summary and the
// Stripe Payment Element (Checkout Sessions, ui_mode=elements) styled with the Appearance API from the
// app theme. Card data only ever lives in Stripe's iframe. No inline script or style (strict CSP).
//
// mountCheckout({ root, theme, backend, item, preview })
//   theme   : { name, logoSvg, tagline, appearance, features: {key: label}, legal }
//   backend : { load() -> {publishableKey, items:[{key,name,amountCents,period,features[],badge}]},
//               start(item) -> {clientSecret, publishableKey, session},
//               status(session) -> {status, payment, active} }
//   item    : the plan/product key from ?plan= or ?product=
//   preview : render without Stripe (a styled stand-in for screenshots and offline review)

// RedX copy: the console never sets innerHTML, so the logo is an <img> (theme.logoSrc).
function logo(theme) {
  const img = document.createElement('img');
  img.src = theme.logoSrc; img.alt = ''; img.width = 40; img.height = 40;
  return h('span', { class: 'co-logo' }, img);
}

const STRIPE_JS = 'https://js.stripe.com/endive/stripe.js';

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat()) if (c != null) el.append(c.nodeType ? c : document.createTextNode(String(c)));
  return el;
}

export function money(cents, currency = 'usd') {
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: currency.toUpperCase(), minimumFractionDigits: cents % 100 ? 2 : 0 }).format(cents / 100);
}

export function periodLabel(p) {
  return { month: '/ month', year: '/ year', once: 'one time' }[p] || '';
}

function loadStripe() {
  if (window.Stripe) return Promise.resolve(window.Stripe);
  return new Promise((ok, fail) => {
    const s = h('script', { src: STRIPE_JS, async: true });
    s.addEventListener('load', () => (window.Stripe ? ok(window.Stripe) : fail(new Error('Stripe.js did not load'))));
    s.addEventListener('error', () => fail(new Error('Stripe.js could not be loaded')));
    document.head.append(s);
  });
}

function idemKey() {
  const k = 'co-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
  return k;
}

function summary(theme, item) {
  return h('section', { class: 'co-summary' },
    h('div', { class: 'co-brand' }, logo(theme), h('span', { class: 'co-appname' }, theme.name)),
    item.badge ? h('div', { class: 'co-badge' }, item.badge) : null,
    h('h1', { class: 'co-plan' }, item.name),
    h('div', { class: 'co-price' }, h('span', { class: 'co-amount' }, money(item.amountCents, item.currency)), h('span', { class: 'co-period' }, periodLabel(item.period))),
    item.blurb ? h('p', { class: 'co-blurb' }, item.blurb) : null,
    h('ul', { class: 'co-features' }, (item.features || []).map((f) => h('li', {}, h('span', { class: 'co-tick', 'aria-hidden': 'true' }, '✓'), f))),
    h('p', { class: 'co-fine' }, item.period === 'once'
      ? 'One payment. Nothing renews.'
      : `Renews automatically ${item.period === 'year' ? 'every year' : 'every month'}. Cancel any time in billing settings; access runs to the end of the paid period.`),
  );
}

function payPanel(theme, item, onPay) {
  const err = h('div', { class: 'co-error', role: 'alert' });
  const btn = h('button', { class: 'co-pay', type: 'submit', disabled: true }, h('span', { class: 'co-pay-label' }, `Pay ${money(item.amountCents, item.currency)}`));
  const pe = h('div', { id: 'payment-element', class: 'co-element' });
  const form = h('form', { class: 'co-form', onsubmit: (e) => { e.preventDefault(); onPay(btn, err); } },
    h('h2', { class: 'co-h2' }, 'Payment'),
    pe, err, btn,
    h('p', { class: 'co-secure' }, h('span', { 'aria-hidden': 'true' }, '🔒 '), 'Payments are processed securely by Stripe. ', theme.legal || ''));
  return { panel: h('section', { class: 'co-pay-panel' }, form), pe, btn, err };
}

// a static stand-in of the Payment Element, styled from the same appearance variables
function previewElement(theme) {
  const field = (label, ph, extra = '') => h('label', { class: 'co-pv-field ' + extra }, h('span', { class: 'co-pv-label' }, label), h('span', { class: 'co-pv-input' }, ph));
  return h('div', { class: 'co-pv' },
    h('div', { class: 'co-pv-tabs' }, h('span', { class: 'co-pv-tab co-pv-on' }, '💳 Card'), h('span', { class: 'co-pv-tab' }, '🏦 Bank'), h('span', { class: 'co-pv-tab' }, 'Link')),
    field('Card number', '1234 1234 1234 1234'),
    h('div', { class: 'co-pv-row' }, field('Expiration', 'MM / YY', 'half'), field('CVC', 'CVC', 'half')),
    field('Country', 'United States'),
    h('p', { class: 'co-pv-note' }, 'Preview: Stripe\'s secure payment form renders here in this theme once the keys are set.'));
}

export async function mountCheckout({ root, theme, backend, item: key, preview = false, returnPage = false, session = '' }) {
  root.textContent = '';
  const shell = h('main', { class: 'co-shell' });
  root.append(shell);
  if (returnPage) return mountReturn(shell, theme, backend, session);
  let data;
  try { data = await backend.load(); } catch (e) { shell.append(h('div', { class: 'co-card co-msg' }, 'Could not load plans: ', e.message || String(e))); return; }
  const items = data.items || [];
  const item = items.find((x) => x.key === key) || null;
  if (!item) {
    shell.append(h('section', { class: 'co-card co-pick' },
      h('div', { class: 'co-brand' }, logo(theme), h('span', { class: 'co-appname' }, theme.name)),
      h('h1', { class: 'co-plan' }, theme.pickTitle || 'Choose a plan'),
      (key && !item) || !items.length ? h('div', { class: 'co-error', role: 'alert' }, !items.length ? 'Nothing is on sale right now. Please try again later.' : 'That plan is not on sale right now. Pick another one below.') : null,
      h('div', { class: 'co-grid' }, items.map((x) => h('a', { class: 'co-tile', href: `?${x.period === 'once' ? 'product' : 'plan'}=${encodeURIComponent(x.key)}${preview ? '&preview=1' : ''}` },
        h('strong', {}, x.name), h('span', { class: 'co-tile-price' }, money(x.amountCents, x.currency), ' ', h('small', {}, periodLabel(x.period))))))));
    return;
  }
  const card = h('div', { class: 'co-card' });
  shell.append(card);
  card.append(summary(theme, item));
  let actions = null;
  const { panel, pe, btn, err } = payPanel(theme, item, async (b, e) => {
    if (!actions) return;
    b.disabled = true; b.classList.add('co-busy'); e.textContent = '';
    const r = await actions.confirm();
    if (r.type === 'error') { e.textContent = r.error.message || 'The payment did not go through.'; b.disabled = false; b.classList.remove('co-busy'); }
    // success: Stripe redirects to the session's return_url
  });
  card.append(panel);
  if (preview || !data.publishableKey) {
    pe.append(previewElement(theme));
    btn.disabled = true;
    if (!preview) err.textContent = 'Checkout is not switched on yet (the server has no Stripe publishable key).';
    return;
  }
  try {
    const started = await backend.start(item, idemKey());
    const Stripe = await loadStripe();
    const stripe = Stripe(started.publishableKey || data.publishableKey);
    const checkout = stripe.initCheckoutElementsSdk({ clientSecret: started.clientSecret, elementsOptions: { appearance: theme.appearance } });
    const el = checkout.createPaymentElement({ layout: { type: 'tabs' } });
    el.mount(pe);
    const res = await checkout.loadActions();
    if (res.type === 'error') throw new Error(res.error.message);
    actions = res.actions;
    btn.disabled = false;
  } catch (e) {
    err.textContent = e.message || String(e);
  }
}

async function mountReturn(shell, theme, backend, session) {
  const card = h('div', { class: 'co-card co-done' });
  shell.append(card);
  const title = h('h1', { class: 'co-plan' }, 'Confirming your payment…');
  const msg = h('p', { class: 'co-blurb' }, 'This takes a few seconds.');
  card.append(h('div', { class: 'co-brand' }, logo(theme), h('span', { class: 'co-appname' }, theme.name)), h('div', { class: 'co-burst', 'aria-hidden': 'true' }), title, msg);
  for (let i = 0; i < 20; i++) {
    let st;
    try { st = await backend.status(session); } catch (e) { title.textContent = 'We could not read this checkout'; msg.textContent = e.message || String(e); return; }
    if (st.status === 'complete' && st.active) {
      card.classList.add('co-ok');
      title.textContent = theme.thanks || 'You are all set';
      msg.textContent = 'Your purchase is active on your account. A receipt is on its way to your email.';
      card.append(h('a', { class: 'co-pay co-link', href: theme.homeHref || '/' }, theme.homeLabel || 'Continue'));
      return;
    }
    if (st.status === 'expired') { title.textContent = 'This checkout expired'; msg.textContent = 'Nothing was charged. Start again from the plan page.'; return; }
    if (st.status === 'complete' && st.payment !== 'paid') { title.textContent = 'Payment processing'; msg.textContent = 'Bank payments can take a few days. We will switch it on as soon as it clears.'; }
    await new Promise((r) => setTimeout(r, 1500));
  }
  msg.textContent = 'Payment received. It can take a minute to show up; refresh this page if it does not.';
}

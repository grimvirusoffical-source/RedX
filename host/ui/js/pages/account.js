// Red-XAI Accounts: "Sign in with Red-XAI Account" and the sign-up flow (ToS gate, live red/green hints,
// confirm boxes with a copy arrow, date of birth with a calendar, 2FA choice). redxd re-checks every field.
import { h, icon, toast, debounce } from '../util.js';
import { api } from '../api.js';
import { drawQR } from '../qr.js';

let cfgCache = null;
/** GET /v1/auth/config (cached); {enabled:false} when this host has no Red-XAI Accounts sign-in. */
export async function accountsConfig() {
  if (cfgCache) return cfgCache;
  try { cfgCache = await api('GET', '/v1/auth/config', { key: '', noAuthRedirect: true }); } catch { cfgCache = { enabled: false }; }
  return cfgCache;
}

export const SIGNIN_ERRORS = {
  state: 'That sign-in did not start in this browser (or took too long). Please try again.',
  expired: 'The sign-in took too long. Please try again.',
  access_denied: 'Red-XAI Accounts did not allow this sign-in (for example, the account is under the minimum age for RedX).',
  exchange: 'RedX could not finish the sign-in with Red-XAI Accounts. Please try again.',
  token: 'The answer from Red-XAI Accounts could not be verified, so RedX did not sign you in.',
  provider: 'Red-XAI Accounts reported a problem with the sign-in.',
  unavailable: 'Red-XAI Accounts cannot be reached right now. Try again in a minute, or sign in with an API key.',
  busy: 'Too many sign-ins are in progress. Try again in a few minutes.',
  email_unverified: 'This account’s email is not confirmed yet. Open the link we sent, or resend it below, then sign in.',
};

/** The block under the API-key form: Sign in / Create account. */
export function accountButtons(cfg, onSignup) {
  return h('div', { class: 'acct-block' },
    h('div', { class: 'or-sep' }, h('span', null, 'or')),
    h('a', { class: 'btn primary big', id: 'acct-signin', href: '/v1/auth/login' }, icon('user', 18), ' Sign in with Red-XAI Account'),
    h('button', { class: 'btn big', id: 'acct-signup', type: 'button', onclick: onSignup }, 'Create a Red-XAI Account'),
    h('p', { class: 'muted small' }, 'One Red-XAI Account works in every Red-XAI app. ', h('a', { href: cfg.forgot_password, rel: 'noopener' }, 'Forgot your password?')));
}

// ---------- rules (mirror of the Red-XAI Accounts v1 contract; the server checks again) ----------
const SAFE_DEFAULT = '!#$%&()*+,-./:;=?@[]^_{|}~';
const EMAIL_RE = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;

export function usernameChecks(u) {
  const n = [...u].length;
  const letters = (u.match(/[A-Za-z]/g) || []).length;
  return [
    { id: 'length', ok: n >= 8 && n <= 32, message: '8 to 32 characters' },
    { id: 'chars', ok: n > 0 && /^[A-Za-z0-9_.-]+$/.test(u), message: 'Only letters, numbers, _ . and -' },
    { id: 'letters', ok: letters >= 3, message: 'At least 3 letters' },
  ];
}
export function passwordChecks(p, safe = SAFE_DEFAULT) {
  const n = [...p].length;
  const chars = [...p];
  const isSafe = (c) => safe.includes(c);
  return [
    { id: 'length', ok: n >= 12 && n <= 665, message: '12 to 665 characters' },
    { id: 'upper', ok: /[A-Z]/.test(p), message: 'An upper-case letter (A–Z)' },
    { id: 'lower', ok: /[a-z]/.test(p), message: 'A lower-case letter (a–z)' },
    { id: 'digit', ok: /[0-9]/.test(p), message: 'A number (0–9)' },
    { id: 'special', ok: chars.some(isSafe), message: 'A special character: ' + safe },
    { id: 'chars', ok: n > 0 && chars.every((c) => /[A-Za-z0-9]/.test(c) || isSafe(c)), message: 'No spaces, quotes, backslashes, backticks or < >' },
  ];
}
export function emailChecks(e) {
  e = e.trim();
  return [{ id: 'syntax', ok: e.length > 0 && e.length <= 254 && EMAIL_RE.test(e), message: 'A real email address, like name@example.com' }];
}
const NAME_MAX = 50;
function isNameChar(c) {
  return /\p{L}/u.test(c) || c === ' ' || c === "'" || c === '\u2019' || c === '-' || c === '.' || c === '\u2010' || c === '\u2011';
}
/** first/middle/last: 1–50 letters (any script), spaces, apostrophes, hyphens and periods; middle may be empty. */
export function nameChecks(value, required = true) {
  const s = String(value ?? '').trim();
  if (!required && s.length === 0) {
    return [
      { id: 'length', ok: true, message: 'Optional — 1 to 50 characters if you add one' },
      { id: 'chars', ok: true, message: 'Letters, spaces, apostrophes, hyphens and periods' },
      { id: 'letters', ok: true, message: 'At least one letter' },
    ];
  }
  const chars = [...s];
  const letters = chars.filter((c) => /\p{L}/u.test(c)).length;
  return [
    { id: 'length', ok: chars.length >= 1 && chars.length <= NAME_MAX, message: '1 to 50 characters' },
    { id: 'chars', ok: chars.length > 0 && chars.every(isNameChar), message: 'Letters, spaces, apostrophes, hyphens and periods' },
    { id: 'letters', ok: letters >= 1, message: 'At least one letter' },
  ];
}
/** Shown under the check-your-email screen. Empty when the server did not send an expiry. */
export function pendingUntilText(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 0) return '';
  return 'This sign-up is held until ' + new Date(n).toLocaleString() + '. If the email is not confirmed by then, the username and email can be used again.';
}
/** Sign-up failures. email_taken covers an address already in use, including an owner
 * address, and the wording stays the same either way. too_many_pending is final:
 * the form shows it and does not send the sign-up again. */
export function signupErrorText(err) {
  const body = (err && err.body) || {};
  const code = body.error || '';
  if (code === 'email_taken') return 'That email is already in use.';
  if (code === 'too_many_pending') return 'Too many pending sign-ups for this email. Verify one, or try again later.';
  if (body.message) return body.message;
  if (err && err.message && err.message !== code) return err.message;
  return 'The account could not be created. Try again.';
}
/** Rate-limit and other failures from POST /v1/auth/email/resend. */
export function resendErrorText(err) {
  const body = (err && err.body) || {};
  if (err && err.status === 429) {
    const sec = Number(body.retryAfter) > 0 ? Math.ceil(Number(body.retryAfter)) : 60;
    const base = body.message && body.message !== 'rate_limited' ? body.message : 'Too many verification emails from this network.';
    if (new RegExp('\\b' + sec + '\\b').test(base)) return base;
    return base.replace(/\s+$/, '') + ' Try again in ' + sec + ' seconds.';
  }
  if (body.message) return body.message;
  if (err && err.message && err.message !== 'rate_limited') return err.message;
  return 'The verification email could not be sent. Try again.';
}
/** Parses MM/DD/YYYY strictly; returns a Date (UTC) or null. */
export function parseDOB(s) {
  const m = /^(\d{2})\/(\d{2})\/(\d{4})$/.exec(s.trim());
  if (!m) return null;
  const [mo, d, y] = [+m[1], +m[2], +m[3]];
  const t = new Date(Date.UTC(y, mo - 1, d));
  return t.getUTCFullYear() === y && t.getUTCMonth() === mo - 1 && t.getUTCDate() === d ? t : null;
}
export function ageOn(birth, now = new Date()) {
  let y = now.getFullYear() - birth.getUTCFullYear();
  const md = (now.getMonth() + 1) * 100 + now.getDate();
  const bd = (birth.getUTCMonth() + 1) * 100 + birth.getUTCDate();
  if (md < bd) y--;
  return y;
}
/** Age is derived for the hint only; it is never stored. */
export function dobChecks(s, minAge = 13) {
  const t = parseDOB(s);
  const now = new Date();
  const today = Date.UTC(now.getFullYear(), now.getMonth(), now.getDate());
  const fmtOK = !!t && t.getTime() <= today;
  const age = fmtOK ? ageOn(t, now) : -1;
  const rangeOK = fmtOK && age >= 0 && age <= 100;
  return { age, checks: [
    { id: 'format', ok: fmtOK, message: 'MM/DD/YYYY, a real date, not in the future' },
    { id: 'range', ok: rangeOK, message: 'Age 0 to 100' },
    { id: 'min_age', ok: rangeOK && age >= minAge, message: `At least ${minAge} years old` },
  ] };
}
const allOK = (checks) => checks.every((c) => c.ok);

/** Shown when a live username/email check never reaches the server (after one retry). */
export const REMOTE_CHECK_OFFLINE = "Couldn't check — check your connection.";

/** True when the browser failed before any HTTP answer (VPN, offline, host unreachable). */
export function isUnreachable(err) {
  return !!err && err.status === 0;
}

/** Call fn, and once more if the first attempt never reached the server. */
export async function retryUnreachable(fn) {
  try {
    return await fn();
  } catch (e) {
    if (!isUnreachable(e)) throw e;
    return await fn();
  }
}

/** Message for a failed live check. Network failures do not claim redxd is down. */
export function remoteCheckMessage(err) {
  if (isUnreachable(err)) return REMOTE_CHECK_OFFLINE;
  return 'Could not check right now: ' + (err && err.message ? err.message : 'error');
}

function hintList(id) {
  const ul = h('ul', { class: 'hints', id, 'aria-live': 'polite' });
  ul.show = (checks) => {
    ul.replaceChildren(...checks.map((c) => h('li', { class: 'hint-item ' + (c.ok ? 'good' : 'bad'), 'data-check': c.id },
      h('span', { class: 'hint-dot', 'aria-hidden': 'true' }, c.ok ? '✓' : '✕'), ' ', c.message, h('span', { class: 'sr-only' }, c.ok ? ' (done)' : ' (needed)'))));
  };
  return ul;
}

function copyArrow(from, to, label, after) {
  return h('button', { class: 'icon-btn copy-arrow', type: 'button', title: label, 'aria-label': label, onclick: () => { to.value = from.value; after(); } }, '⇅');
}

/** Resend the verification link. The login is the username. known hides the box when the sign-up already has it. */
export function emailResendControl({ login = '', known = false } = {}) {
  const input = h('input', { class: 'input', id: 'email-resend-login', type: 'text', autocomplete: 'username', maxlength: 32, value: login, 'aria-label': 'Username' });
  const btn = h('button', { class: 'btn', id: 'email-resend', type: 'button' }, 'Resend verification email');
  const note = h('p', { class: 'muted small', id: 'email-resend-note' });
  const err = h('div', { class: 'form-err', id: 'email-resend-err', role: 'alert', hidden: true });
  let timer = 0;
  const cooldown = (sec) => {
    clearTimeout(timer);
    let left = Math.max(1, Math.ceil(sec));
    const tick = () => {
      if (left <= 0) {
        btn.disabled = false;
        btn.textContent = 'Resend verification email';
        return;
      }
      btn.disabled = true;
      btn.textContent = 'Resend in ' + left + 's';
      left -= 1;
      timer = setTimeout(tick, 1000);
    };
    tick();
  };
  btn.onclick = async () => {
    const who = (known ? login : input.value).trim();
    err.hidden = true;
    note.textContent = '';
    if (!who || who.includes('@')) {
      err.textContent = 'Enter your username. Resend uses the username, not the email address.';
      err.hidden = false;
      return;
    }
    btn.disabled = true;
    try {
      await api('POST', '/v1/auth/email/resend', { key: '', noAuthRedirect: true, json: { login: who } });
      note.textContent = known
        ? 'Another link is on its way. It can take a minute to arrive.'
        : 'If that account is waiting for a confirmation email, another link is on its way.';
      cooldown(60);
    } catch (e) {
      err.textContent = resendErrorText(e);
      err.hidden = false;
      if (e.status === 429) cooldown(Number(e.body && e.body.retryAfter) > 0 ? Number(e.body.retryAfter) : 60);
      else btn.disabled = false;
    }
  };
  const kids = [];
  if (!known) kids.push(h('label', { class: 'field' }, h('span', { class: 'field-label' }, 'Username'), input));
  kids.push(btn, note, err);
  return h('div', { class: 'email-resend', id: 'email-resend-box' }, kids);
}

// ---------- sign-up ----------
export function renderSignup(onBack) {
  const card = h('div', { class: 'auth-card wide signup' });
  const back = h('button', { class: 'btn small', type: 'button', onclick: onBack }, '← Back to sign in');
  card.append(h('div', { class: 'row gap' }, back), h('h2', null, 'Create a Red-XAI Account'), h('p', { class: 'muted' }, 'Loading the Terms of Service…'));
  (async () => {
    let tos, rules;
    try {
      [tos, rules] = await Promise.all([api('GET', '/v1/auth/tos', { key: '', noAuthRedirect: true }), api('GET', '/v1/auth/rules', { key: '', noAuthRedirect: true })]);
    } catch (e) {
      card.replaceChildren(h('div', { class: 'row gap' }, back), h('h2', null, 'Create a Red-XAI Account'), h('div', { class: 'form-err', role: 'alert' }, e.message));
      return;
    }
    tosStep(card, back, tos, rules);
  })();
  return h('div', { class: 'auth' }, card);
}

function tosStep(card, back, tos, rules) {
  const box = h('div', { class: 'tos-box', id: 'tos-box', tabindex: '0', role: 'document', 'aria-label': 'Terms of Service' }, tos.text);
  const readBtn = h('button', { class: 'btn', id: 'tos-read', type: 'button', disabled: true }, 'Read ToS');
  const agreeBtn = h('button', { class: 'btn primary', id: 'tos-agree', type: 'button', disabled: true }, 'Agree to ToS');
  const note = h('p', { class: 'muted small', id: 'tos-note' }, 'Scroll to the bottom of the terms to continue.');
  const err = h('div', { class: 'form-err', role: 'alert', hidden: true });
  let grant = '';
  const atBottom = () => box.scrollTop + box.clientHeight >= box.scrollHeight - 4;
  const check = () => { if (!grant && atBottom()) { readBtn.disabled = false; note.textContent = 'Now click “Read ToS”.'; } };
  box.addEventListener('scroll', check);
  setTimeout(check, 50);
  readBtn.onclick = async () => {
    readBtn.disabled = true;
    err.hidden = true;
    try {
      const r = await api('POST', '/v1/auth/tos/read', { key: '', noAuthRedirect: true, json: { version: tos.version } });
      grant = r.grant;
      agreeBtn.disabled = false;
      note.textContent = 'You read the terms. Click “Agree to ToS” to accept them.';
    } catch (e) { err.textContent = e.message; err.hidden = false; readBtn.disabled = false; }
  };
  agreeBtn.onclick = async () => {
    agreeBtn.disabled = true;
    try {
      const r = await api('POST', '/v1/auth/tos/agree', { key: '', noAuthRedirect: true, json: { grant } });
      formStep(card, back, tos, rules, { grant: r.grant, version: tos.version, agreedAt: new Date() });
    } catch (e) { err.textContent = e.message; err.hidden = false; agreeBtn.disabled = false; }
  };
  card.replaceChildren(h('div', { class: 'row gap' }, back), h('h2', null, tos.title || 'Terms of Service'),
    h('p', { class: 'muted small' }, 'Version ' + tos.version), box, note, err, h('div', { class: 'row gap tos-actions' }, readBtn, agreeBtn));
}

function formStep(card, back, tos, rules, accepted) {
  const safe = (rules.password && rules.password.safeSpecials) || SAFE_DEFAULT;
  const minAge = Math.max(13, rules.minAge || 13);
  const inp = (id, attrs = {}) => h('input', { class: 'input', id, name: id, autocomplete: 'off', spellcheck: 'false', ...attrs });
  const first = inp('su-first', { autocomplete: 'given-name', maxlength: 80 });
  const middle = inp('su-middle', { autocomplete: 'additional-name', maxlength: 80 });
  const last = inp('su-last', { autocomplete: 'family-name', maxlength: 80 });
  const user = inp('su-username', { autocomplete: 'username', maxlength: 64 });
  const email = inp('su-email', { type: 'email', autocomplete: 'email', maxlength: 254 });
  const email2 = inp('su-email2', { type: 'email', maxlength: 254, 'aria-label': 'Confirm email' });
  const pass = inp('su-password', { type: 'password', autocomplete: 'new-password', maxlength: 665 });
  const pass2 = inp('su-password2', { type: 'password', autocomplete: 'new-password', maxlength: 665, 'aria-label': 'Confirm password' });
  const dob = inp('su-dob', { placeholder: 'MM/DD/YYYY', inputmode: 'numeric', maxlength: 10 });
  const cal = h('input', { class: 'input cal', id: 'su-dob-cal', type: 'date', 'aria-label': 'Pick your date of birth from a calendar' });
  const phone = inp('su-phone', { type: 'tel', placeholder: '+15555550123', autocomplete: 'tel' });
  const ackFalse = h('input', { type: 'checkbox', id: 'su-ack-false' });
  const ackNo2fa = h('input', { type: 'checkbox', id: 'su-ack-no2fa' });
  const hF = hintList('hints-first'); const hM = hintList('hints-middle'); const hL = hintList('hints-last');
  const hU = hintList('hints-username'); const hE = hintList('hints-email'); const hE2 = hintList('hints-email2');
  const hP = hintList('hints-password'); const hP2 = hintList('hints-password2'); const hD = hintList('hints-dob');
  const ageNote = h('div', { class: 'form-err', id: 'su-age-block', role: 'alert', hidden: true }, `You must be at least ${minAge} to create a Red-XAI Account.`);
  const remote = { username: null, email: null };
  const today = new Date();
  cal.max = today.toISOString().slice(0, 10);
  cal.min = (today.getFullYear() - 100) + '-01-01';

  const tfaOpts = [
    ['phone', 'Phone', 'A code by text message when you sign in.'],
    ['app', 'App', 'An authenticator app (Google Authenticator, 1Password, Authy…).'],
    ['redxai_auth', 'Red-XAI Auth', 'Coming soon'],
    ['none', 'None', 'Not recommended.'],
  ];
  let tfa = 'app';
  const phoneRow = h('div', { class: 'tfa-extra', hidden: true }, h('label', { class: 'field' }, h('span', { class: 'field-label' }, 'Phone number with country code'), phone));
  const noneRow = h('div', { class: 'tfa-extra warn-box', id: 'su-no2fa-warning', hidden: true }, icon('alert', 16), ' ',
    tos.no2faWarning || 'Without two-factor authentication anyone who learns your password can take over your account.',
    h('label', { class: 'check' }, ackNo2fa, ' I understand and accept this risk'));
  const tfaGroup = h('div', { class: 'tfa', role: 'radiogroup', 'aria-label': 'Two-factor authentication' },
    tfaOpts.map(([v, label, sub]) => {
      const dis = v === 'redxai_auth';
      const r = h('input', { type: 'radio', name: 'su-2fa', value: v, id: 'su-2fa-' + v, checked: v === tfa, disabled: dis });
      r.addEventListener('change', () => { tfa = v; phoneRow.hidden = v !== 'phone'; noneRow.hidden = v !== 'none'; update(); });
      return h('label', { class: 'tfa-opt' + (dis ? ' disabled' : ''), for: 'su-2fa-' + v }, r,
        h('span', null, h('b', null, label), dis ? h('span', { class: 'chip soon' }, 'Coming soon') : null, h('small', { class: 'muted' }, ' ' + sub)));
    }));

  const submit = h('button', { class: 'btn primary big', id: 'su-submit', type: 'button', disabled: true }, 'Create account');
  const err = h('div', { class: 'form-err', id: 'su-err', role: 'alert', hidden: true });

  function update() {
    const nf = nameChecks(first.value, true);
    const nm = nameChecks(middle.value, false);
    const nl = nameChecks(last.value, true);
    hF.show(nf); hM.show(nm); hL.show(nl);
    const u = usernameChecks(user.value.trim());
    if (remote.username && remote.username.value === user.value.trim()) u.push(...remote.username.checks);
    hU.show(u);
    const e = emailChecks(email.value);
    if (remote.email && remote.email.value === email.value.trim()) e.push(...remote.email.checks);
    hE.show(e);
    const e2 = [{ id: 'match', ok: email2.value.trim() !== '' && email2.value.trim().toLowerCase() === email.value.trim().toLowerCase(), message: 'Both email addresses match' }];
    hE2.show(e2);
    const p = passwordChecks(pass.value, safe);
    hP.show(p);
    const p2 = [{ id: 'match', ok: pass2.value !== '' && pass2.value === pass.value, message: 'Both passwords match' }];
    hP2.show(p2);
    const d = dobChecks(dob.value, minAge);
    hD.show(d.checks);
    ageNote.hidden = !(d.checks[1].ok && !d.checks[2].ok);
    const tfaOK = tfa === 'app' || (tfa === 'phone' && /^\+[1-9][0-9]{7,14}$/.test(phone.value.trim())) || (tfa === 'none' && ackNo2fa.checked);
    const remoteOK = remote.username && remote.username.value === user.value.trim() && allOK(remote.username.checks) &&
      remote.email && remote.email.value === email.value.trim() && allOK(remote.email.checks);
    submit.disabled = !(allOK(nf) && allOK(nm) && allOK(nl) && allOK(u) && allOK(e) && allOK(e2) && allOK(p) && allOK(p2) && allOK(d.checks) && ackFalse.checked && tfaOK && remoteOK);
  }
  const checkRemote = (field, input) => debounce(async () => {
    const v = input.value.trim();
    const local = field === 'username' ? usernameChecks(v) : emailChecks(v);
    if (!allOK(local)) return;
    const post = () => api('POST', '/v1/auth/validate/' + field, { key: '', noAuthRedirect: true, json: { [field]: v } });
    try {
      // One retry: a VPN or a blip used to look like "redxd is down" on the first failure.
      const r = await retryUnreachable(post);
      const have = new Set(local.map((c) => c.id));
      remote[field] = { value: v, checks: (r.checks || []).filter((c) => !have.has(c.id)) };
    } catch (e2) {
      // The server checks every field again on submit; this hint is only for the form.
      remote[field] = { value: v, checks: [{ id: 'available', ok: false, message: remoteCheckMessage(e2) }] };
    }
    update();
  }, 350);
  const ru = checkRemote('username', user); const re = checkRemote('email', email);
  [first, middle, last].forEach((x) => x.addEventListener('input', update));
  user.addEventListener('input', () => { update(); ru(); });
  email.addEventListener('input', () => { update(); re(); });
  [email2, pass, pass2, phone].forEach((x) => x.addEventListener('input', update));
  [ackFalse, ackNo2fa].forEach((x) => x.addEventListener('change', update));
  dob.addEventListener('input', () => {
    // typing 07042001 becomes 07/04/2001
    const digits = dob.value.replace(/[^0-9]/g, '').slice(0, 8);
    if (!dob.value.includes('/') || /^\d{2}\/\d{2}\/\d{0,4}$/.test(dob.value) === false) {
      dob.value = digits.length > 4 ? digits.slice(0, 2) + '/' + digits.slice(2, 4) + '/' + digits.slice(4) : digits.length > 2 ? digits.slice(0, 2) + '/' + digits.slice(2) : digits;
    }
    const t = parseDOB(dob.value);
    cal.value = t ? t.toISOString().slice(0, 10) : '';
    update();
  });
  cal.addEventListener('change', () => {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(cal.value);
    if (m) dob.value = `${m[2]}/${m[3]}/${m[1]}`;
    update();
  });

  submit.onclick = async () => {
    submit.disabled = true;
    err.hidden = true;
    const body = { firstName: first.value.trim(), middleName: middle.value.trim(), lastName: last.value.trim(),
      username: user.value.trim(), password: pass.value, passwordConfirm: pass2.value, email: email.value.trim(), emailConfirm: email2.value.trim(),
      dob: dob.value.trim(), tosGrant: accepted.grant, twoFactor: tfa, phone: tfa === 'phone' ? phone.value.trim() : '', acceptNo2faRisk: tfa === 'none' && ackNo2fa.checked,
      acknowledgeFalseInfo: ackFalse.checked };
    try {
      const r = await api('POST', '/v1/auth/signup', { key: '', noAuthRedirect: true, json: body });
      pass.value = pass2.value = '';
      if (r.step === 'verify_email' && !r.handle) checkEmailStep(card, r);
      else twoFAStep(card, r);
    } catch (e) {
      const b = e.body || {};
      // One attempt. too_many_pending and email_taken are answers, not transient failures.
      err.textContent = signupErrorText(e);
      err.hidden = false;
      if (b.error === 'tos_grant_invalid' || b.error === 'tos_changed') { toast('Please read and agree to the terms again.', 'warn'); tosStep(card, h('span'), tos, rules); return; }
      update();
    }
  };

  const fld = (label, input, hints, extra) => h('div', { class: 'field' }, h('label', { class: 'field-label', for: input.id }, label), extra ? h('div', { class: 'row gap tight' }, input, extra) : input, hints);
  card.replaceChildren(
    h('div', { class: 'row gap' }, back),
    h('h2', null, 'Create a Red-XAI Account'),
    h('p', { class: 'ok-text small', id: 'tos-accepted' }, icon('check', 14), ` You agreed to the Terms of Service (version ${accepted.version}) at ${accepted.agreedAt.toLocaleString()}.`),
    fld('First name', first, hF),
    fld('Middle name (optional)', middle, hM),
    fld('Last name', last, hL),
    fld('Username', user, hU),
    fld('Email', email, hE),
    fld('Confirm email', email2, hE2, copyArrow(email, email2, 'Copy the email into the confirm box', update)),
    fld('Password', pass, hP),
    fld('Confirm password', pass2, hP2, copyArrow(pass, pass2, 'Copy the password into the confirm box', update)),
    fld('Date of birth (MM/DD/YYYY)', dob, hD, cal),
    ageNote,
    h('p', { class: 'muted small' }, 'Your age is worked out from your date of birth when needed. RedX never stores your age or your date of birth.'),
    h('div', { class: 'warn-box', id: 'su-false-info' }, icon('alert', 16), ' ',
      tos.falseInfoWarning || 'If you give false information, the account cannot be recovered.',
      h('label', { class: 'check' }, ackFalse, ' I understand: false information means my account cannot be recovered')),
    h('h3', null, 'Two-factor authentication'), tfaGroup, phoneRow, noneRow,
    err, submit);
  update();
}

/** Check-your-email page after sign-up, and after an unverified sign-in (email_unverified). */
export function renderUnverified(login, onBack) {
  const card = h('div', { class: 'auth-card wide signup' });
  const back = h('button', { class: 'btn small', id: 'su-check-back', type: 'button', onclick: onBack }, '← Back to sign in');
  const raw = String(login || '').trim();
  const email = raw.includes('@') ? raw : '';
  checkEmailStep(card, { account: { email, username: email ? '' : raw }, emailSent: true, signIn: true }, back);
  return h('div', { class: 'auth' }, card);
}

function checkEmailStep(card, r, back) {
  const email = (r.account && r.account.email) || '';
  const username = (r.account && r.account.username) || '';
  const shown = email || r.emailMasked || '';
  const failed = r.emailSent === false;
  const parts = [];
  if (back) parts.push(h('div', { class: 'row gap' }, back));
  parts.push(h('h2', { id: 'su-check-email' }, 'Check your email'));
  if (r.signIn) parts.push(h('p', null, 'This account’s email is not confirmed yet. Open the link we sent, then sign in.'));
  if (shown) {
    parts.push(failed
      ? h('p', null, 'The verification email to ', h('b', { id: 'su-check-address' }, shown), ' could not be sent just now.')
      : h('p', null, 'We sent a verification link to ', h('b', { id: 'su-check-address' }, shown), '.'));
  } else {
    parts.push(h('p', { id: 'su-check-address' }, failed
      ? 'The verification email could not be sent just now.'
      : 'We sent a verification link to the email address on this account.'));
  }
  parts.push(h('p', null, failed
    ? 'Use Resend to try again. The account cannot sign in until you open the link.'
    : 'Open the link in that email, then sign in. The account cannot sign in until the link is opened.'));
  if (r.message) parts.push(h('p', { class: 'muted' }, r.message));
  const hold = pendingUntilText(r.pendingUntilMs);
  if (hold) parts.push(h('p', { class: 'muted small', id: 'su-pending-until' }, hold));
  // The authenticator key is returned once, on the first sign-up. A resume does not include it.
  if (!r.resumed && r.totp && r.totp.secret) {
    const cv = h('canvas', { class: 'qr', id: 'su-totp-qr', 'aria-label': 'QR code for your authenticator app' });
    try { drawQR(cv, r.totp.otpauthUri, { scale: 5 }); } catch { /* the secret below still works */ }
    parts.push(h('h3', null, 'Authenticator app'),
      h('p', null, 'Add this key to your authenticator app now. It is shown only this once. You confirm the code after you sign in, not during sign-up.'),
      cv, h('div', { class: 'keybox' }, h('code', { id: 'su-totp-secret' }, r.totp.secret)));
  } else if (r.resumed && r.twoFactor === 'app') {
    const link = h('a', { id: 'su-2fa-reenroll', rel: 'noopener' }, 'Red-XAI Account');
    if (cfgCache && cfgCache.hosted_account) link.href = cfgCache.hosted_account;
    parts.push(h('p', { id: 'su-2fa-reenroll-note' },
      'That key was shown only once, on the first sign-up. After you open the email link and sign in, re-enrol two-factor authentication from your ', link, ' page if you no longer have it.'));
    if (!cfgCache || !cfgCache.hosted_account) {
      accountsConfig().then((cfg) => { if (cfg && cfg.hosted_account) link.href = cfg.hosted_account; }).catch(() => {});
    }
  }
  parts.push(emailResendControl({ login: username, known: !!username }));
  parts.push(h('a', { class: 'btn primary big', id: 'su-signin', href: '/v1/auth/login' }, 'Sign in with Red-XAI Account'),
    h('p', { class: 'muted small' }, 'Sign in only after you open the link in the email.'));
  card.replaceChildren(...parts);
}

function twoFAStep(card, r) {
  const done = () => card.replaceChildren(h('h2', null, 'Your Red-XAI Account is ready'),
    h('p', null, 'We sent a verification email to ', h('b', null, r.account && r.account.email || 'your address'), '. Confirm it, then sign in.'),
    h('a', { class: 'btn primary big', id: 'su-signin', href: '/v1/auth/login' }, 'Sign in with Red-XAI Account'));
  if (!r.handle) return done();
  const code = h('input', { class: 'input mono', id: 'su-2fa-code', inputmode: 'numeric', maxlength: 8, autocomplete: 'one-time-code', placeholder: '123456' });
  const err = h('div', { class: 'form-err', role: 'alert', hidden: true });
  const go = h('button', { class: 'btn primary big', id: 'su-2fa-go', type: 'button' }, 'Turn on two-factor authentication');
  go.onclick = async () => {
    go.disabled = true;
    err.hidden = true;
    try {
      await api('POST', '/v1/auth/signup/2fa', { key: '', noAuthRedirect: true, json: { handle: r.handle, code: code.value } });
      done();
    } catch (e) { err.textContent = (e.body && e.body.message) || e.message; err.hidden = false; go.disabled = false; }
  };
  const parts = [h('h2', null, 'Set up two-factor authentication')];
  if (r.totp) {
    const cv = h('canvas', { class: 'qr', id: 'su-totp-qr', 'aria-label': 'QR code for your authenticator app' });
    try { drawQR(cv, r.totp.otpauthUri, { scale: 5 }); } catch { /* the secret below still works */ }
    parts.push(h('p', null, 'Scan this with your authenticator app, or type the key by hand. Then enter the 6-digit code it shows.'), cv,
      h('div', { class: 'keybox' }, h('code', { id: 'su-totp-secret' }, r.totp.secret)));
  } else {
    parts.push(h('p', null, 'We sent a code by text message. Enter it below.'));
  }
  parts.push(h('label', { class: 'field' }, h('span', { class: 'field-label' }, 'Code'), code), err, go);
  if (!r.totp && cfgCache && cfgCache.sms_resend) {
    const resend = h('button', { class: 'btn', id: 'su-2fa-resend', type: 'button' }, 'Resend text message');
    let busy = false;
    resend.onclick = async () => {
      if (busy) return;
      busy = true; resend.disabled = true; err.hidden = true;
      try {
        await api('POST', '/v1/auth/signup/2fa/resend', { key: '', noAuthRedirect: true, json: { handle: r.handle } });
        toast('Another code is on its way.', 'ok');
      } catch (e) { err.textContent = (e.body && e.body.message) || e.message; err.hidden = false; }
      setTimeout(() => { busy = false; resend.disabled = false; }, 30000);
    };
    parts.push(resend);
  }
  card.replaceChildren(...parts);
}

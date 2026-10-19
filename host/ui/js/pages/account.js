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
    submit.disabled = !(allOK(u) && allOK(e) && allOK(e2) && allOK(p) && allOK(p2) && allOK(d.checks) && ackFalse.checked && tfaOK && remoteOK);
  }
  const checkRemote = (field, input) => debounce(async () => {
    const v = input.value.trim();
    const local = field === 'username' ? usernameChecks(v) : emailChecks(v);
    if (!allOK(local)) return;
    try {
      const r = await api('POST', '/v1/auth/validate/' + field, { key: '', noAuthRedirect: true, json: { [field]: v } });
      const have = new Set(local.map((c) => c.id));
      remote[field] = { value: v, checks: (r.checks || []).filter((c) => !have.has(c.id)) };
    } catch (e2) {
      remote[field] = { value: v, checks: [{ id: 'available', ok: false, message: 'Could not check right now: ' + e2.message }] };
    }
    update();
  }, 350);
  const ru = checkRemote('username', user); const re = checkRemote('email', email);
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
    const body = { username: user.value.trim(), password: pass.value, passwordConfirm: pass2.value, email: email.value.trim(), emailConfirm: email2.value.trim(),
      dob: dob.value.trim(), tosGrant: accepted.grant, twoFactor: tfa, phone: tfa === 'phone' ? phone.value.trim() : '', acceptNo2faRisk: tfa === 'none' && ackNo2fa.checked,
      acknowledgeFalseInfo: ackFalse.checked };
    try {
      const r = await api('POST', '/v1/auth/signup', { key: '', noAuthRedirect: true, json: body });
      pass.value = pass2.value = '';
      twoFAStep(card, r);
    } catch (e) {
      const b = e.body || {};
      err.textContent = b.message || e.message;
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
  card.replaceChildren(...parts);
}

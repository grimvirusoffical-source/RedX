// A small code editor: a transparent <textarea> over a highlighted <pre>. Line numbers, bracket
// matching, undo/redo, find/replace, auto-indent and auto-pairing, error squiggles with line:col,
// autocomplete. Vanilla JS, no dependencies.
import { tokenize, bracketAt, inStringOrComment, offsetOf, lineCol } from './tokenizers.js';

const LINE_H = 20;
const MAX_HL = 200000;

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

/**
 * @param {object} o
 * @param {'box'|'boxql'} [o.language]
 * @param {string} [o.value]
 * @param {boolean} [o.readOnly]
 * @param {string} [o.height]  css height, default 320px
 * @param {(v:string)=>void} [o.onChange]
 * @param {()=>void} [o.onRun]   Ctrl/Cmd+Enter
 * @param {()=>void} [o.onSave]  Ctrl/Cmd+S
 * @param {(text:string,pos:number)=>({from:number,items:{label:string,detail?:string,insert?:string}[]}|null)} [o.complete]
 */
export function createEditor(o = {}) {
  let lang = o.language || 'box';
  let readOnly = !!o.readOnly;
  const root = el('div', 'rx-editor');
  root.style.height = o.height || '320px';
  const findBar = el('div', 'rx-find');
  findBar.hidden = true;
  const body = el('div', 'rx-ebody');
  const gutter = el('div', 'rx-gutter');
  const gInner = el('div', 'rx-ginner');
  gutter.append(gInner);
  const scroller = el('div', 'rx-scroller');
  const hl = el('pre', 'rx-hl');
  hl.setAttribute('aria-hidden', 'true');
  const hlInner = el('div', 'rx-hlinner');
  hl.append(hlInner);
  const ta = el('textarea', 'rx-ta');
  ta.spellcheck = false;
  ta.setAttribute('autocapitalize', 'off');
  ta.setAttribute('autocomplete', 'off');
  ta.setAttribute('autocorrect', 'off');
  ta.setAttribute('wrap', 'off');
  ta.setAttribute('aria-label', 'Code editor');
  ta.value = o.value || '';
  ta.readOnly = readOnly;
  const popup = el('div', 'rx-pop');
  popup.hidden = true;
  const marks = el('div', 'rx-gmarks');
  gutter.append(marks);
  scroller.append(hl, ta, popup);
  body.append(gutter, scroller);
  const status = el('div', 'rx-status');
  const stPos = el('span', 'rx-stpos');
  const stMsg = el('button', 'rx-stmsg');
  stMsg.type = 'button';
  const stLang = el('span', 'rx-stlang');
  status.append(stPos, stMsg, stLang);
  root.append(findBar, body, status);

  // ---- state ----
  let toks = [];
  let toksFor = null;
  let diags = [];
  let findMarks = [];
  let findCur = -1;
  let undo = [];
  let redo = [];
  let cur = { v: ta.value, a: 0, b: 0 };
  let lastT = 0;
  let lastTyping = false;
  let acItems = null;
  let acSel = 0;
  let acFrom = 0;

  function tokensNow() {
    if (toksFor !== ta.value) {
      toks = ta.value.length > MAX_HL ? [] : tokenize(ta.value, lang);
      toksFor = ta.value;
    }
    return toks;
  }

  // ---- rendering ----
  function render() {
    const text = ta.value;
    const tk = tokensNow();
    const ms = [];
    // bracket matching
    const pos = ta.selectionStart;
    if (ta.selectionStart === ta.selectionEnd && tk.length) {
      const bi = bracketAt(tk, pos);
      if (bi >= 0) {
        const b = tk[bi];
        if (b.p >= 0) {
          ms.push({ s: b.s, e: b.e, c: 'br-match' }, { s: tk[b.p].s, e: tk[b.p].e, c: 'br-match' });
        } else {
          ms.push({ s: b.s, e: b.e, c: 'br-bad' });
        }
      }
    }
    findMarks.forEach((m, k) => ms.push({ s: m.s, e: m.e, c: k === findCur ? 'find-cur' : 'find' }));
    diags.forEach((d) => { if (d.s != null) ms.push({ s: d.s, e: d.e, c: 'squiggle' }); });
    hlInner.textContent = '';
    if (text.length > MAX_HL) {
      hlInner.append(document.createTextNode(text + '\n'));
    } else {
      const pts = new Set([0, text.length]);
      for (const t of tk) { pts.add(t.s); pts.add(t.e); }
      for (const m of ms) { pts.add(Math.max(0, m.s)); pts.add(Math.min(text.length, m.e)); }
      const arr = [...pts].filter((p) => p >= 0 && p <= text.length).sort((a, b) => a - b);
      let ti = 0;
      const frag = document.createDocumentFragment();
      for (let k = 0; k + 1 < arr.length; k++) {
        const a = arr[k];
        const b = arr[k + 1];
        while (ti < tk.length && tk[ti].e <= a) ti++;
        const t = ti < tk.length && tk[ti].s <= a && a < tk[ti].e ? tk[ti].t : '';
        let cls = t ? 'tk-' + t : '';
        for (const m of ms) if (m.s <= a && b <= m.e) cls += ' ' + m.c;
        const piece = text.slice(a, b);
        if (cls) {
          const sp = document.createElement('span');
          sp.className = cls.trim();
          sp.textContent = piece;
          frag.append(sp);
        } else {
          frag.append(document.createTextNode(piece));
        }
      }
      frag.append(document.createTextNode('\n'));
      hlInner.append(frag);
    }
    renderGutter();
    renderStatus();
    syncScroll();
  }

  let lastLines = -1;
  function renderGutter() {
    const lines = ta.value.split('\n').length;
    if (lines !== lastLines) {
      lastLines = lines;
      const w = String(lines).length;
      gutter.style.width = Math.max(w, 2) * 8.2 + 24 + 'px';
      let s = '';
      for (let k = 1; k <= lines; k++) s += k + '\n';
      gInner.textContent = s;
    }
    marks.textContent = '';
    for (const d of diags) {
      const m = el('div', 'rx-gmark');
      m.style.top = (d.line - 1) * LINE_H + 'px';
      m.title = d.message || 'error';
      marks.append(m);
    }
    syncScroll();
  }

  function renderStatus() {
    const lc = lineCol(ta.value, ta.selectionStart);
    stPos.textContent = `Ln ${lc.line}, Col ${lc.col}`;
    stLang.textContent = (lang === 'boxql' ? 'BoxQL' : 'Box') + (readOnly ? ' · read-only' : '');
    if (diags.length) {
      const d = diags[0];
      stMsg.textContent = `${d.line}:${d.col} ${d.message}`;
      stMsg.className = 'rx-stmsg err';
      stMsg.title = 'Click to jump to the error';
    } else {
      stMsg.textContent = '';
      stMsg.className = 'rx-stmsg';
    }
  }

  function syncScroll() {
    hlInner.style.transform = `translate(${-ta.scrollLeft}px, ${-ta.scrollTop}px)`;
    gInner.style.transform = `translateY(${-ta.scrollTop}px)`;
    marks.style.transform = `translateY(${-ta.scrollTop}px)`;
  }

  // ---- editing primitives with our own undo stack ----
  function snapshot() { return { v: ta.value, a: ta.selectionStart, b: ta.selectionEnd }; }
  function pushUndo(prevState) {
    undo.push(prevState);
    if (undo.length > 500) undo.shift();
    redo = [];
  }
  function applyState(st) {
    const sl = ta.scrollLeft;
    const stp = ta.scrollTop;
    ta.value = st.v;
    ta.setSelectionRange(st.a, st.b);
    ta.scrollLeft = sl;
    ta.scrollTop = stp;
    cur = snapshot();
    changed(false);
  }
  function edit(start, end, text, selA, selB) {
    if (readOnly) return;
    pushUndo(cur.v === ta.value ? { ...cur } : snapshot());
    const v = ta.value;
    const sl = ta.scrollLeft;
    const stp = ta.scrollTop;
    ta.value = v.slice(0, start) + text + v.slice(end);
    const a = selA == null ? start + text.length : selA;
    ta.setSelectionRange(a, selB == null ? a : selB);
    ta.scrollLeft = sl;
    ta.scrollTop = stp;
    lastTyping = false;
    cur = snapshot();
    changed(true);
  }
  function changed(user) {
    closePopup();
    render();
    if (findBar.hidden === false) runFind(false);
    if (user && o.onChange) o.onChange(ta.value);
    if (!user && o.onChange) o.onChange(ta.value);
  }
  function doUndo() {
    if (!undo.length) return;
    redo.push(snapshot());
    applyState(undo.pop());
  }
  function doRedo() {
    if (!redo.length) return;
    undo.push(snapshot());
    applyState(redo.pop());
  }

  ta.addEventListener('beforeinput', (e) => {
    if (e.inputType === 'historyUndo') { e.preventDefault(); doUndo(); }
    else if (e.inputType === 'historyRedo') { e.preventDefault(); doRedo(); }
  });
  ta.addEventListener('input', (e) => {
    const now = Date.now();
    const typing = e.inputType === 'insertText' || e.inputType === 'deleteContentBackward' || e.inputType === 'deleteContentForward';
    if (!(typing && lastTyping && now - lastT < 700 && undo.length)) pushUndo({ ...cur });
    redo = [];
    lastTyping = typing;
    lastT = now;
    cur = snapshot();
    toksFor = null;
    render();
    if (findBar.hidden === false) runFind(false);
    if (o.onChange) o.onChange(ta.value);
    if (typing && e.data && /[\w{:$.]/.test(e.data)) autocomplete(false);
    else closePopup();
  });
  const selUpdate = () => { cur = { v: cur.v, a: ta.selectionStart, b: ta.selectionEnd }; if (cur.v !== ta.value) cur = snapshot(); renderStatusAndBrackets(); };
  function renderStatusAndBrackets() { render(); }
  ta.addEventListener('keyup', (e) => { if (!/^(Shift|Control|Meta|Alt)$/.test(e.key)) selUpdate(); });
  ta.addEventListener('mouseup', selUpdate);
  ta.addEventListener('focus', selUpdate);
  ta.addEventListener('scroll', () => { syncScroll(); closePopup(); });
  stMsg.addEventListener('click', () => { if (diags[0]) goto(diags[0].line, diags[0].col); });

  const indentUnit = '    ';
  const closers = { '[': ']', '(': ')', '{': '}', '"': '"' };
  ta.addEventListener('keydown', (e) => {
    const mod = e.ctrlKey || e.metaKey;
    if (popup.hidden === false) {
      if (e.key === 'ArrowDown') { e.preventDefault(); acSel = (acSel + 1) % acItems.length; paintPopup(); return; }
      if (e.key === 'ArrowUp') { e.preventDefault(); acSel = (acSel - 1 + acItems.length) % acItems.length; paintPopup(); return; }
      if (e.key === 'Enter' || e.key === 'Tab') { e.preventDefault(); acceptPopup(); return; }
      if (e.key === 'Escape') { e.preventDefault(); closePopup(); return; }
    }
    if (mod && e.key.toLowerCase() === 'z' && !e.shiftKey) { e.preventDefault(); doUndo(); return; }
    if (mod && (e.key.toLowerCase() === 'y' || (e.key.toLowerCase() === 'z' && e.shiftKey))) { e.preventDefault(); doRedo(); return; }
    if (mod && e.key.toLowerCase() === 'f') { e.preventDefault(); openFind(); return; }
    if (mod && e.key === 'Enter') { e.preventDefault(); if (o.onRun) o.onRun(); return; }
    if (mod && e.key.toLowerCase() === 's') { e.preventDefault(); if (o.onSave) o.onSave(); return; }
    if (mod && e.key === ' ') { e.preventDefault(); autocomplete(true); return; }
    if (e.key === 'Escape' && !findBar.hidden) { closeFind(); return; }
    if (readOnly || mod || e.altKey) return;
    const v = ta.value;
    const a = ta.selectionStart;
    const b = ta.selectionEnd;
    if (e.key === 'Tab') {
      e.preventDefault();
      if (a !== b && v.slice(a, b).includes('\n') || e.shiftKey) {
        const ls = v.lastIndexOf('\n', a - 1) + 1;
        const seg = v.slice(ls, b);
        const out = e.shiftKey ? seg.replace(/^( {1,4}|\t)/gm, '') : seg.replace(/^/gm, indentUnit);
        edit(ls, b, out, ls, ls + out.length);
      } else {
        edit(a, b, indentUnit);
      }
      return;
    }
    if (e.key === 'Enter') {
      e.preventDefault();
      const ls = v.lastIndexOf('\n', a - 1) + 1;
      const line = v.slice(ls, a);
      const ind = /^[ \t]*/.exec(line)[0];
      const before = v.slice(0, a).trimEnd();
      const last = before[before.length - 1];
      const next = v[b];
      if ((last === '[' || last === '(' || last === '{') && closers[last] === next) {
        const ins = '\n' + ind + indentUnit + '\n' + ind;
        edit(a, b, ins, a + 1 + ind.length + indentUnit.length);
      } else if (last === '[' || last === '(' || last === '{' || last === ',' && false) {
        edit(a, b, '\n' + ind + indentUnit);
      } else {
        edit(a, b, '\n' + ind);
      }
      return;
    }
    if (e.key === 'Backspace' && a === b && a > 0) {
      const pc = v[a - 1];
      if (closers[pc] && v[a] === closers[pc]) { e.preventDefault(); edit(a - 1, a + 1, ''); return; }
    }
    if (e.key.length === 1) {
      const c = e.key;
      // over-type a closer
      if ((c === ']' || c === ')' || c === '}' || c === '"') && a === b && v[a] === c) { e.preventDefault(); ta.setSelectionRange(a + 1, a + 1); render(); return; }
      if (closers[c]) {
        const sk = inStringOrComment(tokensNow(), a);
        const nxt = v[b] || '';
        if (a !== b) { e.preventDefault(); edit(a, b, c + v.slice(a, b) + closers[c], a + 1, b + 1); return; }
        if (!sk && (c !== '"' || !/[\w\\]/.test(v[a - 1] || '')) && (nxt === '' || /[\s\])},:;]/.test(nxt))) {
          e.preventDefault();
          edit(a, b, c + closers[c], a + 1);
          return;
        }
      }
    }
  });

  // ---- autocomplete ----
  function autocomplete(force) {
    if (!o.complete || readOnly) return;
    const r = o.complete(ta.value, ta.selectionStart, force);
    if (!r || !r.items || !r.items.length) { closePopup(); return; }
    acItems = r.items.slice(0, 40);
    acFrom = r.from;
    acSel = 0;
    paintPopup();
  }
  function paintPopup() {
    popup.textContent = '';
    acItems.forEach((it, k) => {
      const row = el('div', 'rx-pi' + (k === acSel ? ' sel' : ''));
      row.append(el('span', 'rx-pl', it.label));
      if (it.detail) row.append(el('span', 'rx-pd', it.detail));
      row.addEventListener('mousedown', (ev) => { ev.preventDefault(); acSel = k; acceptPopup(); });
      popup.append(row);
    });
    const lc = lineCol(ta.value, acFrom);
    const x = (lc.col - 1) * charW() + 12 - ta.scrollLeft;
    const y = lc.line * LINE_H + 6 - ta.scrollTop;
    popup.style.left = Math.max(0, Math.min(x, scroller.clientWidth - 220)) + 'px';
    popup.style.top = Math.min(y, scroller.clientHeight - 30) + 'px';
    popup.hidden = false;
  }
  function closePopup() { popup.hidden = true; acItems = null; }
  function acceptPopup() {
    const it = acItems && acItems[acSel];
    if (!it) return closePopup();
    const ins = it.insert != null ? it.insert : it.label;
    const cursorAt = it.cursor != null ? it.cursor : ins.length;
    const a = ta.selectionStart;
    closePopup();
    edit(acFrom, a, ins, acFrom + cursorAt);
  }
  let cw = 0;
  function charW() {
    if (cw) return cw;
    const m = el('span', null, 'M'.repeat(50));
    m.style.cssText = 'position:absolute;visibility:hidden;white-space:pre;font:inherit';
    scroller.append(m);
    cw = m.getBoundingClientRect().width / 50 || 8;
    m.remove();
    return cw;
  }
  ta.addEventListener('blur', () => setTimeout(closePopup, 120));

  // ---- find / replace ----
  const fInput = el('input', 'rx-fi');
  fInput.placeholder = 'Find';
  fInput.setAttribute('aria-label', 'Find');
  const rInput = el('input', 'rx-fi');
  rInput.placeholder = 'Replace';
  rInput.setAttribute('aria-label', 'Replace with');
  const fCount = el('span', 'rx-fc');
  const mk = (t, title, fn) => { const b = el('button', 'rx-fb', t); b.type = 'button'; b.title = title; b.addEventListener('click', fn); return b; };
  let matchCase = false;
  const caseBtn = mk('Aa', 'Match case', () => { matchCase = !matchCase; caseBtn.classList.toggle('on', matchCase); runFind(true); });
  findBar.append(fInput, mk('↑', 'Previous (Shift+Enter)', () => stepFind(-1)), mk('↓', 'Next (Enter)', () => stepFind(1)), caseBtn, fCount,
    rInput, mk('Replace', 'Replace this match', replaceOne), mk('All', 'Replace all', replaceAll), mk('✕', 'Close (Esc)', closeFind));
  fInput.addEventListener('input', () => runFind(true));
  fInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); stepFind(e.shiftKey ? -1 : 1); }
    if (e.key === 'Escape') { e.preventDefault(); closeFind(); }
  });
  rInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); replaceOne(); }
    if (e.key === 'Escape') { e.preventDefault(); closeFind(); }
  });
  function openFind() {
    findBar.hidden = false;
    const sel = ta.value.slice(ta.selectionStart, ta.selectionEnd);
    if (sel && !sel.includes('\n')) fInput.value = sel;
    fInput.focus();
    fInput.select();
    runFind(true);
  }
  function closeFind() { findBar.hidden = true; findMarks = []; findCur = -1; render(); ta.focus(); }
  function runFind(jump) {
    const q = fInput.value;
    findMarks = [];
    if (q) {
      const hay = matchCase ? ta.value : ta.value.toLowerCase();
      const nd = matchCase ? q : q.toLowerCase();
      for (let i = hay.indexOf(nd); i >= 0 && findMarks.length < 5000; i = hay.indexOf(nd, i + Math.max(nd.length, 1))) findMarks.push({ s: i, e: i + nd.length });
    }
    if (findCur >= findMarks.length) findCur = findMarks.length - 1;
    if (jump && findMarks.length) {
      const p = ta.selectionStart;
      findCur = Math.max(0, findMarks.findIndex((m) => m.s >= p));
      reveal(findMarks[findCur].s);
    } else if (!findMarks.length) findCur = -1;
    fCount.textContent = q ? (findMarks.length ? `${findCur + 1}/${findMarks.length}` : 'none') : '';
    render();
  }
  function stepFind(d) {
    if (!findMarks.length) return;
    findCur = (findCur + d + findMarks.length) % findMarks.length;
    reveal(findMarks[findCur].s);
    fCount.textContent = `${findCur + 1}/${findMarks.length}`;
    render();
  }
  function replaceOne() {
    if (readOnly || findCur < 0) return;
    const m = findMarks[findCur];
    edit(m.s, m.e, rInput.value);
  }
  function replaceAll() {
    if (readOnly || !findMarks.length) return;
    const q = fInput.value;
    const re = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), matchCase ? 'g' : 'gi');
    const out = ta.value.replace(re, () => rInput.value);
    edit(0, ta.value.length, out, 0);
  }
  function reveal(pos) {
    const lc = lineCol(ta.value, pos);
    const y = (lc.line - 1) * LINE_H;
    if (y < ta.scrollTop || y > ta.scrollTop + ta.clientHeight - LINE_H * 2) ta.scrollTop = Math.max(0, y - ta.clientHeight / 2);
    const x = (lc.col - 1) * charW();
    if (x < ta.scrollLeft || x > ta.scrollLeft + ta.clientWidth - 40) ta.scrollLeft = Math.max(0, x - 80);
  }

  // ---- public API ----
  function goto(line, col) {
    const off = offsetOf(ta.value, line, col);
    ta.focus();
    ta.setSelectionRange(off, off);
    reveal(off);
    render();
  }
  function setDiagnostics(list) {
    const text = ta.value;
    diags = (list || []).map((d) => {
      const s = offsetOf(text, d.line, d.col);
      let e = s + (d.len || 0);
      if (!d.len) {
        const t = tokensNow().find((x) => x.s <= s && s < x.e);
        e = t ? t.e : Math.min(text.length, s + 1);
        if (e === s) e = Math.min(text.length, s + 1);
      }
      return { ...d, s, e: Math.max(e, s) };
    });
    render();
  }
  function setValue(v, keepUndo) {
    ta.value = v;
    if (!keepUndo) { undo = []; redo = []; }
    cur = snapshot();
    toksFor = null;
    diags = [];
    closePopup();
    render();
  }
  function setLanguage(l) { lang = l; toksFor = null; render(); }
  function setReadOnly(r) { readOnly = r; ta.readOnly = r; render(); }
  function insertAtCursor(text) { edit(ta.selectionStart, ta.selectionEnd, text); ta.focus(); }

  // initial paint after layout
  render();
  return {
    el: root,
    textarea: ta,
    getValue: () => ta.value,
    setValue,
    setLanguage,
    setReadOnly,
    setDiagnostics,
    clearDiagnostics: () => setDiagnostics([]),
    goto,
    focus: () => ta.focus(),
    insertAtCursor,
    openFind,
    undo: doUndo,
    redo: doRedo,
    getCaret: () => ta.selectionStart,
    tokens: () => tokensNow(),
  };
}

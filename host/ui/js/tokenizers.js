// Tokenizers for Box text (.red-xai.db, -qs, -qs-ls, -link, -pulse, -sec, -code files) and BoxQL commands.
// Pure functions with no DOM access, so they can be unit-tested with `node --test`.
//
// A token is {s, e, t, p}: start offset, end offset (exclusive), type, and for brackets the index
// of the partner token (-1 when unmatched). Whitespace is not tokenized.

export const VERBS = ['Get', 'Add', 'Set', 'Delete', 'Require', 'Tx', 'Explain', 'Watch'];
export const OPTIONS = ['Sort', 'Limit', 'Offset', 'Group', 'Topic', 'Count'];
export const FUNCTIONS = ['Count', 'Sum', 'Avg', 'Min', 'Max'];
export const KEYWORDS = ['TRUE', 'FALSE', 'NELL'];
export const WORD_OPS = ['in', 'starts', 'has', 'hasany'];

const isIdStart = (c) => /[A-Za-z_]/.test(c);
const isIdPart = (c) => /[A-Za-z0-9_-]/.test(c);
const isDigit = (c) => c >= '0' && c <= '9';

// token types that end an operand (so a following '-' is an operator, not a sign)
const OPERAND_END = new Set(['ident', 'field', 'box', 'file', 'number', 'string', 'keyword', 'param', 'function']);

/**
 * @param {string} text
 * @param {'box'|'boxql'} lang
 * @returns {{s:number,e:number,t:string,p:number}[]}
 */
export function tokenize(text, lang = 'box') {
  const toks = [];
  const n = text.length;
  const stack = []; // {kind, idx}
  let i = 0;
  let prev = null; // previous significant token
  let afterBrace = false;
  const push = (s, e, t) => {
    const tok = { s, e, t, p: -1 };
    toks.push(tok);
    prev = tok;
    return tok;
  };
  const nextNonSpace = (j) => {
    while (j < n && /\s/.test(text[j])) j++;
    return j;
  };
  while (i < n) {
    const c = text[i];
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') { i++; continue; }
    // comment << ... >>
    if (c === '<' && text[i + 1] === '<') {
      const end = text.indexOf('>>', i + 2);
      const e = end < 0 ? n : end + 2;
      const tok = { s: i, e, t: 'comment', p: -1 };
      toks.push(tok); // comments are whitespace: they do not change `prev`
      i = e;
      continue;
    }
    // string
    if (c === '"') {
      let j = i + 1;
      let closed = false;
      while (j < n) {
        if (text[j] === '\\') { j += 2; continue; }
        if (text[j] === '"') { closed = true; j++; break; }
        if (text[j] === '\n') break;
        j++;
      }
      if (j > n) j = n;
      push(i, j, closed ? 'string' : 'error');
      afterBrace = false;
      i = j;
      continue;
    }
    // parameter
    if (c === '$' && i + 1 < n && isIdStart(text[i + 1])) {
      let j = i + 1;
      while (j < n && isIdPart(text[j])) j++;
      push(i, j, 'param');
      afterBrace = false;
      i = j;
      continue;
    }
    // TTL marker (3600) (~5) (30)* (N@T)
    if (c === '(') {
      const m = /^\(\s*~?\d+(\s*@\s*\d+)?\s*\)\*?/.exec(text.slice(i, i + 64));
      if (m) {
        push(i, i + m[0].length, 'ttl');
        afterBrace = false;
        i += m[0].length;
        continue;
      }
    }
    // number (a '-' is a sign only where an operand is expected)
    if (isDigit(c) || (c === '-' && isDigit(text[i + 1] || '') && !(prev && OPERAND_END.has(prev.t)) && !(prev && (prev.t === 'punct' && (prev.x === ']' || prev.x === ')'))))) {
      let j = i + (c === '-' ? 1 : 0);
      while (j < n && isDigit(text[j])) j++;
      if (text[j] === '.' && isDigit(text[j + 1] || '')) { j++; while (j < n && isDigit(text[j])) j++; }
      if ((text[j] === 'e' || text[j] === 'E') && (isDigit(text[j + 1] || '') || ((text[j + 1] === '+' || text[j + 1] === '-') && isDigit(text[j + 2] || '')))) {
        j += 2;
        while (j < n && isDigit(text[j])) j++;
      }
      push(i, j, 'number');
      afterBrace = false;
      i = j;
      continue;
    }
    // identifier / keyword / verb / field ...
    if (isIdStart(c)) {
      let j = i + 1;
      while (j < n && isIdPart(text[j])) j++;
      const word = text.slice(i, j);
      const k = nextNonSpace(j);
      const nx = text[k] || '';
      let t = 'ident';
      const up = word.toUpperCase();
      if (afterBrace) {
        t = lang === 'boxql' && VERBS.includes(word) ? 'verb' : 'marker';
      } else if (KEYWORDS.includes(up)) {
        t = 'keyword';
      } else if (up === 'ID' && stack.length && stack[stack.length - 1].kind === '[') {
        t = 'keyword';
      } else if (lang === 'boxql' && WORD_OPS.includes(word) && prev && OPERAND_END.has(prev.t)) {
        t = 'operator';
      } else if (nx === ':' && text[k + 1] !== ']' && lang === 'boxql' && !(prev && prev.x === ':')) {
        t = 'file';
      } else if (prev && prev.x === ':' && nx !== '(' ) {
        t = 'box';
      } else if (nx === '[' && !(prev && prev.x === '.')) {
        t = 'box';
      } else if (lang === 'boxql' && OPTIONS.includes(word) && nx === '=' && text[k + 1] !== '=') {
        t = 'option';
      } else if (nx === '(' && lang === 'boxql') {
        t = 'function';
      } else if (prev && prev.x === '.') {
        t = 'field';
      } else if (lang === 'boxql') {
        t = 'field';
      }
      push(i, j, t);
      afterBrace = false;
      i = j;
      continue;
    }
    // operators
    if (c === '@') {
      let len = 1;
      if (text.startsWith('@!>', i)) len = 3;
      else if (text.startsWith('@>', i)) len = 2;
      push(i, i + len, len > 1 ? 'link' : 'punct').x = '@';
      afterBrace = false;
      i += len;
      continue;
    }
    if (c === '-' && text[i + 1] === '>') { push(i, i + 2, 'arrow'); i += 2; afterBrace = false; continue; }
    if (c === '.' && text[i + 1] === '.') { push(i, i + 2, 'operator'); i += 2; afterBrace = false; continue; }
    if ('<>!=+-/&|?*'.includes(c) && !(c === '*' && prev && prev.x === ')')) {
      let len = 1;
      if ((c === '<' || c === '>' || c === '!' || c === '=') && text[i + 1] === '=') len = 2;
      const t = c === '=' || c === '*' ? 'punct' : 'operator';
      push(i, i + len, t).x = c;
      afterBrace = false;
      i += len;
      continue;
    }
    // brackets
    if (c === ';' && text[i + 1] === '[') {
      const tok = push(i, i + 2, 'list');
      tok.x = ';[';
      stack.push({ kind: 'list', idx: toks.length - 1 });
      afterBrace = false;
      i += 2;
      continue;
    }
    if (c === '{' || c === '[' || c === '(') {
      const tok = push(i, i + 1, c === '{' ? 'brace' : 'bracket');
      tok.x = c;
      stack.push({ kind: c, idx: toks.length - 1 });
      afterBrace = c === '{';
      i++;
      continue;
    }
    if (c === '}' || c === ']' || c === ')') {
      const want = c === '}' ? '{' : c === ']' ? '[' : '(';
      const top = stack[stack.length - 1];
      let tok;
      if (c === ']' && top && top.kind === 'list') {
        // ;[ ... ]:  closes with "]:"
        stack.pop();
        const withColon = text[i + 1] === ':';
        tok = push(i, i + (withColon ? 2 : 1), withColon ? 'list' : 'error');
        tok.x = ']';
        tok.p = top.idx;
        toks[top.idx].p = toks.length - 1;
        if (!withColon) { tok.p = top.idx; }
        i += withColon ? 2 : 1;
      } else if (top && top.kind === want) {
        stack.pop();
        tok = push(i, i + 1, c === '}' ? 'brace' : 'bracket');
        tok.x = c;
        tok.p = top.idx;
        toks[top.idx].p = toks.length - 1;
        i++;
      } else {
        tok = push(i, i + 1, 'error');
        tok.x = c;
        i++;
      }
      afterBrace = false;
      continue;
    }
    if (',:;.~'.includes(c)) {
      push(i, i + 1, 'punct').x = c;
      afterBrace = false;
      i++;
      continue;
    }
    // anything else is an error token (one character)
    push(i, i + 1, 'error');
    afterBrace = false;
    i++;
  }
  return toks;
}

/** Index of the bracket token touching offset pos (just before or at it), or -1. */
export function bracketAt(toks, pos) {
  let best = -1;
  for (let k = 0; k < toks.length; k++) {
    const t = toks[k];
    if (t.s > pos) break;
    if (!(t.t === 'brace' || t.t === 'bracket' || t.t === 'list' || (t.t === 'error' && '}])'.includes(t.x || '')))) continue;
    if (t.e === pos || t.s === pos) {
      if (t.s === pos) return k; // bracket right after the caret wins over the one before it
      best = k;
    }
  }
  return best;
}

/** True if offset pos is inside a string or comment token. */
export function inStringOrComment(toks, pos) {
  for (const t of toks) {
    if (t.s >= pos) break;
    if ((t.t === 'string' || t.t === 'comment' || t.t === 'error') && pos < t.e) return t.t;
  }
  return '';
}

/**
 * Pull "line:col" out of a server error message. Understands BoxQL ("syntax error at 1:33") and
 * Box ("line 3, col 7"). Returns null when the message has no position.
 */
export function parseErrorPos(msg) {
  if (!msg) return null;
  let m = /\bat (\d+):(\d+)\b/.exec(msg);
  if (m) return { line: +m[1], col: +m[2] };
  m = /\bline (\d+),? col(?:umn)? (\d+)\b/i.exec(msg);
  if (m) return { line: +m[1], col: +m[2] };
  m = /\b(\d+):(\d+)\b/.exec(msg);
  if (m) return { line: +m[1], col: +m[2] };
  return null;
}

/** Offset of 1-based line:col in text (clamped). */
export function offsetOf(text, line, col) {
  let off = 0;
  for (let l = 1; l < line; l++) {
    const nl = text.indexOf('\n', off);
    if (nl < 0) return text.length;
    off = nl + 1;
  }
  return Math.min(off + Math.max(col - 1, 0), text.length);
}

/** 1-based line and column of an offset. */
export function lineCol(text, off) {
  let line = 1;
  let last = -1;
  for (let k = text.indexOf('\n'); k >= 0 && k < off; k = text.indexOf('\n', k + 1)) { line++; last = k; }
  return { line, col: off - last };
}

/** Finds `$name` parameters in a BoxQL command (ignoring strings and comments). */
export function findParams(text) {
  const seen = [];
  for (const t of tokenize(text, 'boxql')) {
    if (t.t === 'param') {
      const name = text.slice(t.s + 1, t.e);
      if (!seen.includes(name)) seen.push(name);
    }
  }
  return seen;
}

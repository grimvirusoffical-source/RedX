// Run with: node --test host/uitest   (the Go test TestJSTokenizerSuite does this when node exists)
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  tokenize, bracketAt, inStringOrComment, parseErrorPos, offsetOf, lineCol, findParams,
  VERBS, OPTIONS,
} from '../ui/js/tokenizers.js';

const kinds = (src, lang) => tokenize(src, lang).map((t) => [src.slice(t.s, t.e), t.t]);
const only = (src, lang, type) => kinds(src, lang).filter(([, t]) => t === type).map(([s]) => s);

test('BoxQL: verbs, files, boxes, fields, operators, params, options, functions', () => {
  const q = '{Get[]} = players:Player[Level > $min, Name starts "A"] -> [Name, n = Count()], Limit = 5';
  assert.deepEqual(only(q, 'boxql', 'verb'), ['Get']);
  assert.deepEqual(only(q, 'boxql', 'file'), ['players']);
  assert.deepEqual(only(q, 'boxql', 'box'), ['Player']);
  assert.deepEqual(only(q, 'boxql', 'field'), ['Level', 'Name', 'Name', 'n']);
  assert.deepEqual(only(q, 'boxql', 'operator'), ['>', 'starts']);
  assert.deepEqual(only(q, 'boxql', 'param'), ['$min']);
  assert.deepEqual(only(q, 'boxql', 'option'), ['Limit']);
  assert.deepEqual(only(q, 'boxql', 'function'), ['Count']);
  assert.deepEqual(only(q, 'boxql', 'arrow'), ['->']);
  assert.deepEqual(only(q, 'boxql', 'string'), ['"A"']);
  assert.deepEqual(only(q, 'boxql', 'number'), ['5']);
});

test('every BoxQL verb is recognised after {', () => {
  for (const v of VERBS) {
    const src = `{${v}[]} = f:B[ID=1]`;
    assert.deepEqual(only(src, 'boxql', 'verb'), [v], v);
  }
  assert.ok(OPTIONS.includes('Limit') && OPTIONS.includes('Offset') && OPTIONS.includes('Sort'));
});

test('Box text: markers, strings, numbers (incl. negative), links, comments, keywords', () => {
  const src = '{Name[]} = "Ann" << note >> , {Level[]} = -7.5, {Guild[]} = "g.red-xai.db":Guild[ID=1] @> x\n{On[]} = TRUE';
  assert.deepEqual(only(src, 'box', 'marker'), ['Name', 'Level', 'Guild', 'On']);
  assert.deepEqual(only(src, 'box', 'comment'), ['<< note >>']);
  assert.deepEqual(only(src, 'box', 'number'), ['-7.5', '1']);
  assert.deepEqual(only(src, 'box', 'link'), ['@>']);
  assert.ok(only(src, 'box', 'keyword').includes('TRUE'));
  assert.deepEqual(only(src, 'box', 'string'), ['"Ann"', '"g.red-xai.db"']);
});

test('comments hide their contents and do not break operand detection', () => {
  const src = '5 << - 3 >> -2';
  const k = kinds(src, 'box');
  // the comment is transparent: after the operand 5, '-' is an operator, not a sign
  assert.deepEqual(k.map(([, t]) => t), ['number', 'comment', 'operator', 'number']);
  assert.equal(only('x = -2', 'box', 'number')[0], '-2');
});

test('bracket matching pairs partners and flags unmatched ones', () => {
  const src = '{Get[]} = f:B[ID=1]';
  const toks = tokenize(src, 'boxql');
  const open = toks.findIndex((t) => t.t === 'brace');
  assert.equal(src[toks[toks[open].p].s], '}');
  assert.equal(toks[toks[open].p].p, open);
  const bad = tokenize('{Get[]} = f:B[ID=1)', 'boxql');
  assert.equal(bad.at(-1).t, 'error');
  const lone = tokenize('[ {A[]} = 1', 'box');
  assert.equal(lone[0].p, -1);
});

test('unterminated string is an error token running to the end', () => {
  const src = 'x = "unterminated';
  const t = tokenize(src, 'box').at(-1);
  assert.equal(t.t, 'error');
  assert.equal(t.e, src.length);
});

test('bracketAt finds the bracket touching the caret', () => {
  const src = '{A[]}';
  const toks = tokenize(src, 'box');
  assert.equal(src[toks[bracketAt(toks, 0)].s], '{');
  assert.equal(src[toks[bracketAt(toks, 5)].s], '}');
  assert.equal(bracketAt(toks, 2) >= 0, true);
});

test('inStringOrComment', () => {
  const src = 'a "str" << c >> b';
  const toks = tokenize(src, 'box');
  assert.equal(inStringOrComment(toks, 4), 'string');
  assert.equal(inStringOrComment(toks, 10), 'comment');
  assert.equal(inStringOrComment(toks, 0), '');
});

test('parseErrorPos understands server messages', () => {
  assert.deepEqual(parseErrorPos('query: syntax error at 1:33: expected a value'), { line: 1, col: 33 });
  assert.deepEqual(parseErrorPos('parse error: line 3, col 7: bad'), { line: 3, col: 7 });
  assert.deepEqual(parseErrorPos('boom at 12:4'), { line: 12, col: 4 });
  assert.equal(parseErrorPos('no position here'), null);
  assert.equal(parseErrorPos(''), null);
});

test('offsetOf and lineCol are inverses and clamp', () => {
  const text = 'ab\ncde\nf';
  for (let off = 0; off <= text.length; off++) {
    const { line, col } = lineCol(text, off);
    assert.equal(offsetOf(text, line, col), off, `off ${off}`);
  }
  assert.equal(offsetOf(text, 99, 1), text.length);
  assert.equal(offsetOf(text, 1, 99), text.length);
});

test('findParams ignores strings and comments, de-duplicates', () => {
  assert.deepEqual(findParams('{Get[]} = f:B[A = $a, B = $b, C = $a] << $c >> -> *'), ['a', 'b']);
  assert.deepEqual(findParams('{Get[]} = f:B[Name = "$x"]'), []);
});

test('tokens never overlap and stay inside the text (fuzz)', () => {
  let seed = 12345;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  const alphabet = ['{', '}', '[', ']', '(', ')', '"', '<<', '>>', '@>', '->', '$p', 'Get', 'ID', '=', ',', ' ', '\n', '-', '5', '.', ':', 'x', '\\'];
  for (let n = 0; n < 300; n++) {
    let s = '';
    for (let k = rnd() * 40; k > 0; k--) s += alphabet[Math.floor(rnd() * alphabet.length)];
    for (const lang of ['box', 'boxql']) {
      let end = 0;
      for (const t of tokenize(s, lang)) {
        assert.ok(t.s >= end && t.e > t.s && t.e <= s.length, `${lang} ${JSON.stringify(s)} ${JSON.stringify(t)}`);
        end = t.e;
      }
    }
  }
});

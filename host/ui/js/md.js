// A small, safe Markdown renderer for the built-in help (headings, code fences, tables, lists, quotes,
// inline code/bold/italic/links). Builds DOM nodes; never uses innerHTML.
import { h } from './util.js';
import { tokenize } from './tokenizers.js';

export function highlight(text, lang) {
  const toks = tokenize(text, lang);
  const out = [];
  let last = 0;
  for (const t of toks) {
    if (t.s > last) out.push(text.slice(last, t.s));
    out.push(h('span', { class: 'tk-' + t.t }, text.slice(t.s, t.e)));
    last = t.e;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function slug(s) { return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''); }

function inline(text, docLink) {
  const out = [];
  const re = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\[[^\]]+\]\([^)]+\))|(\*[^*\s][^*]*\*)/g;
  let last = 0;
  let m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const s = m[0];
    if (m[1]) out.push(h('code', null, s.slice(1, -1)));
    else if (m[2]) out.push(h('strong', null, s.slice(2, -2)));
    else if (m[4]) out.push(h('em', null, s.slice(1, -1)));
    else {
      const mm = /\[([^\]]+)\]\(([^)]+)\)/.exec(s);
      const href = mm[2];
      const dm = /^([A-Z_]+)\.md(#.*)?$/.exec(href);
      if (dm && docLink) out.push(h('a', { href: '#/help/' + dm[1].toLowerCase() }, mm[1]));
      else if (/^https?:/.test(href)) out.push(h('a', { href, target: '_blank', rel: 'noopener noreferrer' }, mm[1]));
      else out.push(mm[1]);
    }
    last = m.index + s.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export function renderMarkdown(src, { docLink = true } = {}) {
  const root = h('div', { class: 'md' });
  const toc = [];
  const lines = src.replace(/\r/g, '').split('\n');
  let i = 0;
  while (i < lines.length) {
    const ln = lines[i];
    let m;
    if ((m = /^```(\w*)/.exec(ln))) {
      const lang = m[1];
      const buf = [];
      i++;
      while (i < lines.length && !lines[i].startsWith('```')) buf.push(lines[i++]);
      i++;
      const code = buf.join('\n');
      const hl = lang === 'boxql' ? 'boxql' : lang === 'box' ? 'box' : /^\s*(\{|\[|<<)/.test(code) && !lang ? 'box' : null;
      root.append(h('pre', { class: 'code' }, h('code', null, hl ? highlight(code, hl) : code)));
      continue;
    }
    if ((m = /^(#{1,4})\s+(.*)$/.exec(ln))) {
      const lvl = m[1].length;
      const id = slug(m[2]);
      root.append(h('h' + lvl, { id: 'h-' + id }, inline(m[2], docLink)));
      if (lvl <= 3) toc.push({ lvl, text: m[2].replace(/[`*]/g, ''), id: 'h-' + id });
      i++;
      continue;
    }
    if (/^\s*\|.*\|\s*$/.test(ln) && /^\s*\|[\s:|-]+\|\s*$/.test(lines[i + 1] || '')) {
      const cells = (l) => l.trim().replace(/^\||\|$/g, '').split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, '|'));
      const head = cells(ln);
      i += 2;
      const rows = [];
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) rows.push(cells(lines[i++]));
      root.append(h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', null, h('tr', null, head.map((c) => h('th', null, inline(c, docLink))))),
        h('tbody', null, rows.map((r) => h('tr', null, r.map((c) => h('td', null, inline(c, docLink)))))))));
      continue;
    }
    if (/^\s*([-*]|\d+\.)\s+/.test(ln)) {
      const ordered = /^\s*\d+\./.test(ln);
      const items = [];
      while (i < lines.length && /^\s*([-*]|\d+\.)\s+/.test(lines[i])) {
        let t = lines[i].replace(/^\s*([-*]|\d+\.)\s+/, '');
        i++;
        while (i < lines.length && /^\s{2,}\S/.test(lines[i]) && !/^\s*([-*]|\d+\.)\s+/.test(lines[i])) t += ' ' + lines[i++].trim();
        items.push(h('li', null, inline(t, docLink)));
      }
      root.append(h(ordered ? 'ol' : 'ul', null, items));
      continue;
    }
    if (/^>\s?/.test(ln)) {
      const buf = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) buf.push(lines[i++].replace(/^>\s?/, ''));
      root.append(h('blockquote', null, inline(buf.join(' '), docLink)));
      continue;
    }
    if (/^---+\s*$/.test(ln)) { root.append(h('hr')); i++; continue; }
    if (!ln.trim()) { i++; continue; }
    const buf = [ln];
    i++;
    while (i < lines.length && lines[i].trim() && !/^(```|#{1,4}\s|\s*([-*]|\d+\.)\s+|>|\|)/.test(lines[i])) buf.push(lines[i++]);
    root.append(h('p', null, inline(buf.join(' '), docLink)));
  }
  return { el: root, toc };
}

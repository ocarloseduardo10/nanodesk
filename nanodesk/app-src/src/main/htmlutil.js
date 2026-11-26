/**
 * NanoDesk — utilidades HTML (processo principal, ZERO dependências)
 * ==================================================================
 * Usado pelo Leitor de notícias (1.4.0, inspirado em FreshRSS/Miniflux/
 * rssPresso) e pelo Modo Leitura:
 *  - parseHtml: parser TOLERANTE (não lança; nunca usa eval) que produz
 *    uma árvore simples { el, text } — lida com tags não fechadas, CDATA,
 *    comentários, DOCTYPE, atributos sem aspas e conteúdo cru de
 *    <script>/<style>/<textarea>/<title>;
 *  - serialize: reconstrói HTML escapando texto e atributos;
 *  - sanitizeHtml: LISTA BRANCA de tags/atributos/esquemas — remove
 *    scripts, handlers de evento, javascript:/data: em links, iframes,
 *    formulários e SVG/MathML inteiros, resolve URLs relativas e limita
 *    tamanho/profundidade (defesa contra feeds maliciosos);
 *  - textOf / findAll / metaContent: consultas simples na árvore.
 */
'use strict';

/* ---------------- entidades ---------------- */

const NAMED_ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0',
  copy: '\u00a9', reg: '\u00ae', trade: '\u2122', hellip: '\u2026',
  mdash: '\u2014', ndash: '\u2013', lsquo: '\u2018', rsquo: '\u2019',
  ldquo: '\u201c', rdquo: '\u201d', laquo: '\u00ab', raquo: '\u00bb',
  bull: '\u2022', middot: '\u00b7', deg: '\u00b0', plusmn: '\u00b1',
  times: '\u00d7', divide: '\u00f7', euro: '\u20ac', pound: '\u00a3',
  cent: '\u00a2', yen: '\u00a5', sect: '\u00a7', para: '\u00b6'
};

function decodeEntities(s) {
  if (!s || s.indexOf('&') < 0) return String(s || '');
  return String(s).replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]{1,31});/g, (m, body) => {
    if (body[0] === '#') {
      const hex = body[1] === 'x' || body[1] === 'X';
      const code = parseInt(body.slice(hex ? 2 : 1), hex ? 16 : 10);
      if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return '\ufffd';
      if (code === 0 || (code >= 0xd800 && code <= 0xdfff)) return '\ufffd';
      try { return String.fromCodePoint(code); } catch (_) { return '\ufffd'; }
    }
    return NAMED_ENTITIES[body.toLowerCase()] || m;
  });
}

function encodeText(s) {
  return String(s == null ? '' : s).replace(/[&<>]/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
}

function encodeAttr(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ---------------- parser tolerante ---------------- */

/* VOID apenas os que JAMAIS têm conteúdo nem em feeds (RSS/Atom usam
 * <link>com texto</link> — por isso link/embed/param/source/track viram
 * tags normais, fechadas implicitamente pelo unwind da pilha ou pela
 * reabertura da mesma tag) */
const VOID_TAGS = new Set(['area', 'base', 'br', 'col', 'hr', 'img',
  'input', 'meta', 'wbr']);

const RAWTEXT_TAGS = new Set(['script', 'style', 'textarea', 'title',
  'xmp', 'noembed', 'noframes']);

/* tag X fecha (implicitamente) a tag Y quando X abre sob Y aberto */
const CLOSES = {
  li: { li: 1 },
  p: { p: 1 },
  dt: { dt: 1, dd: 1 },
  dd: { dt: 1, dd: 1 },
  option: { option: 1 },
  link: { link: 1 },
  embed: { embed: 1 },
  param: { param: 1 },
  source: { source: 1 },
  track: { track: 1 },
  tr: { tr: 1, td: 1, th: 1 },
  td: { td: 1, th: 1 },
  th: { td: 1, th: 1 },
  thead: { thead: 1, tbody: 1, tfoot: 1, tr: 1, td: 1, th: 1 },
  tbody: { thead: 1, tbody: 1, tfoot: 1, tr: 1, td: 1, th: 1 },
  tfoot: { thead: 1, tbody: 1, tfoot: 1, tr: 1, td: 1, th: 1 },
  h1: { h1: 1, p: 1 }, h2: { h2: 1, p: 1 }, h3: { h3: 1, p: 1 },
  h4: { h4: 1, p: 1 }, h5: { h5: 1, p: 1 }, h6: { h6: 1, p: 1 },
  div: { p: 1 }, ul: { p: 1 }, ol: { p: 1 }, table: { p: 1 },
  blockquote: { p: 1 }, pre: { p: 1 }, section: { p: 1 }, article: { p: 1 }
};

/* tags que abrem fechando um <p> aberto (comportamento HTML) */
const P_CLOSERS = new Set(['address', 'article', 'aside', 'blockquote', 'details',
  'div', 'dl', 'fieldset', 'figcaption', 'figure', 'footer', 'form', 'h1', 'h2',
  'h3', 'h4', 'h5', 'h6', 'header', 'hr', 'main', 'menu', 'nav', 'ol', 'p',
  'pre', 'section', 'table', 'ul']);

const MAX_NODES = 20000;
const MAX_DEPTH = 100;   // profundidade máxima da árvore (anti stack-overflow)

function parseHtml(html) {
  const root = { type: 'el', tag: '#root', attrs: {}, children: [] };
  let cur = root;
  let count = 1;
  const stack = [root];
  const s = String(html == null ? '' : html);
  let i = 0;
  const n = s.length;

  const pushText = (raw) => {
    if (!raw) return;
    if (count >= MAX_NODES) return;
    const last = cur.children[cur.children.length - 1];
    if (last && last.type === 'text') last.text += raw;
    else { cur.children.push({ type: 'text', text: raw }); count++; }
  };

  while (i < n) {
    const lt = s.indexOf('<', i);
    if (lt < 0) { pushText(s.slice(i)); break; }
    if (lt > i) pushText(s.slice(i, lt));
    if (count >= MAX_NODES) break;

    // comentário <!-- ... --> / CDATA / DOCTYPE / PI
    if (s.startsWith('<!--', lt)) {
      const end = s.indexOf('-->', lt + 4);
      i = end < 0 ? n : end + 3;
      continue;
    }
    if (s.startsWith('<![CDATA[', lt)) {
      const end = s.indexOf(']]>', lt + 9);
      pushText(s.slice(lt + 9, end < 0 ? n : end));
      i = end < 0 ? n : end + 3;
      continue;
    }
    if (/^<!/.test(s.slice(lt, lt + 2)) || /^<\?/.test(s.slice(lt, lt + 2))) {
      const end = s.indexOf('>', lt);
      i = end < 0 ? n : end + 1;
      continue;
    }
    // tag de fechamento
    if (s[lt + 1] === '/') {
      const end = s.indexOf('>', lt);
      if (end < 0) break;
      const name = s.slice(lt + 2, end).trim().toLowerCase().split(/\s/)[0];
      if (name && !VOID_TAGS.has(name)) {
        const idx = stack.map(x => x.tag).lastIndexOf(name);
        if (idx > 0) { // idx 0 é #root — nunca fecha
          // fecha a tag encontrada E todas as que estão abertas acima dela
          while (stack.length > idx) stack.pop();
          cur = stack[stack.length - 1];
        }
      }
      i = end + 1;
      continue;
    }
    // tag de abertura
    const m = /^<([a-zA-Z][a-zA-Z0-9:_-]*)/.exec(s.slice(lt, lt + 64));
    if (!m) { pushText('&lt;'); i = lt + 1; continue; }
    const tag = m[1].toLowerCase();
    let j = lt + 1 + m[1].length;
    const attrs = {};
    let selfClose = false;
    while (j < n && count < MAX_NODES * 4) {
      while (j < n && /[\s\u0000]/.test(s[j])) j++;
      if (s[j] === '>') { j++; break; }
      if (s[j] === '/' && s[j + 1] === '>') { selfClose = true; j += 2; break; }
      if (j >= n) break;
      const am = /^([^\s=/>]+)\s*(?:=\s*("([^"]*)"|'([^']*)'|[^\s>]*))?/.exec(s.slice(j, j + 4096));
      if (!am) { j++; continue; }
      const aname = am[1].toLowerCase();
      if (attrs[aname] === undefined) {
        // grupos: 2 = valor inteiro; 3 = entre aspas duplas; 4 = simples;
        // valor sem aspas fica só no grupo 2
        let aval = '';
        if (am[2] !== undefined) {
          if (am[3] !== undefined) aval = am[3];
          else if (am[4] !== undefined) aval = am[4];
          else aval = am[2];
        }
        attrs[aname] = decodeEntities(aval);
      }
      j += am[0].length;
      if (am[0].length === 0) j++; // segurança contra laço infinito
    }
    i = j;

    if (tag === 'script' || tag === 'style' || RAWTEXT_TAGS.has(tag)) {
      const node = { type: 'el', tag, attrs, children: [] };
      cur.children.push(node);
      count++;
      const closeRe = new RegExp('</' + tag + '\\s*>', 'i');
      const rest = s.slice(i);
      const cm = closeRe.exec(rest);
      const raw = cm ? rest.slice(0, cm.index) : rest;
      if (raw) node.children.push({ type: 'text', text: raw });
      i = cm ? i + cm.index + cm[0].length : n;
      continue;
    }

    if (VOID_TAGS.has(tag) || selfClose) {
      cur.children.push({ type: 'el', tag, attrs, children: [] });
      count++;
      continue;
    }

    // auto-fechamento implícito
    while (stack.length > 1) {
      const top = stack[stack.length - 1].tag;
      if (CLOSES[tag] && CLOSES[tag][top]) { stack.pop(); continue; }
      if (P_CLOSERS.has(tag) && top === 'p') { stack.pop(); continue; }
      break;
    }
    const node = { type: 'el', tag, attrs, children: [] };
    cur.children.push(node);
    count++;
    // profundidade além do limite: o nó vira IRMÃO (a pilha não cresce)
    if (stack.length >= MAX_DEPTH) continue;
    stack.push(node);
    cur = node;
  }
  return root;
}

/* ---------------- consultas ---------------- */

function findAll(node, pred, out) {
  out = out || [];
  if (!node || !node.children) return out;
  for (const c of node.children) {
    if (c.type === 'el') {
      if (pred(c)) out.push(c);
      findAll(c, pred, out);
    }
  }
  return out;
}

function findByTag(node, tag) {
  return findAll(node, c => c.tag === tag);
}

function textOf(node) {
  if (!node) return '';
  if (node.type === 'text') return node.text;
  let out = '';
  for (const c of node.children || []) out += textOf(c);
  return out;
}

function metaContent(root, key) {
  const k = key.toLowerCase();
  const metas = findByTag(root, 'meta');
  for (const m of metas) {
    const name = (m.attrs.name || m.attrs.property || '').toLowerCase();
    if (name === k) return (m.attrs.content || '').trim();
  }
  return '';
}

/* ---------------- serialização e sanitização ---------------- */

const DROP_WITH_CONTENT = new Set(['script', 'style', 'noscript', 'iframe',
  'object', 'embed', 'applet', 'template', 'svg', 'math', 'form', 'input',
  'button', 'select', 'option', 'textarea', 'meta', 'link', 'base', 'audio',
  'video', 'source', 'track', 'canvas', 'dialog', 'frame', 'frameset',
  'marquee', 'object']);

const ALLOWED_TAGS = new Set(['p', 'br', 'hr', 'h1', 'h2', 'h3', 'h4', 'h5',
  'h6', 'ul', 'ol', 'li', 'blockquote', 'pre', 'code', 'strong', 'b', 'em',
  'i', 'u', 's', 'sub', 'sup', 'a', 'img', 'figure', 'figcaption', 'table',
  'thead', 'tbody', 'tfoot', 'tr', 'td', 'th', 'caption', 'span', 'div',
  'small', 'abbr', 'q', 'cite', 'time', 'dl', 'dt', 'dd', 'details', 'summary',
  'mark', 'kbd', 'samp', 'var', 'wbr']);

const ALLOWED_ATTRS = {
  a: new Set(['href', 'title']),
  img: new Set(['src', 'alt', 'title', 'width', 'height']),
  abbr: new Set(['title']),
  td: new Set(['colspan', 'rowspan']),
  th: new Set(['colspan', 'rowspan']),
  time: new Set(['datetime']),
  blockquote: new Set(['cite']),
  q: new Set(['cite'])
};

const GLOBAL_LIMITS = { maxOutput: 320 * 1024, maxAttr: 2048, maxDepth: 150 };

function safeUrl(raw, baseUrl, opts) {
  const v = String(raw || '').trim();
  if (!v || v.length > 4096) return '';
  const low = v.toLowerCase().replace(/[\u0000-\u0020]/g, '');
  if (low.startsWith('javascript:') || low.startsWith('vbscript:') ||
      low.startsWith('file:') || low.startsWith('blob:') || low.startsWith('about:')) return '';
  if (low.startsWith('data:')) {
    if (opts && opts.allowDataImages && /^data:image\/(png|jpe?g|gif|webp|bmp);/i.test(v) && v.length <= 200 * 1024) return v;
    return '';
  }
  let url;
  if (baseUrl) {
    try { url = new URL(v, baseUrl); } catch (_) { return ''; }
  } else {
    try { url = new URL(v); } catch (_) { return ''; }
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return '';
  return url.href;
}

function serialize(node, opts, depth, out) {
  if (depth > GLOBAL_LIMITS.maxDepth || out.length > GLOBAL_LIMITS.maxOutput) return;
  if (node.type === 'text') {
    out.push(encodeText(node.text));
    return;
  }
  const tag = node.tag;
  if (tag === '#root') {
    for (const c of node.children) serialize(c, opts, depth + 1, out);
    return;
  }
  if (DROP_WITH_CONTENT.has(tag)) return;
  if (!ALLOWED_TAGS.has(tag)) {
    // tag desconhecida: mantém o FILHO (texto) sem a tag
    for (const c of node.children) serialize(c, opts, depth + 1, out);
    return;
  }
  const attrs = [];
  const allowed = ALLOWED_ATTRS[tag] || new Set();
  for (const [name, value] of Object.entries(node.attrs || {})) {
    if (!allowed.has(name)) continue;
    let v = String(value == null ? '' : value).slice(0, GLOBAL_LIMITS.maxAttr);
    if (name === 'href' || name === 'src' || name === 'cite') {
      v = safeUrl(v, opts.baseUrl, opts);
      if (!v) continue;
    }
    if (name === 'colspan' || name === 'rowspan' || name === 'width' || name === 'height') {
      if (!/^\d{1,4}$/.test(v)) continue;
    }
    attrs.push(' ' + name + '="' + encodeAttr(v) + '"');
    if (attrs.length > 6) break;
  }
  if (tag === 'a' && attrs.some(a => a.startsWith(' href'))) {
    attrs.push(' rel="noreferrer noopener"');
  }
  const open = '<' + tag + attrs.join('') + '>';
  out.push(open);
  const selfVoid = (tag === 'br' || tag === 'hr' || tag === 'wbr' || tag === 'img');
  if (selfVoid) return;
  for (const c of node.children) serialize(c, opts, depth + 1, out);
  out.push('</' + tag + '>');
}

/**
 * Sanitiza HTML arbitrário (feeds, páginas) para exibição SEGURA na UI.
 * opts: { baseUrl, allowDataImages }
 */
function sanitizeHtml(html, opts) {
  const o = opts || {};
  const root = parseHtml(String(html || '').slice(0, 1024 * 1024));
  const out = [];
  serialize(root, o, 0, out);
  let htmlOut = out.join('');
  if (htmlOut.length > GLOBAL_LIMITS.maxOutput) htmlOut = htmlOut.slice(0, GLOBAL_LIMITS.maxOutput);
  return htmlOut;
}

/** Texto puro e compacto (para resumos). */
function textSummary(html, maxLen) {
  const root = parseHtml(String(html || '').slice(0, 512 * 1024));
  const text = textOf(root).replace(/\s+/g, ' ').trim();
  const limit = maxLen || 300;
  return text.length > limit ? text.slice(0, limit - 1) + '\u2026' : text;
}

module.exports = {
  parseHtml, serialize, sanitizeHtml, textSummary, decodeEntities,
  encodeText, encodeAttr, findAll, findByTag, textOf, metaContent,
  safeUrl, VOID_TAGS
};

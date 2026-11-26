/**
 * NanoDesk — Arquivar página (1.9.0) — processamento de CSS (puro, sem DOM)
 * ------------------------------------------------------------------
 * Parser de regras CSS de nível superior (respeita strings, comentários, parênteses e chaves
 * aninhadas) com as operações que o arquivador precisa:
 *   - absolutizar url() / resolver @import inline;
 *   - remover regras que não casam com nada na página (o DOM é consultado por um "oráculo");
 *   - remover @font-face de famílias não usadas e manter só a melhor fonte (woff2 > woff > ttf);
 *   - trocar url() por data: URIs (via callback, assíncrono, com limites no chamador).
 * Código ORIGINAL (MIT).
 */
'use strict';

const AT_WITH_RULES = new Set(['media', 'supports', 'layer', 'container', 'scope', 'document', '-moz-document']);

/* ---------------------- scanner básico ---------------------- */

/** Avança de i (em '/*') até depois do fim do comentário. */
function skipComment(s, i) {
  const e = s.indexOf('*/', i + 2);
  return e < 0 ? s.length : e + 2;
}
/** Avança de i (aspas) até depois da string. */
function skipString(s, i) {
  const q = s[i];
  let k = i + 1;
  while (k < s.length) {
    const c = s[k];
    if (c === '\\') { k += 2; continue; }
    if (c === q) return k + 1;
    if (c === '\n') return k;   // string não fechada: CSS termina no fim da linha
    k++;
  }
  return s.length;
}
/** Dado s[i]==='{', devolve o índice do '}' correspondente (ou s.length). */
function matchBrace(s, i) {
  let depth = 0;
  let k = i;
  while (k < s.length) {
    const c = s[k];
    if (c === '/' && s[k + 1] === '*') { k = skipComment(s, k); continue; }
    if (c === '"' || c === "'") { k = skipString(s, k); continue; }
    if (c === '\\') { k += 2; continue; }
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) return k; }
    k++;
  }
  return s.length;
}

/**
 * Divide em nós de nível superior.
 * @returns {Array<{type:'rule'|'at', name?:string, prelude:string, body:string|null}>}
 */
function parseSheet(css) {
  const s = String(css == null ? '' : css);
  const out = [];
  let i = 0;
  let start = 0;
  let paren = 0;
  let pre = '';
  const flushPrelude = (to) => { pre += s.slice(start, to); };
  while (i < s.length) {
    const c = s[i];
    if (c === '/' && s[i + 1] === '*') { flushPrelude(i); i = skipComment(s, i); start = i; continue; }
    if (c === '"' || c === "'") { i = skipString(s, i); continue; }
    if (c === '\\') { i += 2; continue; }
    if (c === '(') { paren++; i++; continue; }
    if (c === ')') { if (paren > 0) paren--; i++; continue; }
    if (paren === 0 && c === '{') {
      flushPrelude(i);
      const end = matchBrace(s, i);
      const prelude = pre.trim();
      const body = s.slice(i + 1, end);
      if (prelude) out.push(makeNode(prelude, body));
      pre = ''; i = end + 1; start = i; continue;
    }
    if (paren === 0 && c === ';') {
      flushPrelude(i);
      const prelude = pre.trim();
      if (prelude.startsWith('@')) out.push(makeNode(prelude, null));
      pre = ''; i++; start = i; continue;
    }
    if (paren === 0 && c === '}') { flushPrelude(i); pre = ''; i++; start = i; continue; }   // '}' solto
    i++;
  }
  return out;
}

function makeNode(prelude, body) {
  if (prelude.startsWith('@')) {
    const m = /^@([a-zA-Z-]+)/.exec(prelude);
    return { type: 'at', name: m ? m[1].toLowerCase() : '', prelude, body };
  }
  return { type: 'rule', prelude, body };
}

function stringifySheet(nodes) {
  return nodes.map((n) => (n.body === null ? n.prelude + ';' : n.prelude + '{' + n.body + '}')).join('\n');
}

/* ---------------------- url() ---------------------- */

/**
 * Localiza referências url(...) e strings dentro de image-set(...). Ignora comentários.
 * @returns {Array<{start:number,end:number,url:string}>} (start/end cobrem url(...) ou a string)
 */
function scanUrls(css) {
  const s = String(css == null ? '' : css);
  const found = [];
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '/' && s[i + 1] === '*') { i = skipComment(s, i); continue; }
    if (c === '"' || c === "'") { i = skipString(s, i); continue; }
    const low = s.slice(i, i + 4).toLowerCase();
    const prev = i > 0 ? s[i - 1] : ' ';
    if (low === 'url(' && !/[a-zA-Z0-9_-]/.test(prev)) {
      let k = i + 4;
      while (k < s.length && /\s/.test(s[k])) k++;
      let url = '';
      let end;
      if (s[k] === '"' || s[k] === "'") {
        const e = skipString(s, k);
        url = unescapeCss(s.slice(k + 1, e - 1));
        let m = e;
        while (m < s.length && /\s/.test(s[m])) m++;
        end = s[m] === ')' ? m + 1 : m;
      } else {
        let m = k;
        while (m < s.length && s[m] !== ')') { if (s[m] === '\\') m++; m++; }
        url = unescapeCss(s.slice(k, m).trim());
        end = Math.min(s.length, m + 1);
      }
      found.push({ start: i, end, url });
      i = end; continue;
    }
    if (!/[a-zA-Z0-9_-]/.test(prev) && /^(?:-webkit-)?image-set\(/i.test(s.slice(i, i + 19))) {
      const open = s.indexOf('(', i);
      let depth = 0; let k = open;
      while (k < s.length) {
        const d = s[k];
        if (d === '"' || d === "'") {
          const e = skipString(s, k);
          found.push({ start: k, end: e, url: unescapeCss(s.slice(k + 1, e - 1)), bare: true });
          k = e; continue;
        }
        if (d === '(') depth++;
        else if (d === ')') { depth--; if (depth === 0) { k++; break; } }
        k++;
      }
      i = k; continue;
    }
    i++;
  }
  return found;
}

function unescapeCss(t) {
  return String(t).replace(/\\([0-9a-fA-F]{1,6})\s?/g, (_, h) => { try { return String.fromCodePoint(parseInt(h, 16)); } catch (_e) { return ''; } })
    .replace(/\\(.)/g, '$1');
}

function quoteUrl(u) {
  return '"' + String(u).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\a ') + '"';
}

/**
 * Troca cada referência por fn(url) (síncrono). fn devolve string (nova URL) ou null (mantém)
 * ou '' (remove a referência → url("")).
 */
function replaceUrls(css, fn) {
  const s = String(css == null ? '' : css);
  const refs = scanUrls(s);
  if (!refs.length) return s;
  let out = ''; let last = 0;
  for (const r of refs) {
    out += s.slice(last, r.start);
    const nu = fn(r.url);
    if (nu === null || nu === undefined) out += s.slice(r.start, r.end);
    else out += r.bare ? quoteUrl(nu) : 'url(' + quoteUrl(nu) + ')';
    last = r.end;
  }
  return out + s.slice(last);
}

/** Troca referências por resultados ASSÍNCRONOS (um por URL única; o chamador faz cache/limites). */
async function replaceUrlsAsync(css, fn) {
  const s = String(css == null ? '' : css);
  const refs = scanUrls(s);
  if (!refs.length) return s;
  const uniq = [...new Set(refs.map(r => r.url))];
  const map = new Map();
  await Promise.all(uniq.map(async (u) => { map.set(u, await fn(u)); }));
  return replaceUrls(s, (u) => map.get(u));
}

/** Torna absolutas as url() relativas (mantém data:, #fragmento e URLs inválidas). */
function absolutizeUrls(css, baseUrl) {
  return replaceUrls(css, (u) => {
    const t = String(u).trim();
    if (!t || t.startsWith('#') || /^data:/i.test(t)) return null;
    try { return new URL(t, baseUrl).href; } catch (_) { return null; }
  });
}

/* ---------------------- @import ---------------------- */

/** "@import url(x) layer(a) supports(d:v) screen and (min-width:1px)" → {href, layer, supports, media} */
function parseImport(prelude) {
  let rest = String(prelude).replace(/^@import\s*/i, '').trim();
  let href = '';
  const refs = scanUrls(rest);
  if (refs.length) {
    href = refs[0].url;
    rest = (rest.slice(0, refs[0].start) + ' ' + rest.slice(refs[0].end)).trim();
  } else {
    const m = /^(["'])((?:\\.|(?!\1).)*)\1/.exec(rest);
    if (m) { href = unescapeCss(m[2]); rest = rest.slice(m[0].length).trim(); }
  }
  let layer = null; let supports = null;
  const lm = /^layer(?:\(([^)]*)\))?\s*/i.exec(rest);
  if (lm) { layer = lm[1] === undefined ? '' : lm[1].trim(); rest = rest.slice(lm[0].length); }
  const sm = /^supports\(((?:[^()]|\([^()]*\))*)\)\s*/i.exec(rest);
  if (sm) { supports = sm[1].trim(); rest = rest.slice(sm[0].length); }
  return { href, layer, supports, media: rest.trim() };
}

function wrapImported(css, imp) {
  let out = css;
  if (imp.media) out = '@media ' + imp.media + '{' + out + '}';
  if (imp.supports) out = '@supports (' + imp.supports + '){' + out + '}';
  if (imp.layer !== null) out = '@layer' + (imp.layer ? ' ' + imp.layer : '') + '{' + out + '}';
  return out;
}

/**
 * Resolve @import inline. `fetchText(absUrl)` devolve o texto CSS (ou null). Cada folha importada
 * é absolutizada em relação à PRÓPRIA URL antes de ser inserida. Profundidade e ciclos limitados.
 */
async function inlineImports(css, baseUrl, fetchText, opts) {
  const o = opts || {};
  const maxDepth = o.maxDepth || 4;
  const seen = o.seen || new Set([baseUrl]);
  const walk = async (text, base, depth) => {
    const nodes = parseSheet(text);
    const out = [];
    for (const n of nodes) {
      if (n.type === 'at' && n.name === 'charset') continue;
      if (n.type === 'at' && n.name === 'import') {
        const imp = parseImport(n.prelude);
        let abs = '';
        try { abs = new URL(imp.href, base).href; } catch (_) { abs = ''; }
        if (!abs || depth >= maxDepth || seen.has(abs)) continue;
        seen.add(abs);
        let t = null;
        try { t = await fetchText(abs); } catch (_) { t = null; }
        if (t == null) continue;
        const inner = await walk(absolutizeUrls(t, abs), abs, depth + 1);
        out.push({ type: 'raw', prelude: wrapImported(inner, imp), body: null, raw: true });
        continue;
      }
      out.push(n);
    }
    return out.map((n) => (n.raw ? n.prelude : stringifySheet([n]))).join('\n');
  };
  return walk(absolutizeUrls(css, baseUrl), baseUrl, 0);
}

/* ---------------------- seletores / regras não usadas ---------------------- */

function splitTopLevel(str, sep) {
  const parts = []; let depth = 0; let last = 0; let i = 0;
  while (i < str.length) {
    const c = str[i];
    if (c === '"' || c === "'") { i = skipString(str, i); continue; }
    if (c === '\\') { i += 2; continue; }
    if (c === '(' || c === '[') depth++;
    else if (c === ')' || c === ']') depth = Math.max(0, depth - 1);
    else if (c === sep && depth === 0) { parts.push(str.slice(last, i)); last = i + 1; }
    i++;
  }
  parts.push(str.slice(last));
  return parts;
}

const DYNAMIC_PSEUDO = /:(?:hover|focus|focus-within|focus-visible|active|visited|link|any-link|target|target-within|current|past|future|playing|paused|fullscreen|picture-in-picture|modal|popover-open|user-invalid|user-valid|autofill|-webkit-autofill)(?![\w-])/gi;
const PSEUDO_ELEMENT = /::?(?:before|after|first-line|first-letter|selection|placeholder|backdrop|marker|file-selector-button|cue|part\([^)]*\)|slotted\([^)]*\)|-[a-z-]+|[a-z-]+)(?:\([^)]*\))?(?=$|[\s>+~,.#[:])/gi;

/**
 * Seletor → versão consultável por querySelector (sem estados dinâmicos nem pseudo-elementos).
 * Devolve null se o seletor deve ser considerado "usado" sem consulta (:host, ::slotted, etc.).
 */
function selectorForMatch(sel) {
  let s = String(sel).trim();
  if (!s) return null;
  if (/:host|::slotted|::part|:root\s*$/.test(s) && /:host|::slotted|::part/.test(s)) return null;
  // pseudo-elementos (::x e os legados :before/:after/:first-line/:first-letter)
  s = s.replace(/::[a-zA-Z-]+(?:\([^)]*\))?/g, '').replace(/:(?:before|after|first-line|first-letter)(?![\w-])/gi, '');
  s = s.replace(DYNAMIC_PSEUDO, '');
  s = s.replace(/\s+/g, ' ').trim();
  if (!s) return '*';
  if (/[>+~]$/.test(s)) s += ' *';
  if (/^[>+~]/.test(s)) s = '* ' + s;
  s = s.replace(/([>+~,(])\s*(?=[,)])/g, '$1 *');
  return s;
}

/** Coleta todos os seletores (texto original) de regras de estilo, inclusive dentro de @media etc. */
function collectSelectors(css) {
  const set = new Set();
  const walk = (nodes) => {
    for (const n of nodes) {
      if (n.type === 'rule') { for (const sel of splitTopLevel(n.prelude, ',')) { const t = sel.trim(); if (t) set.add(t); } }
      else if (n.type === 'at' && AT_WITH_RULES.has(n.name) && n.body !== null) walk(parseSheet(n.body));
    }
  };
  walk(parseSheet(css));
  return [...set];
}

/**
 * Remove seletores sem correspondência. `used` é um Map/objeto seletor→boolean (ausente = usado).
 * Regras sem seletor restante são descartadas; @media/@supports/@layer vazios também.
 */
function pruneUnusedRules(css, used) {
  const isUsed = (sel) => {
    const v = used instanceof Map ? used.get(sel) : used[sel];
    return v === undefined ? true : !!v;
  };
  const walk = (nodes) => {
    const out = [];
    for (const n of nodes) {
      if (n.type === 'rule') {
        const keep = splitTopLevel(n.prelude, ',').map(x => x.trim()).filter(x => x && isUsed(x));
        if (keep.length) out.push({ type: 'rule', prelude: keep.join(','), body: n.body });
      } else if (n.type === 'at' && AT_WITH_RULES.has(n.name) && n.body !== null) {
        const inner = walk(parseSheet(n.body));
        if (inner.length) out.push({ type: 'at', name: n.name, prelude: n.prelude, body: stringifySheet(inner) });
      } else out.push(n);
    }
    return out;
  };
  return stringifySheet(walk(parseSheet(css)));
}

/* ---------------------- fontes ---------------------- */

function familyNames(value) {
  const names = [];
  for (const part of splitTopLevel(String(value), ',')) {
    const t = part.trim().replace(/!important\s*$/i, '').trim();
    const m = /^(["'])(.*)\1$/.exec(t);
    names.push((m ? m[2] : t).trim().toLowerCase());
  }
  return names.filter(Boolean);
}

/** Famílias referenciadas por regras que NÃO são @font-face (+ texto de style inline). */
function usedFontFamilies(css, extraText) {
  const used = new Set();
  const scanDecls = (body) => {
    for (const decl of splitTopLevel(body, ';')) {
      const ix = decl.indexOf(':');
      if (ix < 0) continue;
      const prop = decl.slice(0, ix).trim().toLowerCase();
      const val = decl.slice(ix + 1);
      if (prop === 'font-family') familyNames(val).forEach(n => used.add(n));
      else if (prop === 'font') {
        const m = /(?:^|\s)(?:\d*\.?\d+(?:px|pt|em|rem|%|vw|vh|ex|ch)|xx?-small|small|medium|large|x{1,2}-large|smaller|larger)(?:\s*\/\s*[^\s]+)?\s+(.+)$/i.exec(val.trim());
        if (m) familyNames(m[1]).forEach(n => used.add(n));
      } else if (prop.startsWith('--')) {
        const re = /(["'])(.*?)\1/g; let q;
        while ((q = re.exec(val))) used.add(q[2].trim().toLowerCase());
        val.split(',').forEach(x => { const t = x.trim().toLowerCase(); if (/^[a-z][a-z0-9 _-]*$/.test(t)) used.add(t); });
      }
    }
  };
  const walk = (nodes) => {
    for (const n of nodes) {
      if (n.type === 'rule' && n.body) scanDecls(n.body);
      else if (n.type === 'at' && n.name !== 'font-face' && n.body !== null) {
        if (AT_WITH_RULES.has(n.name) || n.name === 'keyframes') walk(parseSheet(n.body)); else scanDecls(n.body);
      }
    }
  };
  walk(parseSheet(css));
  if (extraText) scanDecls(String(extraText));
  return used;
}

function faceFamily(body) {
  for (const decl of splitTopLevel(body || '', ';')) {
    const ix = decl.indexOf(':');
    if (ix > 0 && decl.slice(0, ix).trim().toLowerCase() === 'font-family') return familyNames(decl.slice(ix + 1))[0] || '';
  }
  return '';
}

/** Remove @font-face de famílias que ninguém usa. */
function pruneFontFaces(css, usedSet) {
  const walk = (nodes) => nodes.map((n) => {
    if (n.type === 'at' && n.name === 'font-face') return usedSet.has(faceFamily(n.body)) ? n : null;
    if (n.type === 'at' && AT_WITH_RULES.has(n.name) && n.body !== null) {
      const inner = walk(parseSheet(n.body)).filter(Boolean);
      return inner.length ? { type: 'at', name: n.name, prelude: n.prelude, body: stringifySheet(inner) } : null;
    }
    return n;
  }).filter(Boolean);
  return stringifySheet(walk(parseSheet(css)));
}

const FORMAT_RANK = { woff2: 0, woff: 1, truetype: 2, opentype: 2, 'embedded-opentype': 4, svg: 5 };
function rankSrc(entry) {
  const f = /format\(\s*(["']?)([^"')]+)\1\s*\)/i.exec(entry);
  if (f) { const r = FORMAT_RANK[f[2].toLowerCase()]; return r === undefined ? 3 : r; }
  const u = scanUrls(entry)[0];
  if (u) { const e = /\.([a-z0-9]+)(?:[?#]|$)/i.exec(u.url); if (e) { const r = FORMAT_RANK[({ ttf: 'truetype', otf: 'opentype', eot: 'embedded-opentype' })[e[1].toLowerCase()] || e[1].toLowerCase()]; if (r !== undefined) return r; } }
  return 3;
}

/** Em cada @font-face deixa só a melhor fonte (woff2 > woff > ttf/otf); descarta eot/svg e local(). */
function keepBestFontSource(css) {
  const walk = (nodes) => nodes.map((n) => {
    if (n.type === 'at' && n.name === 'font-face' && n.body) {
      const decls = splitTopLevel(n.body, ';');
      const outDecls = decls.map((d) => {
        const ix = d.indexOf(':');
        if (ix < 0 || d.slice(0, ix).trim().toLowerCase() !== 'src') return d;
        const entries = splitTopLevel(d.slice(ix + 1), ',').map(x => x.trim()).filter(Boolean);
        const withUrl = entries.filter(e => scanUrls(e).length);
        const pool = withUrl.length ? withUrl : entries;
        pool.sort((a, b) => rankSrc(a) - rankSrc(b));
        return pool.length ? 'src:' + pool[0] : d;
      });
      return { type: 'at', name: 'font-face', prelude: n.prelude, body: outDecls.join(';') };
    }
    if (n.type === 'at' && AT_WITH_RULES.has(n.name) && n.body !== null) return { type: 'at', name: n.name, prelude: n.prelude, body: stringifySheet(walk(parseSheet(n.body))) };
    return n;
  });
  return stringifySheet(walk(parseSheet(css)));
}

/**
 * Colapsa espaços/linhas e remove comentários (fora de strings). Só remove espaço adjacente a
 * { } ; , — em qualquer outro lugar o espaço pode ser significativo ("a :hover", "calc(1px + 2px)").
 */
function minifyCss(css) {
  const s = String(css == null ? '' : css);
  const parts = [];
  let last = '';          // último caractere emitido (sem testar a string inteira: O(n))
  let i = 0; let space = false;
  const emit = (t) => { if (t) { parts.push(t); last = t[t.length - 1]; } };
  const tight = (ch) => ch === '{' || ch === '}' || ch === ';' || ch === ',';
  while (i < s.length) {
    const c = s[i];
    if (c === '/' && s[i + 1] === '*') { i = skipComment(s, i); space = true; continue; }
    if (c === '"' || c === "'") {
      const e = skipString(s, i);
      if (space && last && !tight(last)) emit(' ');
      space = false; emit(s.slice(i, e)); i = e; continue;
    }
    if (c === ' ' || c === '\n' || c === '\t' || c === '\r' || c === '\f') { space = true; i++; continue; }
    if (space && last && !tight(last) && !tight(c)) emit(' ');
    space = false;
    // copia o trecho "comum" até o próximo caractere especial de uma vez
    let j = i + 1;
    while (j < s.length) { const d = s[j]; if (d === ' ' || d === '\n' || d === '\t' || d === '\r' || d === '\f' || d === '"' || d === "'" || d === '/') break; j++; }
    emit(s.slice(i, j)); i = j;
  }
  return parts.join('');
}

module.exports = {
  parseSheet, stringifySheet, scanUrls, replaceUrls, replaceUrlsAsync, absolutizeUrls,
  parseImport, inlineImports, splitTopLevel, selectorForMatch, collectSelectors, pruneUnusedRules,
  usedFontFamilies, pruneFontFaces, keepBestFontSource, minifyCss, unescapeCss
};

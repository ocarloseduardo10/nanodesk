/**
 * NanoDesk — Arquivar página (1.9.0) — orquestrador
 * ------------------------------------------------------------------
 * Salva a página inteira em UM arquivo HTML autocontido, de forma NATIVA e PRIVADA:
 *   - roda no processo principal do NanoDesk (sem extensão, sem permissão <all_urls>);
 *   - acessa TODOS os frames (inclusive de outra origem) via webFrameMain;
 *   - busca os recursos pela SESSÃO DA PRÓPRIA ABA (cookies, contêiner, proxy Tor, DoH),
 *     sem limite de CORS e sem nenhum serviço externo;
 *   - ignora rastreadores (lista do bloqueador do NanoDesk) e rede privada/loopback;
 *   - o arquivo gerado leva CSP que BLOQUEIA toda rede e scripts (não "liga para casa" ao abrir),
 *     iframes em sandbox, e um selo SHA-256 verificável localmente.
 *
 * Este módulo não importa Electron: recebe "deps" (frames, fetch, relógio, filtros) — assim é
 * testado em Node com jsdom. Código ORIGINAL (MIT); nada do SingleFile (AGPL) foi copiado.
 */
'use strict';

const css = require('./archive-css');
const util = require('./archive-util');
const netLimits = require('./net-limits');
const crypto = require('crypto');
const { snapshotSource } = require('./archive-snapshot');

const MB = 1024 * 1024;

const DEFAULTS = Object.freeze({
  blockNetwork: true,          // CSP no arquivo salvo
  removeHidden: false,
  removeUnusedStyles: true,
  removeUnusedFonts: true,
  loadLazy: true,
  skipTrackers: true,
  selectionOnly: false,
  keepFormValues: true,
  compressCss: true,
  maxResources: 4000,
  maxResourceBytes: 25 * MB,
  maxTotalBytes: 400 * MB,
  concurrency: 6,
  timeoutMs: 20000,
  lazyMaxMs: 6000,
  maxImageEdge: 0              // 0 = sem redução (precisa de deps.transformImage)
});

const CSP = "default-src 'none'; img-src data:; media-src data:; font-src data:; style-src 'unsafe-inline'; frame-src data: about:; form-action 'none'; base-uri 'none'";

/* ---------------------- helpers ---------------------- */

function jsonLit(v) { return JSON.stringify(v); }

class Semaphore {
  constructor(n) { this.n = Math.max(1, n); this.q = []; }
  async run(fn) {
    if (this.n <= 0) await new Promise((r) => this.q.push(r));
    this.n -= 1;
    try { return await fn(); } finally { this.n += 1; const next = this.q.shift(); if (next) next(); }
  }
}

function withTimeout(promise, ms, label) {
  let t;
  return Promise.race([
    promise,
    new Promise((_, rej) => { t = setTimeout(() => rej(new Error(label || 'tempo esgotado')), ms); })
  ]).finally(() => clearTimeout(t));
}

function decodeText(buf, contentType) {
  const b = Buffer.from(buf);
  let label = 'utf-8';
  if (b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) return b.subarray(3).toString('utf8');
  const m = /charset=([\w-]+)/i.exec(String(contentType || ''));
  if (m) label = m[1];
  else {
    const at = /^@charset\s+"([\w-]+)"/.exec(b.subarray(0, 100).toString('latin1'));
    if (at) label = at[1];
  }
  try { return new TextDecoder(label).decode(b); } catch (_) { return b.toString('utf8'); }
}

function urlNoHash(u) { try { const x = new URL(u); x.hash = ''; return x.href; } catch (_) { return String(u || ''); } }

/* ---------------------- busca de recursos ---------------------- */

class Fetcher {
  constructor(deps, o, pageUrl, stats) {
    this.deps = deps; this.o = o; this.pageUrl = pageUrl; this.stats = stats;
    this.cache = new Map();
    this.sem = new Semaphore(o.concurrency);
    this.total = 0;
  }
  fail(url, why) {
    if (why === 'bloqueado') this.stats.blocked += 1; else if (why === 'privada' || why === 'esquema') this.stats.skipped += 1; else this.stats.failed += 1;
    if (this.stats.problems.length < 60) this.stats.problems.push({ url: String(url).slice(0, 200), motivo: why });
    return { ok: false, why };
  }
  /** @returns {Promise<{ok:boolean, buf?:Buffer, type?:string, why?:string}>} */
  get(url, referrer) {
    const key = urlNoHash(url);
    if (this.cache.has(key)) return this.cache.get(key);
    const p = this._get(url, referrer);
    this.cache.set(key, p);
    return p;
  }
  async _get(url, referrer) {
    if (!util.isFetchableUrl(url, this.pageUrl)) return this.fail(url, /^https?:/i.test(url) ? 'privada' : 'esquema');
    if (this.o.skipTrackers && this.deps.shouldBlock && this.deps.shouldBlock(url)) return this.fail(url, 'bloqueado');
    if (this.total >= this.o.maxTotalBytes) return this.fail(url, 'limite-total');
    return this.sem.run(async () => {
      try {
        const res = await withTimeout(this.deps.fetch(url, referrer || this.pageUrl), this.o.timeoutMs, 'tempo esgotado');
        if (!res || !res.ok) return this.fail(url, 'http-' + (res ? res.status : 'erro'));
        // 1.9.2: teto em STREAMING (antes: Content-Length + arrayBuffer() inteiro em memória)
        let buf;
        try { buf = await withTimeout(netLimits.readBodyLimited(res, this.o.maxResourceBytes), this.o.timeoutMs, 'tempo esgotado'); }
        catch (e) { if (e && e.code === 'BODY_TOO_LARGE') return this.fail(url, 'grande-demais'); throw e; }
        this.total += buf.length;
        this.stats.fetched += 1;
        this.stats.bytes += buf.length;
        return { ok: true, buf, type: res.headers && res.headers.get ? res.headers.get('content-type') || '' : '' };
      } catch (e) {
        return this.fail(url, String(e && e.message ? e.message : e).slice(0, 60));
      }
    });
  }
  async text(url, referrer) {
    const r = await this.get(url, referrer);
    return r.ok ? decodeText(r.buf, r.type) : null;
  }
}

/* ---------------------- frames ---------------------- */

function exec(F, expr) { return F.frame.exec(expr); }

async function prepareFrames(rootFrame, o, progress, NS) {
  const frames = [];
  let counter = 0;
  const prepOpts = { removeHidden: o.removeHidden, selectionOnly: o.selectionOnly, keepFormValues: o.keepFormValues, maxResources: o.maxResources };
  const visit = async (frame, parent, parentToken, depth) => {
    const F = { frame, parent, parentToken, prefix: parent ? 'c' + (++counter) + '_' : '', prep: null, children: [] };
    frames.push(F);
    const pre = snapshotSource(NS);
    if (!parent && o.loadLazy) {
      try { await exec(F, pre + 'window[' + jsonLit(NS) + '].settle(' + jsonLit({ maxMs: o.lazyMaxMs }) + ');'); } catch (_) { /* segue sem rolar */ }
    }
    F.prep = await exec(F, pre + 'window[' + jsonLit(NS) + '].prepare(' + jsonLit(Object.assign({}, prepOpts, { idPrefix: F.prefix, selectionOnly: !parent && o.selectionOnly })) + ');');
    if (progress) progress({ phase: 'estrutura', frames: frames.length });
    if (depth >= 3) return;
    const kids = (frame.children || []).slice();
    for (const it of (F.prep.iframes || [])) {
      const want = urlNoHash(it.src);
      const ix = kids.findIndex((k) => urlNoHash(k.url) === want);
      if (ix < 0) continue;
      const kid = kids.splice(ix, 1)[0];
      await visit(kid, F, it.token, depth + 1);
    }
  };
  await visit(rootFrame, null, null, 0);
  return frames;
}

/* ---------------------- pipeline de CSS ---------------------- */

async function oracle(F, scope, selectors, cache, NS) {
  const need = [];
  const norm = new Map();
  for (const s of selectors) {
    const n = css.selectorForMatch(s);
    norm.set(s, n);
    if (n !== null && !cache.has(scope + '\u0000' + n) && !need.includes(n)) need.push(n);
  }
  for (let i = 0; i < need.length; i += 400) {
    const chunk = need.slice(i, i + 400);
    let res;
    try { res = await exec(F, 'window[' + jsonLit(NS) + '].matches(' + jsonLit(scope) + ',' + jsonLit(chunk) + ');'); } catch (_) { res = chunk.map(() => true); }
    chunk.forEach((n, k) => cache.set(scope + '\u0000' + n, res[k] !== false));
  }
  const used = new Map();
  for (const s of selectors) {
    const n = norm.get(s);
    used.set(s, n === null ? true : cache.get(scope + '\u0000' + n) !== false);
  }
  return used;
}

async function inlineCssUrls(text, referrer, fetcher, o, deps) {
  return css.replaceUrlsAsync(text, async (u) => {
    const t = String(u).trim();
    if (!t || t.startsWith('#') || /^data:/i.test(t)) return null;
    const r = await fetcher.get(t, referrer);
    if (!r.ok) return 'data:,';
    let mime = util.sniffMime(r.buf, r.type, t);
    let buf = r.buf;
    if (!/^(image|font)\//.test(mime) && !/^application\/(font|x-font|vnd\.ms-fontobject)/.test(mime)) return 'data:,';
    if (o.maxImageEdge > 0 && /^image\/(png|jpeg|webp)$/.test(mime) && deps.transformImage) {
      try { const tr = await deps.transformImage(buf, mime, { maxEdge: o.maxImageEdge }); if (tr && tr.buf && tr.buf.length < buf.length) { buf = tr.buf; mime = tr.mime || mime; } } catch (_) { /* mantém original */ }
    }
    return util.toDataUri(buf, mime);
  });
}

/* ---------------------- principal ---------------------- */

/**
 * @param {object} deps
 *   rootFrame: {url, exec(code)->Promise, children:[...]}
 *   fetch(url, referrer) -> Promise<{ok,status,headers:{get},arrayBuffer()}>
 *   shouldBlock?(url) -> boolean
 *   transformImage?(buf, mime, {maxEdge}) -> Promise<{buf,mime}>
 *   now?() -> Date
 *   onProgress?(info)
 * @param {object} userOpts  ver DEFAULTS
 * @returns {Promise<{html:string, title:string, url:string, fileBase:string, stats:object}>}
 */
async function archivePage(deps, userOpts) {
  const o = Object.assign({}, DEFAULTS, userOpts || {});
  const now = deps.now ? deps.now() : new Date();
  const progress = deps.onProgress || null;
  const stats = { fetched: 0, failed: 0, blocked: 0, skipped: 0, bytes: 0, frames: 0, cssRulesDropped: 0, problems: [] };

  const NS = '__nd_' + crypto.randomBytes(9).toString('hex');
  const frames = await prepareFrames(deps.rootFrame, o, progress, NS);
  stats.frames = frames.length;
  const root = frames[0];
  const pageUrl = root.prep.url || deps.rootFrame.url;
  const fetcher = new Fetcher(deps, o, pageUrl, stats);

  /* 1) folhas de estilo: texto → @import → poda de regras */
  const items = [];
  for (const F of frames) for (const st of (F.prep.styles || [])) items.push({ F, st });
  const sels = new Map();
  const cache = new Map();
  let doneItems = 0;
  for (const it of items) {
    const { st, F } = it;
    let text = st.text;
    if (st.kind === 'inline') { it.out = st.text; continue; }
    if (st.href) {
      const fetched = await fetcher.text(st.href, F.prep.url);
      if (fetched != null) text = fetched;
    }
    if (text == null) { it.out = ''; continue; }
    const base = st.href || st.base || F.prep.url;
    text = await css.inlineImports(text, base, (u) => fetcher.text(u, base));
    if (o.removeUnusedStyles) {
      const list = css.collectSelectors(text);
      if (list.length) {
        const used = await oracle(F, st.scope, list, cache, NS);
        const before = list.length;
        text = css.pruneUnusedRules(text, used);
        stats.cssRulesDropped += Math.max(0, before - css.collectSelectors(text).length);
      }
    }
    if (st.media && /\S/.test(st.media) && st.media.toLowerCase() !== 'all') { /* o atributo media do <style> já limita */ }
    it.out = text;
    doneItems += 1;
    if (progress) progress({ phase: 'estilos', done: doneItems, total: items.length });
  }

  /* 2) fontes: só as famílias realmente usadas, e só o melhor formato */
  if (o.removeUnusedFonts) {
    const usedFamilies = new Set();
    for (const it of items) {
      const u = css.usedFontFamilies(it.st.kind === 'inline' ? '' : it.out, it.st.kind === 'inline' ? it.out : '');
      u.forEach((x) => usedFamilies.add(x));
    }
    for (const it of items) if (it.st.kind !== 'inline') it.out = css.pruneFontFaces(it.out, usedFamilies);
  }
  for (const it of items) if (it.st.kind !== 'inline') it.out = css.keepBestFontSource(it.out);

  /* 3) url() → data: URI */
  let k = 0;
  for (const it of items) {
    const ref = it.st.href || it.st.base || it.F.prep.url;
    const abs = it.st.kind === 'inline' ? css.absolutizeUrls(it.out, it.st.base || it.F.prep.url) : it.out;
    let out = await inlineCssUrls(abs, ref, fetcher, o, deps);
    if (o.compressCss && it.st.kind !== 'inline') out = css.minifyCss(out);
    it.final = out;
    k += 1;
    if (progress && k % 5 === 0) progress({ phase: 'recursos-css', done: k, total: items.length });
  }

  /* 4) imagens e ícones referenciados no HTML */
  const resTasks = [];
  const perFrame = new Map(frames.map((F) => [F, { resources: {}, styles: {}, frames: {} }]));
  let rdone = 0; const rtotal = frames.reduce((n, F) => n + (F.prep.resources || []).length, 0);
  for (const F of frames) {
    for (const r of (F.prep.resources || [])) {
      resTasks.push((async () => {
        const got = await fetcher.get(r.url, r.base || F.prep.url);
        if (got.ok) {
          let mime = util.sniffMime(got.buf, got.type, r.url);
          let buf = got.buf;
          if (/^image\//.test(mime)) {
            if (o.maxImageEdge > 0 && /^image\/(png|jpeg|webp)$/.test(mime) && deps.transformImage) {
              try { const tr = await deps.transformImage(buf, mime, { maxEdge: o.maxImageEdge }); if (tr && tr.buf && tr.buf.length < buf.length) { buf = tr.buf; mime = tr.mime || mime; } } catch (_) { /* mantém */ }
            }
            perFrame.get(F).resources[r.id] = util.toDataUri(buf, mime);
          } else { stats.skipped += 1; if (stats.problems.length < 60) stats.problems.push({ url: r.url.slice(0, 200), motivo: 'tipo-' + mime }); }
        }
        rdone += 1;
        if (progress && rdone % 10 === 0) progress({ phase: 'imagens', done: rdone, total: rtotal });
      })());
    }
  }
  await Promise.all(resTasks);
  for (const it of items) perFrame.get(it.F).styles[it.st.id] = it.final;

  /* 5) entrega os dados aos frames (em partes) e finaliza de dentro para fora */
  const putChunks = async (F, data) => {
    for (const kind of ['resources', 'styles', 'frames']) {
      const entries = Object.entries(data[kind] || {});
      let chunk = {}; let size = 0;
      const flush = async () => { if (size > 0 || Object.keys(chunk).length) { await exec(F, 'window[' + jsonLit(NS) + '].put(' + jsonLit({ [kind]: chunk }) + ');'); chunk = {}; size = 0; } };
      for (const [id, v] of entries) {
        chunk[id] = v; size += String(v).length;
        if (size > 6 * MB) await flush();
      }
      await flush();
    }
    await exec(F, 'window[' + jsonLit(NS) + '].put(' + jsonLit({ resources: { __final: 1 }, styles: { __final: 1 } }) + ');');
  };
  const savedAt = now.toISOString();
  let rootHtml = '';
  for (let i = frames.length - 1; i >= 0; i--) {
    const F = frames[i];
    await putChunks(F, perFrame.get(F));
    const meta = i === 0 ? { csp: o.blockNetwork ? CSP : '', sourceUrl: pageUrl, savedAt } : {};
    const html = await exec(F, 'window[' + jsonLit(NS) + '].finalize(' + jsonLit(meta) + ');');
    try { await exec(F, 'window[' + jsonLit(NS) + '].dispose();'); } catch (_) { /* ignorado */ }
    if (F.parent) perFrame.get(F.parent).frames[F.parentToken] = html; else rootHtml = html;
  }

  /* 6) montagem final + selo */
  const title = String(root.prep.title || '').trim();
  const header = util.buildHeader({ url: pageUrl, title, savedAt });
  const sealed = util.sealArchive(header + rootHtml);
  const fileBase = util.buildFileName(o.fileTemplate, { title, url: pageUrl, date: now });
  stats.bytesOut = Buffer.byteLength(sealed, 'utf8');
  return { html: sealed, title, url: pageUrl, fileBase, stats };
}

module.exports = { archivePage, DEFAULTS, CSP, decodeText, Fetcher };

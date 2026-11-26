/**
 * NanoDesk — Leitor de notícias (1.4.0, zero dependências)
 * ==================================================================
 * Implementa no navegador o que os projetos de referência fazem:
 *  - FreshRSS  → gestão de inscrições com importação/exportação OPML;
 *  - Miniflux  → leitura minimalista e LIMPEZA DE RASTREADORES dos links
 *                (parâmetros utm_*, fbclid, gclid… removidos dos artigos);
 *  - rssPresso → minimalismo (lista de feeds → lista de artigos → leitura).
 *
 * Privacidade coerente com o NanoDesk:
 *  - as inscrições e o estado "lido" vivem SÓ NA MEMÓRIA (MemoryStore);
 *  - os feeds são buscados pela MESMA sessão anônima de navegação
 *    (cookies voláteis, UA real, nada no disco);
 *  - exportar OPML é uma ação EXPLÍCITA do usuário (arquivo escolhido
 *    por ele) — o app nunca grava nada por conta própria.
 */
'use strict';

const crypto = require('crypto');
const htmlutil = require('./htmlutil');
const netLimits = require('./net-limits');

const LIMITS = {
  maxFeeds: 100,
  maxItemsPerFeed: 200,
  maxFetchBytes: 8 * 1024 * 1024,
  fetchTimeoutMs: 15000
};

/* Parâmetros de rastreamento removidos dos links de artigos (estilo
 * Miniflux). Prefixos utm_/pk_/mc_ cobrem as variantes mais comuns. */
const TRACKING_PARAMS = new Set([
  'fbclid', 'gclid', 'gclsrc', 'dclid', 'gbraid', 'wbraid', 'msclkid',
  'igshid', '_hsenc', '_hsmi', 'vero_id', 'vero_conv', 'yclid', 'twclid',
  'ttclid', 'mkt_tok', 'ck_subscriber_id', 's_cid', 'ncid', 'oaid',
  'rb_clickid', 'dm_i', 'elqtrackid', 'sr_share', 'cvid', 'ref', 'ref_src',
  'ref_url', 'cmpid', 'campaign_id', 'newsletter_id'
]);

function stripTrackingParams(url) {
  try {
    const u = new URL(String(url || ''));
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return url;
    const drop = [];
    for (const k of Array.from(u.searchParams.keys())) {
      const kl = k.toLowerCase();
      if (TRACKING_PARAMS.has(kl) || kl.startsWith('utm_') ||
          kl.startsWith('pk_') || kl.startsWith('mc_') || kl.startsWith('hsa_')) {
        drop.push(k);
      }
    }
    for (const k of drop) u.searchParams.delete(k);
    return u.href;
  } catch (_) {
    return String(url || '');
  }
}

function hashId(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex').slice(0, 24);
}

/* ---------------- parser de feeds (RSS 2.0 / Atom / RDF) ---------------- */

function fieldText(el) {
  return htmlutil.decodeEntities(htmlutil.textOf(el)).replace(/\s+/g, ' ').trim();
}

function pick(links, rel) {
  if (!links.length) return '';
  if (rel) {
    const hit = links.find(l => (l.attrs.rel || '').toLowerCase() === rel);
    if (hit) return hit.attrs.href || '';
  }
  return links[0].attrs.href || '';
}

function childNamed(el, names) {
  for (const c of el.children || []) {
    if (c.type === 'el' && names.includes(c.tag)) return c;
  }
  return null;
}

function parseFeed(xml, sourceUrl) {
  const root = htmlutil.parseHtml(String(xml || '').slice(0, LIMITS.maxFetchBytes));
  const first = root.children.find(c => c.type === 'el');
  if (!first) throw new Error('Feed vazio ou inválido.');

  let channel, itemsRaw, type;
  if (first.tag === 'rss' || first.tag === 'channel') {
    channel = first.tag === 'rss' ? childNamed(first, ['channel']) : first;
    type = 'rss';
    itemsRaw = channel ? channel.children.filter(c => c.type === 'el' && c.tag === 'item') : [];
  } else if (first.tag === 'feed') {
    channel = first;
    type = 'atom';
    itemsRaw = first.children.filter(c => c.type === 'el' && c.tag === 'entry');
  } else if (/:?rdf$/i.test(first.tag)) {
    channel = childNamed(first, ['channel']);
    type = 'rdf';
    itemsRaw = first.children.filter(c => c.type === 'el' && c.tag === 'item');
  } else {
    throw new Error('Formato não reconhecido como RSS/Atom.');
  }
  if (!channel) throw new Error('Feed sem canal.');

  const feedLinks = (channel.children || []).filter(c => c.type === 'el' && c.tag === 'link');
  const meta = {
    type,
    title: fieldText(childNamed(channel, ['title']) || { children: [] }) ||
      htmlutil.metaContent(channel, 'title') || 'Feed sem título',
    link: type === 'atom' ? pick(feedLinks, 'alternate') || pick(feedLinks) : fieldText(feedLinks[0] || { children: [] }),
    description: fieldText(childNamed(channel, ['description', 'subtitle', 'tagline']) || { children: [] })
  };
  if (!meta.link && sourceUrl) meta.link = sourceUrl;

  const now = Date.now();
  const items = [];
  for (const it of itemsRaw.slice(0, LIMITS.maxItemsPerFeed)) {
    const links = (it.children || []).filter(c => c.type === 'el' && c.tag === 'link');
    let url = '';
    let guid = fieldText(childNamed(it, ['guid', 'id']) || { children: [] });
    if (type === 'atom') {
      url = pick(links, 'alternate') || pick(links);
    } else {
      url = fieldText(links[0] || { children: [] });
    }
    url = stripTrackingParams(url);
    const title = fieldText(childNamed(it, ['title']) || { children: [] }) || '(sem título)';
    const rawDate = fieldText(childNamed(it, ['pubdate', 'published', 'updated', 'dc:date']) || { children: [] });
    let ts = rawDate ? Date.parse(rawDate) : NaN;
    if (!Number.isFinite(ts)) ts = now;

    let descRaw = fieldText(childNamed(it, ['description', 'summary']) || { children: [] });
    let contentRaw = fieldText(childNamed(it, ['content:encoded', 'content']) || { children: [] });
    if (!contentRaw && descRaw) contentRaw = descRaw;
    if (!descRaw && contentRaw) descRaw = htmlutil.textSummary(contentRaw, 300);

    const authorEl = childNamed(it, ['author']);
    const author = authorEl
      ? fieldText(childNamed(authorEl, ['name']) || authorEl)
      : fieldText(childNamed(it, ['dc:creator']) || { children: [] });

    const base = url || meta.link || sourceUrl || '';
    const id = hashId((guid || url || title + '|' + ts) + '@' + (base));
    items.push({
      id,
      title: title.slice(0, 300),
      url,
      author: author.slice(0, 120),
      ts,
      summaryHtml: descRaw ? htmlutil.sanitizeHtml(descRaw, { baseUrl: base, allowDataImages: true }) : '',
      contentHtml: contentRaw
        ? htmlutil.sanitizeHtml(contentRaw, { baseUrl: base, allowDataImages: true })
          .slice(0, LIMITS.maxFetchBytes)
        : ''
    });
  }
  items.sort((a, b) => b.ts - a.ts);
  return { meta, items };
}

/* ---------------- descoberta de feed em páginas HTML ---------------- */

const FEED_TYPES = new Set(['application/rss+xml', 'application/atom+xml',
  'application/rss', 'application/atom', 'text/xml', 'application/xml']);

function discoverFeeds(htmlText, pageUrl) {
  const root = htmlutil.parseHtml(String(htmlText || '').slice(0, 1024 * 1024));
  const out = [];
  for (const link of htmlutil.findByTag(root, 'link')) {
    const rel = (link.attrs.rel || '').toLowerCase();
    const type = (link.attrs.type || '').toLowerCase();
    if (!rel.split(/\s+/).includes('alternate') || !FEED_TYPES.has(type)) continue;
    const href = htmlutil.safeUrl(link.attrs.href, pageUrl, {});
    if (href) out.push({ url: href, title: htmlutil.decodeEntities(link.attrs.title || '') });
  }
  // fallback comum: <a> para feed.xml / rss (rssPresso faz o mesmo)
  if (!out.length) {
    for (const a of htmlutil.findByTag(root, 'a')) {
      const href = htmlutil.safeUrl(a.attrs.href, pageUrl, {});
      if (href && /\.(xml|rss)$/i.test(new URL(href).pathname)) {
        out.push({ url: href, title: fieldText(a) || 'Feed' });
        if (out.length >= 3) break;
      }
    }
  }
  return out.slice(0, 8);
}

/* ---------------- OPML (estilo FreshRSS) ---------------- */

function opmlEscape(s) {
  return String(s == null ? '' : s)
    .replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c]));
}

function generateOpml(feeds) {
  const lines = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<opml version="2.0">',
    '<head><title>Inscrições do NanoDesk</title>' +
      '<dateCreated>' + new Date().toUTCString() + '</dateCreated></head>',
    '<body>'
  ];
  for (const f of feeds) {
    lines.push('  <outline type="rss" text="' + opmlEscape(f.title) +
      '" title="' + opmlEscape(f.title) + '" xmlUrl="' + opmlEscape(f.url) + '"' +
      (f.siteUrl ? ' htmlUrl="' + opmlEscape(f.siteUrl) + '"' : '') + '/>');
  }
  lines.push('</body>', '</opml>');
  return lines.join('\n');
}

function parseOpml(xmlText) {
  const root = htmlutil.parseHtml(String(xmlText || '').slice(0, 4 * 1024 * 1024));
  const out = [];
  for (const o of htmlutil.findByTag(root, 'outline')) {
    const xmlUrl = htmlutil.safeUrl(o.attrs.xmlurl || '', null, {});
    if (!xmlUrl) continue;
    out.push({
      title: htmlutil.decodeEntities(o.attrs.title || o.attrs.text || '') || xmlUrl,
      url: xmlUrl,
      siteUrl: htmlutil.safeUrl(o.attrs.htmlurl || '', null, {})
    });
    if (out.length >= LIMITS.maxFeeds) break;
  }
  return out;
}

/* ---------------- busca (fetch) pela sessão anônima ---------------- */

async function fetchText(session, url) {
  const res = await session.fetch(url, {
    signal: AbortSignal.timeout(LIMITS.fetchTimeoutMs),
    headers: {
      'Accept': 'application/rss+xml, application/atom+xml, application/xml, text/xml, text/html;q=0.8, */*;q=0.5',
      'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.7'
    },
    disableCache: false
  });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  // 1.9.2: teto aplicado em STREAMING (Content-Length pode faltar ou mentir)
  try { return await netLimits.readTextLimited(res, LIMITS.maxFetchBytes); }
  catch (e) { if (e && e.code === 'BODY_TOO_LARGE') throw new Error('Resposta maior que o limite.'); throw e; }
}

/* Página HTML (não feed): começa com doctype/html OU contém <html> no início.
 * CUIDADO: <?xml ...?> NÃO é sinal de HTML — é justamente feed/XML. */
const looksLikeHtml = (t) => /^\uFEFF?\s*(<!DOCTYPE\s+html|<html[\s>])/i.test(t) ||
  /<html[\s>]/i.test(t.slice(0, 2048));

/**
 * Baixa e interpreta uma URL como feed. Se a URL for uma página HTML,
 * tenta descobrir o feed declarado nela (um salto, sem recursão).
 */
async function fetchFeed(session, url) {
  let target = url;
  let text = await fetchText(session, target);
  if (looksLikeHtml(text)) {
    const found = discoverFeeds(text, target);
    if (!found.length) throw new Error('A página não declara um feed RSS/Atom.');
    target = found[0].url;
    text = await fetchText(session, target);
    if (looksLikeHtml(text)) throw new Error('Feed declarado não retornou XML.');
  }
  const parsed = parseFeed(text, target);
  parsed.meta.link = parsed.meta.link || target;
  parsed.discoveredUrl = target !== url ? target : null;
  return parsed;
}

/* ---------------- serviço de estado (só memória) ---------------- */

/**
 * store: MemoryStore (items: []); session: sessão anônima;
 * notify: callback após qualquer mudança (para push ao renderer).
 */
function createReaderService({ store, session, notify }) {
  const feeds = () => store.get('items', []);
  const setFeeds = (list) => { store.set('items', list); notify && notify(); };

  function recalcUnread(f) {
    f.unread = f.items.reduce((n, i) => n + (i.read ? 0 : 1), 0);
  }

  function findFeed(feedId) { return feeds().find(f => f.id === feedId) || null; }
  function findItem(itemId) {
    for (const f of feeds()) {
      const it = f.items.find(i => i.id === itemId);
      if (it) return { feed: f, item: it };
    }
    return null;
  }

  async function subscribe(rawUrl) {
    const url = String(rawUrl || '').trim();
    if (!/^https?:\/\//i.test(url)) throw new Error('Informe uma URL http/https.');
    if (feeds().length >= LIMITS.maxFeeds) throw new Error('Limite de ' + LIMITS.maxFeeds + ' inscrições nesta sessão.');
    if (feeds().some(f => f.url === url || f.addedVia === url)) throw new Error('Você já acompanha este feed.');

    const parsed = await fetchFeed(session, url);
    // a URL digitada pode ser a de um SITE cujo feed já foi adicionado
    if (feeds().some(f => f.url === (parsed.discoveredUrl || url))) {
      throw new Error('Você já acompanha este feed.');
    }
    const f = {
      id: hashId('feed|' + (parsed.discoveredUrl || url)) + hashId(url).slice(0, 8),
      url: parsed.discoveredUrl || url,
      addedVia: url,
      siteUrl: parsed.meta.link || '',
      title: parsed.meta.title,
      description: parsed.meta.description,
      addedAt: Date.now(),
      lastFetchAt: Date.now(),
      lastError: '',
      unread: 0,
      items: parsed.items.map(i => ({ ...i, read: false, feedId: null }))
    };
    for (const i of f.items) i.feedId = f.id;
    recalcUnread(f);
    setFeeds(feeds().concat([f]));
    return f;
  }

  function remove(feedId) {
    setFeeds(feeds().filter(f => f.id !== feedId));
  }

  function mergeItems(f, parsed) {
    const known = new Map(f.items.map(i => [i.id, i]));
    const merged = [];
    for (const p of parsed.items) {
      const old = known.get(p.id);
      if (old) {
        old.title = p.title;
        old.url = p.url || old.url;
        old.summaryHtml = p.summaryHtml || old.summaryHtml;
        old.contentHtml = p.contentHtml || old.contentHtml;
        old.ts = p.ts || old.ts;
        merged.push(old);
      } else {
        merged.push({ ...p, read: false, feedId: f.id });
      }
    }
    merged.sort((a, b) => b.ts - a.ts);
    f.items = merged.slice(0, LIMITS.maxItemsPerFeed);
    recalcUnread(f);
  }

  async function refresh(feedId) {
    const targets = feedId && feedId !== 'all' ? [findFeed(feedId)].filter(Boolean) : feeds();
    if (!targets.length) return { ok: true, updated: 0, failed: 0 };
    let updated = 0, failed = 0;
    for (const f of targets) {
      try {
        const parsed = await fetchFeed(session, f.addedVia || f.url);
        mergeItems(f, parsed);
        if (parsed.meta.title) f.title = parsed.meta.title;
        f.lastFetchAt = Date.now();
        f.lastError = '';
        updated++;
      } catch (e) {
        f.lastError = String(e && e.message ? e.message : e).slice(0, 200);
        f.lastFetchAt = Date.now();
        failed++;
      }
    }
    setFeeds(feeds());
    return { ok: true, updated, failed };
  }

  function list() {
    return feeds().map(f => ({
      id: f.id, url: f.url, siteUrl: f.siteUrl, title: f.title,
      description: f.description,
      // não lido calculado ao vivo — o contador nunca dessincroniza
      unread: f.items.reduce((n, i) => n + (i.read ? 0 : 1), 0),
      lastError: f.lastError,
      total: f.items.length, lastFetchAt: f.lastFetchAt
    }));
  }

  /** Itens de um feed ('all' junta tudo, mais recentes primeiro). */
  function items(feedId, opts) {
    const o = opts || {};
    const src = feedId && feedId !== 'all'
      ? (findFeed(feedId) || { items: [] }).items
      : feeds().flatMap(f => f.items);
    let list = src.slice().sort((a, b) => b.ts - a.ts);
    if (o.unreadOnly) list = list.filter(i => !i.read);
    return list.slice(0, o.limit || 400).map(i => ({
      id: i.id, feedId: i.feedId, title: i.title, url: i.url, author: i.author,
      ts: i.ts, read: i.read,
      summaryHtml: o.withSummary === false ? '' : i.summaryHtml
    }));
  }

  function item(itemId) {
    const hit = findItem(itemId);
    if (!hit) return null;
    return {
      id: hit.item.id, feedId: hit.feed.id, feedTitle: hit.feed.title,
      title: hit.item.title, url: hit.item.url, author: hit.item.author,
      ts: hit.item.ts, read: hit.item.read, contentHtml: hit.item.contentHtml,
      summaryHtml: hit.item.summaryHtml
    };
  }

  function markRead(itemId, read) {
    const hit = findItem(itemId);
    if (!hit) return false;
    hit.item.read = read !== false;
    recalcUnread(hit.feed);
    setFeeds(feeds());
    return true;
  }

  function markAllRead(feedId) {
    const targets = feedId && feedId !== 'all' ? [findFeed(feedId)].filter(Boolean) : feeds();
    for (const f of targets) for (const i of f.items) i.read = true;
    for (const f of targets) recalcUnread(f);
    setFeeds(feeds());
    return true;
  }

  function opml() { return generateOpml(feeds()); }

  async function importOpml(xmlText) {
    const outlines = parseOpml(xmlText);
    if (!outlines.length) throw new Error('Nenhum feed encontrado no arquivo OPML.');
    let added = 0, failed = 0, skipped = 0;
    for (const o of outlines) {
      if (feeds().length >= LIMITS.maxFeeds) { skipped++; continue; }
      if (feeds().some(f => f.url === o.url || f.addedVia === o.url)) { skipped++; continue; }
      try {
        const parsed = await fetchFeed(session, o.url);
        const f = {
          id: hashId('feed|' + o.url) + hashId(parsed.meta.title).slice(0, 8),
          url: parsed.discoveredUrl || o.url,
          addedVia: o.url,
          siteUrl: parsed.meta.link || o.siteUrl || '',
          title: o.title || parsed.meta.title,
          description: parsed.meta.description,
          addedAt: Date.now(), lastFetchAt: Date.now(), lastError: '',
          unread: 0,
          items: parsed.items.map(i => ({ ...i, read: false, feedId: null }))
        };
        for (const i of f.items) i.feedId = f.id;
        recalcUnread(f);
        setFeeds(feeds().concat([f]));
        added++;
      } catch (_) { failed++; }
    }
    return { added, failed, skipped };
  }

  return {
    subscribe, remove, refresh, list, items, item, markRead, markAllRead,
    opml, importOpml, findItem
  };
}

module.exports = {
  parseFeed, discoverFeeds, generateOpml, parseOpml, stripTrackingParams,
  fetchFeed, fetchText, createReaderService, LIMITS, TRACKING_PARAMS
};

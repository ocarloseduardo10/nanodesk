/**
 * NanoDesk — Modo Leitura (1.4.0, zero dependências)
 * ==================================================================
 * Extração do conteúdo principal de uma página para leitura limpa,
 * SEM bloqueios de anúncio e SEM contornar paywalls: o Modo Leitura
 * lê o MESMO HTML público que o site entrega a qualquer navegador —
 * se o site só entrega o artigo após login/assinatura, o modo leitura
 * NÃO o revela. É o recurso padrão "reader mode" presente no Firefox,
 * Safari e Edge, adaptado ao NanoDesk.
 *
 * Pipeline: fetch pela sessão anônima → parser tolerante → escolha do
 * candidato com maior densidade de parágrafos → limpeza (nav, aside,
 * footer, formulários, scripts) → sanitização por lista branca.
 */
'use strict';

const htmlutil = require('./htmlutil');
const { fetchText } = require('./reader');

const STRIP_TAGS = new Set(['script', 'style', 'noscript', 'nav', 'header',
  'footer', 'aside', 'form', 'iframe', 'button', 'select', 'textarea',
  'input', 'svg', 'canvas', 'video', 'audio', 'template', 'dialog',
  'figure', 'menu']);

function scoreContainer(el) {
  let score = 0;
  const walk = (n, depth) => {
    if (depth > 25 || !n.children) return;
    for (const c of n.children) {
      if (c.type !== 'el') continue;
      if (['p', 'blockquote', 'pre', 'li'].includes(c.tag)) {
        score += Math.min(htmlutil.textOf(c).trim().length, 3000);
      } else if (/^h[1-6]$/.test(c.tag)) {
        score += Math.min(htmlutil.textOf(c).trim().length, 400);
      } else {
        walk(c, depth + 1);
      }
    }
  };
  walk(el, 0);
  return score;
}

function cleanInside(el) {
  const drop = [];
  for (const c of el.children) {
    if (c.type === 'el' && STRIP_TAGS.has(c.tag)) { drop.push(c); continue; }
    if (c.type === 'el') cleanInside(c);
  }
  for (const d of drop) el.children.splice(el.children.indexOf(d), 1);
}

/** Escolhe o melhor container de artigo entre candidatos plausíveis. */
function pickArticleRoot(root) {
  const articles = htmlutil.findByTag(root, 'article');
  if (articles.length) {
    return articles.reduce((best, a) => (scoreContainer(a) >= scoreContainer(best) ? a : best));
  }
  const mains = [
    ...htmlutil.findAll(root, c => (c.attrs.role || '').toLowerCase() === 'main'),
    ...htmlutil.findByTag(root, 'main')
  ];
  if (mains.length) {
    return mains.reduce((best, m) => (scoreContainer(m) >= scoreContainer(best) ? m : best));
  }
  // heurística: div/section com maior densidade de parágrafos
  const candidates = htmlutil.findAll(root, c =>
    ['div', 'section', 'td', 'body'].includes(c.tag));
  let best = null, bestScore = 0;
  for (const c of candidates) {
    const s = scoreContainer(c);
    if (s > bestScore) { best = c; bestScore = s; }
  }
  return best;
}

function extractFromHtml(htmlText, baseUrl) {
  const root = htmlutil.parseHtml(String(htmlText || '').slice(0, 1024 * 1024));

  const title = htmlutil.metaContent(root, 'og:title') ||
    htmlutil.metaContent(root, 'twitter:title') ||
    (() => {
      const t = htmlutil.findByTag(root, 'title')[0];
      return t ? htmlutil.decodeEntities(htmlutil.textOf(t)).trim() : '';
    })() ||
    (() => {
      const h = htmlutil.findByTag(root, 'h1')[0];
      return h ? htmlutil.textSummary(htmlutil.decodeEntities(htmlutil.textOf(h)), 200) : '';
    })();

  const byline = htmlutil.metaContent(root, 'author') ||
    htmlutil.metaContent(root, 'article:author') || '';

  const chosen = pickArticleRoot(root);
  if (!chosen) throw new Error('Não foi possível localizar o conteúdo do artigo.');

  cleanInside(chosen);

  // Remove subtrees que continuam sem parágrafos úteis (menus escondidos)
  const inner = chosen.children.filter(c => c.type !== 'el' ||
    !['nav', 'aside', 'footer', 'header'].includes(c.tag));
  const probe = { type: 'el', tag: '#root', attrs: {}, children: inner };
  const out = [];
  htmlutil.serialize(probe, { baseUrl, allowDataImages: true }, 0, out);
  const contentHtml = out.join('').slice(0, 320 * 1024);
  const plainText = htmlutil.textOf(htmlutil.parseHtml(contentHtml))
    .replace(/\s+/g, ' ').trim();

  if (plainText.replace(/\s/g, '').length < 200) {
    throw new Error('Esta página não tem texto de artigo extraível (app/quiz/resultado dinâmico?).');
  }

  return {
    title: (title || 'Artigo').slice(0, 300),
    byline: String(byline).slice(0, 200),
    siteName: htmlutil.metaContent(root, 'og:site_name').slice(0, 120),
    url: baseUrl,
    wordCount: plainText.split(/\s+/).length,
    contentHtml
  };
}

async function extractArticle(session, url) {
  if (!/^https?:\/\//i.test(String(url || ''))) {
    throw new Error('O Modo Leitura precisa de uma página http/https.');
  }
  const html = await fetchText(session, url);
  return extractFromHtml(html, url);
}

module.exports = { extractArticle, extractFromHtml, pickArticleRoot, scoreContainer };

/**
 * NanoDesk — Limpeza de parâmetros de rastreamento (1.6.0, FASE 4)
 * ==================================================================
 * Conceito do projeto aberto ClearURLs (github.com/ClearURLs/Addon,
 * GPL-3.0) REIMPLEMENTADO do zero em código original (MIT NanoDesk):
 * nenhuma linha do ClearURLs é copiada — apenas a ideia de remover
 * parâmetros cuja única função é rastrear o clique entre sites.
 *
 * Duas camadas de regras:
 *  1. GLOBAIS — parâmetros reconhecidos em QUALQUER site:
 *     utm_*, fbclid, gclid, msclkid, dclid, twclid, ttclid, igshid,
 *     mc_eid, _hsenc/_hsmi, yclid, pk_/hsa_ (variantes), spm/scn…
 *  2. POR SITE — parâmetros de rastreamento específicos de domínios
 *     conhecidos (YouTube "si", X/Twitter "t"/"s", Instagram "igsh",
 *     TikTok "_t/_r/web_id", Spotify "si", LinkedIn "trk" etc.).
 *
 * Princípios:
 *  - NUNCA remover parâmetro funcional (IDs de página, buscas, âncoras
 *    e fragments ficam intocados);
 *  - falha silenciosa: URL imprevisível volta EXATAMENTE igual;
 *  - puro e testável — nenhum acesso a Electron aqui.
 */
'use strict';

/** Parâmetros globais de rastreamento (minúsculas). */
const GLOBAL_PARAMS = new Set([
  // Google / DoubleClick
  'fbclid', 'gclid', 'gclsrc', 'dclid', 'gbraid', 'wbraid', 'msclkid',
  // Meta
  'fb_action_ids', 'fb_action_types', 'fb_ref', 'fb_source', 'fbclid',
  'rdid', 'share_url_id',
  // X / Twitter / TikTok
  'twclid', 'ttclid', 'tt_content', '_wchar',
  // Instagram
  'igshid', 'igsh', 'img_index',
  // Analytics de e-mail/marketing
  'mc_eid', 'mc_cid', '_hsenc', '_hsmi', 'vero_id', 'vero_conv',
  'ck_subscriber_id', 's_cid', 'mkt_tok', 'elqtrackid', 'dm_i',
  // Anúncios BR/latam
  'yclid', 'oaid', 'rb_clickid', 'cvid', 'ncid',
  // Alibaba/aliexpress e genéricos chineses
  'spm', 'scm', 'share_id', 'pvid', 'aff_platform', 'aff_trace_key',
  // Genéricos de campanha
  'campaign_id', 'campaignid', 'ad_id', 'adset_id', 'adgroup_id',
  'newsletter_id', 'sr_share', 'ref_src', 'ref_url', 'cmpid'
]);

/** Prefixos globais (qualquer parâmetro que comece com eles). */
const GLOBAL_PREFIXES = ['utm_', 'pk_', 'hsa_', 'mc_', 'mtm_'];

/**
 * Regras por site: hostname (sufixo casa com subdomínios) →
 * parâmetros a remover (minúsculas, exatos) ou prefixo "prefixo:*".
 */
const SITE_RULES = [
  { host: 'youtube.com', params: ['si'], prefixes: [] },
  { host: 'youtu.be', params: ['si'], prefixes: [] },
  { host: 'x.com', params: ['t', 's'], prefixes: [] },
  { host: 'twitter.com', params: ['t', 's'], prefixes: [] },
  { host: 'tiktok.com', params: ['_r', '_t', 'is_from_webapp', 'sender_device', 'sender_web_id', 'web_id', 'u_code', 'share_app_id', 'share_link_id', 'tt_from'], prefixes: [] },
  { host: 'spotify.com', params: ['si', 'context@'], prefixes: [] },
  { host: 'linkedin.com', params: ['trk', 'trkInfo', 'original_referer', 'originalSubdomain', 'licu', 'lipi', 'trackingId', 'refreshed'], prefixes: [] },
  { host: 'instagram.com', params: ['igshid', 'igsh', 'eex', 'li'], prefixes: [] },
  { host: 'facebook.com', params: ['rdid', 'share_url_id', 'comment_id_tracking'], prefixes: [] },
  { host: 'amazon.', params: ['tag', 'ascsubtag', 'ascsource', 'content-id', 'ref_', 'pd_rd_w', 'pd_rd_r', 'pd_rd_wg', 'pf_rd_p', 'pf_rd_r', 'pf_rd_s', 'pf_rd_t', 'pf_rd_i', 'pf_rd_m', 'qid', 'sr', 'psc', 'smid', 'creative_id', 'crid'], prefixes: ['pd_rd_', 'pf_rd_', 'ref_'] },
  { host: 'mercadolivre.com', params: ['matt_tool', 'matt_word'], prefixes: [] },
  { host: 'mercadolibre.com', params: ['matt_tool', 'matt_word'], prefixes: [] },
  { host: 'shopee.com', params: ['af_siteid', 'pid', 'c', 'smtt', 'utm_content'], prefixes: [] },
  { host: 'reddit.com', params: ['share_id', 'utm_name'], prefixes: [] },
  { host: 'bing.com', params: ['form', 'sk', 'sc', 'qs', 'qsh'], prefixes: [] },
  // CORREÇÃO 1.6.7: "id" era FUNCIONAL em steamcommunity.com
  // (sharedfiles/filedetails/?id=..., marketplace etc.) — os links quebravam.
  // ClearURLs original só remove "snr"; voltamos a remover apenas ele.
  { host: 'steamcommunity.com', params: ['snr'], prefixes: [] },
  { host: 'store.steampowered.com', params: ['snr', 'gamedt', 'curator_clanid'], prefixes: [] },
  { host: 'aliexpress.com', params: ['aff_platform', 'aff_trace_key', 'algo_pvid', 'algo_exp_id', 'btsid', 'ws_ab_test'], prefixes: [] },
  { host: 'globo.com', params: ['utm_source', 'utm_medium'], prefixes: ['utm_'] },
  { host: 'g1.globo.com', params: [], prefixes: ['utm_'] },
  { host: 'uol.com.br', params: ['tgb', 'tgs', 'cmpid'], prefixes: [] },
  { host: 'terra.com.br', params: ['utm_source', 'utm_medium'], prefixes: ['utm_'] }
];

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch (e) { return ''; }
}

/** Regras por site aplicáveis ao host (host exato ou sufixo). */
function siteRulesFor(host) {
  if (!host) return [];
  return SITE_RULES.filter(r => {
    const h = r.host.toLowerCase();
    if (h.endsWith('.')) {
      // prefixo de domínio (ex.: "amazon.") casa amazon.com, amazon.com.br…
      return host === h.slice(0, -1) || host.startsWith(h) || host.includes('.' + h);
    }
    return host === h || host.endsWith('.' + h);
  });
}

function dropParam(name, host) {
  const kl = name.toLowerCase();
  if (GLOBAL_PARAMS.has(kl)) return true;
  for (const p of GLOBAL_PREFIXES) if (kl.startsWith(p)) return true;
  for (const r of siteRulesFor(host)) {
    if (r.params.some(p => p.toLowerCase() === kl)) return true;
    for (const pre of (r.prefixes || [])) if (kl.startsWith(pre)) return true;
  }
  return false;
}

/**
 * Remove parâmetros de rastreamento de uma URL.
 * @param {string} url
 * @param {object} [opts] { skipHosts?: string[] } — hosts (sufixos) a pular
 * @returns {{ url: string, removed: string[] }} URL final (string idêntica
 *          à original quando nada é removido ou quando a URL é inválida).
 */
function cleanUrl(url, opts = {}) {
  const raw = String(url == null ? '' : url);
  let u;
  try { u = new URL(raw); } catch (_) { return { url: raw, removed: [] }; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return { url: raw, removed: [] };
  const host = u.hostname.toLowerCase();
  for (const skip of (opts.skipHosts || [])) {
    const s = String(skip || '').toLowerCase();
    if (s && (host === s || host.endsWith('.' + s))) return { url: raw, removed: [] };
  }
  if (!u.search) return { url: raw, removed: [] };

  const removed = [];
  for (const k of Array.from(u.searchParams.keys())) {
    if (dropParam(k, host)) { u.searchParams.delete(k); removed.push(k); }
  }
  if (!removed.length) return { url: raw, removed: [] };

  // searchParams.delete pode deixar "?" ou "&" soltos — URL normaliza sozinha.
  return { url: u.href, removed };
}

/** Variante de conveniência: devolve apenas a string final. */
function cleanUrlStr(url, opts = {}) {
  return cleanUrl(url, opts).url;
}

/** Metadados para documentação/painel (contagem de regras). */
function rulesInfo() {
  return {
    globalParams: GLOBAL_PARAMS.size,
    globalPrefixes: GLOBAL_PREFIXES.slice(),
    siteRules: SITE_RULES.length,
    credit: 'Conceito ClearURLs (GPL-3.0) — reimplementação original MIT'
  };
}

module.exports = {
  GLOBAL_PARAMS,
  GLOBAL_PREFIXES,
  SITE_RULES,
  cleanUrl,
  cleanUrlStr,
  siteRulesFor,
  rulesInfo
};

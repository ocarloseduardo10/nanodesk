/**
 * NanoDesk — Bloqueador de anúncios (1.3.0)
 * ==================================================================
 * Camada de filtragem acoplada à sessão de navegação (webRequest),
 * executada no processo principal ANTES de qualquer requisição.
 *
 * Três motores integrados em UM único listener onBeforeRequest
 * (o Electron aceita apenas um listener por canal de webRequest):
 *  1. NATIVO — listas internas de domínios + padrões de URL;
 *  2. GHOSTERY (@ghostery/adblocker) — EasyList + EasyPrivacy,
 *     rebaixadas a cada inicialização (auto-update) e mantidas só
 *     na pasta temporária da sessão. Filtros cosméticos (CSS) são
 *     injetados por aba via injectCosmetics().
 *  3. HOSTS (1.6.0, FASE 4) — StevenBlack/hosts (MIT) baixado em
 *     tempo de execução (nada é embutido nem gravado no disco);
 *     bloqueio por domínio no mesmo estilo do parser de hosts.
 *
 * CORREÇÃO 1.3.0 (allowlist): antes, quando o SITE DE ORIGEM estava
 * na allowlist, TODAS as requisições dele eram liberadas — inclusive
 * rastreadores de terceiros. Agora a allowlist só libera recursos
 * cujo PRÓPRIO host esteja na lista: um site autorizado continua
 * com rastreadores de terceiros bloqueados.
 *
 * Estratégia nativa (enxuta, por desempenho):
 *  1. AD_HOSTS      — domínios de ad-networks/rastreadores
 *                     (casa também com subdomínios);
 *  2. URL_PATTERNS  — trechos de URL típicos de anúncios.
 */
'use strict';

const { normalizeHostname } = require('../shared/validation');

/** Domínios bloqueados (matches também em subdomínios). */
const AD_HOSTS = [
  // 1.9.1 — gravadores de sessão/digitação (registram teclas, cliques e rolagem; alguns capturam
  // o que é digitado em formulários). O EasyPrivacy embutido já os cobre no motor principal; esta
  // lista estática é a REDE DE SEGURANÇA para antes do motor carregar e para o arquivador de páginas.
  'logrocket.com', 'logrocket.io', 'lr-ingest.io', 'lr-in.com', 'lr-in-prod.com', 'lr-hosted.com',
  'mouseflow.com', 'smartlook.com', 'smartlook.cloud', 'inspectlet.com', 'luckyorange.com', 'luckyorange.net',
  'sessioncam.com', 'heapanalytics.com', 'heap.io', 'crazyegg.com', 'glassboxdigital.com', 'quantummetric.com',
  'contentsquare.net', 'contentsquare.com', 'c-sq.net', 'ptengine.com', 'ptengine.jp', 'usabilla.com',
  'decibelinsight.net', 'decibelinsight.com', 'tealeaf.com', 'clicktale.net', 'clicktale.com', 'userreplay.net',
  'sessionstack.com', 'smartlook.com', 'mousestats.com', 'hotjar.io', 'fullstory.com', 'fs.fullstory.com',
  'hotjar.com', 'clarity.ms',
  // Google / DoubleClick / AdSense
  'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
  'googletagservices.com', 'google-analytics.com', 'analytics.google.com',
  'adservice.google.com', 'adservice.google.com.br', 'pagead.google.com',
  '2mdn.net', 'flashtalking.com', 'serving-sys.com',
  // Meta / X / LinkedIn
  'connect.facebook.net', 'an.facebook.com', 'ads-twitter.com',
  'analytics.twitter.com', 'px.ads.linkedin.com', 'snap.licdn.com',
  // Microsoft / rastreio
  'bat.bing.com', 'clarity.ms',
  // Amazon / exchanges de mídia
  'amazon-adsystem.com', 'adnxs.com', 'adsafeprotected.com', 'adsrvr.org',
  'rubiconproject.com', 'openx.net', 'pubmatic.com', 'smartadserver.com',
  'casalemedia.com', '33across.com', 'sharethrough.com', 'sonobi.com',
  'indexww.com', 'indexexchange.com', 'yieldmo.com', 'gumgum.com',
  'teads.tv', 'yieldlab.net', 'adform.net', 'doubleverify.com', 'media.net',
  'mediavine.com', 'adthrive.com', 'raptive.com', 'conversantmedia.com',
  'liadm.com', 'bidswitch.net', 'bidr.io', 'ads.yahoo.com', 'adcolony.com',
  'applovin.com', 'vungle.com', 'inmobi.com', 'mopub.com', 'smaato.net',
  'criteo.com', 'criteo.net', 'adsco.re',
  // Widgets de anúncio (taboola/outbrain e similares)
  'taboola.com', 'taboolasyndication.com', 'outbrain.com', 'revcontent.com',
  'mgid.com', 'content-ad.net', 'zergnet.com',
  // Redes agressivas / pop-under
  'propellerads.com', 'propellerclick.com', 'adsterra.com', 'hilltopads.net',
  'popads.net', 'popcash.net', 'popmyads.com', 'exoclick.com', 'exosrv.com',
  'juicyads.com', 'trafficjunky.net', 'trafficfactory.biz',
  'onclickads.net', 'onclckds.com',
  // Analítica / rastreadores
  'scorecardresearch.com', 'quantserve.com', 'quantcount.com', 'moatads.com',
  'hotjar.com', 'hotjar.io', 'mixpanel.com', 'segment.io', 'segment.com',
  'amplitude.com', 'fullstory.com', 'chartbeat.com', 'chartbeat.net',
  'nr-data.net', 'js-agent.newrelic.com', 'cloudflareinsights.com',
  'mc.yandex.ru', 'an.yandex.ru', 'top-fwz1.mail.ru', 'adfox.ru',
  'adriver.ru', 'parsely.com', 'branch.io', 'appsflyer.com', 'adjust.com',
  'kochava.com',
  // Outros
  'zedo.com', 'adroll.com', 'sitescout.com', 'buysellads.com', 'admob.com'
];

/** Padrões de URL (substring, aplicados em minúsculas). */
const URL_PATTERNS = [
  '/pagead/', '/adsbygoogle', '/gampad/ads', '/api/stats/ads',
  '/adserver/', '/ad-server/', '/advert/', '/adverts/', '/adbanner',
  '/banner_ad', '/adframe', '/ads.js', '/ads.min.js', '/prebid',
  '/popunder', '/adlog', '/adx.js'
];

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch (e) { return ''; }
}

// 1.5.2: require() em cada requisição de rede era desperdício — carrega uma vez.
let _ghosteryRequest = null;
function ghosteryRequestClass() {
  if (!_ghosteryRequest) _ghosteryRequest = require('@ghostery/adblocker').Request;
  return _ghosteryRequest;
}
let _tldtsParse = null;
function tldtsParse() {
  if (_tldtsParse === null) {
    try { _tldtsParse = require('tldts-experimental').parse; } catch (_) { _tldtsParse = false; }
  }
  return _tldtsParse || null;
}

const AD_HOST_SET = new Set(AD_HOSTS);

function domainMatches(host, domain) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  const d = String(domain || '').toLowerCase().replace(/\.$/, '');
  return h === d || h.endsWith('.' + d);
}

/** Retorna a regra que casou ({type, rule}) ou null se permitido.
 *  1.6.0: aceita um conjunto EXTRA de domínios (motor hosts/StevenBlack)
 *  via matchUrl(url, { hostSet }) — mantido puro para os testes. */
function matchUrl(url, opts = {}) {
  if (!url) return null;
  const u = String(url).toLowerCase();
  if (!/^https?:\/\//.test(u)) return null;
  const h = hostOf(u);
  if (!h) return null;
  // Verifica somente os sufixos do hostname: O(nº de rótulos), não O(nº de regras).
  let candidate = h.replace(/\.$/, '');
  const extra = opts.hostSet instanceof Set ? opts.hostSet : null;
  while (candidate) {
    if (AD_HOST_SET.has(candidate)) return { type: 'dominio', rule: candidate };
    if (extra && extra.has(candidate)) return { type: 'hosts', rule: 'StevenBlack' };
    const dot = candidate.indexOf('.');
    if (dot < 0) break;
    candidate = candidate.slice(dot + 1);
  }
  for (let i = 0; i < URL_PATTERNS.length; i++) {
    if (u.includes(URL_PATTERNS[i])) return { type: 'padrao', rule: URL_PATTERNS[i] };
  }
  return null;
}

/**
 * Mapeia resourceType do Electron para o RequestType do @ghostery/adblocker.
 */
const GHOSTERY_TYPES = {
  mainFrame: 'document',
  subFrame: 'sub_frame',
  stylesheet: 'stylesheet',
  script: 'script',
  image: 'image',
  font: 'font',
  object: 'object',
  xhr: 'xmlhttprequest',
  ping: 'ping',
  cspReport: 'csp_report',
  media: 'media',
  webSocket: 'websocket',
  other: 'other'
};

/**
 * Cria o motor acoplado a uma sessão Electron.
 * @param {Session} session  sessão anônima em memória do NanoDesk
 * @param {object}  opts     { onBlock(info), ghostery?: {match(req), getCosmeticsFilters(opts)} }
 */
function createEngine(session, opts = {}) {
  const state = {
    enabled: true,
    totalBlocked: 0,   // contagem apenas da sessão atual (nunca persistida)
    nativeBlocked: 0,
    ghosteryBlocked: 0,
    hostsBlocked: 0,   // 1.6.0 — camada StevenBlack
    hosts: null,       // Set<string> de domínios (sem persistência)
    truncated: 0,      // 1.6.7: scriptlets/CSS cortados (visível em stats)
    // Serviços oficiais do Workspace ficam fora do bloqueio para evitar
    // que scripts/recursos funcionais sejam confundidos com publicidade.
    allow: new Set([
      'workspace.google.com', 'drive.google.com', 'docs.google.com',
      'sheets.google.com', 'slides.google.com', 'forms.google.com',
      'calendar.google.com', 'mail.google.com'
    ]),
    recent: [],
    ghostery: null
  };

  const allowHit = (host) => {
    if (!host) return false;
    for (const d of state.allow) if (domainMatches(host, d)) return true;
    return false;
  };

  const ghosteryHit = (url, resourceType, referrer) => {
    const g = state.ghostery;
    if (!g || typeof g.match !== 'function') return null;
    try {
      const Request = ghosteryRequestClass();
      const type = GHOSTERY_TYPES[resourceType] || 'other';
      const req = Request.fromRawDetails({
        url,
        sourceUrl: referrer || '',
        type
      });
      // CORREÇÃO 1.3.1: Engine.match() devolve um objeto MatchingResult
      // { match: boolean, filter, exception, ... } — SEMPRE truthy. O
      // código antigo (mode && mode !== 'none') tratava TODA requisição
      // como bloqueada assim que o motor carregava, derrubando todos os
      // subrecursos de todos os sites. O critério correto é result.match === true.
      const result = g.match(req);
      if (!(result && result.match === true)) return null;
      // 1.6.3: guarda o filtro que casou (aparece em "bloqueados recentes") e o
      // recurso NEUTRALIZADO (redirect), usado no lugar do cancelamento seco —
      // evita quebrar sites e detecção anti-adblock (ex.: stubs de analytics/ads).
      let label = 'EasyList/EasyPrivacy';
      try { if (result.filter && result.filter.toString) label = String(result.filter.toString()).slice(0, 90) || label; } catch (_) { /* mantém */ }
      return { type: 'ghostery', rule: label, redirect: result.redirect && result.redirect.dataUrl ? result.redirect.dataUrl : '' };
    } catch (_) {
      return null; // motor externo não pode derrubar a navegação
    }
  };

  // CORREÇÃO 1.6.7: WebSockets entram no filtro (anúncios/popunders via
  // ws://wss:// não eram vistos pelo listener).
  session.webRequest.onBeforeRequest({ urls: ['http://*/*', 'https://*/*', 'ws://*/*', 'wss://*/*'] }, (details, callback) => {
    if (!state.enabled) return callback({});
    // Nunca cancela a navegação principal: se o usuário digitou o endereço
    // de um site (ex.: segment.com), a página precisa abrir. O bloqueio vale
    // para recursos incorporados (scripts, imagens, iframes, XHR...).
    if (details.resourceType === 'mainFrame') return callback({});
    // 1.7.3: páginas de LOGIN (e os sites do mesmo SSO) nunca têm requisições bloqueadas —
    // telemetria/BotGuard do Google (play.google.com/log, gen_204…) bloqueada deixa o login
    // "suspeito" ("Este navegador ou app pode não ser seguro"). Com a origem correta (1.6.3)
    // as regras $third-party passaram a casar de verdade e o problema apareceu.
    if (state.bypass) {
      try {
        let srcH = '';
        try { srcH = hostOf((details.frame && details.frame.url) || (details.webContents && details.webContents.getURL()) || details.referrer || ''); } catch (_) { srcH = ''; }
        if (state.bypass(srcH, hostOf(details.url))) return callback({});
      } catch (_) { /* segue o filtro normal */ }
    }
    let hit = matchUrl(details.url, { hostSet: state.hosts });
    // 1.6.3: a ORIGEM da requisição é a página/frame que a fez — não o Referer
    // (que pode vir vazio/recortado e fazia regras $third-party e $domain falharem).
    let sourceUrl = '';
    try { sourceUrl = (details.frame && details.frame.url) || (details.webContents && details.webContents.getURL()) || ''; } catch (_) { /* usa o referrer */ }
    if (!/^https?:/i.test(sourceUrl)) sourceUrl = details.referrer || '';
    if (!hit) hit = ghosteryHit(details.url, details.resourceType, sourceUrl);
    if (!hit) return callback({});
    const host = hostOf(details.url);
    // CORREÇÃO 1.3.0: allowlist vale apenas para o host do PRÓPRIO recurso.
    // A origem (referrer) NÃO libera mais rastreadores de terceiros.
    if (allowHit(host)) return callback({});

    state.totalBlocked++;
    if (hit.type === 'ghostery') state.ghosteryBlocked++;
    else if (hit.type === 'hosts') state.hostsBlocked++;
    else state.nativeBlocked++;
    state.recent.unshift({
      host,
      url: String(details.url).slice(0, 240),
      rule: hit.rule,
      type: hit.type,
      ts: Date.now()
    });
    if (state.recent.length > 60) state.recent.length = 60;
    if (typeof opts.onBlock === 'function') opts.onBlock({ host, rule: hit.rule, type: hit.type });
    if (hit.redirect) return callback({ redirectURL: hit.redirect });   // 1.6.3: recurso neutralizado
    callback({ cancel: true });
  });

  const cleanHost = (h) => normalizeHostname(h);

  /**
   * Filtros cosméticos do motor Ghostery: injeta CSS nas abas quando
   * estão prontas. Falhas são silenciosas (recurso de melhoria).
   */
  async function injectCosmetics(wc, url) {
    const g = state.ghostery;
    if (!g || !state.enabled || !wc || !url) return;
    if (!/^https?:\/\//i.test(url)) return;
    try {
      let domain = '';
      try {
        const parse = tldtsParse();
        if (parse) domain = (parse(url) || {}).domain || '';
      } catch (_) { /* tldts indisponível: segue sem domínio base */ }
      const res = g.getCosmeticsFilters({
        url,
        hostname: hostOf(url),
        domain,
        getBaseRules: true,
        getInjectionRules: true,
        getExtendedRules: false,
        getRulesFromDOM: false,
        getRulesFromHostname: true
      });
      if (res && res.active !== false && res.styles) {
        await wc.insertCSS(String(res.styles).slice(0, 2 * 1024 * 1024), { cssOrigin: 'author' });
      }
    } catch (_) { /* cosméticos são best-effort */ }
  }

  /**
   * 1.6.3: filtros cosméticos + SCRIPTLETS de uma frame (usado pelo preload, ANTES dos
   * scripts da página). Antes só o CSS era usado e os scriptlets do uBlock Origin
   * (json-prune, set-constant…), que neutralizam anúncios do YouTube, eram descartados.
   * @param {string} url  URL da frame
   * @param {object} [o]  { classes, ids, hrefs } para regras baseadas no DOM
   * @returns {{styles:string, scripts:string[]}}
   */
  function cosmetics(url, o = {}) {
    const out = { styles: '', scripts: [] };
    const g = state.ghostery;
    if (!g || !state.enabled || typeof g.getCosmeticsFilters !== 'function') return out;
    if (!/^https?:\/\//i.test(String(url || ''))) return out;
    const host = hostOf(url);
    if (!host || allowHit(host)) return out;
    try {
      let domain = '';
      try { const parse = tldtsParse(); if (parse) domain = (parse(url) || {}).domain || ''; } catch (_) { /* sem domínio base */ }
      const dom = !!(o.classes || o.ids || o.hrefs);
      const res = g.getCosmeticsFilters({
        url, hostname: host, domain,
        classes: o.classes, ids: o.ids, hrefs: o.hrefs,
        getBaseRules: !dom,
        getInjectionRules: !dom,
        getExtendedRules: false,
        getRulesFromHostname: !dom,
        getRulesFromDOM: dom
      });
      if (!res || res.active === false) return out;
      if (res.styles) {
        if (res.styles.length > 2 * 1024 * 1024) state.truncated++;
        out.styles = String(res.styles).slice(0, 2 * 1024 * 1024);
      }
      if (Array.isArray(res.scripts)) {
        // CORREÇÃO 1.6.7: limite de 256 KB podia cortar um scriptlet ao meio —
        // o SyntaxError não é capturado pelo try do isolate (erro de PARSE) e o
        // scriptlet inteiro sumia em silêncio. Nenhuma regra uBO chega perto de
        // 512 KB; o corte (se um dia acontecer) fica contabilizado em stats().
        out.scripts = res.scripts.slice(0, 80).map(x => {
          const s = String(x);
          if (s.length > 512 * 1024) state.truncated++;
          return s.slice(0, 512 * 1024);
        });
      }
    } catch (_) { /* cosméticos são best-effort */ }
    return out;
  }

  return {
    cosmetics,
    setEnabled(v) { state.enabled = !!v; },
    /** 1.7.3: fn(hostOrigem, hostRequisição) => true libera a requisição (login/SSO). */
    setBypass(fn) { state.bypass = typeof fn === 'function' ? fn : null; },
    isEnabled() { return state.enabled; },
    /** Liga o motor Ghostery (EasyList/EasyPrivacy) ao motor nativo. */
    setGhostery(blocker) { state.ghostery = blocker || null; },
    hasGhostery() { return !!state.ghostery; },
    /** 1.6.0 — instala a camada hosts (StevenBlack). Lista vazia = desliga. */
    setHosts(domains) {
      if (Array.isArray(domains) && domains.length) {
        state.hosts = new Set(domains);
      } else {
        state.hosts = null;
      }
    },
    hostsCount() { return state.hosts ? state.hosts.size : 0; },
    injectCosmetics,
    stats() {
      return {
        enabled: state.enabled,
        session: state.totalBlocked,
        total: state.totalBlocked,
        native: state.nativeBlocked,
        ghostery: state.ghosteryBlocked,
        hosts: state.hostsBlocked,
        hostsCount: state.hosts ? state.hosts.size : 0,
        truncated: state.truncated,
        // CORREÇÃO 1.6.7: a lista real em uso (o rótulo antigo omitia uBlock
        // Origin e StevenBlack — o painel dizia "EasyList + EasyPrivacy" mesmo
        // com as listas do uBO ativas, incluindo os scriptlets do YouTube).
        lists: state.ghostery
          ? 'EasyList + EasyPrivacy + uBlock Origin' + (state.hosts ? ' + StevenBlack hosts' : '')
          : (state.hosts ? 'nativas + StevenBlack hosts' : 'nativas')
      };
    },
    recent() { return state.recent.slice(0, 40); },
    allow(host) { const h = cleanHost(host); if (h) state.allow.add(h); return [...state.allow]; },
    disallow(host) { const h = cleanHost(host); if (h) state.allow.delete(h); return [...state.allow]; },
    allowlist() { return [...state.allow]; }
  };
}

module.exports = { AD_HOSTS, URL_PATTERNS, matchUrl, createEngine, GHOSTERY_TYPES };

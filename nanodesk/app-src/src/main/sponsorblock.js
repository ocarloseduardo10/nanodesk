/**
 * NanoDesk — SponsorBlock nativo (1.7.0)
 * ==================================================================
 * Baseado no projeto SponsorBlock (github.com/ajayyy/SponsorBlock,
 * GPL-3.0, © Ajay Ramachandran e contribuidores). NENHUM código é
 * copiado: a integração usa a API PÚBLICA oficial
 * (https://sponsor.ajay.app/api/skipSegments), que devolve os
 * segmentos patrocinados reportados pela comunidade para um vídeo.
 *
 * O que faz no NanoDesk:
 *  - Ao abrir um vídeo do YouTube (ou do Piped/Invidious escolhido),
 *    o script injetado consulta a API enviando APENAS o ID do vídeo
 *    e pula automaticamente os segmentos das categorias selecionadas
 *    (patrocínio, autopromoção, interação, intro, outro, prévia,
 *    enrolação), com aviso discreto na tela.
 *  - Funciona em /watch, /shorts, /embed, navegação SPA do YouTube e
 *    nos frontends Piped/Invidious.
 *
 * Limites honestos:
 *  - Se a API estiver inacessível (offline/Tor), o vídeo toca
 *    normalmente, sem pular nada.
 *  - Segmentos são trabalhos da comunidade: podem não existir ou
 *    chegar com alguns segundos de diferença.
 *
 * Núcleo puro (testável): categorias, rótulos, montagem da URL da
 * API, normalização de segmentos e o script injetável (mundo
 * principal, idempotente, 100% em try/catch).
 */
'use strict';

const crypto = require('crypto');   // 1.8.11: prefixo SHA-256 (k-anonimato); https do Node não é mais usado
const MAX_SCRIPT_BYTES = 32 * 1024; // trava de segurança

/** Categorias disponíveis (ids da API) + rótulos em PT-BR. */
const CATEGORIES = [
  ['sponsor', 'Patrocínio'],
  ['selfpromo', 'Autopromoção'],
  ['interaction', 'Interação (curtir/inscrever)'],
  ['intro', 'Introdução'],
  ['outro', 'Encerramento'],
  ['preview', 'Prévia/Recapitulação'],
  ['filler', 'Enrolação'],
  ['music_offtopic', 'Música não relacionada']
];

const DEFAULT_CATEGORIES = ['sponsor', 'selfpromo', 'interaction', 'intro', 'outro', 'preview', 'filler'];

/** Rótulo de uma categoria (puro). */
function labelFor(cat) {
  const hit = CATEGORIES.find(c => c[0] === String(cat || ''));
  return hit ? hit[1] : String(cat || 'segmento');
}

/** Filtra a lista configurada contra as categorias válidas (puro). */
function sanitizeCategories(list) {
  const valid = new Set(CATEGORIES.map(c => c[0]));
  const out = (Array.isArray(list) ? list : [])
    .map(x => String(x || ''))
    .filter(x => valid.has(x));
  return out.length ? [...new Set(out)] : DEFAULT_CATEGORIES.slice();
}

/**
 * Hosts atendidos pelo pulo automático.
 *
 * 1.8.8+: o sistema de vídeo NATIVO Piped/Invidious/FreeTube foi
 * REMOVIDO — o YouTube abre comum (protegido por ytguard + adblock).
 * SponsorBlock agora atende APENAS hosts do YouTube (Piped/Invidious
 * cuidam dos seus próprios segmentos via API interna quando existem).
 */
const SB_HOSTS = [
  'youtube.com', 'www.youtube.com', 'm.youtube.com', 'music.youtube.com',
  'youtube-nocookie.com', 'www.youtube-nocookie.com'
];

/**
 * O host é atendido? (puro) — aceita instâncias extras configuradas
 * pelo usuário (uma URL https por linha) para futuras políticas
 * personalizadas. Hoje o padrão é apenas YouTube.
 */
function isSponsorBlockHost(host, extraUrls) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h) return false;
  if (SB_HOSTS.some(d => h === d || h.endsWith('.' + d))) return true;
  for (const raw of String(extraUrls || '').split(/\r?\n/)) {
    try {
      const u = new URL(raw.trim());
      if (u.protocol === 'https:' && (u.hostname.toLowerCase() === h || h.endsWith('.' + u.hostname.toLowerCase()))) return true;
    } catch (_) { /* linha inválida: ignora */ }
  }
  return false;
}

/** Prefixo SHA-256 (4 hex) do ID do vídeo — a API do SponsorBlock aceita só o
 *  prefixo (k-anonimato): o servidor NUNCA recebe o ID do vídeo assistido. */
function hashPrefix(videoId) {
  return crypto.createHash('sha256').update(String(videoId || '')).digest('hex').slice(0, 4);
}

/**
 * URL da API para um vídeo (puro). 1.8.11: usa /skipSegments/<prefixo-do-hash>
 * em vez de ?videoID=<id> (P-02 da auditoria). A resposta traz TODOS os vídeos
 * cujo hash começa com o prefixo; o filtro pelo ID exato é local
 * (extractSegmentsForVideo).
 */
function apiSegmentsUrl(videoId, cats) {
  const id = String(videoId || '');
  if (!/^[A-Za-z0-9_-]{6,20}$/.test(id)) return null;
  const list = sanitizeCategories(cats);
  return 'https://sponsor.ajay.app/api/skipSegments/' + hashPrefix(id) +
    '?categories=' + encodeURIComponent(JSON.stringify(list)) +
    '&actionTypes=' + encodeURIComponent(JSON.stringify(['skip']));
}

/** Da resposta por prefixo ([{videoID, segments:[...]}, ...]) extrai só os
 *  segmentos do vídeo pedido, no formato que parseSegments entende (puro). */
function extractSegmentsForVideo(json, videoId) {
  if (!Array.isArray(json)) return [];
  const id = String(videoId || '');
  const out = [];
  for (const entry of json) {
    if (!entry || String(entry.videoID || '') !== id || !Array.isArray(entry.segments)) continue;
    for (const seg of entry.segments) out.push(seg);
  }
  return out;
}

/**
 * Busca segmentos na API do SponsorBlock a partir do PROCESSO PRINCIPAL
 * (Node.js https) — NÃO sujeito ao CSP da página. Isto é CRÍTICO: o
 * YouTube tem uma CSP estrita (connect-src) que BLOQUEIA fetches para
 * sponsor.ajay.app feitos a partir do mundo principal da página. Uma
 * extensão de navegador contorna isso buscando do background script;
 * aqui o equivalente é buscar do main process (Node.js).
 * @param {string} videoId
 * @param {string[]} cats
 * @returns {Promise<Array<{s:number,e:number,cat:string,uuid:string}>>}
 */
function fetchSegments(videoId, cats, fetchFn) {
  // 1.8.11: o fetch vem da SESSÃO do navegador (proxy/Tor/DoH do app) — o https.get
  // do Node saía pela rede direta do SO e ignorava o proxy (vazava o IP em torMode)
  // e identificava o app com um User-Agent próprio (P-03). Sem fetchFn: fail-closed.
  return new Promise((resolve) => {
    const url = apiSegmentsUrl(videoId, cats);
    if (!url || typeof fetchFn !== 'function') return resolve([]);
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    const timer = setTimeout(() => finish([]), 8000);
    Promise.resolve()
      .then(() => fetchFn(url, { headers: { 'accept': 'application/json' } }))
      .then((res) => (res && res.ok ? res.json() : []))
      .then((json) => finish(parseSegments(extractSegmentsForVideo(json, videoId))))
      .catch(() => finish([]))
      .then(() => clearTimeout(timer));
  });
}

/**
 * Normaliza a resposta da API (puro).
 * @returns {Array<{s:number,e:number,cat:string,uuid:string}>}
 */
function parseSegments(json) {
  if (!Array.isArray(json)) return [];
  const out = [];
  for (const it of json) {
    try {
      const seg = it && Array.isArray(it.segment) ? it.segment : null;
      if (!seg || seg.length !== 2) continue;
      const s = Number(seg[0]);
      const e = Number(seg[1]);
      if (!Number.isFinite(s) || !Number.isFinite(e) || e <= s) continue;
      if (e - s > 7200) continue; // nada com mais de 2h é "segmento"
      out.push({ s, e, cat: String(it.category || ''), uuid: String(it.UUID || '') });
    } catch (_) { /* item inválido: ignora */ }
  }
  return out;
}

/**
 * Script injetável (mundo principal, idempotente). O main passa as
 * opções já validadas. 100% em try/catch: qualquer falha NUNCA pode
 * quebrar a página.
 *
 * CORREÇÃO 1.8.9 (CSP bypass): o YouTube tem uma CSP estrita (connect-src)
 * que BLOQUEIA fetches para sponsor.ajay.app feitos a partir do mundo
 * principal da página. Em vez de fazer fetch direto (que falha
 * silenciosamente no YouTube), o script sinaliza o ID do vídeo via
 * console.log com um token; o processo principal (Node.js, não sujeito
 * a CSP) busca os segmentos e os injeta de volta chamando
 * window.__nanodeskSbSet(id, segments). O script também tenta fetch
 * direto como fallback (funciona em sites sem CSP estrita, ex.: Piped).
 */
function buildScript(opts) {
  const cats = sanitizeCategories(opts && opts.cats);
  const showToast = (opts && opts.toast) !== false;
  const script = String.raw`
(function () {
  if (window.__nanodeskSponsorBlock) return;
  window.__nanodeskSponsorBlock = 1;
  var CATS = ${JSON.stringify(cats)};
  var TOAST = ${showToast ? 'true' : 'false'};
  var LABEL = ${JSON.stringify(Object.fromEntries(CATEGORIES))};
  var API = 'https://sponsor.ajay.app/api/skipSegments/';
  var cache = Object.create(null);
  var segs = [], curId = null, skipped = Object.create(null);
  var pendingFetch = {};

  function vid() {
    try {
      var u = new URL(location.href);
      var v = u.searchParams.get('v');
      if (v && /^[A-Za-z0-9_-]{11}$/.test(v)) return v;
      var m = u.pathname.match(/\/(?:shorts|embed|live|watch)\/?([A-Za-z0-9_-]{11})(?:[\/?#]|$)/);
      return m ? m[1] : null;
    } catch (_) { return null; }
  }
  function stat(secs) {
    try { document.dispatchEvent(new CustomEvent('nd-sb-skip', { detail: { secs: secs || 0 } })); } catch (_) {}
  }
  function toast(msg) {
    if (!TOAST) return;
    try {
      var t = document.getElementById('nd-sb-toast');
      if (!t) {
        t = document.createElement('div');
        t.id = 'nd-sb-toast';
        t.style.cssText = 'position:fixed;bottom:22px;right:22px;z-index:2147483647;background:rgba(13,15,26,.94);' +
          'color:#e8f0ff;padding:9px 14px;border-radius:10px;font:13px system-ui,sans-serif;' +
          'border:1px solid rgba(124,92,255,.55);box-shadow:0 8px 30px rgba(0,0,0,.45);opacity:0;' +
          'transition:opacity .25s;pointer-events:none;';
        (document.body || document.documentElement).appendChild(t);
      }
      t.textContent = msg;
      t.style.opacity = '1';
      clearTimeout(t._nd);
      t._nd = setTimeout(function () { t.style.opacity = '0'; }, 2100);
    } catch (_) {}
  }
  /* (A) fetch direto — funciona em sites sem CSP estrita (Piped, Invidious).
   *    No YouTube o CSP bloqueia; o fallback (B) cuida disso. */
  /* lê o corpo da resposta em streaming e CANCELA se passar de max bytes; null = grande demais/sem stream */
  async function readCapped(r, max) {
    var rd = r.body && r.body.getReader ? r.body.getReader() : null;
    if (!rd) return null;
    var chunks = []; var n = 0;
    for (;;) {
      var x = await rd.read();
      if (x.done) break;
      n += x.value.byteLength;
      if (n > max) { try { await rd.cancel(); } catch (e) { /* ignorado */ } return null; }
      chunks.push(x.value);
    }
    var all = new Uint8Array(n); var o = 0;
    chunks.forEach(function (c) { all.set(c, o); o += c.byteLength; });
    return new TextDecoder().decode(all);
  }

  async function loadDirect(id) {
    if (cache[id] && Date.now() - cache[id].t < 600000) { segs = cache[id].s; return true; }
    try {
      /* 1.8.11: envia só o PREFIXO do SHA-256 do ID (k-anonimato), nunca o ID. */
      if (!window.crypto || !crypto.subtle || !window.TextEncoder) return false;
      var dig = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(id));
      var hex = Array.prototype.map.call(new Uint8Array(dig), function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
      var u = API + hex.slice(0, 4) +
        '?categories=' + encodeURIComponent(JSON.stringify(CATS)) +
        '&actionTypes=' + encodeURIComponent(JSON.stringify(['skip']));
      var r = await fetch(u);
      if (r.ok) {
        var txt = await readCapped(r, 2 * 1024 * 1024);   // 1.9.3: teto em streaming também aqui (antes: r.json() sem limite)
        if (txt === null) return false;
        var j = JSON.parse(txt);
        var mine = [];
        (Array.isArray(j) ? j : []).forEach(function (e) {
          if (e && e.videoID === id && Array.isArray(e.segments)) mine = mine.concat(e.segments);
        });
        segs = mine
          .map(function (x) {
            try { return { s: Number(x.segment[0]), e: Number(x.segment[1]), cat: String(x.category || ''), uuid: String(x.UUID || '') }; }
            catch (_) { return null; }
          })
          .filter(function (x) { return x && x.e > x.s && (x.e - x.s) < 7200; });
        cache[id] = { t: Date.now(), s: segs };
        return true;
      }
    } catch (_) { /* CSP bloqueou ou rede falhou — fallback abaixo */ }
    return false;
  }
  /* (B) sinaliza o main process via console-message para buscar os segmentos
   *    (Node.js não sofre CSP). O main injeta de volta chamando
   *    window.__nanodeskSbSet(id, segments). */
  function requestFromMain(id) {
    if (pendingFetch[id]) return;
    pendingFetch[id] = true;
    try { console.log('%c__nanodesk_sb_request__' + id, 'color:transparent'); } catch (_) {}
    /* timeout: se o main não responder em 10s, libera para tentar de novo */
    setTimeout(function () { pendingFetch[id] = false; }, 10000);
  }
  /* Recebe segmentos injetados pelo main process. Chamado via
   * webContents.executeJavaScript('window.__nanodeskSbSet(...)'). */
  window.__nanodeskSbSet = function (id, segments) {
    try {
      if (id !== curId) return; /* resposta de um vídeo antigo — ignora */
      pendingFetch[id] = false;
      var arr = Array.isArray(segments) ? segments : [];
      segs = arr
        .map(function (x) {
          try { return { s: Number(x.s), e: Number(x.e), cat: String(x.cat || ''), uuid: String(x.uuid || '') }; }
          catch (_) { return null; }
        })
        .filter(function (x) { return x && x.e > x.s && (x.e - x.s) < 7200; });
      cache[id] = { t: Date.now(), s: segs };
      bind();
      onTime();
    } catch (_) {}
  };
  function onTime() {
    try {
      if (!segs.length) return;
      var v = document.querySelector('video');
      if (!v) return;
      var t = v.currentTime;
      for (var i = 0; i < segs.length; i++) {
        var s = segs[i];
        if (t >= s.s - 0.25 && t < s.e - 0.35 && !skipped[s.uuid || (s.s + ':' + s.e)]) {
          skipped[s.uuid || (s.s + ':' + s.e)] = 1;
          v.currentTime = s.e;
          stat(s.e - s.s);
          toast('\u23ED ' + (LABEL[s.cat] || s.cat) + ' pulado (SponsorBlock)');
          break;
        }
      }
    } catch (_) {}
  }
  function bind() {
    try {
      var v = document.querySelector('video');
      if (v && !v._ndSb) {
        v._ndSb = 1;
        v.addEventListener('timeupdate', onTime);
        v.addEventListener('loadeddata', function () {
          skipped = Object.create(null);
          setTimeout(onTime, 250);
        });
      }
    } catch (_) {}
  }
  async function checkNav() {
    try {
      var id = vid();
      if (id !== curId) {
        curId = id;
        segs = [];
        skipped = Object.create(null);
        if (id) {
          /* tenta fetch direto primeiro (rápido se CSP permitir); */
          var ok = await loadDirect(id);
          if (!ok) requestFromMain(id); /* CSP bloqueou → main process busca */
          bind();
          onTime();
        }
      }
    } catch (_) {}
  }
  try { document.addEventListener('yt-navigate-finish', checkNav, true); } catch (_) {}
  setInterval(checkNav, 1500);
  setInterval(bind, 1000);
  checkNav();
})();
`;
  const ok = script.includes('__nanodeskSponsorBlock') &&
    script.includes('__nanodeskSbSet') &&
    script.includes('__nanodesk_sb_request__') &&
    Buffer.byteLength(script) <= MAX_SCRIPT_BYTES;
  return ok ? script.trim() : '';
}

/** Metadados para diagnóstico (painel). */
function describe(cats) {
  return {
    id: 'nanodesk-sponsorblock',
    api: 'https://sponsor.ajay.app',
    categories: sanitizeCategories(cats),
    bytes: Buffer.byteLength(buildScript({ cats })),
    note: 'Pula patrocínios automaticamente via API pública do SponsorBlock (envia apenas o ID do vídeo).'
  };
}

module.exports = {
  CATEGORIES, DEFAULT_CATEGORIES, SB_HOSTS, MAX_SCRIPT_BYTES,
  labelFor, sanitizeCategories, isSponsorBlockHost, apiSegmentsUrl, hashPrefix,
  extractSegmentsForVideo, fetchSegments, parseSegments, buildScript, describe
};

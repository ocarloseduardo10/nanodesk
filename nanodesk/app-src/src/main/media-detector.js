/**
 * NanoDesk — Detector de mídia (1.9.5)
 * ==================================================================
 * Núcleo PURO (testável sem Electron) que classifica recursos de áudio,
 * vídeo e streaming a partir de três fontes combinadas:
 *
 *  1. REDE (webRequest do processo principal): MIME type + Content-Length
 *     + Content-Disposition + extensão da URL — a fonte mais confiável.
 *  2. DOM (script injetado na página via executeJavaScript): elementos
 *     <audio>, <video>, <source>, currentSrc, duração, resolução.
 *  3. MANIFESTOS: .m3u8 (HLS), .mpd (MPEG-DASH) — detectados pela URL
 *     e pelo MIME type (application/vnd.apple.mpegurl, application/dash+xml).
 *
 *  O módulo só CLASSIFICA e DESDUPA. A coleta dos dados (chamadas Electron
 *  à webRequest/executeJavaScript) fica no main.js — aqui é a camada de
 *  regras pura, fácil de testar e de auditar.
 *
 *  Estrutura MediaResource (especificação 6.4):
 *    { id, tabId, webContentsId?, url, title, mimeType?, extension?,
 *      fileSize?, duration?, width?, height?, bitrate?,
 *      mediaType: 'audio'|'video'|'stream'|'unknown',
 *      source: 'network'|'dom'|'context-menu'|'manifest',
 *      variants?: [{url, quality, bandwidth}],
 *      detectedAt }
 */
'use strict';

const crypto = require('crypto');

/* ---------------- Tabelas de classificação ---------------- */

const MIME_TO_TYPE = {
  // áudio
  'audio/mpeg': 'audio', 'audio/mp3': 'audio', 'audio/mp4': 'audio',
  'audio/m4a': 'audio', 'audio/aac': 'audio', 'audio/aacp': 'audio',
  'audio/x-aac': 'audio', 'audio/wav': 'audio', 'audio/x-wav': 'audio',
  'audio/wave': 'audio', 'audio/flac': 'audio', 'audio/x-flac': 'audio',
  'audio/ogg': 'audio', 'audio/vorbis': 'audio',
  'audio/opus': 'audio', 'audio/webm': 'audio',
  'audio/x-matroska': 'audio',
  // vídeo
  'video/mp4': 'video', 'video/mpeg': 'video', 'video/webm': 'video',
  'video/ogg': 'video', 'video/x-matroska': 'video', 'video/matroska': 'video',
  'video/quicktime': 'video', 'video/x-msvideo': 'video', 'video/avi': 'video',
  'video/x-flv': 'video', 'video/3gpp': 'video', 'video/3gpp2': 'video',
  'video/x-mpeg': 'video', 'video/x-mpeg2': 'video',
  // streaming (manifestos)
  'application/vnd.apple.mpegurl': 'stream',
  'application/x-mpegurl': 'stream',
  'application/mpegurl': 'stream',
  'application/dash+xml': 'stream',
  'application/vnd.ms-sstr+xml': 'stream'
};

const EXT_TO_TYPE = {
  // áudio
  mp3: 'audio', m4a: 'audio', aac: 'audio', wav: 'audio', wave: 'audio',
  flac: 'audio', ogg: 'audio', opus: 'audio', oga: 'audio',
  mka: 'audio', wma: 'audio', amr: 'audio', aiff: 'audio', aif: 'audio',
  // vídeo
  mp4: 'video', m4v: 'video', mpeg: 'video', mpg: 'video', webm: 'video',
  ogv: 'video', mov: 'video', mkv: 'video', avi: 'video', flv: 'video',
  wmv: 'video', '3gp': 'video', '3g2': 'video', ts: 'video', m2ts: 'video',
  // streaming
  m3u8: 'stream', m3u: 'stream', mpd: 'stream'
};

/** Manifest signatures by URL path (case-insensitive). */
const STREAM_PATH_RX = /\.(m3u8?|mpd)(?:[?#]|$)/i;
/** HLS by MIME */
const HLS_MIME_RX = /application\/(?:vnd\.apple\.)?mpegurl/i;
/** DASH by MIME */
const DASH_MIME_RX = /application\/dash\+xml/i;

/** Recursos de rede que NUNCA são mídia (filtros de falsos positivos).
 *  1.9.5 CORREÇÃO: 'mainFrame' e 'subFrame' REMOVIDOS da lista de rejeição —
 *  um MP3/MP4 aberto DIRETO na URL é mainFrame e DEVE ser detectado. O filtro
 *  agora só rejeita tipos que JAMAIS carregam mídia (stylesheet, script, font,
 *  favicon, ping, beacon). xhr/fetch são mantidos mas só contam se o MIME
 *  confirmar (já tratado na lógica de classificação). */
const NON_MEDIA_RESOURCE_TYPES = new Set([
  'stylesheet', 'script', 'font', 'favicon', 'ping', 'beacon'
  // mainFrame/subFrame/xhr/fetch/image REMOVIDOS — mídia pode vir por qualquer um
]);

/** Tamanho mínimo para considerar uma requisição como "mídia potencial" sem MIME. */
const MIN_MEDIA_BYTES = 64 * 1024;   // 64 KB — abaixo disso quase sempre é thumbnail/preview

/** Máximo de recursos mantidos por aba (limite de memória). */
const MAX_RESOURCES_PER_TAB = 200;

/** Tamanho máximo de URL armazenada (evita accumulating bloat em URLs com query enorme). */
const MAX_URL_LEN = 1024;

/* ---------------- Utilitários puros ---------------- */

function safeUrl(u) {
  const s = String(u || '');
  if (!/^https?:\/\//i.test(s)) return null;
  if (s.length > MAX_URL_LEN) return null;
  try { return new URL(s).href; } catch (_) { return null; }
}

function hostOf(u) {
  try { return new URL(u).hostname.toLowerCase(); } catch (_) { return ''; }
}

function extOf(urlOrPath) {
  const s = String(urlOrPath || '').split(/[?#]/)[0];
  const m = s.match(/\.([a-z0-9]{2,5})$/i);
  return m ? m[1].toLowerCase() : '';
}

/** 1.9.5 — Extrai o último segmento da URL (nome do arquivo) para usar como título.
 *  Ex.: "https://ex.com/path/S3_65060_WL3eIntroDT_01_UR_06_10.mp3?token=abc"
 *       → "S3_65060_WL3eIntroDT_01_UR_06_10.mp3" */
function urlFilenameOf(url) {
  try {
    const u = new URL(url);
    const segments = u.pathname.split('/').filter(Boolean);
    const last = segments[segments.length - 1];
    if (last) return decodeURIComponent(last).slice(0, 180);
  } catch (_) { /* não é URL válida */ }
  return '';
}

/** Gera id estável por (tabId, url) — desduplica o mesmo recurso detectado por 2 fontes. */
function resId(tabId, url) {
  return crypto.createHash('sha1').update(String(tabId) + '\0' + String(url)).digest('hex').slice(0, 20);
}

/** Sanitiza título (não vaza conteúdo da página nem quebra HTML). */
function safeTitle(s) {
  return String(s || '').replace(/[\r\n\t<>]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 180);
}

/** Lê Content-Length de um headers map (case-insensitive).
 *  1.9.6: também extrai tamanho total de Content-Range (bytes 0-N/TOTAL).
 *  Em requests ranged (206 Partial Content), Content-Length é só o tam. do chunk,
 *  mas Content-Range tem o total real do arquivo. */
function readContentLength(headers, statusCode) {
  if (!headers || typeof headers !== 'object') return 0;
  // 1) Content-Range: "bytes 0-1048575/12345678" → total = 12345678
  const crKey = Object.keys(headers).find(x => x.toLowerCase() === 'content-range');
  if (crKey) {
    const crVal = String(Array.isArray(headers[crKey]) ? headers[crKey][0] : headers[crKey] || '');
    const rangeMatch = crVal.match(/\/\s*(\d+)\s*$/);
    if (rangeMatch) {
      const total = parseInt(rangeMatch[1], 10);
      if (Number.isFinite(total) && total > 0) return total;
    }
    // 206 sem Content-Range: tamanho não confiável
    if (statusCode === 206) return 0;
  }
  // 2) Content-Length padrão
  const k = Object.keys(headers).find(x => x.toLowerCase() === 'content-length');
  if (!k) return 0;
  const v = Array.isArray(headers[k]) ? headers[k][0] : headers[k];
  const n = parseInt(String(v || '').replace(/[^\d]/g, ''), 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

/** 1.9.6 — Remove parâmetros de byte-range da URL e colapsa chunks em URL única.
 *  Facebook/Instagram servem .mp4 em chunks com ?bytestart=0&byteend=1048575;
 *  sem isto, cada chunk aparece como recurso separado.
 *  Inspirado no media-grabber (background.js normalizeMediaUrl).
 *  @returns {{url: string, wasRanged: boolean}} */
const RANGE_PARAMS = ['bytestart', 'byteend', 'range', 'rn', 'rbuf'];
function normalizeMediaUrl(urlStr) {
  try {
    const u = new URL(String(urlStr || ''));
    let stripped = false;
    for (const p of RANGE_PARAMS) {
      if (u.searchParams.has(p)) { u.searchParams.delete(p); stripped = true; }
    }
    return { url: u.toString(), wasRanged: stripped };
  } catch (_) { return { url: String(urlStr || ''), wasRanged: false }; }
}

/** 1.9.6 — Detecta URLs de segmentos de stream (.ts/.m4s, googlevideo, segment numerado).
 *  Segmentos individuais não devem aparecer como itens separados no painel —
 *  só o manifesto (.m3u8/.mpd) deve aparecer. Inspirado no media-grabber. */
function isStreamSegment(urlStr) {
  const s = String(urlStr || '');
  if (!s) return false;
  if (/\.(ts|m4s|cmfv|cmfa)(\?|#|$)/i.test(s)) return true;
  if (/\/videoplayback\b|googlevideo\.com\//i.test(s)) return true;
  if (/[/_-](seg|segment|chunk|frag)[-_/.]?\d/i.test(s)) return true;
  return false;
}

/** 1.9.6 — Detecta imagens de redes sociais na CDN de vídeo (fbcdn.net serve ambas).
 *  Evita falso positivo de "vídeo" em URLs como fbcdn.net/p320x320/123.jpg. */
function isSocialMediaImage(urlStr) {
  const s = String(urlStr || '').toLowerCase();
  if (!s) return false;
  if (/\.(jpg|jpeg|png|gif|webp|bmp|svg)(\?|#|$)/i.test(s)) return true;
  if (/fbcdn\.net/.test(s) && /\/(p\d+x\d+|s\d+x\d+)\//.test(s)) return true;
  return false;
}

/** Lê Content-Disposition e extrai filename (RFC 6266 simplificado). */
function readContentDisposition(headers) {
  if (!headers || typeof headers !== 'object') return null;
  const k = Object.keys(headers).find(x => x.toLowerCase() === 'content-disposition');
  if (!k) return null;
  const raw = String(Array.isArray(headers[k]) ? headers[k][0] : headers[k] || '');
  // filename*=UTF-8''<valor> | filename="<valor>"
  const star = raw.match(/filename\*=utf-8''([^;]+)/i);
  if (star) try { return decodeURIComponent(star[1]); } catch (_) { /* segue */ }
  const quoted = raw.match(/filename\s*=\s*"([^"]+)"/i);
  if (quoted) return quoted[1];
  const plain = raw.match(/filename\s*=\s*([^;]+)/i);
  if (plain) return plain[1].trim();
  return null;
}

function readContentType(headers) {
  if (!headers || typeof headers !== 'object') return '';
  const k = Object.keys(headers).find(x => x.toLowerCase() === 'content-type');
  if (!k) return '';
  const v = String(Array.isArray(headers[k]) ? headers[k][0] : headers[k] || '');
  return v.split(';')[0].trim().toLowerCase();
}

/**
 * 1.9.5 — MIME types que o servidor pode declarar e que EXPLICITAMENTE indicam
 * que NÃO é mídia (tem prioridade sobre a extensão da URL). Ex.: um XHR para
 * /api/data.mp4?id=123 com content-type: application/json é JSON, não vídeo.
 */
const EXPLICITLY_NON_MEDIA_MIME_RX = /^(text\/(html|css|plain|javascript|csv|xml))|(application\/(json|x-www-form-urlencoded|javascript|xml|soap|manifest))|(image\/)|(font\/)|(application\/vnd\.ms-fontobject)|(application\/font-)/i;

function isExplicitlyNonMediaMime(mime) {
  return EXPLICITLY_NON_MEDIA_MIME_RX.test(String(mime || ''));
}

/* ---------------- Classificação ---------------- */

/**
 * Classifica uma requisição de rede. Devolve null se NÃO for mídia.
 * @param {object} req {
 *   url, tabId, webContentsId?, resourceType?, headers?, method?
 * }
 * @returns {MediaResource|null}
 */
function classifyNetwork(req) {
  let rawUrl = safeUrl(req && req.url);
  if (!rawUrl) return null;
  const tabId = String((req && req.tabId) || '');
  if (!tabId) return null;

  // HEAD/OPTIONS não são transferências de mídia
  const method = String((req && req.method) || 'GET').toUpperCase();
  if (method !== 'GET') return null;

  // 1.9.6 — Normaliza URL: remove parâmetros de byte-range (bytestart, byteend, etc.)
  // para colapsar chunks do mesmo arquivo em um único recurso.
  const { url, wasRanged } = normalizeMediaUrl(rawUrl);

  // 1.9.6 — Filtra segmentos individuais de stream (.ts/.m4s, googlevideo, seg123).
  // Só o manifesto (.m3u8/.mpd) deve aparecer — os segmentos são细节 do stream.
  if (isStreamSegment(url)) return null;

  // 1.9.6 — Filtra imagens de redes sociais (fbcdn.net serve imagens E vídeos).
  if (isSocialMediaImage(url)) return null;

  const mime = readContentType(req.headers);
  const ext = extOf(url);
  const statusCode = Number(req.statusCode) || 0;
  const size = readContentLength(req.headers, statusCode);
  const filename = readContentDisposition(req.headers);

  // 1) Stream por manifesto (URL ou MIME)
  if (STREAM_PATH_RX.test(url) || HLS_MIME_RX.test(mime) || DASH_MIME_RX.test(mime)) {
    const streamType = DASH_MIME_RX.test(mime) || /\.mpd(?:[?#]|$)/i.test(url) ? 'dash' : 'hls';
    return {
      id: resId(tabId, url),
      tabId,
      webContentsId: req.webContentsId || undefined,
      url,
      title: safeTitle(filename || streamLabel(streamType, url)),
      mimeType: mime || (streamType === 'hls' ? 'application/vnd.apple.mpegurl' : 'application/dash+xml'),
      extension: streamType === 'hls' ? 'm3u8' : 'mpd',
      fileSize: size || undefined,
      mediaType: 'stream',
      streamKind: streamType,
      source: 'manifest',
      detectedAt: Date.now()
    };
  }

  // 2) MIME type explícito de mídia (fonte mais confiável)
  let type = mime ? MIME_TO_TYPE[mime] : null;

  // 1.9.5 CORREÇÃO: se o servidor declarou EXPLICITAMENTE um MIME que NÃO é de
  // mídia (ex.: application/json, text/html, text/css), isso TEM PRIORIDADE sobre
  // a extensão da URL. Antes, um XHR para /data.mp4?id=123 com content-type
  // application/json era classificado como vídeo — agora é rejeitado.
  // Só usamos a extensão como FALLBACK quando o MIME está AUSENTE ou é genérico.
  if (!type && mime && isExplicitlyNonMediaMime(mime)) {
    return null;   // servidor disse explicitamente que NÃO é mídia
  }

  // 3) Sem MIME de mídia (ou MIME ausente): tenta extensão — MAS só se for uma
  //    extensão CONHECIDA de mídia (evita tratar .php?id=12345 como vídeo).
  if (!type && ext && EXT_TO_TYPE[ext]) {
    type = EXT_TO_TYPE[ext];
  }

  // 4) Sem MIME nem extensão conhecida: NÃO é mídia — evita falso positivo
  //    (especificação 6.2: "não considere automaticamente toda requisição
  //    grande como mídia"). Antes era: qualquer Coleta com size>1MB virava
  //    mídia, o que puxava XHR JSON de API como "vídeo".
  if (!type) return null;

  // 5) Filtro por resourceType: stylesheet/script/font/favicon/ping/beacon
  //    NUNCA são mídia (mesmo com extensão .mp3 na URL — é um CSS disfarçado).
  //    xhr/fetch/mainFrame/subFrame/image foram REMOVIDOS do filtro (1.9.5)
  //    porque mídia legítima pode vir por qualquer um desses caminhos.
  if (req.resourceType && NON_MEDIA_RESOURCE_TYPES.has(req.resourceType)) {
    return null;
  }

  // 6) Tamanho mínimo quando não há MIME explícito de mídia (ext-only)
  //    evita contar previews/thumbnails de 4 KB como "vídeo"
  if (!MIME_TO_TYPE[mime] && size > 0 && size < MIN_MEDIA_BYTES) return null;

  const finalExt = ext || (filename ? extOf(filename) : '');
  // 1.9.5: título melhorado — usa o último segmento da URL (nome do arquivo)
  // quando não há Content-Disposition. Antes caía no hostname (ex.: "learn.eltnngl.com"
  // em vez de "S3_65060_WL3eIntroDT_01_UR_06_10.mp3").
  const urlFilename = urlFilenameOf(url);
  return {
    id: resId(tabId, url),
    tabId,
    webContentsId: req.webContentsId || undefined,
    url,
    title: safeTitle(filename || urlFilename || hostOf(url) || 'recurso'),
    mimeType: mime || undefined,
    extension: finalExt || undefined,
    fileSize: size || undefined,
    mediaType: type,
    source: 'network',
    detectedAt: Date.now()
  };
}

function streamLabel(kind, url) {
  return (kind === 'dash' ? 'MPEG-DASH' : 'HLS') + ' · ' + hostOf(url);
}

/* ---------------- Mescla DOM + rede (desduplica) ---------------- */

/**
 * Mescla uma lista de recursos DOM (de executeJavaScript) com o estado atual.
 * Recursos de rede já detectados têm prioridade — DOM só acrescenta info
 * extra (duração, largura/altura) e novos recursos não vistos pela rede.
 * @param {Map<string,MediaResource>} state por id
 * @param {Array} domResources vindos da página
 * @param {string} tabId
 * @returns {Array} ids novos/adicionados (para push incremental)
 */
function mergeDom(state, domResources, tabId) {
  const newIds = [];
  if (!Array.isArray(domResources) || !domResources.length) return newIds;
  for (const r of domResources.slice(0, 60)) {   // teto: 60 elementos DOM por varredura
    const url = safeUrl(r && r.url);
    if (!url) continue;
    const id = resId(tabId, url);
    const existing = state.get(id);
    if (existing) {
      // enriquece o recurso de rede com metadados do DOM
      if (r.duration && !existing.duration) existing.duration = Math.max(0, Math.round(Number(r.duration) * 10) / 10);
      if (r.width && !existing.width) existing.width = Math.round(Number(r.width));
      if (r.height && !existing.height) existing.height = Math.round(Number(r.height));
      if (r.bitrate && !existing.bitrate) existing.bitrate = Math.round(Number(r.bitrate));
      // 1.9.5: atualiza o título se o DOM tem um título melhor (não-vazio e diferente
      // do fallback automático de hostname ou nome-de-arquivo-da-URL).
      if (r.title) {
        const fallback1 = hostOf(existing.url);
        const fallback2 = urlFilenameOf(existing.url);
        if (existing.title === fallback1 || existing.title === fallback2 || !existing.title) {
          existing.title = safeTitle(r.title);
        }
      }
      // se a rede classificou como 'unknown' mas o DOM sabe que é 'audio'/'video', promove
      if (r.mediaType && (existing.mediaType === 'unknown' || !existing.mediaType)) {
        existing.mediaType = r.mediaType;
      }
      continue;
    }
    // novo recurso detectado só pelo DOM
    const ext = extOf(url);
    let type = r.mediaType === 'audio' || r.mediaType === 'video' ? r.mediaType : (ext && EXT_TO_TYPE[ext] || 'unknown');
    if (STREAM_PATH_RX.test(url)) type = 'stream';
    const resource = {
      id, tabId, url,
      title: safeTitle(r.title || hostOf(url) || 'recurso DOM'),
      mimeType: r.mimeType || undefined,
      extension: ext || undefined,
      duration: r.duration ? Math.max(0, Math.round(Number(r.duration) * 10) / 10) : undefined,
      width: r.width ? Math.round(Number(r.width)) : undefined,
      height: r.height ? Math.round(Number(r.height)) : undefined,
      mediaType: type,
      source: 'dom',
      detectedAt: Date.now()
    };
    state.set(id, resource);
    newIds.push(id);
  }
  return newIds;
}

/* ---------------- Estado por aba ---------------- */

/**
 * Cria um detector por aba. Mantém um Map<id, MediaResource> em memória.
 * Limites: MAX_RESOURCES_PER_TAB por aba; recursos antigos (>30 min sem
 * atualização) são descartados (limpeza periódica no caller).
 */
function createDetectorState() {
  const resources = new Map();
  const seenUrls = new Set();   // URLs já contadas (evita recontagem em redirect)

  return {
    add(resource) {
      if (!resource || !resource.id) return false;
      if (resources.size >= MAX_RESOURCES_PER_TAB && !resources.has(resource.id)) {
        // remove o mais antigo (FIFO por detectedAt)
        let oldestId = null, oldestTs = Infinity;
        for (const [id, r] of resources) {
          if (r.detectedAt < oldestTs) { oldestTs = r.detectedAt; oldestId = id; }
        }
        if (oldestId) resources.delete(oldestId);
      }
      const existing = resources.get(resource.id);
      if (existing) {
        // atualiza metadados (size pode vir depois, MIME pode mudar em redirect)
        if (resource.fileSize && !existing.fileSize) existing.fileSize = resource.fileSize;
        if (resource.mimeType && !existing.mimeType) existing.mimeType = resource.mimeType;
        existing.detectedAt = Date.now();
        return false;
      }
      resources.set(resource.id, resource);
      return true;
    },
    mergeDom(domList, tabId) { return mergeDom(resources, domList, tabId); },
    list() { return [...resources.values()]; },
    has(url) { return resources.has(resId(resources.values().next().value && resources.values().next().value.tabId, url)); },
    get(id) { return resources.get(id); },
    remove(id) { return resources.delete(id); },
    clear() { resources.clear(); seenUrls.clear(); },
    prune(maxAgeMs) {
      const cutoff = Date.now() - maxAgeMs;
      let removed = 0;
      for (const [id, r] of resources) {
        if (r.detectedAt < cutoff) { resources.delete(id); removed++; }
      }
      return removed;
    },
    size() { return resources.size; }
  };
}

/* ---------------- Script injetado na página (DOM) ---------------- */

/**
 * Devolve o script (string) para ser executado via wc.executeJavaScript.
 * Coleta <audio>, <video>, <source> e metadados sem modificar a página.
 * Roda UMA VEZ por chamada de "Detectar mídia" — não há MutationObserver
 * contínuo (especificação 6.3: "não injete scripts continuamente").
 */
const DOM_PROBE_SCRIPT = `(function () {
  var out = [];
  function pushMedia(el, kind) {
    try {
      var src = el.currentSrc || el.src || (el.querySelector && el.querySelector('source') && el.querySelector('source').src) || '';
      if (!src) return;
      var w = el.videoWidth || el.width || 0;
      var h = el.videoHeight || el.height || 0;
      var d = (typeof el.duration === 'number' && isFinite(el.duration)) ? el.duration : 0;
      out.push({
        url: src,
        mediaType: kind,
        duration: d,
        width: w,
        height: h,
        mimeType: el.type || '',
        title: (el.title || (el.getAttribute && el.getAttribute('aria-label')) || '').slice(0, 120)
      });
    } catch (_) {}
  }
  try {
    var vids = document.querySelectorAll('video');
    for (var i = 0; i < vids.length && i < 30; i++) pushMedia(vids[i], 'video');
    var auds = document.querySelectorAll('audio');
    for (var j = 0; j < auds.length && j < 30; j++) pushMedia(auds[j], 'audio');
    // <source> órfãos (sem <video>/<audio> pai direto)
    var srcs = document.querySelectorAll('source[src]');
    for (var k = 0; k < srcs.length && k < 20; k++) {
      try {
        var s = srcs[k];
        var src = s.src || '';
        if (!src) continue;
        var type = s.type || '';
        var mediaType = 'unknown';
        if (/^audio\//i.test(type)) mediaType = 'audio';
        else if (/^video\//i.test(type)) mediaType = 'video';
        else if (/mpegurl/i.test(type) || /\.m3u8/i.test(src)) mediaType = 'stream';
        else if (/dash/i.test(type) || /\.mpd/i.test(src)) mediaType = 'stream';
        out.push({ url: src, mediaType: mediaType, mimeType: type, title: '' });
      } catch (_) {}
    }
    // <a href> direto para extensões de mídia (download link explícito)
    var anchors = document.querySelectorAll('a[href]');
    for (var m = 0; m < anchors.length && m < 60; m++) {
      try {
        var a = anchors[m];
        var h = a.href || '';
        if (!/^https?:/i.test(h)) continue;
        if (/\\.(mp3|m4a|aac|wav|flac|ogg|opus|mp4|m4v|webm|ogv|mov|mkv|avi|m3u8|mpd)(?:[?#]|$)/i.test(h)) {
          // evita duplicar o que já está em out
          if (!out.some(function (r) { return r.url === h; })) {
            out.push({ url: h, mediaType: 'unknown', title: (a.textContent || '').slice(0, 80) });
          }
        }
      } catch (_) {}
    }
    // 1.9.5 — FALLBACK: Resource Timing API. Pega TODOS os recursos carregados
    // pela página (inclusive os que o webRequest hook perdeu por timing ou
    // substituição de listener). Filtra por extensão de mídia na URL.
    try {
      var entries = performance.getEntriesByType('resource');
      for (var e = 0; e < entries.length && e < 200; e++) {
        try {
          var ent = entries[e];
          var u = ent.name || '';
          if (!/^https?:/i.test(u)) continue;
          // Só adiciona se a URL tem extensão de mídia conhecida
          if (/\.(mp3|m4a|aac|wav|flac|ogg|opus|mp4|m4v|webm|ogv|mov|mkv|m3u8|mpd)(?:[?#]|$)/i.test(u)) {
            // evita duplicar o que já está em out
            if (!out.some(function (r) { return r.url === u; })) {
              var mt = 'unknown';
              if (/\.(mp3|m4a|aac|wav|flac|ogg|opus)(?:[?#]|$)/i.test(u)) mt = 'audio';
              else if (/\.(mp4|m4v|webm|ogv|mov|mkv)(?:[?#]|$)/i.test(u)) mt = 'video';
              else if (/\.(m3u8?|mpd)(?:[?#]|$)/i.test(u)) mt = 'stream';
              out.push({
                url: u, mediaType: mt,
                title: u.split('/').pop().split('?')[0].slice(0, 80),
                duration: 0, width: 0, height: 0, mimeType: ''
              });
            }
          }
        } catch (_) {}
      }
    } catch (_) {}
  } catch (_) {}
  return out;
})();`;

/* ---------------- Detecção de variantes HLS/DASH (parsing aprimorado 1.9.6) ---------------- */

/**
 * Parse de um manifesto .m3u8 (HLS). 1.9.6: aprimorado com base no video-download-extension
 * e media-grabber — agora suporta:
 *   - Master playlists (#EXT-X-STREAM-INF com BANDWIDTH/RESOLUTION/CODECS/FRAME-RATE/AUDIO)
 *   - Audio renditions (#EXT-X-MEDIA:TYPE=AUDIO com GROUP-ID/NAME/LANGUAGE/URI)
 *   - Detecção de DRM (#EXT-X-KEY com METHOD≠NONE)
 *   - Init segments (#EXT-X-MAP:URI=...)
 *   - Detecção de live (!#EXT-X-ENDLIST)
 *   - Media playlists (segments diretos, sem variantes)
 * @param {string} m3u8Text
 * @param {string} baseUrl  para resolver URLs relativas
 * @returns {{variants: Array, audios: Array, encrypted: boolean, live: boolean, segments: Array, initUrl: string|null}}
 */
function parseHlsVariants(m3u8Text, baseUrl) {
  try {
    const text = String(m3u8Text || '').replace(/^\uFEFF/, '');   // strip BOM
    if (!text.startsWith('#EXTM3U')) return { variants: [], audios: [], encrypted: false, live: true, segments: [], initUrl: null };
    const lines = text.split(/\r?\n/);
    const variants = [];
    const audios = [];
    const audioGroups = new Map();
    const segments = [];
    let initUrl = null;
    let encrypted = false;
    let hasEndList = false;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      // DRM detection
      if (line.startsWith('#EXT-X-KEY')) {
        if (!/METHOD=NONE/i.test(line)) encrypted = true;
        continue;
      }
      // Init segment (fMP4)
      if (line.startsWith('#EXT-X-MAP:')) {
        const m = /URI="([^"]+)"/.exec(line);
        if (m) initUrl = resolveUrl(m[1], baseUrl);
        continue;
      }
      // Audio renditions
      if (line.startsWith('#EXT-X-MEDIA:') && /TYPE=AUDIO/i.test(line)) {
        const g = /GROUP-ID="([^"]+)"/i.exec(line);
        const u = /URI="([^"]+)"/i.exec(line);
        const n = /NAME="([^"]+)"/i.exec(line);
        const l = /LANGUAGE="([^"]+)"/i.exec(line);
        if (g && u) {
          const audio = {
            groupId: g[1], name: n ? n[1] : '',
            language: l ? l[1] : '', url: resolveUrl(u[1], baseUrl)
          };
          if (!audioGroups.has(g[1])) { audioGroups.set(g[1], audio.url); audios.push(audio); }
        }
        continue;
      }
      // Master playlist variants
      if (line.startsWith('#EXT-X-STREAM-INF:')) {
        const next = (lines[i + 1] || '').trim();
        if (!next || next.startsWith('#')) continue;
        const attrs = line.slice('#EXT-X-STREAM-INF:'.length);
        const bw = (attrs.match(/BANDWIDTH=(\d+)/) || [])[1];
        const res = (attrs.match(/RESOLUTION=(\d+x\d+)/) || [])[1];
        const codecs = (attrs.match(/CODECS="([^"]+)"/) || [])[1];
        const frameRate = (attrs.match(/FRAME-RATE=([\d.]+)/) || [])[1];
        const aud = (attrs.match(/AUDIO="([^"]+)"/) || [])[1];
        const url = resolveUrl(next, baseUrl);
        if (url) variants.push({
          url, bandwidth: bw ? Number(bw) : undefined,
          resolution: res, codecs, frameRate: frameRate ? Number(frameRate) : undefined,
          audioGroup: aud || null,
          label: res ? res + (frameRate ? '@' + frameRate : '') : (bw ? Math.round(bw / 1000) + 'kbps' : 'variante')
        });
        continue;
      }
      // Media playlist: segments diretos (linhas sem #)
      if (!line.startsWith('#') && /^https?:\/\//i.test(line) || (!line.startsWith('#') && baseUrl)) {
        const segUrl = resolveUrl(line, baseUrl);
        if (segUrl) segments.push(segUrl);
        continue;
      }
      if (line === '#EXT-X-ENDLIST') hasEndList = true;
    }

    return {
      variants: variants.sort((a, b) => (b.bandwidth || 0) - (a.bandwidth || 0)),
      audios,
      encrypted,
      live: !hasEndList,
      segments,
      initUrl
    };
  } catch (_) {
    return { variants: [], audios: [], encrypted: false, live: true, segments: [], initUrl: null };
  }
}

/**
 * Parse de um manifesto .mpd (MPEG-DASH). 1.9.6: aprimorado com base no video-download-extension.
 * Suporta:
 *   - <Representation> com BaseURL direto (single-segment)
 *   - <Representation> com SegmentTemplate ($RepresentationID$, $Number$, $Time$, $Bandwidth$)
 *   - <Representation> com SegmentList/SegmentURL
 *   - Detecção de DRM (<ContentProtection>)
 *   - Detecção de live (type="dynamic")
 *   - mimeType, codecs, width, height, bandwidth, frameRate
 * @returns {{variants: Array, encrypted: boolean, live: boolean, duration: number|null}}
 */
function parseDashVariants(mpdText, baseUrl) {
  try {
    const xml = String(mpdText || '');
    if (/<ContentProtection/i.test(xml)) return { variants: [], encrypted: true, live: false, duration: null };
    const live = /<MPD\b[^>]*\btype="dynamic"/i.test(xml);
    const durMatch = /mediaPresentationDuration="([^"]+)"/i.exec(xml);
    const duration = durMatch ? parseIsoDuration(durMatch[1]) : null;
    const variants = [];
    const repRx = /<Representation\b([^>]*)>([\s\S]*?)<\/Representation>/gi;
    let m;
    while ((m = repRx.exec(xml)) !== null) {
      const attrs = m[1];
      const body = m[2];
      const bw = (attrs.match(/(?<![A-Za-z])bandwidth="(\d+)"/) || [])[1];
      const w = (attrs.match(/(?<![A-Za-z])width="(\d+)"/) || [])[1];
      const h = (attrs.match(/(?<![A-Za-z])height="(\d+)"/) || [])[1];
      const codecs = (attrs.match(/(?<![A-Za-z])codecs="([^"]+)"/) || [])[1];
      const frameRate = (attrs.match(/(?<![A-Za-z])frameRate="([\d.]+)"/) || [])[1];
      const id = (attrs.match(/(?<![A-Za-z])id="([^"]+)"/) || [])[1];
      const mime = (attrs.match(/(?<![A-Za-z])mimeType="([^"]+)"/) || [])[1];
      // 1) BaseURL direto — arquivo completo baixável
      const direct = body.match(/<BaseURL>([\s\S]*?)<\/BaseURL>/i);
      if (direct) {
        const url = resolveUrl(direct[1].trim(), baseUrl);
        if (url) variants.push({
          url, bandwidth: bw ? Number(bw) : undefined,
          width: w ? Number(w) : undefined, height: h ? Number(h) : undefined,
          codecs, frameRate: frameRate ? Number(frameRate) : undefined,
          type: mime || 'video/mp4',
          label: (w && h) ? w + 'x' + h : (bw ? Math.round(bw / 1000) + 'kbps' : ('rep ' + (id || '?')))
        });
        continue;
      }
      // 2) SegmentTemplate — não é diretamente baixável, mas registramos a info
      //    (o download de DASH segmentado exige fetch+concat de segments — futuro)
      const tmpl = body.match(/<SegmentTemplate\b([^>]*)\/?>([\s\S]*?)<\/SegmentTemplate>/i) ||
                   body.match(/<SegmentTemplate\b([^>]*)\/>/i);
      if (tmpl) {
        const media = (tmpl[1].match(/media="([^"]+)"/) || [])[1];
        if (media) {
          const filled = fillDashTemplate(media, { id: id || '', bandwidth: bw || '', number: '1', time: '0' });
          const url = resolveUrl(filled, baseUrl);
          variants.push({
            url, bandwidth: bw ? Number(bw) : undefined,
            width: w ? Number(w) : undefined, height: h ? Number(h) : undefined,
            codecs, frameRate: frameRate ? Number(frameRate) : undefined,
            type: mime || 'video/mp4', segmented: true,
            label: (w && h) ? w + 'x' + h : (bw ? Math.round(bw / 1000) + 'kbps' : ('rep ' + (id || '?')))
          });
        }
      }
    }
    return {
      variants: variants.sort((a, b) => (b.bandwidth || 0) - (a.bandwidth || 0)),
      encrypted: false, live, duration
    };
  } catch (_) {
    return { variants: [], encrypted: false, live: false, duration: null };
  }
}

/** Substitui $RepresentationID$, $Number$, $Time$, $Bandwidth$ em um template DASH. */
function fillDashTemplate(tmpl, vars) {
  return String(tmpl || '')
    .replace(/\$\$/g, '\x00')   // $$ vira $ (placeholder temporário)
    .replace(/\$RepresentationID\$/g, vars.id || '')
    .replace(/\$Number%0*(\d+)d\$/g, (_, w) => String(vars.number || '').padStart(Number(w), '0'))
    .replace(/\$Number\$/g, vars.number || '')
    .replace(/\$Time\$/g, vars.time || '')
    .replace(/\$Bandwidth\$/g, vars.bandwidth || '')
    .replace(/\x00/g, '$');
}

/** Parse ISO 8601 duration (PT1H30M15S → 5415 seconds). */
function parseIsoDuration(s) {
  const m = String(s || '').match(/^P(?:([\d.]+)D)?(?:T(?:([\d.]+)H)?(?:([\d.]+)M)?(?:([\d.]+)S)?)?$/);
  if (!m) return null;
  const days = parseFloat(m[1] || '0');
  const hours = parseFloat(m[2] || '0');
  const mins = parseFloat(m[3] || '0');
  const secs = parseFloat(m[4] || '0');
  return days * 86400 + hours * 3600 + mins * 60 + secs || null;
}

function resolveUrl(maybeRel, base) {
  try { return new URL(maybeRel, base).href; } catch (_) { return ''; }
}

/* ---------------- Exports ---------------- */

module.exports = {
  MIME_TO_TYPE, EXT_TO_TYPE, NON_MEDIA_RESOURCE_TYPES,
  MIN_MEDIA_BYTES, MAX_RESOURCES_PER_TAB, MAX_URL_LEN,
  STREAM_PATH_RX, HLS_MIME_RX, DASH_MIME_RX,
  classifyNetwork, mergeDom, parseHlsVariants, parseDashVariants,
  createDetectorState, DOM_PROBE_SCRIPT,
  // 1.9.6 — novas utils
  normalizeMediaUrl, isStreamSegment, isSocialMediaImage, urlFilenameOf,
  isExplicitlyNonMediaMime,
  // utils expostas para testes/integração
  safeUrl, hostOf, extOf, resId, safeTitle,
  readContentLength, readContentDisposition, readContentType,
  streamLabel
};

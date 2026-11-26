/**
 * NanoDesk — Proteção contra fingerprinting (1.6.0, FASE 4)
 * ==================================================================
 * Conceito do projeto aberto CanvasBlocker (github.com/kkapsner/
 * CanvasBlocker, GPL-3.0) reimplementado em código original (MIT),
 * seguindo a diretriz da especificação: REDUÇÃO de superfície de
 * identificação com CONSISTÊNCIA entre APIs — NÃO randomização
 * indiscriminada (que tornaria o navegador MAIS identificável).
 *
 * O que é protegido (script injetado no mundo principal da página):
 *  1. Canvas 2D — toDataURL/toBlob/getImageData recebem ruído LSB
 *     determinístico (mesmo ruído dentro da sessão → leituras
 *     repetidas são consistentes entre si, mas diferentes do "real");
 *     visualmente idêntico (±1 em poucos pixels de amostra).
 *  2. WebGL/Contexto de GPU — WEBGL_debug_renderer_info (37445/37446)
 *     responde valores genéricos populares ("Intel") em vez do GPU
 *     real; strings básicas vendor/renderer ficam intactas.
 *  3. AudioContext — ruído de amplitude ~1e-7 (inaudível) nos dados
 *     de amostra/analizador, quebrando o fingerprint de áudio sem
 *     alterar a audição.
 *  4. OffscreenCanvas — convertToBlob passa pelo mesmo caminho ruído.
 *
 * O que NÃO é mexido de propósito (consistência > disfarce):
 *  - navigator.userAgent/platform/languages, timezone, tela:
 *    mentir aqui cria inconsistência detectável; o UA já é o padrão
 *    do Chromium no Windows e o DNT/GPC já são enviados.
 *
 * Injeção: o preload isolado (fingerprint-preload.js) roda em TODAS
 * as frames da sessão e executa este script no mundo principal via
 * webFrame.executeJavaScript — o único caminho que afeta o mundo da
 * página com contextIsolation:true. Idempotente (guarda no window).
 * Núcleo puro: nada aqui toca o Electron.
 */
'use strict';

/**
 * Gera o script de hooks (string autocontida).
 * @param {object} [opts] {
 *   noisePixels?: number,
 *   platform?: string           — coerência da máscara WebGL com a identidade do UA;
 *   webglVendor?: string        — sobrescreve a máscara explicitamente;
 *   webglRenderer?: string,
 *   timezone?: string           — 1.6.7 (abas Tor): fuso falso (ex.: 'UTC');
 *   locale?: string             — 1.6.7 (abas Tor): idioma falso (ex.: 'en-US');
 *   blockWebRtc?: boolean       — 1.6.7 (abas Tor): RTCPeerConnection/getUserMedia desativados
 * }
 *
 * CORREÇÕES 1.6.7 (buracos que um fingerprinter explorava):
 *  - AudioBuffer.copyFromChannel lia as amostras REAIS (bypass trivial do ruído);
 *  - AnalyserNode faltava getFloat/ByteTimeDomainData (cobertura incompleta é,
 *    em si, um sinal de spoofing);
 *  - WebGLRenderingContext/2.readPixels devolvia a RENDERIZAÇÃO real (sem ruído);
 *  - o hook do Analyser mutava o PRNG global (SEED): leituras de canvas
 *    intercaladas com leituras de áudio produziam ruídos diferentes para o
 *    MESMO canvas — o Analyser agora usa estado local, como os demais hooks;
 *  - a máscara WebGL era "Intel Iris OpenGL Engine" (string exclusiva do
 *    macOS) enquanto o UA dizia Windows — contradição detectável; agora a
 *    string ANGLE/D3D11 é usada no Windows (padrão do alvo do NanoDesk).
 */
function buildHookScript(opts = {}) {
  const noisePixels = Math.min(64, Math.max(8, Number(opts.noisePixels) || 24));
  const platform = String(opts.platform || 'win32');
  // Par coerente com o UA Windows (ANGLE/D3D11 é o caminho gráfico padrão do
  // Chrome no Windows; "Intel Iris OpenGL Engine" só existe no macOS).
  const WIN_VENDOR = 'Google Inc. (Intel)';
  const WIN_RENDERER = 'ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00003E9B) Direct3D11 vs_5_0 ps_5_0, D3D11)';
  const MAC_VENDOR = 'Intel Inc.';
  const MAC_RENDERER = 'Intel Iris OpenGL Engine';
  const webglVendor = String(opts.webglVendor || (platform === 'darwin' ? MAC_VENDOR : WIN_VENDOR));
  const webglRenderer = String(opts.webglRenderer || (platform === 'darwin' ? MAC_RENDERER : WIN_RENDERER));
  const tz = String(opts.timezone || '');
  const locale = String(opts.locale || '');
  const blockRtc = opts.blockWebRtc === true;
  return (
    '(function () {' +
    'if (window.__nanodeskFp) return window.__nanodeskFp;' +
    // ---- semente estável da sessão (não persistida) ----
    'var SEED = 0;' +
    'try { var b = new Uint8Array(8); (window.crypto||{}).getRandomValues(b);' +
    'for (var i=0;i<8;i++) SEED = (SEED*256 + b[i]) >>> 0; } catch(_) { SEED = (Date.now()>>>0); }' +
    'function rnd(n){ SEED = (Math.imul(SEED, 1664525) + 1013904223) >>> 0; return (SEED >>> 8) % n; }' +
    // PRNG LOCAL (estado próprio, não muta SEED) — 1.6.5/1.6.7
    'function localRnd(seedIn){ var st = seedIn >>> 0; return function(n){ st = (Math.imul(st, 1664525) + 1013904223) >>> 0; return (st >>> 8) % n; }; }' +
    'function inFrame(){ try { return window.self !== window.top; } catch(_) { return true; } }' +
    'var HOOKED = { canvas:0, webgl:0, audio:0 };' +
    // ---- 1.7.2: foto dos originais ANTES de qualquer hook (para mascarar toString no fim) ----
    'var __T = [];' +
    'function __snap(o, p){ try { if (!o) return; var d = Object.getOwnPropertyDescriptor(o, p); if (d) __T.push({ o: o, p: p, v: d.value, g: d.get }); } catch(_){ } }' +
    'function __pr(n){ try { return (typeof window[n] !== "undefined" && window[n].prototype) ? window[n].prototype : null; } catch(_){ return null; } }' +
    '[["HTMLCanvasElement",["toDataURL","toBlob"]],["CanvasRenderingContext2D",["getImageData"]],["OffscreenCanvas",["convertToBlob"]],' +
    '["WebGLRenderingContext",["getParameter","readPixels"]],["WebGL2RenderingContext",["getParameter","readPixels"]],' +
    '["AudioBuffer",["getChannelData","copyFromChannel"]],["AnalyserNode",["getFloatFrequencyData","getByteFrequencyData","getFloatTimeDomainData","getByteTimeDomainData"]],' +
    '["Date",["getTimezoneOffset","toLocaleString","toLocaleDateString","toLocaleTimeString"]],["Navigator",["language","languages"]]].forEach(function(e){' +
    '  var pr = __pr(e[0]); e[1].forEach(function(m){ __snap(pr, m); }); });' +
    'try { if (typeof Intl !== "undefined" && Intl.DateTimeFormat) __snap(Intl.DateTimeFormat.prototype, "resolvedOptions"); } catch(_){ }' +
    (tz ? (
      // ---- 0) Fuso horário falso (abas Tor) — Intl + Date ----
      'try {' +
      '  var TZ=' + JSON.stringify(tz) + ';' +
      '  if (Date.prototype.getTimezoneOffset){ var oTO = Date.prototype.getTimezoneOffset;' +
      '    Date.prototype.getTimezoneOffset = function(){ try { return 0; } catch(_){ return oTO.apply(this, arguments); } }; }' +
      '  if (typeof Intl !== "undefined" && Intl.DateTimeFormat && Intl.DateTimeFormat.prototype){' +
      '    var oR = Intl.DateTimeFormat.prototype.resolvedOptions;' +
      '    Intl.DateTimeFormat.prototype.resolvedOptions = function(){' +
      '      var r = oR.apply(this, arguments); try { r.timeZone = TZ; } catch(_){ } return r; }; }' +
      '  if (typeof Date !== "undefined" && Date.prototype.toLocaleString){' +
      '    var oLS = Date.prototype.toLocaleString, oLD = Date.prototype.toLocaleDateString, oLT = Date.prototype.toLocaleTimeString;' +
      '    var wrap = function(orig){ return function(){ try { var a = Array.prototype.slice.call(arguments);' +
      '      if (!a.length || a[0] === undefined) a[0] = TZ;' +
      '      else if (a[0] !== null && typeof a[0] === "object" && !a[1]) a[1] = Object.assign({}, a[0], { timeZone: TZ });' +
      '      else if (a[1] && typeof a[1] === "object") a[1] = Object.assign({}, a[1], { timeZone: TZ });' +
      '      return orig.apply(this, a); } catch(_){ return orig.apply(this, arguments); } }; };' +
      '    Date.prototype.toLocaleString = wrap(oLS);' +
      '    Date.prototype.toLocaleDateString = wrap(oLD);' +
      '    Date.prototype.toLocaleTimeString = wrap(oLT); }' +
      '} catch (_) { }'
    ) : '') +
    (locale ? (
      // ---- 0b) Idioma falso (abas Tor) — evita reduzir o conjunto de anonimato ----
      'try {' +
      '  var LOC=' + JSON.stringify(locale) + ',' +
      '  LOCS=' + JSON.stringify(locale.split(',').map(s => s.trim())) + ';' +
      '  try { Object.defineProperty(Navigator.prototype, "language", { get: function(){ return LOC; }, configurable: true }); } catch(_){' +
      '    try { navigator.language = LOC; } catch(__){ } }' +
      '  try { Object.defineProperty(Navigator.prototype, "languages", { get: function(){ return LOCS; }, configurable: true }); } catch(_){' +
      '    try { navigator.languages = LOCS; } catch(__){ } }' +
      '} catch (_) { }'
    ) : '') +
    (blockRtc ? (
      // ---- 0c) WebRTC DESLIGADO (abas Tor): a política disable_non_proxied_udp
      // ainda permitia TURN sobre TCP sair pela rota direta — o IP real vazava.
      // O Tor Browser desliga o WebRTC; fazemos o mesmo.
      'try {' +
      '  var msg = function(){ throw new DOMException("WebRTC é desativado em abas Tor (NanoDesk).", "NotSupportedError"); };' +
      '  if (typeof RTCPeerConnection !== "undefined") { window.RTCPeerConnection = function(){ return msg(); }; window.RTCPeerConnection.prototype = undefined; }' +
      '  try { window.webkitRTCPeerConnection = window.RTCPeerConnection; } catch(_){ }' +
      '  if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia){' +
      '    navigator.mediaDevices.getUserMedia = function(){ return Promise.reject(new DOMException("Negado em abas Tor", "NotAllowedError")); }; }' +
      '} catch (_) { }'
    ) : '') +
    // ---- 1) Canvas 2D: ruído LSB determinístico ----
    'try {' +
    '  var N = ' + noisePixels + ';' +
    // 1.6.5: PRNG LOCAL por chamada, semeado só pela semente da sessão + tamanho dos dados.
    '  function noiseData(imageData){' +
    '    var d = imageData.data, len = d.length;' +
    '    if (!len) return imageData;' +
    '    var lr = localRnd((SEED ^ Math.imul(len, 2654435761)) >>> 0);' +
    '    for (var k=0;k<N && len;k++){' +
    '      var idx = lr(len >> 2) << 2;' +
    '      var ch = idx + (lr(3));' +   // canal R/G/B (não o alpha)
    '      var bit = lr(2) ? 1 : -1;' +
    '      var v = d[ch] + bit;' +
    '      if (v < 0) v = 0; if (v > 255) v = 255;' +
    '      d[ch] = v;' +
    '    }' +
    '    return imageData;' +
    '  }' +
    '  var ctxProto = (typeof CanvasRenderingContext2D !== "undefined") ? CanvasRenderingContext2D.prototype : null;' +
    '  if (ctxProto && ctxProto.getImageData){' +
    '    var origGet = ctxProto.getImageData;' +
    '    ctxProto.getImageData = function(){ var r = origGet.apply(this, arguments); try{ noiseData(r); }catch(_){ } return r; };' +
    '    HOOKED.canvas++;' +
    '  }' +
    '  function noisySnapshot(canvas){' +
    '    var c = document.createElement("canvas");' +
    '    c.width = canvas.width; c.height = canvas.height;' +
    '    var cx = c.getContext("2d");' +
    '    cx.drawImage(canvas, 0, 0);' +
    '    try { var rd = (typeof origGet === \"function\") ? origGet : cx.getImageData;' +
    '      var id = rd.call(cx, 0, 0, c.width, c.height); cx.putImageData(noiseData(id), 0, 0); } catch(_) { return null; }' +
    '    return c;' +
    '  }' +
    '  if (typeof HTMLCanvasElement !== "undefined") {' +
    '    var hp = HTMLCanvasElement.prototype;' +
    '    if (hp.toDataURL){ var oDU = hp.toDataURL;' +
    '      hp.toDataURL = function(){ var c = noisySnapshot(this); return c ? oDU.apply(c, arguments) : oDU.apply(this, arguments); }; HOOKED.canvas++; }' +
    '    if (hp.toBlob){ var oB = hp.toBlob;' +
    '      hp.toBlob = function(cb){ var c = noisySnapshot(this); return c ? oB.apply(c, arguments) : oB.apply(this, arguments); }; HOOKED.canvas++; }' +
    '  }' +
    '  if (typeof OffscreenCanvas !== "undefined" && OffscreenCanvas.prototype && OffscreenCanvas.prototype.convertToBlob){' +
    '    var oCTB = OffscreenCanvas.prototype.convertToBlob;' +
    '    OffscreenCanvas.prototype.convertToBlob = function(o){' +
    '      try { var reg = document.createElement("canvas"); reg.width=this.width; reg.height=this.height;' +
    '        reg.getContext("2d").drawImage(this,0,0); var c = noisySnapshot(reg);' +
    '        if (c && typeof oB === "function") return new Promise(function(res, rej){' +
    '          try { oB.call(c, function(b){ b ? res(b) : rej(new DOMException("convertToBlob falhou","EncodingError")); }, o && o.type, o && o.quality); } catch(e){ rej(e); }' +
    '        });' +
    '      } catch(_){ }' +
    '      return oCTB.apply(this, arguments);' +
    '    };' +
    '    HOOKED.canvas++;' +
    '  }' +
    '} catch (_) { }' +
    // ---- 2) WebGL: GPU genérica coerente com a plataforma do UA ----
    'try {' +
    '  var V_UNMASKED_VENDOR = 37445, V_UNMASKED_RENDERER = 37446;' +
    '  var GENERIC_VENDOR = ' + JSON.stringify(webglVendor) + ', GENERIC_RENDERER = ' + JSON.stringify(webglRenderer) + ';' +
    // ruído LSB do readPixels (renderização real era legível sem proteção)
    '  function noisePixelsBuf(arr, w, h, bytesPerPixel){' +
    '    try { var len = arr.length; if (!len) return;' +
    '      var lr = localRnd((SEED ^ Math.imul(len, 40503)) >>> 0);' +
    '      var step = Math.max(bytesPerPixel, Math.floor(len / 512) * bytesPerPixel || bytesPerPixel);' +
    '      for (var i = 0; i < len; i += step){ arr[i] = (arr[i] + (lr(3) - 1)) & 255; } } catch(_){ }' +
    '  }' +
    '  function maskGl(proto){' +
    '    if (!proto || !proto.getParameter) return;' +
    '    var gp = proto.getParameter;' +
    '    proto.getParameter = function(p){' +
    '      if (p === V_UNMASKED_VENDOR) return GENERIC_VENDOR;' +
    '      if (p === V_UNMASKED_RENDERER) return GENERIC_RENDERER;' +
    '      return gp.apply(this, arguments);' +
    '    };' +
    '    if (proto.readPixels){ var oRP = proto.readPixels;' +
    '      proto.readPixels = function(x, y, w, h, fmt, type, pixels){' +
    '        var r = oRP.apply(this, arguments);' +
    '        try { if (pixels && pixels.length) noisePixelsBuf(pixels, w, h, 4); } catch(_){ }' +
    '        return r; };' +
    '    }' +
    '  }' +
    '  if (typeof WebGLRenderingContext !== "undefined") { maskGl(WebGLRenderingContext.prototype); HOOKED.webgl++; }' +
    '  if (typeof WebGL2RenderingContext !== "undefined") { maskGl(WebGL2RenderingContext.prototype); HOOKED.webgl++; }' +
    '} catch (_) { }' +
    // ---- 3) AudioContext: ruído inaudível ----
    'try {' +
    '  if (typeof AudioBuffer !== "undefined" && AudioBuffer.prototype && AudioBuffer.prototype.getChannelData){' +
    '    var oGC = AudioBuffer.prototype.getChannelData;' +
    '    var noised = (typeof WeakSet !== "undefined") ? new WeakSet() : null;' +
    '    function noiseBuf(data){' +
    '      try { if (noised && noised.has(data)) return;' +
    '        var as = (SEED ^ Math.imul(data.length, 2654435761)) >>> 0;' +
    '        var step = Math.max(1, Math.floor(data.length / 2048));' +
    '        for (var i = 0; i < data.length; i += step){ as = (Math.imul(as, 1664525) + 1013904223) >>> 0; data[i] += (((as >>> 8) % 3) - 1) * 1e-7; }' +
    '        if (noised) noised.add(data);' +
    '      } catch(_){ }' +
    '    }' +
    '    AudioBuffer.prototype.getChannelData = function(){' +
    '      var data = oGC.apply(this, arguments); noiseBuf(data); return data;' +
    '    };' +
    // CORREÇÃO 1.6.7: copyFromChannel lia as amostras REAIS — bypass do ruído.
    '    if (AudioBuffer.prototype.copyFromChannel){ var oCC = AudioBuffer.prototype.copyFromChannel;' +
    '      AudioBuffer.prototype.copyFromChannel = function(dest, ch, off){' +
    '        var r = oCC.apply(this, arguments);' +
    '        try { var full = oGC.call(this, ch); noiseBuf(full);' +
    '          var start = (typeof off === "number" && off >= 0) ? off : 0;' +
    '          for (var i = 0; i < dest.length && start + i < full.length; i++) dest[i] = full[start + i]; } catch(_){ }' +
    '        return r; };' +
    '    }' +
    '    HOOKED.audio++;' +
    '  }' +
    '  if (typeof AnalyserNode !== "undefined" && AnalyserNode.prototype){' +
    '    var an = AnalyserNode.prototype;' +
    // CORREÇÃO 1.6.7: PRNG LOCAL (não muta o SEED global — antes leituras
    // de áudio mudavam o ruído futuro de CANVAS, quebrando a consistência).
    // (comentários ficam AQUI no gerador: dentro da string concatenada em
    // uma linha, um "//" engoliria o resto do script gerado)
    '    var anState = (SEED ^ 0x9E3779B9) >>> 0;' +
    '    function anRnd(n){ anState = (Math.imul(anState, 1664525) + 1013904223) >>> 0; return (anState >>> 8) % n; }' +
    '    if (an.getFloatFrequencyData){ var oFF = an.getFloatFrequencyData;' +
    '      an.getFloatFrequencyData = function(arr){ oFF.apply(this, arguments); try{ for (var i=0;i<arr.length;i+=97) arr[i] += (anRnd(3)-1)*1e-7; }catch(_){} }; HOOKED.audio++; }' +
    '    if (an.getByteFrequencyData){ var oBF = an.getByteFrequencyData;' +
    '      an.getByteFrequencyData = function(arr){ oBF.apply(this, arguments); try{ for (var i=0;i<arr.length;i+=251) arr[i] = arr[i] ? (arr[i] ^ 1) : 0; }catch(_){} }; HOOKED.audio++; }' +
    // CORREÇÃO 1.6.7: domínio do tempo não era coberto (cobertura incompleta = sinal).
    '    if (an.getFloatTimeDomainData){ var oFT = an.getFloatTimeDomainData;' +
    '      an.getFloatTimeDomainData = function(arr){ oFT.apply(this, arguments); try{ for (var i=0;i<arr.length;i+=101) arr[i] += (anRnd(3)-1)*1e-7; }catch(_){} }; HOOKED.audio++; }' +
    '    if (an.getByteTimeDomainData){ var oBT = an.getByteTimeDomainData;' +
    '      an.getByteTimeDomainData = function(arr){ oBT.apply(this, arguments); try{ for (var i=0;i<arr.length;i+=127) arr[i] = arr[i] ? (arr[i] ^ 1) : 0; }catch(_){} }; HOOKED.audio++; }' +
    '  }' +
    '} catch (_) { }' +
    // ---- 1.7.2: MASCARA toString — função com hook responde "[native code]" como a original.
    // Sem isto, HTMLCanvasElement.prototype.toDataURL.toString() devolvia o código do hook, e
    // verificadores de integridade (BotGuard do login do Google) recusavam o navegador.
    'try {' +
    '  var TS = Function.prototype.toString, MAP = new WeakMap();' +
    '  var patched = new Proxy(TS, { apply: function(t, th, a){ if (MAP.has(th)) return MAP.get(th); return Reflect.apply(t, th, a); } });' +
    '  __T.forEach(function(e){ try {' +
    '    var d = Object.getOwnPropertyDescriptor(e.o, e.p); if (!d) return;' +
    '    var cur = e.g ? d.get : d.value, orig = e.g ? e.g : e.v;' +
    '    if (typeof cur === "function" && typeof orig === "function" && cur !== orig){' +
    '      MAP.set(cur, TS.call(orig));' +
    '      try { Object.defineProperty(cur, "name", { value: orig.name, configurable: true }); } catch(_){ }' +
    '      try { Object.defineProperty(cur, "length", { value: orig.length, configurable: true }); } catch(_){ }' +
    '    } } catch(_){ } });' +
    '  MAP.set(patched, TS.call(TS));' +
    '  Object.defineProperty(Function.prototype, "toString", { value: patched, writable: true, configurable: true, enumerable: false });' +
    '} catch (_) { }' +
    'try { Object.defineProperty(window, "__nanodeskFp", { value: HOOKED, enumerable: false, configurable: true, writable: true }); } catch (_) { window.__nanodeskFp = HOOKED; }' +
    'return HOOKED;' +
    '})();'
  );
}

/** Descrição dos hooks (documentação/painel/testes). */
const HOOKS = [
  { id: 'canvas', label: 'Canvas 2D (toDataURL/toBlob/getImageData + ruído LSB determinístico)' },
  { id: 'webgl', label: 'WebGL: máscara UNMASKED coerente com a plataforma + ruído em readPixels' },
  { id: 'audio', label: 'AudioBuffer (getChannelData/copyFromChannel) + AnalyserNode (frequência e domínio do tempo)' },
  { id: 'tor', label: 'Abas Tor: fuso UTC, idioma en-US e WebRTC desativado (evita vazamento e redução do conjunto de anonimato)' }
];

/** Verificação PURA do script gerado (usada nos testes unitários). */
function verifyScript(script) {
  const erros = [];
  if (typeof script !== 'string' || !script.length) erros.push('script vazio');
  if (!script.includes('__nanodeskFp')) erros.push('sem guarda de idempotência');
  if (!script.includes('37445')) erros.push('sem máscara de UNMASKED_VENDOR');
  if (!script.includes('37446')) erros.push('sem máscara de UNMASKED_RENDERER');
  if (!script.includes('getImageData')) erros.push('sem ruído de canvas');
  if (!script.includes('getChannelData')) erros.push('sem ruído de áudio');
  if (!script.includes('copyFromChannel')) erros.push('sem hook de copyFromChannel');
  if (!script.includes('readPixels')) erros.push('sem ruído de readPixels');
  if (!script.includes('[native code]') && !script.includes('MAP.set(cur, TS.call(orig))')) erros.push('sem máscara de toString');
  try { new Function(script); } catch (e) { erros.push('sintaxe: ' + e.message); }
  return erros;
}


/**
 * 1.7.3 — completa o objeto window.chrome como o Chrome real em páginas comuns
 * (chrome.loadTimes, chrome.csi, chrome.app). No Electron ele vem VAZIO — um sinal clássico de
 * navegador embutido/automatizado que verificadores de login (BotGuard) consultam. Só é usado
 * em páginas de login/identidade (nada além disso é injetado nelas). Funções com toString
 * nativo. Idempotente (não faz nada se loadTimes já existe).
 */
function buildChromeObjectScript() {
  return '(function(){ try {' +
    'if (window.chrome && typeof window.chrome.loadTimes === "function") return;' +
    'if (typeof window.chrome === "undefined") Object.defineProperty(window, "chrome", { value: {}, writable: true, configurable: true, enumerable: true });' +
    'var c = window.chrome; var TS = Function.prototype.toString, MAP = new WeakMap();' +
    'var patched = new Proxy(TS, { apply: function(t, th, a){ if (MAP.has(th)) return MAP.get(th); return Reflect.apply(t, th, a); } });' +
    'function nat(fn, name){ MAP.set(fn, "function " + name + "() { [native code] }"); try { Object.defineProperty(fn, "name", { value: name, configurable: true }); } catch(_){ } return fn; }' +
    'function def(o, k, v){ Object.defineProperty(o, k, { value: v, writable: true, enumerable: true, configurable: true }); }' +
    'var loadTimes = nat(function(){ var t = performance.timing || {}; var ns = (t.navigationStart || Date.now()) / 1000;' +
    '  return { requestTime: ns, startLoadTime: ns, commitLoadTime: (t.responseStart || t.navigationStart || 0) / 1000, finishDocumentLoadTime: (t.domContentLoadedEventEnd || 0) / 1000,' +
    '  finishLoadTime: (t.loadEventEnd || 0) / 1000, firstPaintTime: (t.domContentLoadedEventEnd || t.navigationStart || 0) / 1000, firstPaintAfterLoadTime: 0, navigationType: "Other",' +
    '  wasFetchedViaSpdy: true, wasNpnNegotiated: true, npnNegotiatedProtocol: "h2", wasAlternateProtocolAvailable: false, connectionInfo: "h2" }; }, "loadTimes");' +
    'var csi = nat(function(){ var t = performance.timing || {}; return { onloadT: t.domContentLoadedEventEnd || 0, startE: t.navigationStart || 0, pageT: Date.now() - (t.navigationStart || Date.now()), tran: 15 }; }, "csi");' +
    'var app = { isInstalled: false, InstallState: { DISABLED: "disabled", INSTALLED: "installed", NOT_INSTALLED: "not_installed" }, RunningState: { CANNOT_RUN: "cannot_run", READY_TO_RUN: "ready_to_run", RUNNING: "running" } };' +
    'app.getDetails = nat(function(){ return null; }, "getDetails"); app.getIsInstalled = nat(function(){ return false; }, "getIsInstalled");' +
    'app.installState = nat(function(cb){ if (typeof cb === "function") cb("not_installed"); }, "installState"); app.runningState = nat(function(){ return "cannot_run"; }, "runningState");' +
    'def(c, "loadTimes", loadTimes); def(c, "csi", csi); def(c, "app", app);' +
    'MAP.set(patched, TS.call(TS));' +
    'Object.defineProperty(Function.prototype, "toString", { value: patched, writable: true, configurable: true, enumerable: false });' +
    '} catch (_) { } })();';
}

module.exports = {
  buildChromeObjectScript, buildHookScript, HOOKS, verifyScript };

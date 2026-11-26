/**
 * NanoDesk — Bloqueador de pop-ups ESTRTITO (1.8.8)
 * ==================================================================
 * Inspiração: schomery/popup-blocker (MPL-2.0; correção de licença na
 * auditoria de 2026-11-26 — ver THIRD_PARTY_NOTICES.md). NENHUM código é
 * copiado — o conceito (interceptar window.open, HTMLAnchorElement.click,
 * HTMLFormElement.submit e iframes) é reimplementado como script
 * injetado no mundo principal da página.
 *
 * DIFERENÇA CRÍTICA do popup-blocker.js (que fica no processo principal
 * e usa o setWindowOpenHandler do Electron): ESTE módulo é INJETADO na
 * página, interceptando TODAS as APIs que abrem janelas — incluindo
 * as que o Electron deixa passar porque vieram COM gesto do usuário.
 * O modo "ESTRTITO" bloqueia TODOS os pop-ups, COM OU SEM gesto,
 * exceto same-origin e about:blank (exceções necessárias para o
 * funcionamento de qualquer site legítimo).
 *
 * O main.js decide quando injetar (setting `popupBlockerStrict`).
 *
 * Núcleo puro: monta o script — testável sem Electron.
 */
'use strict';

const MAX_SCRIPT_BYTES = 24 * 1024;

/**
 * Script injetável (mundo principal, idempotente).
 * @param {object} opts { aggressive?: boolean }
 *   aggressive = true → bloqueia até same-origin em alguns casos
 *   (ex.: window.open about:blank forçado por rastreador).
 * 100% em try/catch: falha nunca quebra a página.
 * (puro) — Devolve a string JS pronta para executeJavaScript.
 */
function buildScript(opts) {
  const aggressive = !!(opts && opts.aggressive);
  const script = String.raw`
(function () {
  if (window.__nanodeskPopupBlockerStrict) return;
  window.__nanodeskPopupBlockerStrict = 1;
  var AGGRESSIVE = ${aggressive ? 'true' : 'false'};
  function host(u) {
    try { return new URL(u, location.href).hostname.toLowerCase(); }
    catch (_) { return ''; }
  }
  function sameOrigin(u) {
    try {
      var parsed = new URL(u, location.href);
      // about:blank e srcdoc herdam a origem de quem os cria
      if (parsed.protocol === 'about:' || parsed.protocol === 'javascript:') return !AGGRESSIVE;
      if (parsed.protocol === 'blob:') return true;
      return parsed.origin === location.origin;
    } catch (_) { return false; }
  }
  function blocked(reason, url) {
    try { document.dispatchEvent(new CustomEvent('nd-popup-blocked', { detail: { reason: reason, url: String(url || '').slice(0, 240) } })); } catch (_) {}
  }
  // 1) window.open — BLOQUEIA TUDO, mesmo com user gesture.
  //    Exceção: same-origin / about:blank / blob: (necessário para app legit).
  var nativeOpen = window.open;
  try {
    Object.defineProperty(window, 'open', {
      configurable: true,
      writable: true,
      value: function (url, name, features) {
        var s = String(url || '');
        if (s === '' || s === 'about:blank' || /^javascript:/i.test(s)) {
          // site legit às vezes chama window.open() sem URL para obter uma referência —
          // devolvemos null em modo agressivo; no padrão permitimos só se same-origin implícito
          if (AGGRESSIVE) { blocked('empty', s); return null; }
          return nativeOpen ? nativeOpen.call(window, 'about:blank', name || '', features || '') : null;
        }
        if (sameOrigin(s)) {
          // same-origin: deixa o Electron decidir (setWindowOpenHandler vira aba interna)
          return nativeOpen ? nativeOpen.call(window, s, name || '', features || '') : null;
        }
        blocked('cross-origin', s);
        return null;
      }
    });
  } catch (_) {}
  // 2) HTMLAnchorElement.click() com target=_blank — bloqueia se cross-origin
  try {
    var proto = HTMLAnchorElement.prototype;
    var nativeClick = proto.click;
    proto.click = function () {
      try {
        if (this && this.target && /_blank/i.test(this.target) && this.href && !sameOrigin(this.href)) {
          blocked('anchor-click', this.href);
          return;
        }
      } catch (_) {}
      return nativeClick.apply(this, arguments);
    };
  } catch (_) {}
  // 3) HTMLFormElement.submit() com target=_blank — bloqueia se cross-origin
  try {
    var fproto = HTMLFormElement.prototype;
    var nativeSubmit = fproto.submit;
    fproto.submit = function () {
      try {
        if (this && this.target && /_blank/i.test(this.target) && this.action && !sameOrigin(this.action)) {
          blocked('form-submit', this.action);
          return;
        }
      } catch (_) {}
      return nativeSubmit.apply(this, arguments);
    };
  } catch (_) {}
  // 4) iframes de origem cruzada ocultos (tamanho 0/1px) — bloqueia o carregamento
  try {
    var iframeCreate = document.createElement;
    document.createElement = function (tag) {
      var el = iframeCreate.apply(document, arguments);
      try {
        if (String(tag || '').toLowerCase() === 'iframe') {
          var orig = el.setAttribute ? el.setAttribute.bind(el) : null;
          if (orig) {
            el.setAttribute = function (name, value) {
              if (name === 'src' && value && !sameOrigin(value) &&
                  (el.width === 0 || el.height === 0 || el.style.display === 'none')) {
                blocked('hidden-iframe', value);
                return;
              }
              return orig(name, value);
            };
          }
        }
      } catch (_) {}
      return el;
    };
  } catch (_) {}
  // 5) document.createElement('a').click() com href externo + target _blank — pega
  //    redirecionadores "synthetic click". Já coberto por #2 (proto hook).
  // 6) dispatchEvent em anchors — intercepta clicks sinteticos
  try {
    var nativeDispatch = HTMLAnchorElement.prototype.dispatchEvent;
    HTMLAnchorElement.prototype.dispatchEvent = function (ev) {
      try {
        if (ev && ['click','auxclick','dblclick'].indexOf(ev.type) !== -1 &&
            this.target && /_blank/i.test(this.target) && this.href && !sameOrigin(this.href)) {
          blocked('anchor-dispatch', this.href);
          return false;
        }
      } catch (_) {}
      return nativeDispatch.apply(this, arguments);
    };
  } catch (_) {}
  // 7) MutationObserver para iframes dinamicos com javascript:/data: src
  //    (1.8.10: AGGRESSIVE e boolean — o teste antigo "AGGRESSIVE > 2"
  //     nunca disparava; agora observa sempre que AGGRESSIVE estiver ligado)
  if (AGGRESSIVE) {
    try {
      var checkFrame = function (el) {
        try {
          if (!el || !el.tagName) return;
          if (el.tagName.toUpperCase() !== 'IFRAME' && el.tagName.toUpperCase() !== 'FRAME') return;
          var src = (el.src || '').toLowerCase();
          if (src.indexOf('javascript:') === 0 || src.indexOf('data:') === 0) {
            blocked('dynamic-iframe', src);
            el.remove();
          }
        } catch (_) {}
      };
      new MutationObserver(function (ms) {
        for (var i = 0; i < ms.length; i++) {
          var nodes = ms[i].addedNodes;
          for (var j = 0; j < nodes.length; j++) {
            var n = nodes[j];
            checkFrame(n);
            if (n.querySelectorAll) {
              var frames = n.querySelectorAll('frame,iframe');
              for (var k = 0; k < frames.length; k++) checkFrame(frames[k]);
            }
          }
        }
      }).observe(document, { childList: true, subtree: true });
    } catch (_) {}
  }
})();
`;
  const ok = script.includes('__nanodeskPopupBlockerStrict') &&
             script.includes('window.open') &&
             script.includes('HTMLAnchorElement.prototype') &&
             script.includes('HTMLFormElement.prototype') &&
             Buffer.byteLength(script) <= MAX_SCRIPT_BYTES;
  return ok ? script.trim() : '';
}

module.exports = { buildScript, MAX_SCRIPT_BYTES };

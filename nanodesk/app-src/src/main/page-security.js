/**
 * NanoDesk — Segurança de página injetada (1.8.8)
 * ==================================================================
 * Script injetado no mundo principal da página que detecta (e avisa):
 *  - miners de criptomoeda (Coinhive, Crypto-Loot, JSEcoin, etc.)
 *    pela presença de workers + assinaturas de código;
 *  - iframes ocultos (1x1, offscreen, visibility:hidden) — phishing;
 *  - campos de senha em páginas HTTP (não HTTPS) — phishing MITM;
 *  - auto-download de executáveis (.exe/.scr/.bat/.vbs/.hta) sem gesto.
 *
 * Núcleo puro: monta o script — testável sem Electron.
 * O main.js recebe os eventos via CustomEvent 'nd-page-security'.
 */
'use strict';

const MAX_SCRIPT_BYTES = 28 * 1024;

/**
 * Script injetável (mundo principal, idempotente).
 * 100% em try/catch: falha nunca quebra a página.
 * (puro) — Devolve a string JS pronta para executeJavaScript.
 */
function buildScript() {
  const script = String.raw`
(function () {
  if (window.__nanodeskPageSecurity) return;
  window.__nanodeskPageSecurity = 1;
  function notify(kind, detail) {
    try { document.dispatchEvent(new CustomEvent('nd-page-security', { detail: { kind: kind, detail: String(detail || '').slice(0, 240), url: location.href } })); }
    catch (_) {}
  }
  // 1) Miners de criptomoeda — assinaturas de script/worker
  var MINER_RX = /coinhive|coin-hive|crypto-loot|cryptoloot|jsecoin|coinerra|mineralt|webminerpool|deepminer|coinimp|crypto-webminer|coinhave|projectpoi|nextcore|adless\.io/i;
  function scanForMiners() {
    try {
      var scripts = document.querySelectorAll('script[src]');
      for (var i = 0; i < scripts.length; i++) {
        var s = scripts[i];
        if (MINER_RX.test(s.src || '') || MINER_RX.test(s.textContent || '')) {
          notify('crypto-miner', 'script: ' + String(s.src || '').slice(0, 120));
          try { s.remove(); } catch (_) {}
        }
      }
      // Worker Construtor hookado
      var NativeWorker = window.Worker;
      if (NativeWorker) {
        try {
          Object.defineProperty(window, 'Worker', {
            configurable: true, writable: true,
            value: function (src, opts) {
              var str = String(typeof src === 'string' ? src : (src && src.url || ''));
              if (MINER_RX.test(str)) {
                notify('crypto-miner', 'worker: ' + str.slice(0, 120));
                throw new Error('NanoDesk: miner blocked');
              }
              // CRLF detect: blob: data: workers com texto grande suspeito
              return new NativeWorker(src, opts);
            }
          });
        } catch (_) {}
      }
    } catch (_) {}
  }
  // 2) iframes ocultos (1x1, display:none, position:absolute offscreen)
  function scanHiddenIframes() {
    try {
      var ifrs = document.querySelectorAll('iframe');
      for (var i = 0; i < ifrs.length; i++) {
        var f = ifrs[i];
        var w = f.offsetWidth || 0, h = f.offsetHeight || 0;
        var style = window.getComputedStyle(f);
        var hidden = (w <= 1 && h <= 1) ||
                     style.display === 'none' ||
                     style.visibility === 'hidden' ||
                     style.opacity === '0' ||
                     (parseInt(style.left, 10) < -9999 || parseInt(style.top, 10) < -9999);
        if (hidden && f.src && /^https?:\/\//i.test(f.src)) {
          notify('hidden-iframe', f.src.slice(0, 200));
        }
      }
    } catch (_) {}
  }
  // 3) senha em HTTP (phishing MITM) — somente mainFrame
  function scanHttpPassword() {
    try {
      if (location.protocol !== 'http:') return;
      var pwds = document.querySelectorAll('input[type="password"]');
      if (pwds.length) {
        notify('http-password', location.host + ' (' + pwds.length + ' campo(s) de senha em HTTP)');
      }
    } catch (_) {}
  }
  // 4) auto-download de executáveis sem gesto do usuário
  var lastInput = 0;
  try {
    ['mousedown','mouseup','keydown','touchstart'].forEach(function (ev) {
      document.addEventListener(ev, function () { lastInput = Date.now(); }, true);
    });
  } catch (_) {}
  var RISKY_DL_RX = /\.(exe|scr|bat|cmd|vbs|js|jse|wsf|hta|msi|jar|ps1|lnk|com|pif)(?:$|\?)/i;
  try {
    var origAnchorClick = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function () {
      try {
        if (this && this.href && RISKY_DL_RX.test(this.href) && (Date.now() - lastInput) > 3000) {
          notify('auto-download', this.href.slice(0, 200));
          return;
        }
      } catch (_) {}
      return origAnchorClick.apply(this, arguments);
    };
  } catch (_) {}
  // 5) executa as varreduras em momentos espaçados (protege contra injeção tardia)
  function runAll() {
    scanForMiners();
    scanHiddenIframes();
    scanHttpPassword();
  }
  runAll();
  setTimeout(runAll, 1200);
  setTimeout(runAll, 4000);
  try {
    var obs = new MutationObserver(function () { scanHiddenIframes(); });
    obs.observe(document.documentElement || document.body, { childList: true, subtree: true });
  } catch (_) {}
})();
`;
  const ok = script.includes('__nanodeskPageSecurity') &&
             script.includes('crypto-miner') &&
             script.includes('hidden-iframe') &&
             script.includes('http-password') &&
             script.includes('auto-download') &&
             Buffer.byteLength(script) <= MAX_SCRIPT_BYTES;
  return ok ? script.trim() : '';
}

module.exports = { buildScript, MAX_SCRIPT_BYTES };

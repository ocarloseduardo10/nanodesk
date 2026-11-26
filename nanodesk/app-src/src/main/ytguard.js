/**
 * NanoDesk — Guardião do YouTube (1.8.8)
 * ==================================================================
 * LINHA DE DEFESA DETERMINÍSTICA contra o anti-adblock do YouTube
 * (a tela "Está enfrentando interrupções?" + recarregamento em loop).
 *
 * 1.8.8: REESCRITO COMPLETAMENTE. O YouTube mudou a detecção — agora
 * usa serverContract, attestationRequest, onAbnormalityDetected,
 * Map.prototype.has('onSnackbarMessage'), Array.push(Uint8Array 104/105)
 * e MutationObserver no snackbar. O ytguard anterior só fazia json-prune
 * básico — não era suficiente. Agora cobre TODOS os vetores:
 *  1. json-prune (adPlacements, adSlots, playerAds, adBreaks)
 *  2. replace adPlacements→no_ads, adSlots→no_ads nas respostas
 *  3. Neutralizar onAbnormalityDetected (Promise.prototype.then proxy)
 *  4. Remover snackbar "Está enfrentando interrupções?" via MutationObserver
 *  5. Intercept Map.prototype.has('onSnackbarMessage')
 *  6. Intercept Array.push(Uint8Array 104/105 bytes) — sinal de adblock
 *  7. Remover player-unavailable attribute periodicamente
 */
'use strict';

const YT_GUARD_HOSTS = [
  'youtube.com', 'www.youtube.com', 'm.youtube.com',
  'music.youtube.com', 'youtube-nocookie.com', 'www.youtube-nocookie.com'
];

function isYoutubeGuardHost(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h) return false;
  return YT_GUARD_HOSTS.some(d => h === d || h.endsWith('.' + d));
}

const CORE = String.raw`
(function () {
  if (window.__nanodeskYtGuard) return;
  window.__nanodeskYtGuard = 1;
  var KEYS = ['adPlacements', 'adSlots', 'playerAds', 'adBreaks', 'adBreakHeartbeatParams'];
  function prune(o, depth) {
    try {
      if (!o || typeof o !== 'object' || (depth | 0) > 3) return o;
      for (var i = 0; i < KEYS.length; i++) {
        if (KEYS[i] in o) { try { delete o[KEYS[i]]; } catch (_) {} }
      }
      if (o.playerResponse) prune(o.playerResponse, depth + 1);
      var up = o.unserializedPrefetchData;
      if (up && up.playerResponse) prune(up.playerResponse, depth + 1);
    } catch (_) {}
    return o;
  }
  function isPlayerUrl(u) {
    return typeof u === 'string' &&
      /\/youtubei\/v1\/(?:player|next|resolve_url|get_watch)\?|\/player(?:\?.+)?$|\/playlist\?list=/.test(u);
  }
  function pruneText(t) {
    try { var v = JSON.parse(t); prune(v, 0); return JSON.stringify(v); }
    catch (_) { return t; }
  }
  function replaceAdKeys(t) {
    try { return t.replace(/"adPlacements"/g, '"no_ads"').replace(/"adSlots"/g, '"no_ads"'); }
    catch (_) { return t; }
  }

  // 1) ytInitialPlayerResponse — prune na variavel global
  try {
    var _ipr;
    Object.defineProperty(window, 'ytInitialPlayerResponse', {
      configurable: true,
      get: function () { return _ipr; },
      set: function (v) { _ipr = prune(v, 0); }
    });
  } catch (_) {}

  // 2) fetch — prune + replace adPlacements/adSlots
  try {
    var _fetch = window.fetch;
    if (typeof _fetch === 'function') {
      window.fetch = function () {
        var args = arguments;
        try {
          var input = args[0];
          var url = typeof input === 'string' ? input : (input && input.url) || '';
          var p = _fetch.apply(this, args);
          if (!isPlayerUrl(url)) return p;
          return p.then(function (res) {
            try {
              if (!res || typeof res.clone !== 'function' || typeof res.text !== 'function') return res;
              return res.clone().text().then(function (txt) {
                var modified = replaceAdKeys(pruneText(txt));
                return new Response(modified, { status: res.status, statusText: res.statusText, headers: res.headers });
              }).catch(function () { return res; });
            } catch (_) { return res; }
          });
        } catch (_) { return _fetch.apply(this, args); }
      };
    }
  } catch (_) {}

  // 3) XHR — prune + replace
  try {
    var X = XMLHttpRequest.prototype;
    var _open = X.open, _send = X.send;
    var dText = Object.getOwnPropertyDescriptor(X, 'responseText');
    var dResp = Object.getOwnPropertyDescriptor(X, 'response');
    X.open = function (m, u) { try { this.__ndUrl = u; } catch (_) {} return _open.apply(this, arguments); };
    X.send = function () {
      var xhr = this;
      try {
        if (!xhr.__ndHooked && isPlayerUrl(xhr.__ndUrl)) {
          xhr.__ndHooked = true;
          Object.defineProperty(xhr, 'responseText', {
            configurable: true,
            get: function () {
              try { return replaceAdKeys(pruneText(dText.get.call(xhr))); }
              catch (_) { try { return dText.get.call(xhr); } catch (_) { return ''; } }
            }
          });
          Object.defineProperty(xhr, 'response', {
            configurable: true,
            get: function () {
              try {
                var v = dResp.get.call(xhr);
                if ((xhr.responseType === '' || xhr.responseType === 'text') && typeof v === 'string') return replaceAdKeys(pruneText(v));
                if (xhr.responseType === 'json' && v && typeof v === 'object') return prune(v, 0);
                return v;
              } catch (_) { try { return dResp.get.call(xhr); } catch (_) { return undefined; } }
            }
          });
        }
      } catch (_) {}
      return _send.apply(this, arguments);
    };
  } catch (_) {}

  // 4) NEUTRALIZAR onAbnormalityDetected — Promise.prototype.then proxy
  try {
    var origThen = window.Promise.prototype.then;
    window.Promise.prototype.then = new Proxy(origThen, {
      apply: function (target, self, args) {
        try {
          var fn = args[0];
          if (typeof fn === 'function' && fn.toString().indexOf('onAbnormalityDetected') !== -1) {
            args[0] = function () {};
          }
        } catch (_) {}
        return Reflect.apply(target, self, args);
      }
    });
  } catch (_) {}

  // 5) REMOVER snackbar "Está enfrentando interrupções?" + tela de erro do player
  try {
    var obs = new MutationObserver(function () {
      try {
        var snack = document.querySelector('.ytSnackbarContainerOpened, ytd-notification-action-renderer');
        if (snack && /interrup|facing interruptions|adblock|ad blocker| Est\u00e1 enfrentando/i.test(snack.textContent || '')) {
          snack.remove();
        }
        var err = document.querySelector('#player-error-message-container, ytd-playability-error-supported-renderers');
        if (err && /interrup|adblock|Est\u00e1 enfrentando/i.test(err.textContent || '')) {
          var wf = document.querySelector('ytd-watch-flexy');
          if (wf) wf.removeAttribute && wf.removeAttribute('player-unavailable');
          err.remove();
        }
      } catch (_) {}
    });
    if (document.body) obs.observe(document.body, { childList: true, subtree: true });
    else document.addEventListener('DOMContentLoaded', function () { obs.observe(document.body, { childList: true, subtree: true }); });
  } catch (_) {}

  // 6) Intercept Map.prototype.has('onSnackbarMessage')
  try {
    var origHas = window.Map.prototype.has;
    window.Map.prototype.has = new Proxy(origHas, {
      apply: function (target, self, args) {
        try { if (args[0] === 'onSnackbarMessage') return true; } catch (_) {}
        return Reflect.apply(target, self, args);
      }
    });
  } catch (_) {}

  // 7) Intercept Array.push(Uint8Array 104/105) — sinal de adblock detectado
  try {
    var origPush = window.Array.prototype.push;
    window.Array.prototype.push = new Proxy(origPush, {
      apply: function (target, self, args) {
        try {
          var o = args[0];
          if (o && typeof o === 'object' && o.constructor && o.constructor.name === 'Uint8Array' &&
              o.buffer && o.buffer.byteLength === o.length && (o.length === 104 || o.length === 105)) {
            return 0;
          }
        } catch (_) {}
        return Reflect.apply(target, self, args);
      }
    });
  } catch (_) {}

  // 8) Remover player-unavailable periodicamente
  try {
    setInterval(function () {
      try {
        var wf = document.querySelector('ytd-watch-flexy[player-unavailable]');
        if (wf) {
          var err = wf.querySelector('#player-error-message-container');
          if (err && /interrup|adblock|Est\u00e1 enfrentando/i.test(err.textContent || '')) {
            wf.removeAttribute('player-unavailable');
            err.remove();
          }
        }
      } catch (_) {}
    }, 2000);
  } catch (_) {}
})();
`;

const MARKERS = [
  '__nanodeskYtGuard',
  'ytInitialPlayerResponse',
  'adPlacements',
  'XMLHttpRequest.prototype',
  'onAbnormalityDetected',
  'onSnackbarMessage',
  'player-unavailable',
  'MutationObserver'
];

const MAX_SCRIPT_BYTES = 24 * 1024;

let _script = null;

function buildScript() {
  if (_script !== null) return _script;
  try {
    const s = CORE.trim();
    const ok = MARKERS.every(m => s.includes(m)) && Buffer.byteLength(s) <= MAX_SCRIPT_BYTES;
    _script = ok ? s : '';
  } catch (_) {
    _script = '';
  }
  return _script;
}

function describe() {
  return {
    id: 'nanodesk-ytguard',
    hosts: YT_GUARD_HOSTS.slice(),
    bytes: Buffer.byteLength(buildScript()),
    note: 'Anti-adblock COMPLETO do YouTube: json-prune + replace adPlacements/adSlots + neutralizar onAbnormalityDetected + remover snackbar + intercept Map.has/Array.push + remover player-unavailable.'
  };
}

module.exports = { YT_GUARD_HOSTS, isYoutubeGuardHost, buildScript, describe, MARKERS };

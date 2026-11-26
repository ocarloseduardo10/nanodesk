/**
 * NanoDesk — PopUpOFF nativo (1.9.6-e)
 * ==================================================================
 * Porta da LÓGICA do PopUpOFF v2.1.3 (RomanistHere/PopUpOFF, licença
 * Apache-2.0; correção de licença na auditoria de 2026-11-26 — ver
 * THIRD_PARTY_NOTICES.md). NENHUM código é copiado verbatim — as heurísticas (modos,
 * limites de área, listas de palavras e a whitelist embutida) foram
 * reimplementadas a partir do repositório para rodar como script
 * injetado no mundo principal da página, sem chrome.* (a extensão
 * depende de popup/action/storage que não existem no Electron).
 *
 * O que faz (como a extensão):
 *   - hard ("Agressivo"): esconde TODO elemento position:fixed/sticky
 *     visível — é o que mata modais anti-bloqueador como o do globo
 *     (Funding Choices, fc-ab-root), banners de cookie e overlays.
 *   - easy ("Moderado"): só remove overlays grandes (>=10% da tela),
 *     banners de notificação e elementos com conteúdo típico de
 *     cookie/bloqueador/newsletter (forbWordsEasy), preservando
 *     cabeçalhos fixos e barras laterais (heurística positionCheck).
 *   - delicate ("Delicado"): converte fixos em estáticos em vez de
 *     esconder (páginas onde se quer ler conteúdo atrás de fixos).
 *   - whitelist: hosts onde a extensão não age (Google, YouTube,
 *     WhatsApp, bancos de loja etc. — portado de constants/data.js).
 *
 * ADAPTAÇÕES para o NanoDesk:
 *   - a decisão de modo é por HOST no processo principal (modeForHost),
 *     não por chrome.storage; a injeção é uma vez por frame principal
 *     (bundle nd:frame-init, ANTES dos scripts da página) — quando o
 *     <body> ainda não existe, a varredura inicial espera o
 *     DOMContentLoaded e o MutationObserver cobre todo o resto;
 *   - sem estatísticas e sem a notificação visual da extensão;
 *   - o modo "restaurar conteúdo" (findHidden/unhide, opt-in por site
 *     na extensão) não é exposto nesta rodada (fica como código morto
 *     fiel, desligado) — o comportamento padrão da extensão não muda.
 *
 * O main.js decide quando injetar (setting `overlayBlockerMode`:
 * off | delicate | easy | hard, padrão hard).
 *
 * Núcleo puro: monta o script — testável sem Electron.
 */
'use strict';

const MAX_SCRIPT_BYTES = 32 * 1024;
const VALID_MODES = new Set(['off', 'delicate', 'easy', 'hard']);

/**
 * Whitelist portada do PopUpOFF (constants/data.js, defWebsites):
 * sites que usam position:fixed de forma legítima/essencial (apps,
 * players, e-commerce) — o bloqueador NÃO age neles. Entradas
 * "localhost:PORTA" viram "localhost" (portas variam no NanoDesk).
 */
const POPUP_WHITELIST = new Set([
  'a.goodtime.io', 'about.google', 'app.hubspot.com', 'cal.mixmax.com',
  'calendar.google.com', 'catalog.onliner.by', 'cloud.google.com',
  'discord.com', 'docs.google.com', 'drive.google.com', 'e-dostavka.by',
  'hangouts.google.com', 'mail.google.com', 'music.yandex.com',
  'music.yandex.ru', 'music.youtube.com', 'open.spotify.com',
  'romanisthere.github.io', 'support.google.com', 'trello.com',
  'twitter.com', 'vk.com', 'vk.ru', 'web.telegram.org',
  'www.amazon.co.uk', 'www.amazon.com', 'www.baidu.com', 'www.bing.com',
  'www.facebook.com', 'www.google.com', 'www.inspera.com',
  'www.instagram.com', 'www.linkedin.com', 'www.netflix.com',
  'www.onliner.by', 'www.pinterest.com', 'www.reddit.com',
  'www.spotify.com', 'www.walmart.com', 'www.youtube.com', 'zoom.us',
  'store.steampowered.com', 'www.hackerrank.com', 'www.coursera.org',
  'azure.microsoft.com', 'store.google.com', 'www.oneplus.com',
  'smallpdf.com', 'www.upwork.com', 'www.docusign.com',
  'account.docusign.com', 'go.docusign.com', 'app.docusign.com',
  'app.hellosign.com', 'www.oysho.com', 'www.zara.com', 'www.nike.com',
  'www.adidas.com', 'www.adidas.co.uk', 'www.reebok.co.uk',
  'www.reebok.com', 'www.newbalance.com', 'www.newbalance.co.uk',
  'eu.puma.com', 'us.puma.com', 'www.lacoste.com', 'www.armani.com',
  'www.hugoboss.com', 'www.calvinklein.co.uk', 'www.calvinklein.de',
  'www.victoriassecret.com', 'l.macys.com', 'www.jcpenney.com',
  'www.dillards.com', 'oldnavy.gap.com', 'www.gap.co.uk', 'www.gap.com',
  'www2.hm.com', 'www.hm.com', 'www.childrensplace.com', 'www.carters.com',
  'www.zarahome.com', 'www.ebay.co.uk', 'www.ebay.com', 'www.target.com',
  'www.bestbuy.com', 'www.costco.com', 'www.lowes.com',
  'www.homedepot.com', 'www.walgreens.com', 'www.samsclub.com',
  'www.kohls.com', 'www.ae.com', 'www.forever21.com', 'www.lasenza.com',
  'www.bathandbodyworks.com', 'www.levi.com', 'eu.wrangler.com',
  'www.wrangler.com', 'www.massimodutti.com', 'uk.tommy.com',
  'www.pullandbear.com', 'shop.mango.com', 'www.c-and-a.com',
  'www.bershka.com', 'www.stradivarius.com', 'www.guess.eu',
  'www.guess.com', 'www.dolcegabbana.com', 'www.gucci.com',
  'www.prada.com', 'www.louisvuitton.com', 'www.armaniexchange.com',
  'www.dior.com', 'www.ralphlauren.co.uk', 'www.ralphlauren.com',
  'www.samsung.com', 'www.huawei.com', 'consumer.huawei.com',
  'www.motorola.com', 'www.motorola.co.uk', 'www.sony.net',
  'www.panasonic.com', 'www.lenovo.com', 'www.siemens.com',
  'www.bosch.com', 'www.sony.co.uk', 'www.sony.com', 'www.asus.com',
  'www.mi.com', 'www.apple.com', 'www.lg.com', 'www.realme.com',
  'www.vivo.com', 'lolesports.com', 'aliexpress.ru',
  'www.aliexpress.com', 'whatsapp.com', 'www.twitch.tv',
  'www.fandom.com', 'www.microsoft.com', 'localhost',
  // "moderate by default" na extensão — portado como whitelist de easy:
  // nessas redações a extensão usa o modo moderado mesmo no auto.
  'www.economist.com', 'www.reviewjournal.com', 'www.bostonglobe.com',
  'www.theguardian.com', 'www.theladders.com'
]);

function normalizeHost(hostname) {
  let h = String(hostname || '').toLowerCase().trim();
  if (!h) return '';
  h = h.replace(/\.+$/, '');
  if (h.startsWith('www.')) h = h.slice(4);
  return h;
}

function whitelisted(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/\.+$/, '');
  if (!h) return false;
  const hostPart = h.split(':')[0];                    // host:porta -> host
  const bare = normalizeHost(hostPart);                // tira www. do host
  for (const entry of POPUP_WHITELIST) {
    const entryBare = normalizeHost(entry);            // tira www./porta da entrada
    if (hostPart === entry || bare === entryBare) return true;
    // subdomínio de um host da lista (extensão casa exato; aqui o
    // sufixo evita buracos como m.google.com sem abrir para TLD alheios)
    if (bare.endsWith('.' + entryBare) || hostPart.endsWith('.' + entry)) return true;
  }
  return false;
}

/**
 * (puro) Modo efetivo para um host. 'whitelist' = não injetar;
 * 'off' = setting desligado; inválido cai no padrão (hard).
 */
function modeForHost(hostname, settings) {
  const mode = settings && typeof settings.get === 'function'
    ? String(settings.get('overlayBlockerMode', 'hard') || 'hard').toLowerCase()
    : 'hard';
  if (!VALID_MODES.has(mode) || mode === 'off') return mode === 'off' ? 'off' : 'hard';
  if (whitelisted(hostname)) return 'whitelist';
  return mode;
}

/**
 * Script injetável (mundo principal, top-frame, idempotente).
 * Porta dos helpers.js + modes.js + setup.js (initMode) — sem
 * chrome.*, sem stats, sem notificação, sem troca de modo em página.
 * 100% em try/catch: falha nunca quebra a página.
 */
function buildScript(mode) {
  if (!VALID_MODES.has(mode) || mode === 'off') return '';
  const script = `
(function () {
  if (window.__nanodeskPopUpOFF) return;
  if (window !== window.parent) return;   // só o frame principal (igual à extensão)
  window.__nanodeskPopUpOFF = 1;
  var MODE = '${mode}';

  try {
  /* ---------- helpers (helpers.js) ---------- */
  /* ADAPTAÇÃO document_start: documentElement pode ainda não existir —
   * resolve SEMPRE na hora do uso, nunca na carga do script. */
  var getDoc = function () { return document.documentElement; };
  var getStyle = function (elem, property) {
    try { return window.getComputedStyle(elem, null).getPropertyValue(property); }
    catch (e) { return ''; }
  };
  var setPropImp = function (elem, prop, val) {
    try { elem.style.setProperty(prop, val, 'important'); } catch (e) {}
  };
  var roundToTwo = function (num) { return +(Math.round(num + 'e+2') + 'e-2'); };
  var checkIsInArr = function (arr, item) { return arr.indexOf(item) !== -1; };
  var isDecentElem = function (element) {
    return !(element.nodeName === 'SCRIPT' || element.nodeName === 'HEAD' ||
             element.nodeName === 'BODY' || element.nodeName === 'HTML' ||
             element.nodeName === 'STYLE');
  };

  /* palavras proibidas — porta EXATA de forbWordsEasy (helpers.js) */
  var forbWordsEasy = [
    'cookie', 'privacy', 'adblock', 'ad block', 'blocker', 'ever miss',
    't miss', 'our privacy', 'theguardian', 'bloqueador de anuncios',
    'to continue us', 'mited acces', 'lusive acces', 'left this mon',
    'be the fir', 'ble notif', 's the time', 'ur newslet',
    'gister for fre', 'nload free', 'nload your free', 'gn to youtube',
    'ble deal', 'started for fre', "it's free", 'free trial',
    'tart fre', 'advertisement', '//consent.', 'ign in to youtub'
  ];
  var contentEasyCheck = function (element) {
    try {
      var textCont = String(element.innerHTML || '').toLowerCase();
      for (var i = 0; i < forbWordsEasy.length; i++) {
        if (textCont.indexOf(forbWordsEasy[i]) !== -1) return true;
      }
    } catch (e) {}
    return false;
  };

  /* contadores anti-laco (globals da extensao -> closure aqui) */
  var domObserver = null;
  var infiniteLoopPreventCounter = 0;
  var myTimer = 0;
  var wasNotStoped = true;
  var memoize = MODE === 'easy' ? new WeakMap() : null;

  var removeOverflow = function () {
    var doc = getDoc();
    var body = document.body;
    if (!doc || !body) return;
    var overFlowDoc = getStyle(doc, 'overflow-y');
    var overFlowBody = getStyle(body, 'overflow-y');
    var docPosStyle = getStyle(doc, 'position');
    var bodyPosStyle = getStyle(body, 'position');
    if (overFlowDoc !== 'visible' && overFlowDoc !== 'unset' && overFlowDoc !== 'auto')
      setPropImp(doc, 'overflow-y', 'unset');
    if (overFlowBody !== 'visible' && overFlowBody !== 'unset' && overFlowBody !== 'auto')
      setPropImp(body, 'overflow-y', 'unset');
    if (docPosStyle === 'fixed' || docPosStyle === 'absolute') {
      setPropImp(doc, 'min-height', '100vh');
      setPropImp(doc, 'position', 'relative');
    }
    if (bodyPosStyle === 'fixed' || bodyPosStyle === 'absolute') {
      setPropImp(body, 'position', 'relative');
      setPropImp(body, 'min-height', '100vh');
    }
  };

  /* site-specific da extensão (helpers.js removeListeners) */
  var removeListeners = function () {
    try {
      if (window.location.href.indexOf('glassdoor') !== -1) {
        window.addEventListener('scroll', function (e) { e.stopPropagation(); }, true);
      }
    } catch (e) {}
  };

  var checkToConvertToStatic = function (elem) {
    try {
      if (getStyle(elem, 'overflow') === 'hidden') {
        var rect = elem.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0 && rect.top === 0 && rect.left === 0) {
          setPropImp(elem, 'position', 'static');
          elem.setAttribute('data-popupoff', 'st');
          return true;
        }
      }
    } catch (e) {}
    return false;
  };

  /* videoCheck (helpers.js): overlay cobre a tela mas é um player em fullscreen */
  var videoCheck = function (element) {
    var nodeName = element.nodeName;
    var childNodes = element.childNodes;
    if (nodeName === 'APP-DRAWER') return false;
    var href = '';
    try { href = window.location.href; } catch (e) {}
    if (href.indexOf('www.youtube') !== -1 || href.indexOf('www.google') !== -1) return true;
    if (nodeName === 'VIDEO' || nodeName === 'IMG' || nodeName === 'FORM' ||
        nodeName === 'BUTTON' || nodeName === 'INPUT' || nodeName === 'IFRAME') return false;
    if (element.shadowRoot) return videoCheck(element.shadowRoot);
    if (element.contentDocument) return videoCheck(element.contentDocument);
    for (var i = 0; i < childNodes.length; i++) {
      if (childNodes[i].nodeType === 1 && !videoCheck(childNodes[i])) return false;
    }
    return true;
  };

  /* positionCheckTypeI (helpers.js): heurística do modo MODERADO */
  var positionCheck = function (element, windowArea) {
    if (element.offsetHeight === 0 || element.offsetWidth === 0)
      return { shouldRemove: true, shouldMemo: false };

    var layoutArea = element.offsetHeight * element.offsetWidth;
    var screenValue = roundToTwo(layoutArea / windowArea);
    var offsetBot = window.innerHeight - (element.offsetTop + element.offsetHeight);

    if (screenValue >= 0.98)
      return { shouldRemove: contentEasyCheck(element) || videoCheck(element), shouldMemo: true };

    if (element.offsetTop <= 100 && element.offsetHeight <= 250 && element.offsetWidth > 640) {
      if (element.id === 'onesignal-slidedown-container')
        return { shouldRemove: true, shouldMemo: true };
      return { shouldRemove: false, shouldMemo: true };   // é um cabeçalho!
    }
    if (element.offsetLeft <= 0 && element.offsetWidth <= 360 && screenValue >= 0.1)
      return { shouldRemove: false, shouldMemo: true };   // sidebar youtube/facebook
    if (screenValue < 0.98 && screenValue >= 0.1)
      return { shouldRemove: contentEasyCheck(element), shouldMemo: true };
    if (screenValue <= 0.02 && element.offsetTop > 100)
      return { shouldRemove: false, shouldMemo: true };
    if (offsetBot <= 212)
      return { shouldRemove: contentEasyCheck(element), shouldMemo: true };
    if (screenValue <= 0.1 && element.offsetTop > 100)
      return { shouldRemove: false, shouldMemo: true };
    return { shouldRemove: false, shouldMemo: false };
  };

  var additionalChecks = function (element, checkElem) {
    try {
      if (getStyle(element, 'filter') !== 'none' || getStyle(element, '-webkit-filter') !== 'none') {
        setPropImp(element, 'filter', 'none');
        setPropImp(element, '-webkit-filter', 'none');
      }
    } catch (e) {}
    if (element.shadowRoot) checkElemWithSibl(element.shadowRoot, checkElem);
  };

  var checkElemWithSibl = function (element, checkElem) {
    try {
      if (element instanceof HTMLElement) {
        checkElem(element);
        if (wasNotStoped) {
          var elems = element.querySelectorAll('*');
          checkElems(elems, checkElem);
        }
      } else if (element instanceof ShadowRoot) {
        var els = element.querySelectorAll('*');
        checkElems(els, checkElem);
      }
    } catch (e) {}
  };

  var checkElems = function (elems, checkElem) {
    var arr = [];
    for (var i = 0; i < elems.length; i++) arr.push(elems[i]);
    for (var j = 0; j < arr.length; j++) checkElem(arr[j]);
  };

  /* removeDomWatcher (helpers.js): observer desconectado -> rescan único após 2s */
  var removeDomWatcher = function (action) {
    try {
      if (domObserver) { domObserver.disconnect(); domObserver = null; }
      if (wasNotStoped) {
        setTimeout(function () {
          var body = document.body;
          if (!body) return;
          action(body.getElementsByTagName('*'));
        }, 2000);
      }
      wasNotStoped = false;
    } catch (e) {}
  };

  var makePrevLoop = function (threshold) {
    return function () {
      if (infiniteLoopPreventCounter > threshold) {
        return true;   // quem chama desconecta (removeDomWatcher)
      }
      infiniteLoopPreventCounter++;
      if (myTimer === 0) {
        myTimer = setTimeout(function () {
          infiniteLoopPreventCounter = 0;
          clearTimeout(myTimer);
          myTimer = 0;
        }, 1000);
      }
      return false;
    };
  };

  var checkMutation = function (mutation, checkElem) {
    if (mutation.target.nodeName === 'SCRIPT' || mutation.target.nodeName === 'HEAD' ||
        mutation.target.nodeName === 'STYLE') return;
    checkElemWithSibl(mutation.target, checkElem);
    var added = mutation.addedNodes;
    for (var i = 0; i < added.length; i++) {
      var element = added[i];
      if (element.nodeName !== '#text' && element.nodeName !== '#comment' &&
          element.nodeName !== 'SCRIPT' && element.nodeName !== 'HEAD' &&
          element.nodeName !== 'STYLE') {
        checkElemWithSibl(element, checkElem);
      }
    }
    removeOverflow();
  };

  var watchMutations = function (mutations, prevLoop, checkElem) {
    var processedElems = [];
    for (var i = 0; i < mutations.length; i++) {
      if (prevLoop()) { removeDomWatcher(currentAction); break; }
      var mutation = mutations[i];
      if (mutation.attributeName === 'data-popupoff') continue;
      var isProcessed = checkIsInArr(processedElems, mutation.target);
      if (isProcessed) continue;   // (original: vale para todos os modos sem restore)
      processedElems.push(mutation.target);
      checkMutation(mutation, checkElem);
    }
  };

  var watchDOM = function (prevLoop, checkElem) {
    if (!domObserver) {
      domObserver = new MutationObserver(function (mutations) {
        try { watchMutations(mutations, prevLoop, checkElem); } catch (e) {}
      });
    }
    try {
      var d = getDoc();
      if (d) domObserver.observe(d, { childList: true, subtree: true, attributes: true });
    } catch (e) {}
  };

  /* ---------- modos (modes.js) ---------- */
  var currentAction = null;

  var makeCheckElem = function (mode) {
    if (mode === 'hard') {
      return function checkElem(element) {
        if (!isDecentElem(element)) return;
        var elemPosStyle = getStyle(element, 'position');
        if (elemPosStyle === 'fixed' || elemPosStyle === 'sticky') {
          if (checkToConvertToStatic(element)) return;
          if (element.getAttribute('data-popupoff') === 'notification') return;
          if (getStyle(element, 'display') !== 'none')
            element.setAttribute('data-popupoff', 'bl');
          setPropImp(element, 'display', 'none');
        }
        additionalChecks(element, checkElem);
      };
    }
    if (mode === 'easy') {
      return function checkElem(element) {
        if (!isDecentElem(element)) return;
        var elemPosStyle = getStyle(element, 'position');
        if (elemPosStyle === 'fixed' || elemPosStyle === 'sticky') {
          if (checkToConvertToStatic(element)) return;
          if (element.getAttribute('data-popupoff') === 'notification') return;
          var memoized = memoize.has(element);
          var decision = memoized
            ? { shouldRemove: memoize.get(element), shouldMemo: false }
            : positionCheck(element, parseFloat(window.innerHeight * window.innerWidth));
          if (decision.shouldRemove) {
            if (getStyle(element, 'display') !== 'none')
              element.setAttribute('data-popupoff', 'bl');
            setPropImp(element, 'display', 'none');
          }
          if (!memoized && decision.shouldMemo) memoize.set(element, decision.shouldRemove);
        }
        additionalChecks(element, checkElem);
      };
    }
    /* delicate: converte fixed/sticky em estático (modes.js staticMode) */
    return function checkElem(element) {
      if (!isDecentElem(element)) return;
      var elemPosStyle = getStyle(element, 'position');
      if (elemPosStyle === 'fixed' || elemPosStyle === 'sticky') {
        if (element.getAttribute('data-popupoff') === 'notification') return;
        element.setAttribute('data-popupoff', 'st');
        setPropImp(element, 'position', 'relative');
      }
      additionalChecks(element, checkElem);
    };
  };

  var startMode = function (mode) {
    var checkElem = makeCheckElem(mode);
    var threshold = mode === 'hard' ? 1600 : (mode === 'easy' ? 1200 : 1500);
    var prevLoop = makePrevLoop(threshold);
    var action = function (elems) {
      removeOverflow();
      checkElems(elems, checkElem);
      removeListeners();
      watchDOM(prevLoop, checkElem);
    };
    currentAction = action;
    /* ADAPTAÇÃO: injeção ocorre ANTES dos scripts da página — o body pode
     * não existir ainda. Varredura inicial espera o DOM (uma vez); a partir
     * daí o MutationObserver cobre todo o resto (inclusive SPAs). */
    var run = function () {
      var body = document.body;
      if (!body) {
        document.addEventListener('DOMContentLoaded', function () {
          try { action(document.body.getElementsByTagName('*')); } catch (e) {}
        }, { once: true });
        return;
      }
      action(body.getElementsByTagName('*'));
    };
    run();
  };

  startMode(MODE);
  } catch (e) { /* PopUpOFF nunca pode quebrar a página */ }
})();
`;
  if (script.length > MAX_SCRIPT_BYTES) throw new Error('popup-off: script excede ' + MAX_SCRIPT_BYTES + ' bytes');
  return script;
}

module.exports = {
  buildScript, modeForHost, whitelisted,
  POPUP_WHITELIST, VALID_MODES, MAX_SCRIPT_BYTES
};

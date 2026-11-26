/**
 * NanoDesk — Consent-O-Matic nativo (1.7.0)
 * ==================================================================
 * Baseado no projeto Consent-O-Matic (github.com/cavi-au/Consent-O-Matic,
 * MPL-2.0, © Cavi-Au / Aarhus University). NENHUM código é copiado:
 * é uma implementação própria da MESMA IDEIA — responder popups de
 * consentimento de cookies SEMPRE NEGANDO rastreadores, escolhendo o
 * nível máximo de privacidade disponível no site.
 *
 * Estratégia em camadas (igual ao comportamento "Aggressive" da
 * extensão original):
 *  1) Botões diretos "Recusar tudo / Negar / Reject all" dos CMPs
 *     mais comuns (OneTrust, Cookiebot, Didomi, Quantcast,
 *     Sourcepoint, Usercentrics, Iubenda, CookieYes, Borlabs,
 *     Complianz, Klaro, Osano, Tarteaucitron, HubSpot, Moove,
 *     TrustArc, Termly, Cookie-Script);
 *  2) Busca universal por TEXTO em PT/EN/ES/FR/DE;
 *  3) Nível MÁXIMO: se só existir "Gerenciar/Preferências", abre,
 *     DESMARCA todas as permissões e salva.
 *
 * Roda no mundo principal de TODAS as frames http(s), com:
 *  - cooldown por site (localStorage, 24 h padrão) para não custar
 *    CPU em navegação repetida;
 *  - lista de sites onde NÃO interferir;
 *  - tudo em try/catch (nunca quebra a página).
 *
 * Núcleo puro (testável): níveis, cooldown, whitelist e o script
 * injetável (marcadores verificáveis).
 */
'use strict';

const MAX_SCRIPT_BYTES = 40 * 1024; // trava de segurança

const LEVELS = new Set(['max', 'smart']);

/** Normaliza o nível (puro). */
function normalizeLevel(v) {
  return LEVELS.has(v) ? v : 'max';
}

/** Chave de cooldown de um host (puro). */
function cooldownKey(host) {
  return 'nd_cm_' + String(host || '').toLowerCase().replace(/^www\./, '').slice(0, 120);
}

/** O host está na lista de exceções? (puro — um domínio por linha) */
function isWhitelisted(host, whitelist) {
  const h = String(host || '').toLowerCase();
  if (!h) return false;
  for (const raw of (Array.isArray(whitelist) ? whitelist : [])) {
    const d = String(raw || '').trim().toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
    if (!d) continue;
    if (h === d || h.endsWith('.' + d)) return true;
  }
  return false;
}

/** Sanitiza cooldown (horas) (puro). */
function normalizeCooldownHours(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return 24;
  return Math.round(Math.min(720, Math.max(1, n)));
}

/**
 * Script injetável (mundo principal, idempotente, todas as frames).
 * Avisa o processo principal por evento de DOM ("nd-cm-deny").
 */
function buildScript(opts) {
  const level = normalizeLevel(opts && opts.level);
  const cdHours = normalizeCooldownHours(opts && opts.cooldownHours);
  const whitelist = Array.isArray(opts && opts.whitelist) ? opts.whitelist : [];
  const script = String.raw`
(function () {
  if (window.__nanodeskConsentOMatic) return;
  window.__nanodeskConsentOMatic = 1;
  var LEVEL = ${JSON.stringify(level)};
  var CD_MS = ${cdHours} * 3600000;
  var WHITELIST = ${JSON.stringify(whitelist.map(x => String(x).toLowerCase()))};
  var KEY = 'nd_cm_' + String(location.hostname || '').toLowerCase().replace(/^www\./, '');

  function done() { finished = true; }
  try {
    var prev = Number(localStorage.getItem(KEY)) || 0;
    if (prev && Date.now() - prev < CD_MS) return;
  } catch (_) {}

  function denyEvent() {
    try { document.dispatchEvent(new CustomEvent('nd-cm-deny', { detail: {} })); } catch (_) {}
  }

  var SHADOW_HOSTS = ['#usercentrics-root', '#termly-code-snippet-support',
    '#cookiescript_injected', '#cmpwrapper', '#iubenda-cs-banner', '#shb-consent-privacy'];
  function q(sel) {
    var out = [];
    try { out = Array.prototype.slice.call(document.querySelectorAll(sel)); } catch (_) { out = []; }
    for (var i = 0; i < SHADOW_HOSTS.length; i++) {
      var h = document.querySelector(SHADOW_HOSTS[i]);
      if (h && h.shadowRoot) {
        try { out = out.concat(Array.prototype.slice.call(h.shadowRoot.querySelectorAll(sel))); } catch (_) {}
      }
    }
    return out;
  }
  function visible(el) {
    try {
      var r = el.getBoundingClientRect();
      if (r.width < 2 || r.height < 2) return false;
      var cs = getComputedStyle(el);
      return cs.display !== 'none' && cs.visibility !== 'hidden' && Number(cs.opacity) !== 0;
    } catch (_) { return false; }
  }
  function textOf(el) {
    try {
      var t = (typeof el.value === 'string' && el.value.trim()) ? el.value : (el.textContent || '');
      return t.replace(/\s+/g, ' ').trim().slice(0, 45);
    } catch (_) { return ''; }
  }

  var DIRECT = [
    ['#onetrust-reject-all-handler', 'OneTrust'],
    ['#onetrust-consent-sdk .ot-pc-refuse-all-handler', 'OneTrust'],
    ['#CybotCookiebotDialogBodyButtonDecline', 'Cookiebot'],
    ['#didomi-notice-disagree-button', 'Didomi'],
    ['[data-testid="uc-deny-all-button"]', 'Usercentrics'],
    ['#iubenda-cs-reject-btn', 'Iubenda'],
    ['#cky-btn-reject', 'CookieYes'],
    ['[data-cky-tag="reject-button"]', 'CookieYes'],
    ['#cookie_action_reject', 'CookieYes'],
    ['a[data-brlbs-refuse]', 'Borlabs'],
    ['._brlbs-refuse-btn', 'Borlabs'],
    ['.cmplz-deny', 'Complianz'],
    ['.cmplz-reject', 'Complianz'],
    ['.cm-btn.cm-btn-deny', 'Klaro'],
    ['.cm-btn.cm-btn-decline', 'Klaro'],
    ['.cn-decline', 'Klaro'],
    ['.osano-cm-deny-all', 'Osano'],
    ['.osano-cm-deny', 'Osano'],
    ['#tarteaucitronAllDenied', 'Tarteaucitron'],
    ['#tarteaucitronDenyAll', 'Tarteaucitron'],
    ['#hs-eu-decline-button', 'HubSpot'],
    ['.moove-gdpr-infobar-reject-btn', 'Moove'],
    ['#truste-consent-required', 'TrustArc'],
    ['.sp_choice_type_11', 'Sourcepoint'],
    ['.sp_choice_type_REJECT_ALL', 'Sourcepoint'],
    ['.qc-cmp2-summary-buttons button[mode="secondary"]', 'Quantcast'],
    ['.qc-cmp2-buttons-desktop button[mode="secondary"]', 'Quantcast'],
    // 1.7.1: Globo/G1 (LGPD) e bandeiras brasileiras — o relatório do
    // usuário citou o G1; os seletores por id/classe cobrem os contêineres
    // típicos e o texto decide qual botão é o de RECUSAR.
    ['[id*="lgpd"] button', 'LGPD/Globo'],
    ['[class*="lgpd"] button', 'LGPD/Globo'],
    ['[id*="consent"] button', 'Consentimento'],
    ['[class*="consent"] button', 'Consentimento'],
    ['[data-testid="consent-page-deny"]', 'Globo'],
    ['[data-testid="reject-all"]', 'Globo']
  ];
  // 1.7.1: variantes BR extras (Globo/G1 usa "Continuar sem aceitar"; o
  // restante cobre bandeiras LGPD comuns) + variações EN do "sem aceitar".
  var REJECT_RX = /^(recusar tudo|recusar todos|recuso tudo|recusar|recuso|negar tudo|negar todos|negar|rejeitar tudo|rejeitar todos|rejeitar|reject all|reject everything|reject|deny all|deny|decline all|decline|não aceitar|nao aceitar|não aceito|nao aceito|não concordo|nao concordo|discordo|opt[ -]?out|só (os )?essenciais|so (os )?essenciais|somente (os )?essenciais|apenas (os )?essenciais|essenciais? apenas|essential(ly)? only|only essential|necessary only|só o necessário|continuar sem aceitar|continuar sem concordar|continuar sem permitir|prosseguir sem aceitar|seguir sem aceitar|seguir sem concordar|continuar sem aceitar os cookies|continue without accepting|continue without agreeing|continue without accepting cookies|rechazar todo|rechazar|rechazo|tout refuser|refuser tout|refuser|alles ablehnen|ablehnen|não, obrigado|nao, obrigado|não obrigado|no, thanks|no thanks)$/i;
  var MANAGE_RX = /^(gerenciar|gerenciar preferências|gerenciar cookies|gerir|personalizar|personalizar escolhas|customizar|preferências|preferencias|configurações|configuracoes|configurar|opções|opcoes|manage (preferences|options|cookies)?|settings|cookie settings|preferences|options|customize|customise|mais informações|mais info|show details|mostrar detalhes|detalhes|individual settings|ajustes)$/i;
  var SAVE_RX = /^(salvar(e sair| e sair| e continuar| minhas escolhas| minhas preferências)?|guardar(e continuar)?|confirmar(escolhas)?|confirmar escolhas|confirmar seleção|aplicar|salvar configurações|save( my)? (choices|settings|preferences|selection|and exit)?|confirm( my)? (choices|selections)?|save & exit|save and continue|save settings|confirm choices)$/i;
  var ACCEPT_RX = /aceit|accept|permit|allow|agree|concord|consentir|opt[ -]?in|aceitar tudo|accept all/i;

  function findDirect() {
    for (var i = 0; i < DIRECT.length; i++) {
      var els = q(DIRECT[i][0]);
      for (var j = 0; j < els.length; j++) {
        if (visible(els[j]) && !ACCEPT_RX.test(textOf(els[j]))) return { el: els[j], name: DIRECT[i][1] };
      }
    }
    return null;
  }
  // 1.7.1 — camada LGPD/Globo: procura o botão de RECUSA DENTRO de
  // contêineres de consentimento (id/classe com lgpd/consent/cookie),
  // inclusive em elementos clicáveis não-<button> (div/span com onclick),
  // que a busca genérica por texto não alcança. É o caso do G1/globo.com:
  // a barreira LGPD não usa os CMPs internacionais da lista DIRECT.
  function findLgpdReject() {
    var boxes = q('[id*="lgpd"], [class*="lgpd"], [id*="consent"], [class*="consent"], [id*="cookie"], [class*="cookie"], [data-testid*="consent"]')
      .filter(visible).slice(0, 12);
    for (var i = 0; i < boxes.length; i++) {
      var cands;
      try {
        cands = boxes[i].querySelectorAll('button, a, [role="button"], div[onclick], span[onclick], input[type="button"], input[type="submit"]');
      } catch (_) { continue; }
      for (var j = 0; j < cands.length; j++) {
        var t = textOf(cands[j]);
        if (t && t.length <= 40 && REJECT_RX.test(t) && !ACCEPT_RX.test(t)) return { el: cands[j], name: 'LGPD' };
      }
    }
    return null;
  }
  // 1.7.1 — clique com BORBUCHA: alguns CMPs (incluído o do Globo) escutam
  // o evento no ANCESTRAL, não no próprio botão; el.click() sintético não
  // borbulha de verdade em todos os casos, então reenviamos um MouseEvent
  // com bubbles explícito (sem trocar o el.click() nativo, que continua).
  function findText() {
    var cands = q('button, input[type="button"], input[type="submit"], a[role="button"], [role="button"], a').filter(visible);
    for (var i = 0; i < cands.length; i++) {
      var t = textOf(cands[i]);
      if (t && t.length <= 40 && REJECT_RX.test(t) && !ACCEPT_RX.test(t)) return { el: cands[i], name: 'texto' };
    }
    return null;
  }
  function findManage() {
    var cands = q('button, input[type="button"], a[role="button"], [role="button"], a').filter(visible);
    for (var i = 0; i < cands.length; i++) {
      var t = textOf(cands[i]);
      if (t && t.length <= 40 && MANAGE_RX.test(t) && !ACCEPT_RX.test(t)) return cands[i];
    }
    return null;
  }
  function findSave() {
    var cands = q('button, input[type="button"], a[role="button"], [role="button"]').filter(visible);
    for (var i = 0; i < cands.length; i++) {
      var t = textOf(cands[i]);
      if (t && t.length <= 45 && SAVE_RX.test(t)) return cands[i];
    }
    return null;
  }
  function acceptVisible() {
    var cands = q('button, a[role="button"], [role="button"], input[type="button"]').filter(visible);
    for (var i = 0; i < cands.length; i++) {
      var t = textOf(cands[i]);
      if (t && t.length <= 40 && ACCEPT_RX.test(t)) return true;
    }
    return false;
  }

  var CONTAINER_RX = /consent|cookie|cmp|gdpr|rgpd|privac|didomi|onetrust|usercentrics|qc-cmp2|klaro|osano|borlabs|cmplz|termly|tarteaucitron|iubenda|cky-|sp_message|truste|hs-eu/i;
  function classNameOf(el) {
    try { return typeof el.className === 'string' ? el.className : ((el.className && el.className.baseVal) || ''); }
    catch (_) { return ''; }
  }
  function containers() {
    return q('div, section, aside, dialog, form').filter(function (el) {
      var id = (el.id || '') + ' ' + classNameOf(el);
      if (!CONTAINER_RX.test(id)) return false;
      if (!visible(el)) return false;
      try { return el.querySelector('[role="switch"], input[type="checkbox"], [role="checkbox"]'); } catch (_) { return false; }
    }).slice(0, 8);
  }
  function uncheckAll(scope) {
    var n = 0;
    try {
      var list = scope.querySelectorAll('[role="switch"][aria-checked="true"], [role="checkbox"][aria-checked="true"], input[type="checkbox"]:checked');
      for (var i = 0; i < list.length; i++) { try { list[i].click(); n++; } catch (_) {} }
    } catch (_) {}
    return n;
  }

  function mark() { try { localStorage.setItem(KEY, String(Date.now())); } catch (_) {} }

  var active = false, finished = false;
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  function bubbleClick(el) {
    try { el.click(); } catch (_) {}
    try {
      var ev = new MouseEvent('click', { bubbles: true, cancelable: true, view: window });
      el.dispatchEvent(ev);
    } catch (_) { /* elemento pode ter saído do DOM */ }
  }

  async function attempt() {
    if (finished || active) return;
    active = true;
    try {
      var r = findDirect() || findLgpdReject() || findText();
      if (r) {
        bubbleClick(r.el);
        mark(); denyEvent();
        await sleep(900);
        if (LEVEL === 'max') {
          var sb = findSave();
          if (sb) { try { sb.click(); } catch (_) {} await sleep(300); }
        }
        finished = true;
        return;
      }
      if (LEVEL === 'max' && acceptVisible()) {
        var mg = findManage();
        if (mg) {
          try { mg.click(); } catch (_) {}
          await sleep(1200);
          var cs = containers();
          for (var i = 0; i < cs.length; i++) uncheckAll(cs[i]);
          var save = findSave();
          if (save) {
            try { save.click(); } catch (_) {}
            mark(); denyEvent();
            finished = true;
            return;
          }
        }
      }
    } finally { active = false; }
  }

  try {
    var times = [600, 1800, 4000, 7000, 11000];
    for (var tI = 0; tI < times.length; tI++) setTimeout(attempt, times[tI]);
    var mo = new MutationObserver(function () { if (!finished) setTimeout(attempt, 400); });
    mo.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(function () {
      finished = true;
      try { mo.disconnect(); } catch (_) {}
    }, 30000);
  } catch (_) {}
})();
`;
  const ok = script.includes('__nanodeskConsentOMatic') &&
    script.includes('onetrust-reject-all-handler') &&
    Buffer.byteLength(script) <= MAX_SCRIPT_BYTES;
  return ok ? script.trim() : '';
}

/** Metadados para diagnóstico. */
function describe(opts) {
  return {
    id: 'nanodesk-consentomatic',
    level: normalizeLevel(opts && opts.level),
    cooldownHours: normalizeCooldownHours(opts && opts.cooldownHours),
    bytes: Buffer.byteLength(buildScript(opts || {})),
    note: 'Nega rastreadores nos popups de cookies (baseado na ideia do Consent-O-Matic); nível máximo por padrão. 1.7.1: camada LGPD/Globo (G1) + clique com borbucha.'
  };
}

module.exports = {
  LEVELS, MAX_SCRIPT_BYTES,
  normalizeLevel, cooldownKey, isWhitelisted, normalizeCooldownHours,
  buildScript, describe
};

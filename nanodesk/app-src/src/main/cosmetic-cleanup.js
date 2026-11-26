/**
 * NanoDesk — Limpeza cosmética de anúncios (1.8.8)
 * ==================================================================
 * CSS + script que REMOVE as barras cinzentas de anúncio/residuais
 * que sobram quando o bloqueador nativo derruba o conteúdo mas o
 * container vazio continua ocupando espaço (especialmente Globo/G1,
 * UOL, MSN e portais de notícia).
 *
 * CRÍTICO: alvo `.bstn-ad` (NÃO `.bstn-ads` — o plural pertence ao
 * JS de init do G1 e nunca é um container de anúncio real).
 * Outros alvos: `gib-ad`, `.bastian-feed-item[data-type*="ad"]`.
 *
 * NÃO usamos `:empty` (quebra com containers que têm whitespace/
 * comentários). Escondemos o container DIRETAMENTE com
 * `display: none !important`.
 *
 * Núcleo puro: monta a string CSS/script — testável sem Electron.
 */
'use strict';

const MAX_SCRIPT_BYTES = 16 * 1024;

/**
 * CSS base embutido — esconde containers de anúncio conhecidos.
 * (puro) — Devolve a string CSS pronta para insertCSS.
 */
function buildCss() {
  return [
    /* Globo/G1: bstn-ad (singular) e variante bastian-feed-item com data-type ad */
    '.bstn-ad { display: none !important; }',
    '.bstn-ad-shape, .bstn-ad-badge, .bstn-ad-label { display: none !important; }',
    '[data-bstn-type="ad"], [data-bstn-type="advertisement"] { display: none !important; }',
    '.bastian-feed-item[data-type*="ad"] { display: none !important; }',
    '.bastian-feed-item[data-type="ad"] { display: none !important; }',
    /* Gib-ad (UOL e portais que usam o skeleton "gib") */
    'gib-ad, .gib-ad, .gib-ad-container, .gib-ad-wrapper { display: none !important; }',
    /* Containers vazios genéricos que costumam ser anúncios escondidos */
    '[id^="ad-"][class*="container"] { display: none !important; }',
    '[id^="ads-"][class*="container"] { display: none !important; }',
    /* Barra cinza residual (padding/margin reservado para anúncio) */
    '.ad-slot, .ad-container, .ad-wrapper, .ad-placeholder { display: none !important; }',
    '[data-ad], [data-ad-slot], [data-ad-position] { display: none !important; }',
    /* Anúncios "sponsors" comuns em portais BR */
    '.publicidade, .publi, .publi-box, .advertising { display: none !important; }',
    /* Espaçadores que viram "buracos" cinzas */
    '.ad-spacer, .ad-gap, [class*="ad-slot__container"] { display: none !important; }'
  ].join('\n');
}

/**
 * Script injetável (mundo principal, idempotente) que:
 *  - esconde containers de anúncio ainda vivos no DOM (MutationObserver);
 *  - remove espaçadores cinzentos criados depois da carga;
 *  - NÃO usa :empty — esconde pelo seletor/alvo direto.
 * 100% em try/catch: falha nunca quebra a página.
 * (puro) — Devolve a string JS pronta para executeJavaScript.
 */
function buildScript() {
  const script = String.raw`
(function () {
  if (window.__nanodeskCosmeticCleanup) return;
  window.__nanodeskCosmeticCleanup = 1;
  // Seletores DIRETOS (sem pseudo-classe empty). O alvo .bstn-ad é SINGULAR —
  // o plural .bstn-ads pertence ao JS de init do G1 e nunca é container real.
  var SEL = '.bstn-ad, .bstn-ad-shape, .bstn-ad-badge, .bstn-ad-label, ' +
            '[data-bstn-type="ad"], [data-bstn-type="advertisement"], ' +
            '.bastian-feed-item[data-type*="ad"], .bastian-feed-item[data-type="ad"], ' +
            'gib-ad, .gib-ad, .gib-ad-container, .gib-ad-wrapper, ' +
            '.ad-slot, .ad-container, .ad-wrapper, .ad-placeholder, .ad-spacer, .ad-gap, ' +
            '[data-ad], [data-ad-slot], [data-ad-position], ' +
            '.publicidade, .publi, .publi-box, .advertising, ' +
            '[id^="ad-"][class*="container"], [id^="ads-"][class*="container"]';
  function hide(el) {
    try {
      if (!el || el.dataset && el.dataset.ndClean === '1') return;
      el.style.setProperty('display', 'none', 'important');
      if (el.dataset) el.dataset.ndClean = '1';
    } catch (_) {}
  }
  function sweep() {
    try {
      var nodes = document.querySelectorAll(SEL);
      for (var i = 0; i < nodes.length; i++) hide(nodes[i]);
    } catch (_) {}
  }
  sweep();
  try {
    var obs = new MutationObserver(function (muts) {
      for (var i = 0; i < muts.length; i++) {
        var added = muts[i].addedNodes;
        for (var j = 0; j < added.length; j++) {
          var n = added[j];
          if (n.nodeType !== 1) continue;
          try { if (n.matches && n.matches(SEL)) hide(n); } catch (_) {}
          try {
            var sub = n.querySelectorAll ? n.querySelectorAll(SEL) : null;
            if (sub) for (var k = 0; k < sub.length; k++) hide(sub[k]);
          } catch (_) {}
        }
      }
    });
    // 1.8.10: observar também 'attributes' para capturar elementos que
    // ganham class="ad-…" depois do load (padrão comum de lazy-load de
    // anúncios — sem isso, o observer perdia a mudança e o elemento
    // continuava visível).
    obs.observe(document.documentElement || document.body, {
      childList: true, subtree: true,
      attributes: true, attributeFilter: ['class', 'id']
    });
  } catch (_) {}
  // duas passadas extra (anúncios "tardios")
  setTimeout(sweep, 1500);
  setTimeout(sweep, 4500);
})();
`;
  const ok = script.includes('__nanodeskCosmeticCleanup') &&
             script.includes('.bstn-ad') &&
             !script.includes(':empty') &&
             Buffer.byteLength(script) <= MAX_SCRIPT_BYTES;
  return ok ? script.trim() : '';
}

module.exports = { buildCss, buildScript, MAX_SCRIPT_BYTES };

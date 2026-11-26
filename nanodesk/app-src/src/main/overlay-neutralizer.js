/**
 * NanoDesk — Neutralizador de overlays-armadilha (1.5.1)
 * ==================================================================
 * Camada DOM do RedirectGuard (dikshanagvekar/RedirectGuard, MIT):
 * alguns sites cobrem a página com um elemento INVISÍVEL e clicável
 * ("click hijacking" / "clickjacking de anúncios") — no primeiro toque
 * o usuário abre um anúncio sem saber. O RedirectGuard detecta esses
 * elementos pelas MESMAS características abaixo e aplica
 * `pointer-events: none` para tirar a armadilha do caminho do mouse.
 *
 * Critérios (todos obrigatórios, para NUNCA acertar elementos bons):
 *  - position fixed/absolute;
 *  - z-index alto (>= 500);
 *  - quase invisível: opacity <= 0.35 e/ou fundo transparente;
 *  - cobre uma área grande (>= 50% da largura e 40% da altura);
 *  - sem conteúdo de verdade (pouco texto, sem controles visíveis).
 *
 * O script roda no mundo principal da página via executeJavaScript
 * (funciona mesmo com CSP rígida — não é um recurso carregado).
 * `pointer-events: none` só desativa o CLIQUE no overlay: nada é
 * apagado, escondido ou removido — mudanças de layout zero.
 */
'use strict';

/**
 * Script autocontido (IIFE) que devolve o número de armadilhas
 * neutralizadas. Pode rodar várias vezes na mesma página (1.5.2): elementos já
 * neutralizados ficam com pointer-events:none e são ignorados nas passagens
 * seguintes; __ndOverlayGuard no window apenas conta as execuções.
 *
 * CORREÇÃO 1.6.7 (o YouTube quebrava cliques):
 *  - subárvores funcionais ficam FORA do alcance (#movie_player,
 *    .html5-video-player, ytd-popup-container, .ytp-*): o player usa
 *    camadas transparentes de captura de gesto que casavam com os critérios;
 *  - a armadilha real cobre a PÁGINA INTEIRA — a área mínima sobe de
 *    50%×40% para 85%×85% (antes overlays parciais legítimos eram alvo);
 *  - controles nativos do player/elementos interativos em QUALQUER lugar
 *    do overlay continuam liberando o elemento (critério original).
 */
const OVERLAY_SCRIPT = '(function () {' +
  'try {' +
  // 1.5.2: sem retorno antecipado — o script roda várias vezes (overlays
  // inseridos DEPOIS do carregamento). A idempotência vem do próprio
  // critério: elementos já neutralizados têm pointer-events:none e são pulados.
  'window.__ndOverlayGuard = (window.__ndOverlayGuard || 0) + 1;' +
  'var vw = window.innerWidth || 1024, vh = window.innerHeight || 768;' +
  'var root = document.body;' +
  'if (!root) return 0;' +
  'var all = root.querySelectorAll("*");' +
  'var hits = 0;' +
  'var max = Math.min(all.length, 4000);' +
  'function inProtected(el){' +
  '  try { return !!el.closest("#movie_player,.html5-video-player,.ytp-chrome-bottom,.ytp-chrome-top,ytd-popup-container,video,object,embed"); } catch (_) { return false; }' +
  '}' +
  'for (var i = 0; i < max; i++) {' +
  'var el = all[i];' +
  'if (!el || el === root || el === document.documentElement || el.nodeType !== 1) continue;' +
  'if (inProtected(el)) continue;' +
  'var cs = null;' +
  'try { cs = window.getComputedStyle(el); } catch (_) { continue; }' +
  'if (!cs || cs.pointerEvents === "none" || cs.visibility === "hidden") continue;' +
  'var pos = cs.position;' +
  'if (pos !== "fixed" && pos !== "absolute") continue;' +
  'var z = parseInt(cs.zIndex, 10);' +
  'if (!z || z < 500) continue;' +
  'var r = el.getBoundingClientRect();' +
  // 1.6.7: armadilha real cobre praticamente a página inteira
  'if (r.width < vw * 0.85 || r.height < vh * 0.85) continue;' +
  // quase invisível?
  'var op = parseFloat(cs.opacity);' +
  'if (!isNaN(op) && op > 0.35) continue;' +
  'var bg = String(cs.backgroundColor || "");' +
  // 1.5.2: overlay com opacity <= 0.05 já é invisível, qualquer que seja o
  // fundo (o clássico "opacity:0; background:#000" escapava da detecção)
  'if (!(op <= 0.05)) {' +
  'if (bg.indexOf("rgba") === 0) {' +
  'var pa = bg.replace(/rgba?\\(|\\)/g, "").split(/[,\\s]+/);' +
  'var a = parseFloat(pa[3]);' +
  'if (isNaN(a) || a > 0.35) continue;' +
  '} else if (bg && bg !== "transparent") { continue; }' +
  '}' +
  // conteúdo real?
  'var text = (el.innerText || el.textContent || "");' +
  'if (String(text).trim().length > 40) continue;' +
  'var inter = null;' +
  'try { inter = el.querySelector("a[href],button,input,select,textarea,video,iframe,img,svg"); } catch (_) {}' +
  'if (inter) {' +
  'var ir = null;' +
  'try { ir = inter.getBoundingClientRect(); } catch (_) {}' +
  'if (ir && ir.width > 6 && ir.height > 6) continue;' +
  '}' +
  'el.style.setProperty("pointer-events", "none", "important");' +
  'hits++;' +
  '}' +
  'return hits;' +
  '} catch (_) { return 0; }' +
  '})();';

/** Contagem aproximada de linhas de defesa (metadado p/ auditoria). */
const CRITERIA = [
  'position: fixed/absolute',
  'z-index >= 500',
  'opacity <= 0.35 ou fundo transparente',
  'cobre >= 85% da largura e da altura da janela',
  'fora de subárvores funcionais (player de vídeo, pop-ups do YouTube)',
  'sem conteúdo real (texto curto, sem controles visíveis)',
  'ação: pointer-events none (nada é removido)'
];

module.exports = { OVERLAY_SCRIPT, CRITERIA };

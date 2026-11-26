/**
 * NanoDesk — Bloqueador de pop-ups (1.5.1)
 * ==================================================================
 * Conceitos do projeto aberto madjeek-web/Popup-Blocker-Pro (MIT),
 * reimplementados de forma NATIVA no processo principal do Electron
 * (sem extensões e sem interceptação de APIs dentro das páginas):
 *
 *  - A regra central do Popup-Blocker-Pro é "bloquear aberturas de
 *    janela SEM interação real do usuário". No Electron 45 o
 *    HandlerDetails de setWindowOpenHandler não expõe mais o campo
 *    `userGesture`; por isso o main.js mantém, por aba, o instante da
 *    última entrada REAL (clique/tecla via 'input-event') e marca a
 *    abertura como "com interação" quando ela acontece dentro de uma
 *    janela curta (1000 ms) após essa entrada — o window.open de um
 *    handler de clique roda no mesmo instante; o de um pop-under
 *    automático roda fora de qualquer interação.
 *  - Pop-unders e "tab-unders" (abrir em segundo plano sem pedir)
 *    caem no mesmo caminho — sem gesto, são bloqueados.
 *  - ALLOWLIST por site (só em memória): sites autorizados podem
 *    abrir pop-ups mesmo sem gesto.
 *  - Contadores (sessão e por aba) e registro dos últimos eventos
 *    para o painel "Proteções".
 *
 * Nada aqui acessa o Electron: o núcleo é puro e testável em unitários.
 * O main.js injeta as decisões no handler de janelas de cada aba.
 */
'use strict';

const { normalizeHostname } = require('../shared/validation');

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch (e) { return ''; }
}

function domainMatches(host, domain) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  const d = String(domain || '').toLowerCase().replace(/\.$/, '');
  return h === d || h.endsWith('.' + d);
}

/**
 * Cria o bloqueador de pop-ups.
 * @param {object} opts { maxEvents?: number }
 */
function createPopupBlocker(opts = {}) {
  const maxEvents = Math.min(200, Math.max(10, Number(opts.maxEvents) || 60));
  const state = {
    enabled: true,
    totalBlocked: 0,
    perTab: new Map(),   // tabId -> bloqueios na aba
    recent: [],
    allow: new Set()
  };

  const clean = (h) => normalizeHostname(h);

  const allowHit = (host) => {
    const h = clean(host);
    if (!h) return false;
    for (const d of state.allow) if (domainMatches(h, d)) return true;
    return false;
  };

  /**
   * Decisão central (espelha o critério do Popup-Blocker-Pro):
   * @param {object} req { url, userGesture, sourceHost?, sourceTabId? }
   * @returns {{allow:boolean, reason:string, host:string}}
   */
  function decide(req = {}) {
    const target = hostOf(req.url);
    const host = target || '—';
    if (!state.enabled) return { allow: true, reason: 'desligado', host };
    // Allowlist: site de destino OU site de origem autorizado.
    if (allowHit(target)) return { allow: true, reason: 'allowlist', host };
    if (allowHit(req.sourceHost)) return { allow: true, reason: 'allowlist', host };
    // Gesto real do usuário (clique/tecla) → permitido.
    if (req.userGesture === true) return { allow: true, reason: 'interacao', host };

    // window.open/pop-under/tab-under SEM interação → bloqueado.
    state.totalBlocked++;
    const tid = Number(req.sourceTabId);
    if (Number.isInteger(tid) && tid > 0) {
      state.perTab.set(tid, (state.perTab.get(tid) || 0) + 1);
    }
    state.recent.unshift({
      host,
      url: String(req.url || '').slice(0, 240),
      ts: Date.now()
    });
    if (state.recent.length > maxEvents) state.recent.length = maxEvents;
    return { allow: false, reason: 'sem-interacao', host };
  }

  return {
    setEnabled(v) { state.enabled = !!v; },
    isEnabled() { return state.enabled; },
    decide,
    allow(host) { const h = clean(host); if (h) state.allow.add(h); return [...state.allow]; },
    disallow(host) { const h = clean(host); if (h) state.allow.delete(h); return [...state.allow]; },
    allowlist() { return [...state.allow]; },
    /** Contadores; `tabId` opcional devolve o total da aba. */
    stats(tabId) {
      const tid = Number(tabId);
      return {
        enabled: state.enabled,
        total: state.totalBlocked,
        tab: Number.isInteger(tid) && tid > 0 ? (state.perTab.get(tid) || 0) : 0
      };
    },
    recent() { return state.recent.slice(0, 40); },
    /** Limpa contadores de uma aba ao fechá-la (memória enxuta). */
    resetTab(tabId) { state.perTab.delete(Number(tabId)); }
  };
}

module.exports = { createPopupBlocker, hostOf, domainMatches };

/**
 * NanoDesk — Guardião de redirecionamentos (1.5.1)
 * ==================================================================
 * Conceitos do projeto aberto dikshanagvekar/RedirectGuard (MIT),
 * reimplementados de forma NATIVA nas camadas em que o Electron é
 * mais forte que uma extensão:
 *
 *  1. CAMADA DE REDE/DOMÍNIO — alvos de navegação para redes de
 *     anúncios agressivas/redirecionadores conhecidas (DoubleClick,
 *     ExoClick, PropellerAds, TrafficJunky, PopCash, Go2Speed, PopAds,
 *     Adsterra, HilltopAds, Clickadu, Ad-Maven…) são cortados ANTES do
 *     tráfego seguir (will-navigate / will-redirect + preventDefault).
 *     É o equivalente nativo do rules.json do RedirectGuard.
 *  2. CAMADA DE CADEIA — "farms" de redirecionamento fazem a página
 *     pular por 5–10 domínios em poucos segundos até o anúncio. A
 *     cadeia de cada aba é rastreada: mais de N origens distintas em
 *     uma janela curta de tempo = sequestro de navegação → a travada
 *     atual é cancelada e a cadeia zerada.
 *  3. CAMADA DOM (overlay-neutralizer.js) — neutraliza overlays
 *     invisíveis usados como armadilha de clique.
 *
 *  A camada de clique (onclick="window.location=…", location.href,
 *  form.submit) do RedirectGuard é coberta SEM quebrar sites: no
 *  Electron essas navegações todas passam por will-navigate no
 *  processo principal, onde a camada de rede decide — não é preciso
 *  remendar APIs dentro das páginas (mais estável e compatível).
 *
 * Nada aqui acessa o Electron: núcleo puro e testável em unitários.
 */
'use strict';

const { normalizeHostname } = require('../shared/validation');

/**
 * Redes de anúncios/redirecionamento cujo destino de NAVEGAÇÃO é
 * praticamente sempre malicioso (pop/popunder/redirect). Domínios
 * públicos e documentados; casam também com subdomínios.
 */
const REDIRECT_HOSTS = [
  // Google / DoubleClick (alvos de clique de anúncio)
  'doubleclick.net', 'googlesyndication.com', 'googletagservices.com',
  'googleadservices.com', '2mdn.net',
  // ExoClick (e domínios de veiculação documentados)
  'exoclick.com', 'exosrv.com', 'exdynsrv.com', 'realsrv.com',
  // PropellerAds / Go2Speed / onclickads
  'propellerads.com', 'propellerclick.com', 'propeller-tracking.com',
  'onclickads.net', 'onclckds.com', 'go2speed.org',
  // Redes de pop/popunder
  'popads.net', 'popcash.net', 'popmyads.com',
  // Adsterra / HilltopAds
  'adsterra.com', 'hilltopads.net', 'hilltopads.com',
  // JuicyAds / TrafficJunky / TrafficStars
  'juicyads.com', 'trafficjunky.net', 'trafficfactory.biz',
  'tsyndicate.com', 'trafficstars.com',
  // Corretoras de redirect de baixa reputação
  'clickadu.com', 'adcash.com', 'ad-maven.com', 'admvx.com'
];

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch (e) { return ''; }
}

const REDIRECT_HOST_SET = new Set(REDIRECT_HOSTS);

/** Sufixo: host exato ou subdomínio de uma rede bloqueada. */
function isRedirectHost(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h) return false;
  let candidate = h;
  while (candidate) {
    if (REDIRECT_HOST_SET.has(candidate)) return true;
    const dot = candidate.indexOf('.');
    if (dot < 0) break;
    candidate = candidate.slice(dot + 1);
  }
  return false;
}

/** Regra casada (para exibição) ou null. */
function matchRedirectHost(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h) return null;
  let candidate = h;
  while (candidate) {
    if (REDIRECT_HOST_SET.has(candidate)) return candidate;
    const dot = candidate.indexOf('.');
    if (dot < 0) break;
    candidate = candidate.slice(dot + 1);
  }
  return null;
}

/**
 * Cria o guardião de redirecionamentos.
 * @param {object} opts { maxHops?: number, windowMs?: number, maxEvents?: number }
 */
function createRedirectGuard(opts = {}) {
  const maxHops = Math.min(20, Math.max(2, Number(opts.maxHops) || 7));
  const windowMs = Math.min(120000, Math.max(2000, Number(opts.windowMs) || 15000));
  const maxEvents = Math.min(200, Math.max(10, Number(opts.maxEvents) || 60));
  const state = {
    enabled: true,
    domainBlocked: 0,   // alvo direto em rede de redirect
    chainBlocked: 0,    // cadeia de redirecionamentos exagerada
    clickTraps: 0,      // overlays-armadilha neutralizados (camada DOM)
    recent: [],
    allow: new Set(),
    chains: new Map()   // key -> { base, hops:Set, started, last }
  };

  const clean = (h) => normalizeHostname(h);
  const allowHit = (host) => {
    const h = clean(host);
    if (!h) return false;
    for (const d of state.allow) if (h === d || h.endsWith('.' + d)) return true;
    return false;
  };

  const pushEvent = (kind, rule, url) => {
    state.recent.unshift({
      kind,                                   // 'dominio' | 'cadeia'
      rule: rule || '',
      host: hostOf(url) || '—',
      url: String(url || '').slice(0, 240),
      ts: Date.now()
    });
    if (state.recent.length > maxEvents) state.recent.length = maxEvents;
  };

  /**
   * Checagem pontual do ALVO (will-navigate — clique/JS/forms).
   * Não mexe em cadeia: navegação nova zera o histórico de hops.
   * @returns {{allow:boolean, reason:string, rule:string, host:string}}
   */
  function checkTarget(toUrl) {
    const host = hostOf(toUrl);
    const out = { allow: true, reason: '', rule: '', host: host || '—' };
    if (!state.enabled) return out;
    if (!/^https?:\/\//i.test(String(toUrl || ''))) return out;
    if (allowHit(host)) return out;
    const rule = matchRedirectHost(host);
    if (rule) {
      state.domainBlocked++;
      out.allow = false;
      out.reason = 'dominio';
      out.rule = rule;
      pushEvent('dominio', rule, toUrl);
    }
    return out;
  }

  /**
   * Checagem de REDIRECIONAMENTO (will-redirect): alvo em rede de
   * redirect OU cadeia com origens demais. Mantém o estado da cadeia
   * por aba (key = id da WebContents).
   * @param {object} req { key, fromUrl, toUrl }
   */
  function checkRedirect(req = {}) {
    const out = { allow: true, reason: '', rule: '', host: '—' };
    if (!state.enabled) { state.chains.delete(req.key); return out; }
    const toUrl = String(req.toUrl || '');
    if (!/^https?:\/\//i.test(toUrl)) return out;

    const target = hostOf(toUrl);
    out.host = target || '—';
    if (allowHit(target)) { state.chains.delete(req.key); return out; }

    // 1) Alvo direto em rede de redirect → corta e zera a cadeia.
    const rule = matchRedirectHost(target);
    if (rule) {
      state.domainBlocked++;
      state.chains.delete(req.key);
      out.allow = false;
      out.reason = 'dominio';
      out.rule = rule;
      pushEvent('dominio', rule, toUrl);
      return out;
    }

    // 2) Cadeia: origens distintas visitadas nesta navegação.
    const now = Date.now();
    let chain = state.chains.get(req.key);
    if (!chain) {
      const base = hostOf(req.fromUrl) || target;
      chain = { base, hops: new Set([base]), started: now, last: base };
      state.chains.set(req.key, chain);
    }
    if (now - chain.started > windowMs) {
      chain.hops = new Set([target || chain.base]);
      chain.started = now;
      chain.last = target || chain.base;
      return out;
    }
    if (target && !chain.hops.has(target)) {
      chain.hops.add(target);
      chain.last = target;
    }
    if (chain.hops.size > maxHops) {
      state.chainBlocked++;
      state.chains.delete(req.key);   // zera: navegação legítima recomeça limpa
      out.allow = false;
      out.reason = 'cadeia';
      out.rule = String(chain.hops.size) + ' origens';
      pushEvent('cadeia', out.rule, toUrl);
    }
    return out;
  }

  /** Encerra a cadeia da aba (navegação nova confirmada / aba fechada). */
  function endChain(key) { state.chains.delete(key); }

  /** Contabiliza overlays-armadilha neutralizados pela camada DOM. */
  function noteClickTraps(n) {
    const v = Number(n) || 0;
    if (v > 0) state.clickTraps += v;
    return state.clickTraps;
  }

  return {
    setEnabled(v) {
      state.enabled = !!v;
      if (!state.enabled) state.chains.clear();
    },
    isEnabled() { return state.enabled; },
    isRedirectHost,
    checkTarget,
    checkRedirect,
    endChain,
    noteClickTraps,
    allow(host) { const h = clean(host); if (h) state.allow.add(h); return [...state.allow]; },
    disallow(host) { const h = clean(host); if (h) state.allow.delete(h); return [...state.allow]; },
    allowlist() { return [...state.allow]; },
    stats() {
      return {
        enabled: state.enabled,
        total: state.domainBlocked + state.chainBlocked,
        domain: state.domainBlocked,
        chain: state.chainBlocked,
        clickTraps: state.clickTraps,
        maxHops,
        windowMs
      };
    },
    recent() { return state.recent.slice(0, 40); }
  };
}

module.exports = {
  REDIRECT_HOSTS,
  isRedirectHost,
  matchRedirectHost,
  createRedirectGuard
};

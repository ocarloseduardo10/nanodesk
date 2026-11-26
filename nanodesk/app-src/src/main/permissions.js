/**
 * NanoDesk — Permissões de sites (1.3.1)
 * ==================================================================
 * Inspirado no navegador Blanc (github.com/bnfy/blanc):
 *  - NEGAR POR PADRÃO continua sendo a política (fullscreen e
 *    clipboard-sanitized-write liberados por serem inofensivos);
 *  - câmera, microfone, geolocalização, notificações e MIDI passam
 *    a exibir um PROMPT nativo "Permitir nesta sessão / Negar";
 *  - a decisão vive SÓ EM MEMÓRIA: fechar o NanoDesk esquece tudo
 *    (coerente com a promessa de não salvar nada no PC).
 *
 * Restante (DRM/mediaKeySystem, sensores, clipboard-read etc.)
 * permanece negado sem perguntar — superfície mínima.
 */
'use strict';

/** Permissões liberadas direto (sem risco de identificação/rastreio). */
const PERM_LIBERADAS = new Set(['fullscreen', 'clipboard-sanitized-write']);

/** Permissões que pedem decisão do usuário (prompt nativo). */
const PERM_PROMPT = new Set(['media', 'geolocation', 'notifications', 'midi', 'midi-sysex']);

/**
 * Classifica uma permissão.
 * @returns {'allow'|'prompt'|'deny'}
 */
function policyFor(permission) {
  if (PERM_LIBERADAS.has(permission)) return 'allow';
  if (PERM_PROMPT.has(permission)) return 'prompt';
  return 'deny';
}

/** Rótulos em pt-BR para o diálogo. */
const ROTULOS = {
  media: 'usar a câmera ou o microfone',
  geolocation: 'ver a sua localização',
  notifications: 'mostrar notificações',
  midi: 'acessar dispositivos MIDI',
  'midi-sysex': 'acessar dispositivos MIDI (controle exclusivo)'
};

/** Rótulo amigável; cai para o nome técnico quando desconhecido. */
function labelFor(permission) {
  return ROTULOS[permission] || `o recurso "${permission}"`;
}

/** Extrai origem (scheme://host) de uma URL; falha vira ''. */
function originOf(url) {
  try { return new URL(String(url)).origin; } catch (_) { return ''; }
}

/** Só o host, para exibição no diálogo. */
function hostOf(url) {
  try { return new URL(String(url)).hostname; } catch (_) { return ''; }
}

/**
 * Estado de decisões de UMA sessão (memória do processo principal).
 * @param {Function} ask  async ({ origin, permission }) => boolean
 *                        (abre o diálogo; false se fechado/negado)
 */
class PermissionSession {
  constructor(ask) {
    if (typeof ask !== 'function') throw new TypeError('ask é obrigatório');
    this.ask = ask;
    this.decisions = new Map(); // "origem::permissão" -> boolean
    this.pending = new Map();   // diálogos em aberto (dedupe)
  }

  static key(origin, permission) { return `${origin}::${permission}`; }

  /** Decisão síncrona (setPermissionCheckHandler). */
  check(origin, permission) {
    const policy = policyFor(permission);
    if (policy === 'allow') return true;
    if (policy !== 'prompt') return false;
    return this.decisions.get(PermissionSession.key(origin, permission)) === true;
  }

  /** Decisão assíncrona (setPermissionRequestHandler), com dedupe. */
  async request(origin, permission) {
    const policy = policyFor(permission);
    if (policy === 'allow') return true;
    if (policy !== 'prompt') return false;
    if (!origin) return false; // sem origem conhecida, não há a quem perguntar

    const key = PermissionSession.key(origin, permission);
    if (this.decisions.has(key)) return this.decisions.get(key);
    if (this.pending.has(key)) return this.pending.get(key);

    const p = (async () => {
      try {
        const ok = await this.ask({ origin, permission });
        this.decisions.set(key, ok === true);
        return ok === true;
      } catch (_) {
        this.decisions.set(key, false);
        return false;
      } finally {
        this.pending.delete(key);
      }
    })();
    this.pending.set(key, p);
    return p;
  }
}

module.exports = {
  PERM_LIBERADAS,
  PERM_PROMPT,
  policyFor,
  labelFor,
  originOf,
  hostOf,
  PermissionSession
};

/* NanoDesk — validação compartilhada entre Main e Renderer. */
(function exposeValidation(root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.NanoDeskValidation = api;
})(typeof window !== 'undefined' ? window : null, function createValidation() {
  'use strict';

  const SEARCH_ENGINES = new Set([
    'duckduckgo', 'bing', 'google', 'startpage', 'brave', 'searxng'
  ]);
  const BOOLEAN_SETTINGS = new Set([
    'adblockEnabled', 'adblockScriptlets', 'popupBlockerEnabled', 'redirectGuardEnabled',
    'hibernateTabs', 'doNotTrack', 'askWhereToSave',
    // 1.6.0
    'persistentData', 'httpsFirst', 'blockThirdPartyCookies',
    'webrtcProtect', 'clearUrls', 'fingerprintProtect',
    'urlGateEnabled', 'downloadScan', 'quarantineDownloads',
    // CORREÇÃO 1.6.7: "secureDnsStrict" existia em SETTING_KEYS e na interface,
    // mas NÃO aqui — validateSetting lançava "Configuração desconhecida" e a
    // opção "DNS seguro estrito" NUNCA podia ser ligada (o DoH caía sempre no
    // modo "automatic", com fallback silencioso para DNS em texto claro).
    'secureDnsStrict',
    // 1.6.7: checagem automática de atualização no arranque — OPT-IN
    // (padrão desligado): um navegador de privacidade não deve contatar
    // endoflife.date por conta própria a cada partida.
    'updateCheck',
    // 1.7.0 — nativo: SponsorBlock, Consent-O-Matic, LanguageTool
    'sponsorBlockEnabled', 'sponsorBlockToast',
    'consentomaticEnabled', 'languagetoolEnabled',
    // 1.8.8 — vídeo: legendas e capa embutidos no .mp4 baixado
    'ytdlpSubtitles', 'ytdlpThumbnail',
    // 1.8.8 — proteções ativas novas: redirect, cosmetic, security, malware,
    // popup-strict (schomery-style) e modo agressivo
    'noredirectEnabled', 'adCleanupEnabled', 'pageSecurityScan',
    'malwareSiteBlock', 'popupBlockerStrict', 'popupBlockerAggressive',
    // 1.9.6-e — PopUpOFF nativo (modais/overlays de DOM)
    'overlayBlockerMode',
    // 1.8.9 — cofre de senhas nativo (AES-256-GCM + PBKDF2)
    'vaultEnabled', 'vaultSavePrompt',
    // 1.8.11 — cofre efêmero (só RAM) e cache de filtros em disco
    'vaultEphemeral', 'filtersCacheOnDisk',
    // 1.9.1 — proteção de teclado e de captura de tela
    'keyboardGuard', 'keyboardGuardAuthSites', 'contentProtection', 'clamavPersistDb', 'thirdPartyCookiesStrict',
    // 1.9.0 — arquivar página
    'archiveBlockNetwork', 'archiveRemoveHidden', 'archiveRemoveUnused', 'archiveLoadLazy',
    'archiveSkipTrackers', 'archiveAskWhere', 'archiveKeepForm'
  ]);
  const URL_SETTINGS = new Set([
    'searxngUrl', 'translateUrl', 'secureDnsCustom',
    'linkwardenUrl', 'languagetoolApi'
  ]);
  const SB_CATEGORIES = new Set([
    'sponsor', 'selfpromo', 'interaction', 'intro', 'outro', 'preview',
    'filler', 'music_offtopic'
  ]);
  const CM_LEVELS = new Set(['max', 'smart']);
  const ENUM_SETTINGS = {
    videoQuality: new Set(['best', '1080', '720', 'audio']),
    secureDns: new Set(['off', 'cloudflare', 'cloudflare_family', 'google', 'quad9', 'custom']),
    consentomaticLevel: CM_LEVELS,
    overlayBlockerMode: new Set(['off', 'delicate', 'easy', 'hard'])   // 1.9.6-e
  };

  function parseHttpUrl(value) {
    if (typeof value !== 'string' || value.length === 0 || value.length > 4096) return null;
    if (value !== value.trim() || /[\u0000-\u0020\u007f]/.test(value)) return null;
    try {
      const parsed = new URL(value);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
      if (!parsed.hostname || parsed.username || parsed.password) return null;
      return parsed;
    } catch (_) {
      return null;
    }
  }

  /**
   * 1.9.2 — MESMA ORIGEM de verdade: protocolo + hostname + porta (a comparação anterior do bloqueador
   * de pop-ups olhava só o host e aceitava subdomínios nos dois sentidos). `dest` pode ser relativo a
   * `base`. Origem opaca (data:, about:, file:) NUNCA é "mesma origem". blob:/filesystem: herdam a origem
   * de quem os criou (new URL(...).origin já resolve isso).
   */
  function isSameOrigin(dest, base) {
    try {
      const d = new URL(String(dest), String(base));
      const b = new URL(String(base));
      if (d.origin === 'null' || b.origin === 'null') return false;
      return d.origin === b.origin;
    } catch (_) { return false; }
  }

  function isHttpUrl(value) {
    return !!parseHttpUrl(value);
  }

  /** WebFrameMain: o frame principal não possui parent (API Electron). */
  function isTopLevelFrame(frame) {
    try { return !!frame && frame.parent === null; }
    catch (_) { return false; }
  }

  /** Recebe somente hostname (sem esquema, porta, caminho ou wildcard). */
  function normalizeHostname(value) {
    if (typeof value !== 'string') return '';
    let raw = value.trim().toLowerCase();
    if (!raw || raw.length > 260 || /[\s\u0000-\u001f\u007f/@?#\\]/.test(raw)) return '';
    if (raw.startsWith('*.')) return '';
    if (raw.endsWith('.')) raw = raw.slice(0, -1);
    if (!raw) return '';

    // IPv6 precisa permanecer entre colchetes para corresponder ao URL.hostname.
    if (raw.startsWith('[') && raw.endsWith(']')) {
      try {
        const parsed = new URL('http://' + raw + '/');
        return parsed.hostname === raw && parsed.port === '' ? raw : '';
      } catch (_) { return ''; }
    }
    if (raw.includes(':')) return ''; // evita aceitar portas e formatos ambíguos

    try {
      const parsed = new URL('http://' + raw + '/');
      if (parsed.port || parsed.username || parsed.password || parsed.pathname !== '/') return '';
      let host = parsed.hostname.toLowerCase().replace(/\.$/, '');
      if (host.startsWith('www.')) host = host.slice(4);
      if (!host || host.length > 253) return '';
      const labels = host.split('.');
      if (labels.some(label => !label || label.length > 63 ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) return '';
      return host;
    } catch (_) {
      return '';
    }
  }

  function isPolicyErrorCode(code) {
    const text = String(code == null ? '' : code).toUpperCase();
    if (/^ERR_BLOCKED_BY_(CLIENT|ADMINISTRATOR|EXTENSION)$/.test(text)) return true;
    return [-20, -21, -22].includes(Number(text));
  }

  function validateSetting(key, value) {
    if (key === 'homepage') {
      if (typeof value !== 'string') throw new TypeError('A página inicial precisa ser um texto.');
      const clean = value.trim();
      if (!clean) return '';
      if (!isHttpUrl(clean)) throw new TypeError('A página inicial precisa usar um endereço HTTP ou HTTPS válido, sem credenciais.');
      return clean;
    }
    if (key === 'searchEngine') {
      if (typeof value !== 'string' || !SEARCH_ENGINES.has(value)) {
        throw new TypeError('Mecanismo de pesquisa não permitido.');
      }
      return value;
    }
    if (BOOLEAN_SETTINGS.has(key)) {
      if (typeof value !== 'boolean') throw new TypeError('Esta configuração precisa ser verdadeiro ou falso.');
      return value;
    }
    if (key === 'hibernateMinutes') {
      const number = Number(value);
      if (!Number.isFinite(number)) throw new TypeError('O intervalo de suspensão precisa ser numérico.');
      return Math.round(Math.min(180, Math.max(3, number)));
    }
    // 1.8.9 — cofre nativo: minutos de inatividade antes do autolock
    if (key === 'vaultAutolockMinutes') {
      const n = Number(value);
      if (!Number.isFinite(n)) throw new TypeError('O tempo de autolock precisa ser numérico.');
      return Math.round(Math.min(720, Math.max(1, n)));
    }
    // ---- 1.6.0 ----
    if (key === 'torPort') {
      const n = Number(value);
      if (!Number.isFinite(n)) throw new TypeError('A porta do Tor precisa ser numérica.');
      return Math.round(Math.min(65535, Math.max(1024, n)));
    }
    if (key === 'translateTarget') {
      if (typeof value !== 'string' || !/^[a-z]{2}$/.test(value)) {
        throw new TypeError('Idioma de destino inválido.');
      }
      return value;
    }
    if (URL_SETTINGS.has(key)) {
      if (typeof value !== 'string') throw new TypeError('Este campo precisa ser um endereço.');
      const clean = value.trim();
      if (!clean) return '';
      const parsed = parseHttpUrl(clean);
      if (!parsed) throw new TypeError('Informe um endereço http/https válido.');
      return parsed.href.replace(/\/+$/, '');
    }
    if (ENUM_SETTINGS[key]) {
      if (typeof value !== 'string' || !ENUM_SETTINGS[key].has(value)) {
        throw new TypeError('Valor não permitido para ' + key + '.');
      }
      return value;
    }
    // ---- 1.7.0 (nativo: SponsorBlock / Consent-O-Matic / LanguageTool) ----
    if (key === 'sbCategories') {
      if (!Array.isArray(value)) throw new TypeError('Categorias inválidas.');
      const out = [...new Set(value.map(x => String(x || '')).filter(x => SB_CATEGORIES.has(x)))];
      return out;
    }
    if (key === 'cmCooldownHours') {
      const n = Number(value);
      if (!Number.isFinite(n)) throw new TypeError('O cooldown precisa ser numérico.');
      return Math.round(Math.min(720, Math.max(1, n)));
    }
    if (key === 'cmWhitelist' || key === 'fpExempt') {
      if (!Array.isArray(value)) throw new TypeError('A lista de exceções precisa ser uma lista de domínios.');
      const out = [];
      for (const raw of value) {
        const d = normalizeHostname(raw);
        if (d && !out.includes(d)) out.push(d);
        if (out.length >= 100) break;
      }
      return out;
    }
    if (key === 'languagetoolLang') {
      if (typeof value !== 'string') throw new TypeError('Idioma inválido.');
      const v = value.trim();
      if (v === 'auto') return 'auto';
      if (!/^[a-z]{2}(-[A-Z]{2})?$/.test(v)) throw new TypeError('Idioma inválido.');
      return v;
    }
    throw new TypeError('Configuração desconhecida: ' + String(key));
  }

  return Object.freeze({
    SEARCH_ENGINES,
    BOOLEAN_SETTINGS,
    URL_SETTINGS,
    ENUM_SETTINGS,
    parseHttpUrl,
    isHttpUrl,
    isSameOrigin,
    isTopLevelFrame,
    normalizeHostname,
    isPolicyErrorCode,
    validateSetting
  });
});

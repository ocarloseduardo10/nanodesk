/**
 * NanoDesk — Perfil local OPCIONAL (1.6.0, FASE 2)
 * ==================================================================
 * A identidade do NanoDesk é "zero dados gravados": por padrão,
 * configurações, favoritos e histórico vivem SÓ na RAM. A
 * especificação pede também perfis/configurações persistentes —
 * então existe agora um PERFIL LOCAL EXPLÍCITO E OPCIONAL:
 *
 *  - Desligado (padrão): nada muda — nada é lido nem escrito no disco;
 *    resíduos de sessões antigas continuam sendo apagados na partida.
 *  - Ligado (checkbox "Manter configurações e favoritos entre sessões"):
 *    grava APENAS dois arquivos pequenos em userData:
 *      prefs.json    → { persistentData: boolean } (a própria chave)
 *      settings.json → configurações escolhidas
 *      favorites.json→ favoritos (com pastas/etiquetas)
 *    Histórico, cookies e dados de sites NUNCA são persistidos —
 *    nem com o perfil ligado.
 *
 * Os arquivos são gravados por rename atômico (tmp → final) e com
 * chmod 0600. Nenhuma criptografia própria é inventada (diretriz da
 * especificação: não criar criptografia própria); os dados guardados
 * aqui não são segredos (nada de senhas).
 */
'use strict';

const fs = require('fs');
const path = require('path');

const PREFS_FILE = 'prefs.json';
const SETTINGS_FILE = 'settings.json';
const FAVORITES_FILE = 'favorites.json';
const LEGACY_WIPE = [
  'settings.json', 'history.json', 'favorites.json', 'adblock-allow.json',
  'downloads.json', 'session.json',
  'Local Storage', 'Session Storage', 'IndexedDB', 'databases',
  'Service Worker', 'Cache', 'Code Cache', 'GPUCache', 'Cookies', 'Partitions',
  'Crashpad', 'crashdumps', 'crashDumps',
  'tor-runtime'   // 1.6.1: resíduo do Tor nativo do 1.5.3 (agora vive na pasta temporária)
];

/**
 * 1.9.3 — o perfil local está LIGADO? Lê só o prefs.json (sem criar/Carregar o ProfileStore).
 * Existe porque a limpeza de arranque roda ANTES de initStores(): com `profile` ainda nulo ela
 * concluía "perfil desligado" e APAGAVA settings.json/favorites.json de quem usa perfil persistente
 * (perda de dados a cada reinício).
 */
function isProfileEnabled(dir, deps) {
  const read = (deps && deps.readJson) || readJson;
  const prefs = read(path.join(String(dir || ''), PREFS_FILE));
  return !!(prefs && prefs.persistentData === true);
}

/** Escrita atômica + permissão restrita (best-effort no Windows). */
function writeJsonAtomic(file, data) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 1), 'utf8');
  try { fs.chmodSync(tmp, 0o600); } catch (_) { /* Windows pode negar */ }
  fs.renameSync(tmp, file);
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (_) {
    return null;
  }
}

class ProfileStore {
  /**
   * @param {string} dir   userData do app
   * @param {object} [deps] { readJson, writeJsonAtomic, rmSync } (testes)
   */
  constructor(dir, deps = {}) {
    this.dir = String(dir || '');
    this._read = deps.readJson || readJson;
    this._write = deps.writeJsonAtomic || writeJsonAtomic;
    this.enabled = false;
  }

  file(name) { return path.join(this.dir, name); }

  /**
   * Carrega a chave "persistentData". Se o perfil estava LIGADO,
   * carrega também settings/favorites (objeto ou null).
   * @returns {{ enabled:boolean, settings:object|null, favorites:object|null }}
   */
  load() {
    const prefs = this._read(this.file(PREFS_FILE));
    const enabled = !!(prefs && prefs.persistentData === true);
    this.enabled = enabled;
    if (!enabled) return { enabled: false, settings: null, favorites: null };
    return {
      enabled: true,
      settings: this._read(this.file(SETTINGS_FILE)),
      favorites: this._read(this.file(FAVORITES_FILE))
    };
  }

  setEnabled(v) {
    this.enabled = v === true;
    try {
      this._write(this.file(PREFS_FILE), { persistentData: this.enabled });
    } catch (_) { /* disco cheio/permissão: perfil segue desligado */ }
    if (!this.enabled) {
      // desligar o perfil apaga os dados guardados (o usuário decide
      // conscientemente) — prefs.json permanece com a flag false
      for (const f of [SETTINGS_FILE, FAVORITES_FILE]) {
        try { fs.rmSync(this.file(f), { force: true }); } catch (_) { /* ignorado */ }
      }
    }
    return this.enabled;
  }

  saveSettings(data) {
    if (!this.enabled) return false;
    try { this._write(this.file(SETTINGS_FILE), data || {}); return true; }
    catch (_) { return false; }
  }

  saveFavorites(data) {
    if (!this.enabled) return false;
    try { this._write(this.file(FAVORITES_FILE), data || { items: [] }); return true; }
    catch (_) { return false; }
  }
}

/**
 * Apaga resíduos de versões anteriores — SÓ quando o perfil está
 * desligado (com perfil ativo os arquivos settings/favorites são dados
 * do usuário e precisam sobreviver à partida).
 */
function wipeLegacyData(dir, { keepProfileFiles = true } = {}, deps = {}) {
  const rm = deps.rmSync || ((p, o) => fs.rmSync(p, o));
  for (const name of LEGACY_WIPE) {
    if (keepProfileFiles && (name === 'settings.json' || name === 'favorites.json')) continue;
    try { rm(path.join(dir, name), { recursive: true, force: true }); }
    catch (_) { /* pode não existir */ }
  }
}

module.exports = {
  ProfileStore,
  isProfileEnabled,
  wipeLegacyData,
  writeJsonAtomic,
  readJson,
  FILES: { PREFS_FILE, SETTINGS_FILE, FAVORITES_FILE },
  LEGACY_WIPE
};

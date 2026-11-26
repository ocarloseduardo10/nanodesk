/**
 * NanoDesk — Pacote embutido de listas de filtro (1.3.1)
 * ==================================================================
 * Inspirado no navegador Blanc (github.com/bnfy/blanc): um snapshot
 * do EasyList + EasyPrivacy + resources.json (uBO) acompanha o app
 * e é verificado por SHA-256 a CADA carregamento, servindo como
 * fallback offline do motor Ghostery.
 *
 * Por quê:
 *  - Na 1.3.0, se o CDN não respondesse no arranque, o motor Ghostery
 *    ficava indisponível (só o motor nativo protegia). Agora existe
 *    proteção EasyList/EasyPrivacy mesmo sem internet.
 *  - Hash verificado em runtime: um snapshot adulterado no disco é
 *    descartado em vez de usado (integridade tipo "release assets").
 *
 * Atribuição obrigatória (CC BY-SA 3.0):
 *  - EasyList: © The EasyList authors — https://easylist.to/
 *  - EasyPrivacy: © The EasyList authors — https://easylist.to/
 *  - resources.json: uBlock Origin (GPL-3.0), via assets do
 *    @ghostery/adblocker. Veja README.md > "Listas de filtro".
 *
 * Nada aqui é gravado em disco pelo app: o pacote é somente-leitura
 * e o cache do motor continua na pasta temporária da sessão.
 */
'use strict';

const path = require('path');
const crypto = require('crypto');

/** Arquivos que o manifesto precisa declarar. */
const OBRIGATORIOS = ['easylist', 'easyprivacy'];

/** Calcula SHA-256 de um Buffer, em hex. */
function sha256Buf(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/**
 * Verificação PURA (testável): manifesto × conteúdo carregado.
 * @param {object} manifest manifest.json parseado
 * @param {object} files    { nome: Buffer } para cada arquivo declarado
 * @returns {string[]} lista de erros (vazia = OK)
 */
function verifyManifest(manifest, files) {
  const erros = [];
  if (!manifest || typeof manifest !== 'object' || !manifest.files ||
      typeof manifest.files !== 'object') {
    return ['manifest.json inválido ou sem "files"'];
  }
  for (const key of OBRIGATORIOS) {
    if (!manifest.files[key]) erros.push(`"${key}" ausente no manifesto`);
  }
  for (const key of Object.keys(manifest.files)) {
    const entry = manifest.files[key] || {};
    const buf = files[key];
    if (!Buffer.isBuffer(buf)) { erros.push(`${key}: arquivo ausente`); continue; }
    if (typeof entry.sha256 !== 'string' || entry.sha256.length !== 64) {
      erros.push(`${key}: sha256 ausente/inválido no manifesto`);
      continue;
    }
    if (sha256Buf(buf) !== entry.sha256.toLowerCase()) {
      erros.push(`${key}: hash SHA-256 não confere (arquivo adulterado ou corrompido)`);
    }
  }
  return erros;
}

/**
 * Carrega e verifica o pacote embutido. Lança erro se TUDO não
 * estiver íntegro — o chamador deve tratar (nunca usar listas
 * comprometidas).
 * @param {string} baseDir pasta com manifest.json + arquivos
 * @param {object} deps    { readFileSync } injetável para testes
 */
function loadBundle(baseDir, deps = {}) {
  const read = deps.readFileSync || require('fs').readFileSync;
  const manifestPath = path.join(baseDir, 'manifest.json');
  let manifest;
  try {
    manifest = JSON.parse(read(manifestPath, 'utf8'));
  } catch (e) {
    throw new Error('manifest.json do pacote de filtros ilegível: ' + e.message);
  }

  const files = {};
  for (const key of Object.keys((manifest && manifest.files) || {})) {
    const file = (manifest.files[key] && manifest.files[key].file) || `${key}.txt`;
    try {
      files[key] = read(path.join(baseDir, file));
    } catch (e) {
      files[key] = null; // verifyManifest aponta como ausente
    }
  }

  const erros = verifyManifest(manifest, files);
  if (erros.length) {
    throw new Error('Pacote de filtros NÃO íntegro: ' + erros.join('; '));
  }

  // 1.6.8: TODAS as listas declaradas no manifesto viram texto (o pacote
  // completo acompanha o modo online: uAssets filters + quick-fixes — onde
  // vivem as defesas anti-adblock do YouTube — + unbreak + badware + privacy
  // + resource-abuse + filters por ano).
  const texts = {};
  for (const key of Object.keys(manifest.files)) {
    texts[key] = files[key] ? files[key].toString('utf8') : '';
  }

  /** Ordem fixa de casamento URL→lista. Padrões ANCORADOS ao nome do
   *  arquivo (fim de URL): "privacy.txt" NÃO pode casar dentro de
   *  "easyprivacy.txt" (bug pego pelo teste de regressão 1.6.8). */
  const BY_URL = [
    ['resources\\.json$', 'resources'],      // a URL de resources contém "ublock-origin"
    ['easylist\\.txt$', 'easylist'],
    ['easyprivacy\\.txt$', 'easyprivacy'],
    ['(?:^|[\\\\/])ublock\\.txt$', 'ublock'],
    ['ublock-2020\\.txt$', 'ublock2020'],
    ['ublock-2021\\.txt$', 'ublock2021'],
    ['ublock-2022\\.txt$', 'ublock2022'],
    ['ublock-2023\\.txt$', 'ublock2023'],
    ['ublock-2024\\.txt$', 'ublock2024'],
    ['ublock-2025\\.txt$', 'ublock2025'],
    ['badware\\.txt$', 'badware'],
    ['(?:^|[\\\\/])privacy\\.txt$', 'privacy'],
    ['resource-abuse\\.txt$', 'resourceabuse'],
    ['(?:quick-fixes|quickfixes)\\.txt$', 'quickfixes'],
    ['unbreak\\.txt$', 'unbreak']
  ];

  return {
    meta: {
      generatedAt: manifest.generatedAt || 'desconhecida',
      sources: manifest.sources || {},
      license: manifest.license || 'CC BY-SA 3.0'
    },
    easylist: texts.easylist,
    easyprivacy: texts.easyprivacy,
    resources: texts.resources,
    /** Todas as listas por chave do manifesto (para montar a parseEmbedded). */
    all() { return { ...texts }; },
    /**
     * Serve um "URL" para o fromLists do @ghostery/adblocker:
     * nomes bundled://* devolvem a lista pedida; qualquer outro
     * pedido (resources.json) devolve o resources embutido.
     */
    for(url) {
      const u = String(url);
      for (const [pattern, key] of BY_URL) {
        if (new RegExp(pattern).test(u) && texts[key]) return texts[key];
      }
      return texts.resources;
    }
  };
}

module.exports = { sha256Buf, verifyManifest, loadBundle, OBRIGATORIOS };

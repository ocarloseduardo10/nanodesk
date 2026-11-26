/**
 * NanoDesk — Utilitários de download (puros, testáveis sem Electron)
 * ------------------------------------------------------------------
 * - safeFileName : neutraliza nomes vindos do servidor (path traversal,
 *                  caracteres inválidos e nomes reservados do Windows);
 * - uniquePath   : nunca sobrescreve arquivos existentes ("nome (1).ext");
 * - isRiskyFile  : extensões executáveis/scripts, que o NanoDesk NÃO
 *                  executa automaticamente (confirmação explícita);
 * - sha256File   : verificação de integridade do arquivo salvo;
 * - LIMITS       : limites de tamanho e de downloads simultâneos.
 *
 * O fluxo de download em si usa o electron-dl no processo principal.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const RISKY_EXT = new Set([
  // Windows: executáveis e instaladores
  '.exe', '.msi', '.msix', '.msixbundle', '.appx', '.appxbundle', '.msp',
  '.mst', '.com', '.scr', '.pif', '.cpl', '.msc', '.dll', '.ocx', '.drv',
  // Scripts e automação
  '.bat', '.cmd', '.ps1', '.psm1', '.psd1', '.vbs', '.vbe', '.js', '.jse',
  '.wsf', '.wsh', '.wsb', '.hta', '.sh', '.bash', '.py', '.pyw', '.rb',
  // CORREÇÃO 1.6.7: ".jnilink" não existe (typo) — o intento era ".jnlp"
  // (Java Web Start, realmente arriscado).
  '.pl', '.php', '.jar', '.jnlp',
  // Atalhos e configuração perigosa
  '.lnk', '.url', '.reg', '.inf', '.gadget', '.application', '.appinstaller',
  '.diagcab', '.chm', '.hlp',
  // Outros sistemas / imagens montáveis
  '.apk', '.deb', '.rpm', '.dmg', '.pkg', '.iso', '.img', '.vhd', '.vhdx',
  // 1.8.11: tipos que executam código/abrem recursos remotos no Windows e não estavam na lista
  '.sys', '.ps1xml', '.ps2', '.psc1', '.wsc', '.ws', '.vb', '.vbscript', '.ins', '.isp',
  '.scf', '.theme', '.themepack', '.xbap', '.website', '.rdp', '.job', '.shs', '.shb', '.xnk',
  '.appref-ms', '.library-ms', '.search-ms', '.searchconnector-ms', '.settingcontent-ms', '.diagpkg',
  '.msh', '.msh1', '.msh2', '.mshxml', '.msh1xml', '.msh2xml',
  // macros do Office e vetores de add-in/consulta externa
  '.docm', '.dotm', '.xlsm', '.xltm', '.xlam', '.pptm', '.potm', '.ppam', '.sldm',
  '.xll', '.wll', '.iqy', '.slk', '.ade', '.adp', '.mda', '.accde', '.accdr', '.grp',
  // HTML local (HTML smuggling / phishing aberto no navegador padrão com origem file://)
  '.htm', '.html', '.xhtml', '.mht', '.mhtml', '.svg'
]);

const RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

/** Limites do gerenciador de downloads. */
const LIMITS = {
  maxMB: 2048,        // cancela acima de 2 GB (evita esgotar o disco)
  maxConcurrent: 5    // proteção contra downloads repetitivos em cascata
};

function safeFileName(name) {
  // normaliza separadores do Windows antes de tirar o caminho
  let n = path.basename(String(name || '').replace(/\\/g, '/'));
  n = n.replace(/[<>:"/\\|?*\u0000-\u001f]/g, '_');
  n = n.replace(/^\.+/, '').trim();
  n = n.replace(/[. ]+$/, '');
  if (!n) n = 'download';
  if (RESERVED.test(n)) n = '_' + n;
  if (n.length > 180) {
    const ext = path.extname(n).slice(0, 20);
    n = n.slice(0, 180 - ext.length) + ext;
  }
  return n;
}

function pathKey(candidate) {
  const resolved = path.resolve(candidate);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

/** Considera arquivos existentes e reservas em memória de downloads simultâneos. */
function uniquePath(dir, name, exists = fs.existsSync, reserved = new Set()) {
  const ext = path.extname(name);
  const base = path.basename(name, ext);
  let candidate = path.join(dir, name);
  let i = 0;
  while (exists(candidate) || reserved.has(pathKey(candidate)) || reserved.has(candidate)) {
    i++;
    if (i >= 10000) throw new Error('Não foi possível reservar um nome único para o download.');
    candidate = path.join(dir, base + ' (' + i + ')' + ext);
  }
  return candidate;
}

function isRiskyFile(name) {
  return RISKY_EXT.has(path.extname(String(name || '')).toLowerCase());
}

/** SHA-256 do arquivo salvo (verificação de integridade exibida ao usuário). */
function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath, { highWaterMark: 4 * 1024 * 1024 });
    stream.on('error', reject);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

module.exports = {
  safeFileName, uniquePath, pathKey, isRiskyFile, sha256File,
  RISKY_EXT, LIMITS
};

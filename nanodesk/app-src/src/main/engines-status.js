/**
 * NanoDesk 1.9.3 — estado dos MOTORES de varredura (para o painel de Segurança).
 * ------------------------------------------------------------------
 * Objetivo (auditoria): nunca deixar o usuário supor que há antivírus quando não há. O painel mostra, por
 * motor: se está ATIVO, a versão, a idade/versão das assinaturas e o MOTIVO quando não está disponível.
 * Módulo puro: recebe dependências (existsSync, leitura de cabeçalho .cvd, versão do clamscan).
 */
'use strict';

const fs = require('fs');
const path = require('path');

/** "ClamAV 1.5.4/27123/Tue Nov 17 ..." → {version, dbVersion} */
function parseClamVersion(text) {
  const m = /ClamAV\s+([0-9][0-9.]*)(?:\/(\d+))?/i.exec(String(text || ''));
  return m ? { version: m[1], dbVersion: m[2] ? parseInt(m[2], 10) : 0 } : { version: '', dbVersion: 0 };
}

/** Lê os cabeçalhos dos .cvd/.cld de uma pasta (versão, nº de assinaturas, data de criação). */
function readDbFiles(dir, parseHeader, deps) {
  const d = deps || {};
  const readdir = d.readdirSync || fs.readdirSync;
  const stat = d.statSync || fs.statSync;
  const readHead = d.readHead || ((f) => { const fd = fs.openSync(f, 'r'); try { const b = Buffer.alloc(512); fs.readSync(fd, b, 0, 512, 0); return b; } finally { fs.closeSync(fd); } });
  const out = [];
  let names = [];
  try { names = readdir(dir); } catch (_) { return out; }
  for (const f of names.sort()) {
    const m = /^(main|daily|bytecode)\.(cvd|cld)$/i.exec(f);
    if (!m) continue;
    const full = path.join(dir, f);
    let hdr = null; let mtime = 0; let size = 0;
    try { const st = stat(full); mtime = st.mtimeMs; size = st.size; hdr = parseHeader(readHead(full)); } catch (_) { /* arquivo ilegível */ }
    out.push({ name: f, version: hdr ? hdr.version : 0, sigs: hdr ? hdr.sigs : 0, created: hdr ? hdr.created : '', mtime, size, valid: !!hdr });
  }
  return out;
}

/**
 * @param {object} i
 *   clamBinary, clamBundled, clamVersionText, dbDir, dbPersist, dbStatus {complete, ageDays}, dbFiles[],
 *   skipReasonText, torInUse, yaraBinary, yaraRules, nativeHashCount, appVersion, staleDays
 */
function buildEnginesStatus(i) {
  const stale = i.staleDays || 14;
  const ver = parseClamVersion(i.clamVersionText);
  const dbOk = !!(i.dbStatus && i.dbStatus.complete);
  const age = i.dbStatus ? i.dbStatus.ageDays : Infinity;
  let clamState; let clamWhy = '';
  if (!i.clamBinary) { clamState = 'ausente'; clamWhy = 'Binário do ClamAV não encontrado.'; }
  else if (!dbOk) {
    clamState = 'sem-base';
    clamWhy = i.skipReasonText || (i.torInUse ? 'O Tor está em uso: a base só é baixada pelo Tor, com a sua permissão.' : 'A base de assinaturas ainda não foi baixada.');
  } else if (age > stale) { clamState = 'base-antiga'; clamWhy = 'Base com ' + Math.floor(age) + ' dias (limite ' + stale + ').'; }
  else clamState = 'ativo';
  const daily = (i.dbFiles || []).find((f) => /^daily/i.test(f.name));
  const main = (i.dbFiles || []).find((f) => /^main/i.test(f.name));
  const sigs = (i.dbFiles || []).reduce((n, f) => n + (f.sigs || 0), 0);
  const engines = [
    {
      id: 'clamav', nome: 'ClamAV (antivírus)', estado: clamState, ativo: clamState === 'ativo' || clamState === 'base-antiga',
      versao: ver.version || (i.clamBinary ? '?' : ''), embutido: !!i.clamBundled,
      base: dbOk ? { assinaturas: sigs, daily: daily ? daily.version : 0, main: main ? main.version : 0, idadeDias: Math.floor(age), persistente: !!i.dbPersist, pasta: i.dbDir || '' } : null,
      motivo: clamWhy
    },
    {
      id: 'yara', nome: 'YARA (regras)', estado: i.yaraBinary && i.yaraRules ? 'ativo' : 'indisponivel', ativo: !!(i.yaraBinary && i.yaraRules),
      versao: '', embutido: false, base: null,
      motivo: i.yaraBinary && i.yaraRules ? '' : (!i.yaraRules ? 'Sem regras: defina NANODESK_YARA_RULES.' : 'YARA não está instalado (não vem no pacote).')
    },
    {
      id: 'nativo', nome: 'Scanner nativo (heurístico)', estado: 'ativo', ativo: true, versao: i.appVersion || '', embutido: true,
      base: { hashesDoUsuario: i.nativeHashCount || 0 },
      motivo: 'NÃO é antivírus: procura sinais (estrutura PE, strings, combinações de APIs). Lista de hashes embutida vazia; aceita a sua.'
    }
  ];
  const avAtivo = engines.filter((e) => e.id !== 'nativo' && e.ativo).length > 0;
  return {
    engines,
    antivirusAtivo: avAtivo,
    resumo: avAtivo
      ? 'Há varredura antivírus ativa. Mesmo assim, "nenhuma ameaça detectada" não é garantia de segurança.'
      : 'NENHUM antivírus ativo: os downloads aparecem como "SEM varredura antivírus" (só análise local limitada).'
  };
}

module.exports = { parseClamVersion, readDbFiles, buildEnginesStatus };

/**
 * NanoDesk — Camada CENTRAL de segurança de downloads (1.9.6)
 * ==================================================================
 * ERRO 2 (1.9.5): o fluxo de engines externos (aria2/Gopeed) terminava no
 * DownloadManager.finalizeRec(), que calculava apenas o SHA-256 — sem limite
 * de tamanho, sem validação de destino, sem inspeção, sem quarentena e sem o
 * Security Gateway. Só o fluxo Electron (handleNewDownload) passava por tudo
 * isso. Esta centraliza as regras QUE TODO ENGINE precisa respeitar, em
 * funções PURAS (testáveis sem Electron):
 *
 *  - validateStart(task, opts)      : limites de tamanho e de simultaneidade
 *                                     ANTES de qualquer engine tocar a rede;
 *  - validateTaskProxy(task)        : ERRO 1 — tarefa de aba Tor exige proxy
 *                                     Tor validado (socks5 em loopback);
 *                                     sem proxy, o engine DEVE recusar (a
 *                                     tarefa NUNCA sai por conexão direta);
 *  - isValidTorProxy(proxy)         : só aceita socks5://127.0.0.1:<porta>
 *                                     (o daemon Tor EMBUTIDO do NanoDesk);
 *  - isInsideDir(filePath, dir)     : validação do caminho de destino (o
 *                                     arquivo finalizado tem de estar dentro
 *                                     da pasta acordada — anti path traversal);
 *  - sizeExceedsLimit(bytes, maxMB) : limite de tamanho uniforme (2 GB).
 *
 * O que continua por engine (e por quê):
 *  - Electron: diálogo de executável + will-download no main (fluxo 1.5.x/1.6.x);
 *  - TODOS os engines: ao COMPLETAR, o DownloadManager chama o gate de
 *    segurança injetado (no main.js: tipo real por magic bytes, inspeção de
 *    ZIP, scanner nativo, ClamAV/YARA, veredito, quarentena, eventos) — a
 *    MESMA fila queueScan() do fluxo Electron.
 */
'use strict';

const path = require('path');

/** Proxy Tor válido = SOCKS5 do daemon embutido, apenas em loopback. */
const TOR_PROXY_RE = /^socks5:\/\/127\.0\.0\.1:\d{2,5}$/;

/**
 * Aceita SOMENTE o formato do proxy Tor local do NanoDesk
 * (socks5://127.0.0.1:<porta>, porta do daemon embutido).
 * Qualquer outra coisa (http, host externo, socks remoto) é recusada —
 * um proxy não validado poderia ser uma rota de fuga da rede Tor.
 */
function isValidTorProxy(proxy) {
  return typeof proxy === 'string' && TOR_PROXY_RE.test(proxy);
}

/**
 * A tarefa exige rede via Tor (aba Tor/partição Tor)?
 * @param {object} task tarefa de download (interface download-engine-interface)
 */
function isTorTask(task) {
  return !!(task && task.torRequired === true);
}

/**
 * ERRO 1 (1.9.6) — regra de proxy para TODOS os engines.
 *
 * @param {object} task tarefa (com torRequired?/proxy?)
 * @returns {string|null} null = liberada; texto = motivo da RECUSA
 *   (fail-closed: o engine não inicia a tarefa — nunca conecta direto).
 */
function validateTaskProxy(task) {
  if (!task || typeof task !== 'object') return 'tarefa inválida';
  if (task.proxy !== undefined && task.proxy !== null && task.proxy !== '') {
    // Proxy informado: precisa ser o socks5 de loopback validado.
    if (!isValidTorProxy(task.proxy)) {
      return 'proxy recusado: só é aceito o proxy Tor local do NanoDesk (socks5://127.0.0.1:<porta>)';
    }
    return null;
  }
  if (isTorTask(task)) {
    // Tarefa de aba Tor SEM proxy validado: RECUSA — conexão direta vazaria
    // o IP real exatamente quando o usuário escolheu não expô-lo.
    return 'download interrompido: o proxy Tor não está disponível para validar esta tarefa (falha segura — nenhuma conexão direta foi feita)';
  }
  return null;
}

/**
 * Limite de tamanho uniforme para todos os engines (igual ao fluxo Electron
 * dl.LIMITS.maxMB). @returns {boolean} true = excede, deve ser cancelado.
 */
function sizeExceedsLimit(bytes, maxMB) {
  const n = Number(bytes) || 0;
  const limit = (Number(maxMB) > 0 ? Number(maxMB) : 2048) * 1024 * 1024;
  return n > limit;
}

/**
 * Validação de início (antes de escolher engine): limites de tamanho e de
 * simultaneidade. Pura — o caller informa o número de downloads ativos.
 * @param {object} task tarefa validada (validateTask do engine-interface)
 * @param {object} opts { maxMB?: number, maxConcurrent?: number, activeCount?: number,
 *                        totalExpected?: number }
 * @returns {string|null} null = pode iniciar; texto = motivo da recusa
 */
function validateStart(task, opts = {}) {
  const maxConcurrent = Number(opts.maxConcurrent) || 5;
  const active = Number(opts.activeCount) || 0;
  if (active >= maxConcurrent) {
    return 'Limite de ' + maxConcurrent + ' downloads simultâneos atingido.';
  }
  const expected = Number(opts.totalExpected) || Number(task && task.totalExpected) || 0;
  if (sizeExceedsLimit(expected, opts.maxMB)) {
    return 'Download cancelado: arquivo maior que o limite de ' +
      (Number(opts.maxMB) > 0 ? Number(opts.maxMB) : 2048) + ' MB.';
  }
  return null;
}

/**
 * O caminho do arquivo finalizado está DENTRO da pasta de destino acordada?
 * Usado no finalize de TODO engine (aria2/Gopeed podem auto-renomear, mas o
 * arquivo tem de permanecer na pasta pedida — nunca em ../ nem fora).
 * @returns {boolean} true = caminho válido (dentro de dir)
 */
function isInsideDir(filePath, dir) {
  try {
    if (!filePath || !dir) return false;
    let f = path.resolve(String(filePath));
    let d = path.resolve(String(dir));
    // Windows (NTFS) é insensível a caixa: normalizar ANTES do relative,
    // senão "C:\Downloads" vs "c:\downloads" produzia um rel de "..\..\".
    if (process.platform === 'win32') { f = f.toLowerCase(); d = d.toLowerCase(); }
    if (f === d) return false;                    // é a própria pasta, não um arquivo
    const rel = path.relative(d, f);
    if (rel === '' || rel.startsWith('..')) return false;
    return true;
  } catch (_) { return false; }
}

module.exports = {
  TOR_PROXY_RE,
  isValidTorProxy,
  isTorTask,
  validateTaskProxy,
  validateStart,
  sizeExceedsLimit,
  isInsideDir
};

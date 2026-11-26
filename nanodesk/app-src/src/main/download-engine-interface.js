/**
 * NanoDesk — Interface comum de adaptadores de download (1.9.5)
 * ==================================================================
 * Define o contrato que TODOS os mecanismos (Electron, aria2, Gopeed) implementam.
 * Cada download é atribuído a UM único mecanismo pelo DownloadManager — nunca
 * há disputa (especificação 4.3: "Não permita que aria2, Gopeed e Electron
 * disputem a mesma tarefa").
 *
 * Interface (métodos obrigatórios):
 *   name()                          -> string ('electron'|'aria2'|'gopeed')
 *   isAvailable()                   -> boolean (binário/processo pronto)
 *   start(task)                     -> Promise<string> gid (id interno do engine)
 *   pause(gid)                      -> Promise<boolean>
 *   resume(gid)                     -> Promise<boolean>
 *   cancel(gid)                     -> Promise<boolean>
 *   status(gid)                     -> Promise<EngineStatus>
 *   recover()                       -> Promise<Array> tarefas persistidas (aria2/gopeed)
 *   shutdown()                      -> Promise<void> encerra processo auxiliar se houver
 *
 * EngineStatus = {
 *   state: 'waiting'|'downloading'|'paused'|'completed'|'error'|'verifying',
 *   received, total, speed (bytes/s), etaSec?, error?
 * }
 *
 * Task = {
 *   id (NanoDesk), url, tabId?, webContentsId?, sessionPartition?,
 *   outDir, fileName, headers?, cookies?: [{name,value,domain,path,secure,expirationDate}],
 *   engine?, referrer?, mimeExpected?, totalExpected?
 * }
 *
 * Núcleo puro (sem Electron): só define a interface e tipagem em JSDoc.
 */
'use strict';

/** Estados possíveis (especificação 5). */
const STATES = Object.freeze({
  WAITING: 'waiting',
  RESOLVING: 'resolving',
  DOWNLOADING: 'downloading',
  PAUSED: 'paused',
  COMPLETED: 'completed',
  CANCELLED: 'cancelled',
  ERROR: 'error',
  VERIFYING: 'verifying'
});

/** Template de validação de uma Task antes de passar ao engine. */
function validateTask(task) {
  if (!task || typeof task !== 'object') return 'task ausente';
  if (typeof task.url !== 'string' || !/^https?:\/\//i.test(task.url)) return 'url inválida';
  if (typeof task.outDir !== 'string' || !task.outDir) return 'outDir inválido';
  if (typeof task.fileName !== 'string' || !task.fileName) return 'fileName inválido';
  // path traversal: fileName NÃO pode conter .. ou separadores
  if (/[\\/]/.test(task.fileName) || /\.\./.test(task.fileName)) return 'fileName com path';
  return null;
}

module.exports = { STATES, validateTask };

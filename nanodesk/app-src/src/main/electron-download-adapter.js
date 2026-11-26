/**
 * NanoDesk — Adaptador Electron (1.9.5)
 * ==================================================================
 * Envolve o electron-dl existente no contrato comum de engine. É o engine
 * PADRÃO para downloads que dependem da sessão autenticada da aba (especificação
 * 8: "preserve a sessão correta sem expor cookies ao renderer").
 *
 *  - Não inicia processo auxiliar: usa o electron-dl registrado na Session.
 *  - Pausa/retoma via DownloadItem.pause()/resume() do Electron.
 *  - Não suporta recover() — Electron não persiste tarefas entre reinícios.
 *  - start() devolve o id do DownloadItem (rec.id do main).
 *
 *  Este adaptador É um wrapper fino — a lógica de limite, diálogo de executável,
 *  quarentena e Security Gateway continua no main.js (handleNewDownload).
 *  Aqui só expomos pause/resume/cancel/status no formato comum.
 */
'use strict';

const { STATES, validateTask } = require('./download-engine-interface');

function createElectronAdapter(deps) {
  // deps = { sessionFor: (task) => Session, downloads: módulo downloads.js,
  //         downloadStore, activeDownloadItems: Map, handleNewDownload: fn,
  //         pushDownloads: fn, nowId: fn }
  const d = deps || {};
  const activeItems = d.activeDownloadItems || new Map();   // id -> DownloadItem

  function name() { return 'electron'; }

  function isAvailable() { return true; }   // electron-dl sempre disponível

  /**
   * Inicia um download via electron-dl com a sessão da aba de origem.
   * Devolve o id do registro NanoDesk (rec.id) — o caller usa esse id para
   * pause/resume/cancel.
   */
  async function start(task) {
    const err = validateTask(task);
    if (err) throw new Error(err);
    const ses = d.sessionFor ? d.sessionFor(task) : null;
    if (!ses) throw new Error('sessão indisponível para o download');
    // electron-dl: dl(session, url, opts) devolve o DownloadItem.
    // O handler 'will-download' no main.js já cria o rec e liga os eventos.
    // Aqui só disparamos downloadURL na sessão certa — o fluxo existente
    // cuida do resto (diálogo de executável, limits, scan, etc.).
    try {
      // 1.9.5: downloadURL respeita a sessão (Tor/contêiner) — não cria outro.
      // Para arquivos que precisam de headers/cookies, repassa via options.
      // O electron-dl V5 aceita `session.downloadURL(url, options)`.
      if (typeof ses.downloadURL === 'function') {
        const opts = {};
        if (task.headers) opts.headers = task.headers;
        // cookies: aplicados na sessão ANTES do download pelo caller (não aqui)
        ses.downloadURL(task.url, opts);
      } else {
        // Fallback: API antiga do Electron
        ses.downloadURL(task.url);
      }
      // O rec.id é gerado em handleNewDownload — não conhecemos aqui.
      // Devolvemos um placeholder; o manager associa o rec real quando
      // onStarted dispara. Para simplificar, devolvemos a URL como id
      // temporário e o manager casa por URL.
      return 'electron:' + task.url;
    } catch (e) {
      throw new Error('Falha ao iniciar download Electron: ' + (e && e.message || e));
    }
  }

  async function pause(id) {
    const item = activeItems.get(id);
    if (!item) return false;
    try { item.pause(); return true; } catch (_) { return false; }
  }

  async function resume(id) {
    const item = activeItems.get(id);
    if (!item) return false;
    try { item.resume(); return true; } catch (_) { return false; }
  }

  async function cancel(id) {
    const item = activeItems.get(id);
    if (!item) return false;
    try { item.cancel(); return true; } catch (_) { return false; }
  }

  async function status(id) {
    const item = activeItems.get(id);
    if (!item) return { state: STATES.ERROR, received: 0, total: 0, speed: 0, error: 'item não encontrado' };
    try {
      const received = item.getReceivedBytes();
      const total = item.getTotalBytes();
      const state = item.getState();   // 'progressing' | 'completed' | 'interrupted' | 'cancelled'
      return {
        state: mapState(state),
        received, total,
        speed: item.getCurrentBytesPerSecond ? item.getCurrentBytesPerSecond() : 0,
        path: item.getSavePath()
      };
    } catch (e) {
      return { state: STATES.ERROR, received: 0, total: 0, speed: 0, error: String(e && e.message || e) };
    }
  }

  function mapState(s) {
    if (s === 'progressing') return STATES.DOWNLOADING;
    if (s === 'completed') return STATES.COMPLETED;
    if (s === 'interrupted') return STATES.ERROR;
    if (s === 'cancelled') return STATES.CANCELLED;
    return STATES.WAITING;
  }

  async function recover() { return []; }   // electron-dl não persiste
  async function shutdown() { /* nada — electron-dl não tem processo auxiliar */ }

  return { name, isAvailable, start, pause, resume, cancel, status, recover, shutdown };
}

module.exports = { createElectronAdapter };

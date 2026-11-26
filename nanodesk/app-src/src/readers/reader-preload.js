/**
 * NanoDesk — Preload dos LEITORES internos (PDF e ebook)
 * ==================================================================
 * Roda apenas nas abas-leitor (ndr://readers/...), criadas pelo
 * processo principal. Expõe uma ponte MINÚSCULA via contextBridge:
 *  - env()      -> { kind, src, title } do documento aberto;
 *  - getBytes() -> bytes do arquivo (http/https via sessão anônima,
 *                  caminho local via fs) — nada é escrito no disco;
 *  - pickFileBytes() -> diálogo nativo "abrir arquivo" (PDF ou ebook);
 *  - openInNewTab() -> pede ao app que abra uma URL http/https em aba.
 *
 * O processo principal só aceita IPC de frames cuja URL começa com
 * ndr://readers/ (verificado em isTrustedReaderIpc no main.js).
 * 'use strict' + contextIsolation + sandbox: sem Node nas páginas.
 */
'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('nanodeskrdr', {
  env: () => ipcRenderer.invoke('readers:env'),
  getBytes: (src) => ipcRenderer.invoke('readers:get-bytes', src),
  pickFileBytes: (kind) => ipcRenderer.invoke('readers:pick-file-bytes', kind),
  openInNewTab: (url) => ipcRenderer.invoke('readers:open-in-new-tab', url),
  toast: (msg) => ipcRenderer.invoke('readers:toast', msg)
});

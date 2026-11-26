/**
 * NanoDesk — ponte do leitor de PDF (viewer oficial do mozilla/pdf.js)
 * ==================================================================
 * Este script é injetado DEPOIS do viewer.js no viewer.html vendido.
 * Fluxo:
 *  1. pergunta ao processo principal qual documento abrir (env);
 *  2. recebe os bytes via IPC (http/https pela sessão anônima ou
 *     leitura local) — nada toca o disco;
 *  3. espera o viewer inicializar e abre os bytes como blob: URL
 *     (mesma origem do documento — permitido pela CSP).
 * Sem "src", o viewer fica na tela inicial dele ("Abrir arquivo").
 */
'use strict';
(function () {
  const api = window.nanodeskrdr;
  function mark(st, extra) {
    try { window.__nanodeskPdfState = st + (extra ? ':' + extra : ''); } catch (_) { /* ignora */ }
  }
  mark('script', api ? 'bridge' : 'sem-bridge');
  if (!api) return; // fora do NanoDesk (não deve acontecer)

  async function start() {
    const app = window.PDFViewerApplication;
    if (!app) { mark('sem-viewer'); return; }
    try {
      const env = await api.env();
      mark('env', env && env.kind);
      const envTitle = (env && env.title) || '';
      if (envTitle) {
        try { document.title = envTitle; } catch (_) { /* ignora */ }
      }
      if (!env || !env.src) { mark('sem-src'); return; } // tela inicial do viewer

      const buf = await api.getBytes(env.src);
      mark('bytes', buf && buf.byteLength);
      await app.initializedPromise;
      const blob = new Blob([buf], { type: 'application/pdf' });
      // o pdf.js nomeia a aba com o identificador do blob (UUID) —
      // devolvemos o nome real do arquivo quando o documento terminar.
      if (envTitle) {
        try {
          app.eventBus.on('documentloaded', () => {
            try { document.title = envTitle; } catch (_) { /* ignora */ }
          });
        } catch (_) { /* eventBus indisponível */ }
      }
      await app.open({ url: URL.createObjectURL(blob) });
      if (envTitle) {
        // vence o UUID do blob: o pdf.js usa _title nos títulos derivados
        try { app._title = envTitle; } catch (_) { /* ignora */ }
        try { document.title = envTitle; } catch (_) { /* ignora */ }
      }
      mark('aberto');
    } catch (err) {
      mark('erro', String(err && err.message || err).slice(0, 120));
      // erro visível DENTRO do viewer (mesma UI do pdf.js)
      try {
        const msg = await app.l10n.get('loading_error');
        if (typeof app._documentError === 'function') {
          app._documentError(msg, { message: String(err && err.message || err) });
        } else {
          console.error('[nanodesk:pdf]', err);
        }
      } catch (_) {
        console.error('[nanodesk:pdf]', err);
      }
    }
  }

  if (document.readyState === 'loading') {
    window.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();

/**
 * NanoDesk — Leitor de ebooks (foliate-js, John Factotum — MIT)
 * ==================================================================
 * Formatos: EPUB, MOBI, AZW3/KF8, FB2 e CBZ (detecção pelo conteúdo).
 *  - Livros chegam como Blob: via IPC (bytes baixados/lidos pelo main),
 *    arraste de arquivo ou diálogo nativo — NADA é gravado no PC;
 *  - A CSP desta página bloqueia qualquer script vindo do livro
 *    (recomendação de segurança do próprio foliate-js);
 *  - Controles: sumário, tamanho da letra, paginado/rolagem, temas
 *    (claro/sépia/escuro), slider de progresso e teclado (←/→, PgUp/PgDn).
 * Preferências (tema/letra) valem só para esta sessão — nada persiste.
 */
'use strict';

import './foliate/view.js';
import { createTOCView } from './foliate/ui/tree.js';

// marca de diagnóstico (usada pelos testes E2E)
try { window.__nanodeskEpubState = 'modulo'; } catch (_) { /* ignora */ }

const api = window.nanodeskrdr;
const $ = (s) => document.querySelector(s);

/* ---------------- estado (só memória) ---------------- */

const state = {
  view: null,          // elemento <foliate-view>
  tocView: null,
  flow: 'paginated',   // paginated | scrolled
  theme: 'claro',      // claro | sepia | escuro
  fontScale: 1         // 0.7 … 1.8
};

/* ---------------- estilos injetados no livro ---------------- */

function bookCSS() {
  const px = Math.round(17 * state.fontScale); // 17px base — melhor leitura
  return `
    @namespace epub "http://www.idpf.org/2007/ops";
    html {
      color-scheme: light dark;
      font-size: ${px}px !important;
    }
    body {
      font-family: Georgia, "Times New Roman", serif !important;
      line-height: 1.6 !important;
      letter-spacing: 0.01em !important;
      -webkit-font-smoothing: antialiased !important;
    }
    h1, h2, h3, h4, h5, h6 {
      font-family: -apple-system, system-ui, sans-serif !important;
      line-height: 1.3 !important;
      letter-spacing: -0.01em !important;
    }
    @media (prefers-color-scheme: dark) {
      a:link { color: lightblue; }
    }
    p, li, blockquote, dd {
      line-height: 1.6 !important;
      text-align: justify;
      -webkit-hyphens: auto;
      hyphens: auto;
      -webkit-hyphenate-limit-before: 3;
      -webkit-hyphenate-limit-after: 2;
      -webkit-hyphenate-limit-lines: 2;
      widows: 2;
      orphans: 2;
      margin-bottom: 0.8em !important;
    }
    p:first-of-type { text-indent: 0 !important; }
    p { text-indent: 1.5em !important; }
    [align="left"] { text-align: left; }
    [align="right"] { text-align: right; }
    [align="center"] { text-align: center; }
    [align="justify"] { text-align: justify; }
    pre { white-space: pre-wrap !important; font-family: "SF Mono", "Fira Code", monospace !important; }
    code { font-family: "SF Mono", "Fira Code", monospace !important; }
    img { max-width: 100% !important; height: auto !important; }
    table { max-width: 100% !important; }
    aside[epub|type~="endnote"],
    aside[epub|type~="footnote"],
    aside[epub|type~="note"],
    aside[epub|type~="rearnote"] { display: none; }
  `;
}

function applyStyles() {
  try { state.view?.renderer?.setStyles?.(bookCSS()); } catch (_) { /* fxl */ }
}

/* ---------------- tela / barra ---------------- */

function showOpenScreen() {
  $('#open-screen').classList.remove('hidden');
}

function hideOpenScreen() {
  $('#open-screen').classList.add('hidden');
}

function setTitle(t) {
  $('#r-title').textContent = t || 'Livro';
  try { document.title = (t || 'Livro') + ' — NanoDesk'; } catch (_) { /* ignora */ }
}

function toast(msg) {
  try { api?.toast?.(String(msg).slice(0, 200)); } catch (_) { console.warn(msg); }
}

/* ---------------- abrir livro ---------------- */

async function openBlob(blob, fallbackTitle) {
  // livro anterior: destrói renderer e eventos
  if (state.view) {
    try { state.view.close(); } catch (_) { /* ignora */ }
    state.view.remove();
    state.view = null;
    state.tocView = null;
  }
  $('#toc-body').innerHTML = '';
  $('#toc-panel').hidden = true;
  $('#rdr-main').classList.remove('with-toc');

  const view = document.createElement('foliate-view');
  state.view = view;
  $('#rdr-main').append(view);

  await view.open(blob);
  view.addEventListener('relocate', onRelocate);
  view.addEventListener('load', onLoad);
  view.addEventListener('external-link', (e) => {
    // links externos do livro viram abas do NanoDesk (nunca janelas)
    e.preventDefault();
    try { api?.openInNewTab?.(e.detail.href); } catch (_) { /* ignora */ }
  });

  view.renderer.setAttribute('flow', state.flow);
  applyStyles();
  // o paginator do foliate só carrega a primeira seção ao receber next()
  // (mesmo fluxo da demo oficial da biblioteca)
  try { await view.renderer.next?.(); } catch (_) { /* fxl ou já renderizada */ }

  const { book } = view;
  const meta = book.metadata || {};
  const title = fmtText(meta.title) || fallbackTitle || 'Livro';
  const author = fmtContributor(meta.author);
  setTitle(author ? title + ' — ' + author : title);

  $('#r-slider').hidden = false;
  hideOpenScreen();

  if (book.toc && book.toc.length) {
    state.tocView = createTOCView(book.toc, (href) => {
      view.goTo(href).catch(() => toast('Não foi possível ir ao capítulo.'));
      toggleToc(false);
    });
    $('#toc-body').append(state.tocView.element);
  }

  // marca de abertura concluída (usada pelos testes E2E)
  try { window.__nanodeskEpubState = 'aberto'; } catch (_) { /* ignora */ }
  try { window.__nanodeskEpub = { title, rendered: 'ok' }; } catch (_) { /* ignora */ }
}

function fmtText(x) {
  if (!x) return '';
  if (typeof x === 'string') return x;
  const keys = Object.keys(x);
  return keys.length ? String(x[keys[0]]) : '';
}

function fmtContributor(c) {
  if (!c) return '';
  const one = (x) => (typeof x === 'string' ? x : fmtText(x && x.name));
  return Array.isArray(c) ? c.map(one).filter(Boolean).join(', ') : one(c);
}

async function openFromBytes(bytes, fallbackTitle) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  // File (não Blob): o foliate lê `name` para detectar CBZ/FB2
  const name = String(fallbackTitle || 'livro.epub').split(/[?#]/)[0] || 'livro.epub';
  const file = new File([u8], name, { type: 'application/octet-stream' });
  await openBlob(file, name);
}

/* ---------------- eventos do foliate ---------------- */

function onLoad({ detail: { doc } }) {
  doc.addEventListener('keydown', handleKey);
}

function onRelocate({ detail }) {
  const frac = Number(detail && detail.fraction);
  if (Number.isFinite(frac)) {
    const pct = Math.round(frac * 100);
    $('#r-pct').textContent = pct + '%';
    const slider = $('#r-slider');
    if (slider && document.activeElement !== slider) slider.value = String(Math.round(frac * 1000));
    slider.title = pct + '% do livro';
    // 1.8.8: barra de progresso visual
    var pbar = document.getElementById('nd-reading-progress-bar');
    if (pbar) pbar.style.width = pct + '%';
  }
  const href = detail && detail.tocItem && detail.tocItem.href;
  if (href && state.tocView && state.tocView.setCurrentHref) {
    try { state.tocView.setCurrentHref(href); } catch (_) { /* ignora */ }
  }
}

/* ---------------- sumário ---------------- */

function toggleToc(force) {
  const panel = $('#toc-panel');
  const show = typeof force === 'boolean' ? force : panel.hidden;
  panel.hidden = !show;
  $('#rdr-main').classList.toggle('with-toc', show);
}

/* ---------------- controles ---------------- */

const THEMES = ['claro', 'sepia', 'escuro', 'nord', 'solarized'];
const THEME_LABEL = { claro: 'Claro', sepia: 'Sépia', escuro: 'Escuro', nord: 'Nord', solarized: 'Solarizado' };

function cycleTheme() {
  const next = THEMES[(THEMES.indexOf(state.theme) + 1) % THEMES.length];
  state.theme = next;
  document.body.dataset.theme = next;
  $('#b-theme').textContent = THEME_LABEL[next];
}

function toggleFlow() {
  state.flow = state.flow === 'paginated' ? 'scrolled' : 'paginated';
  try { state.view?.renderer?.setAttribute('flow', state.flow); } catch (_) { /* ignora */ }
  $('#b-flow').textContent = state.flow === 'paginated' ? 'Rolagem' : 'Páginas';
}

function changeFont(delta) {
  state.fontScale = Math.min(1.8, Math.max(0.7, state.fontScale + delta));
  applyStyles();
}

function handleKey(e) {
  const k = e.key;
  if (k === 'ArrowLeft' || k === 'PageUp') { state.view?.goLeft(); e.preventDefault(); }
  else if (k === 'ArrowRight' || k === 'PageDown') { state.view?.goRight(); e.preventDefault(); }
  else if (k === '+') changeFont(+0.1);
  else if (k === '-') changeFont(-0.1);
  else if (k === 'Escape') toggleToc(false);
  else if (k === 'f' || k === 'F') {
    if (!document.fullscreenElement) document.documentElement.requestFullscreen?.().catch(() => {});
    else document.exitFullscreen?.().catch(() => {});
    e.preventDefault();
  }
}

/* ---------------- entrada de arquivos ---------------- */

async function openViaDialog() {
  try {
    const r = await api.pickFileBytes('ebook');
    if (!r || r.canceled) return;
    await openFromBytes(r.bytes, r.name);
  } catch (err) {
    toast('Não foi possível abrir o livro: ' + String(err && err.message || err));
  }
}

async function openFromEnv() {
  try {
    const env = await api.env();
    try { window.__nanodeskEpubState = 'env:' + (env && env.kind); } catch (_) { /* ignora */ }
    if (!env || !env.src) return; // tela inicial
    setTitle(env.title);
    const bytes = await api.getBytes(env.src);
    try { window.__nanodeskEpubState = 'bytes:' + (bytes ? bytes.byteLength : 0); } catch (_) { /* ignora */ }
    await openFromBytes(bytes, env.title);
  } catch (err) {
    try { window.__nanodeskEpubErr = String(err && err.message || err); } catch (_) { /* ignora */ }
    showOpenScreen();
    toast('Não foi possível abrir o livro: ' + String(err && err.message || err));
  }
}

function handleDrop(e) {
  e.preventDefault();
  const file = Array.from(e.dataTransfer?.files || []).find(f => f && f.size);
  if (!file) return;
  openBlob(file, file.name).catch(err =>
    toast('Formato não suportado ou livro corrompido: ' + String(err && err.message || err)));
}

/* ---------------- partida ---------------- */

$('#b-open').addEventListener('click', openViaDialog);
$('#b-open-big').addEventListener('click', openViaDialog);
$('#b-toc').addEventListener('click', () => toggleToc());
$('#b-toc-close').addEventListener('click', () => toggleToc(false));
$('#b-theme').addEventListener('click', cycleTheme);
$('#b-flow').addEventListener('click', toggleFlow);
$('#b-fontinc').addEventListener('click', () => changeFont(+0.1));
$('#b-fontdec').addEventListener('click', () => changeFont(-0.1));
$('#r-slider').addEventListener('input', (e) => {
  const f = Number(e.target.value) / 1000;
  if (Number.isFinite(f)) state.view?.goToFraction(f).catch(() => {});
});
document.addEventListener('keydown', handleKey);
document.addEventListener('dragover', (e) => e.preventDefault());
document.addEventListener('drop', handleDrop);

// 1.8.8: barra de progresso de leitura
(function() {
  var bar = document.createElement('div');
  bar.id = 'nd-reading-progress';
  bar.innerHTML = '<div id="nd-reading-progress-bar"></div>';
  document.body.appendChild(bar);
})();

openFromEnv();

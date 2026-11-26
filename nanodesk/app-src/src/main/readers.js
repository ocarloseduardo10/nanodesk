/**
 * NanoDesk — Leitores internos de documentos (1.5.0)
 * ==================================================================
 * Módulo puro (sem Electron) para:
 *  - classificar alvos de navegação como PDF ou ebook (por extensão);
 *  - validar fontes (URL http/https ou caminho local absoluto);
 *  - descrever títulos e filtros de diálogo.
 *
 * Os leitores em si são:
 *  - PDF  -> viewer oficial do mozilla/pdf.js 3.11.174 (Apache-2.0),
 *            servido em ndr://readers/pdf/…  (src/readers/pdf);
 *  - ebook-> foliate-js 1.0.1 (John Factotum, MIT),
 *            servido em ndr://readers/epub/… (src/readers/epub).
 *
 * Nada é gravado no PC: os bytes ficam em memória e a leitura é
 * renderizada pela aba; ao fechar, tudo some.
 */
'use strict';

const PDF_EXT = ['.pdf'];
const EBOOK_EXT = ['.epub', '.mobi', '.azw', '.azw3', '.fb2', '.cbz'];

/** Limite de bytes aceitos por documento (proteção de memória). */
const MAX_READER_BYTES = 200 * 1024 * 1024; // 200 MB

/** Filtros para os diálogos nativos "abrir arquivo". */
const DIALOG_FILTERS = {
  pdf: [
    { name: 'Documentos PDF', extensions: ['pdf'] }
  ],
  ebook: [
    { name: 'Livros (EPUB, MOBI, AZW3, FB2, CBZ)', extensions: ['epub', 'mobi', 'azw', 'azw3', 'fb2', 'cbz'] }
  ],
  any: [
    { name: 'Documentos e livros', extensions: ['pdf', 'epub', 'mobi', 'azw', 'azw3', 'fb2', 'cbz'] },
    { name: 'Documentos PDF', extensions: ['pdf'] },
    { name: 'Livros (EPUB, MOBI, AZW3, FB2, CBZ)', extensions: ['epub', 'mobi', 'azw', 'azw3', 'fb2', 'cbz'] },
    { name: 'Todos os arquivos', extensions: ['*'] }
  ]
};

const isHttp = (u) => typeof u === 'string' && /^https?:\/\//i.test(u);

/** Extensão (minúscula, com ponto) de uma URL http(s) ou caminho local. */
function extOf(source) {
  const s = String(source || '');
  if (!s) return '';
  // remove query/hash só para achar a extensão do caminho
  let p = s;
  if (isHttp(s)) {
    try {
      const u = new URL(s);
      p = u.pathname;
    } catch (_) { return ''; }
  }
  const clean = p.split(/[?#]/)[0];
  const base = clean.split(/[\\/]/).pop() || '';
  const i = base.lastIndexOf('.');
  return i > 0 ? base.slice(i).toLowerCase() : '';
}

/** Nome de arquivo amigável para título de aba. */
function titleFromSource(source) {
  const s = String(source || '');
  if (!s) return 'Documento';
  if (isHttp(s)) {
    try {
      const u = new URL(s);
      const base = decodeURIComponent(u.pathname.split(/[?#]/)[0].split('/').pop() || '').trim();
      return base || u.hostname || 'Documento';
    } catch (_) { return 'Documento'; }
  }
  const base = decodeURIComponent(s.split(/[?#]/)[0].split(/[\\/]/).pop() || '').trim();
  return base || 'Documento';
}

function hostOf(url) {
  try { return new URL(url).hostname; } catch (_) { return ''; }
}

/**
 * Classifica um alvo de navegação.
 * @returns {null|{kind:'pdf'|'ebook', source:string, title:string}}
 */
function classifyReaderTarget(source) {
  const s = String(source || '');
  if (!s) return null;
  if (!isHttp(s) && !isLocalPath(s)) return null;
  const ext = extOf(s);
  if (PDF_EXT.includes(ext)) {
    return { kind: 'pdf', source: s, title: titleFromSource(s) };
  }
  if (EBOOK_EXT.includes(ext)) {
    return { kind: 'ebook', source: s, title: titleFromSource(s) };
  }
  return null;
}

/** Caminho local absoluto (Windows ou Unix) plausível. */
function isLocalPath(s) {
  const v = String(s || '');
  if (!v || v.length > 1000) return false;
  if (/^[a-zA-Z]:[\\/]/.test(v)) return true;         // C:\… ou C:/…
  if (v.startsWith('\\\\')) return true;              // UNC \\servidor\…
  if (v.startsWith('/') && !v.startsWith('//')) return true; // /unix/…
  if (/^file:\/\//i.test(v)) return true;             // file:///C:/…
  return false;
}

/**
 * Converte a fonte para um caminho local seguro (ou null).
 * Aceita apenas caminhos absolutos e file:/// — sem travessia.
 */
function toLocalPath(source) {
  const s = String(source || '');
  if (/^file:\/\//i.test(s)) {
    try {
      const { fileURLToPath } = require('url');
      return fileURLToPath(s);
    } catch (_) { return null; }
  }
  if (!isLocalPath(s) || isHttp(s)) return null;
  const norm = require('path').normalize(s);
  if (/^([a-zA-Z]:[\\/]|\\\\|\/)/.test(norm)) return norm;
  return null;
}

/** Extensão é aceitável para leitura local (mesma lista de classify). */
function isReaderExtension(source) {
  const ext = extOf(source);
  return PDF_EXT.includes(ext) || EBOOK_EXT.includes(ext);
}

/** Content-Type de resposta HTTP -> alvo de leitor (ou null). */
function classifyContentType(contentType, url) {
  const ct = String(contentType || '').split(';')[0].trim().toLowerCase();
  if (ct === 'application/pdf' || ct === 'application/x-pdf') {
    return { kind: 'pdf', source: url, title: titleFromSource(url) };
  }
  if (ct === 'application/epub+zip' || ct === 'application/x-mobipocket-ebook') {
    return { kind: 'ebook', source: url, title: titleFromSource(url) };
  }
  return null;
}

/** Página ndr:// do leitor correspondente. */
const READER_BASE = 'ndr://readers/';
function readerPageUrl(kind) {
  return kind === 'pdf'
    ? READER_BASE + 'pdf/web/viewer.html'
    : READER_BASE + 'epub/epub.html';
}

module.exports = {
  PDF_EXT,
  EBOOK_EXT,
  MAX_READER_BYTES,
  DIALOG_FILTERS,
  READER_BASE,
  extOf,
  titleFromSource,
  classifyReaderTarget,
  classifyContentType,
  isHttp,
  isLocalPath,
  toLocalPath,
  isReaderExtension,
  readerPageUrl
};

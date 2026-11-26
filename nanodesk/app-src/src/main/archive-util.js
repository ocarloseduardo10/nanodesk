/**
 * NanoDesk — Arquivar página (1.9.0) — utilidades puras (sem Electron, sem DOM)
 * ------------------------------------------------------------------
 * Código ORIGINAL (licença MIT, como o NanoDesk). Escrito do zero: o SingleFile é
 * AGPL-3.0 e NENHUM código dele foi copiado — só as funcionalidades foram usadas
 * como referência de requisitos.
 *
 *  - nome de arquivo seguro para Windows (template, caracteres, nomes reservados);
 *  - SHA-256, data: URI, detecção de tipo (magic numbers) de imagens/fontes;
 *  - política de URLs buscáveis (só http/https; rede privada só se a página for privada);
 *  - prova de integridade local: SHA-256 do arquivo embutido no próprio arquivo
 *    (sem serviço de terceiros) + verificação.
 */
'use strict';

const crypto = require('crypto');

const FORMAT_VERSION = 1;
const PROOF_PLACEHOLDER = '0'.repeat(64);

/* ---------------------- nomes de arquivo ---------------------- */

const RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

/** Remove/substitui o que o Windows não aceita; limita o tamanho; evita nomes reservados. */
function sanitizeFileName(name, maxLen) {
  const max = Math.max(20, Number(maxLen) || 120);
  let s = String(name == null ? '' : name)
    .normalize('NFC')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/[\\/:*?"<>|~]/g, '_')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/^[.\s]+|[.\s]+$/g, '');
  if (!s) s = 'pagina';
  if (RESERVED.test(s)) s = '_' + s;
  if (s.length > max) s = s.slice(0, max).replace(/[.\s]+$/g, '');
  return s || 'pagina';
}

function pad2(n) { return String(n).padStart(2, '0'); }

/**
 * Template: {titulo} {host} {data} {hora}. Resultado SEM extensão.
 * @param {string} template
 * @param {{title?:string, url?:string, date?:Date}} info
 */
function buildFileName(template, info) {
  const i = info || {};
  const d = i.date instanceof Date ? i.date : new Date();
  let host = '';
  try { host = new URL(i.url).hostname.replace(/^www\./, ''); } catch (_) { host = ''; }
  const map = {
    titulo: String(i.title || '').trim() || host || 'pagina',
    host: host || 'sem-host',
    data: d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()),
    hora: pad2(d.getHours()) + '-' + pad2(d.getMinutes())
  };
  const tpl = String(template || '{titulo} ({host}) {data}');
  const out = tpl.replace(/\{(titulo|host|data|hora)\}/g, (_, k) => map[k]);
  return sanitizeFileName(out, 120);
}

/* ---------------------- hash / data URI / tipos ---------------------- */

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function startsWith(buf, bytes, off) {
  const o = off || 0;
  if (buf.length < o + bytes.length) return false;
  for (let i = 0; i < bytes.length; i++) if (buf[o + i] !== bytes[i]) return false;
  return true;
}
const ascii = (buf, from, to) => Buffer.from(buf.subarray(from, to)).toString('latin1');

/** Tipo pelos "magic numbers" (confia no conteúdo, não só no cabeçalho do servidor). */
function sniffMime(buf, headerType, url) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf || []);
  if (startsWith(b, [0x89, 0x50, 0x4e, 0x47])) return 'image/png';
  if (startsWith(b, [0xff, 0xd8, 0xff])) return 'image/jpeg';
  if (ascii(b, 0, 4) === 'GIF8') return 'image/gif';
  if (ascii(b, 0, 4) === 'RIFF' && ascii(b, 8, 12) === 'WEBP') return 'image/webp';
  if (ascii(b, 4, 12) === 'ftypavif' || ascii(b, 4, 12) === 'ftypavis') return 'image/avif';
  if (startsWith(b, [0x00, 0x00, 0x01, 0x00])) return 'image/x-icon';
  if (ascii(b, 0, 4) === 'wOF2') return 'font/woff2';
  if (ascii(b, 0, 4) === 'wOFF') return 'font/woff';
  if (ascii(b, 0, 4) === 'OTTO') return 'font/otf';
  if (startsWith(b, [0x00, 0x01, 0x00, 0x00]) || ascii(b, 0, 4) === 'true') return 'font/ttf';
  const head = ascii(b, 0, 512).trimStart().toLowerCase();
  if (head.startsWith('<svg') || (head.startsWith('<?xml') && head.includes('<svg'))) return 'image/svg+xml';
  const ht = String(headerType || '').split(';')[0].trim().toLowerCase();
  if (ht && ht !== 'application/octet-stream' && /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/.test(ht)) return ht;
  const ext = (/\.([a-z0-9]{2,5})(?:[?#]|$)/i.exec(String(url || '')) || [])[1];
  const byExt = { svg: 'image/svg+xml', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', avif: 'image/avif', ico: 'image/x-icon', woff2: 'font/woff2', woff: 'font/woff', ttf: 'font/ttf', otf: 'font/otf', mp4: 'video/mp4', webm: 'video/webm', mp3: 'audio/mpeg' };
  return byExt[String(ext || '').toLowerCase()] || 'application/octet-stream';
}

function toDataUri(buf, mime) {
  const m = /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/i.test(String(mime || '')) ? mime : 'application/octet-stream';
  return 'data:' + m + ';base64,' + Buffer.from(buf).toString('base64');
}

/* ---------------------- política de URLs ---------------------- */

function parseHttp(u) {
  try {
    const x = new URL(u);
    return (x.protocol === 'http:' || x.protocol === 'https:') ? x : null;
  } catch (_) { return null; }
}

/** Loopback, rede privada, link-local, .local/.internal e nomes sem ponto (intranet). */
function isPrivateHost(host) {
  const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.lan') || h.endsWith('.home.arpa')) return true;
  if (h.endsWith('.onion')) return false;
  const m4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m4) {
    const [a, b] = [Number(m4[1]), Number(m4[2])];
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  if (h.includes(':')) {   // IPv6
    return h === '::1' || h === '::' || /^f[cd]/.test(h) || /^fe[89ab]/.test(h) || h.startsWith('::ffff:');
  }
  return !h.includes('.');
}

/**
 * O recurso pode ser buscado? Só http/https. Se a página é PÚBLICA, recursos de rede privada
 * são ignorados (evita que uma página faça o arquivador tocar roteador/serviços locais).
 */
function isFetchableUrl(url, pageUrl) {
  const u = parseHttp(url);
  if (!u) return false;
  const p = parseHttp(pageUrl);
  if (p && !isPrivateHost(p.hostname) && isPrivateHost(u.hostname)) return false;
  return true;
}

/* ---------------------- escapes ---------------------- */

/** Texto de <style>: impede fechar a tag (</style) e comentários HTML. */
function escapeStyleText(css) {
  return String(css == null ? '' : css).replace(/<\/(style)/gi, '<\\/$1').replace(/<!--/g, '<\\!--');
}

function escapeHtmlComment(s) {
  return String(s == null ? '' : s).replace(/--+/g, '-').replace(/[<>]/g, '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 2000);
}

/* ---------------------- prova de integridade ---------------------- */

/**
 * Cabeçalho do arquivo salvo (comentário HTML) com origem, data e SHA-256.
 * O hash cobre o arquivo INTEIRO com o campo sha256 zerado — qualquer alteração depois
 * de salvo é detectada por verifyArchive(). É prova LOCAL de integridade (não de data).
 */
function buildHeader(meta) {
  const m = meta || {};
  return '<!--\n' +
    ' NanoDesk Arquivo v' + FORMAT_VERSION + '\n' +
    ' url: ' + escapeHtmlComment(m.url) + '\n' +
    ' titulo: ' + escapeHtmlComment(m.title) + '\n' +
    ' salvo-em: ' + escapeHtmlComment(m.savedAt) + '\n' +
    ' sha256: ' + PROOF_PLACEHOLDER + '\n' +
    '-->\n';
}

/** Substitui o hash zerado pelo hash real do documento completo. */
function sealArchive(html) {
  const s = String(html);
  const at = s.indexOf(' sha256: ' + PROOF_PLACEHOLDER);
  if (at < 0 || at > 4000) throw new Error('Cabeçalho do arquivo não encontrado.');
  const hash = sha256Hex(Buffer.from(s, 'utf8'));
  return s.slice(0, at) + ' sha256: ' + hash + s.slice(at + ' sha256: '.length + 64);
}

/** @returns {{ok:boolean, reason?:string, hash?:string, url?:string, savedAt?:string}} */
function verifyArchive(html) {
  const s = String(html == null ? '' : html);
  const m = /^(?:\uFEFF)?<!--\n NanoDesk Arquivo v(\d+)\n url: ([^\n]*)\n titulo: ([^\n]*)\n salvo-em: ([^\n]*)\n sha256: ([0-9a-f]{64})\n-->\n/.exec(s);
  if (!m) return { ok: false, reason: 'Não é um arquivo do NanoDesk (cabeçalho ausente ou alterado).' };
  const at = s.indexOf(' sha256: ' + m[5]);
  const zeroed = s.slice(0, at) + ' sha256: ' + PROOF_PLACEHOLDER + s.slice(at + ' sha256: '.length + 64);
  const hash = sha256Hex(Buffer.from(zeroed, 'utf8'));
  if (hash !== m[5]) return { ok: false, reason: 'O conteúdo foi alterado depois de salvo (hash não confere).', hash, url: m[2], savedAt: m[4] };
  return { ok: true, hash, url: m[2], savedAt: m[4], title: m[3] };
}

module.exports = {
  FORMAT_VERSION, PROOF_PLACEHOLDER,
  sanitizeFileName, buildFileName, sha256Hex, sniffMime, toDataUri,
  isPrivateHost, isFetchableUrl, escapeStyleText, escapeHtmlComment,
  buildHeader, sealArchive, verifyArchive
};

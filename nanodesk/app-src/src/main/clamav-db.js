/**
 * NanoDesk 1.9.2 — base de assinaturas do ClamAV: download por QUALQUER rota (inclusive a sessão Tor),
 * verificação e persistência opcional.
 * ------------------------------------------------------------------
 * Por quê: o freshclam.exe é um subprocesso e não usa o proxy do Tor; com Tor em uso a base não era
 * baixada e o download ficava SEM antivírus. Aqui a base é baixada por uma função `fetch` injetada
 * (no app: a sessão Tor), em streaming, com teto de bytes, e verificada antes de ser aceita:
 *   - cabeçalho "ClamAV-VDB:..." (512 bytes) com versão/assinaturas;
 *   - MD5 do conteúdo (tar.gz após o cabeçalho) igual ao do cabeçalho — detecta corrupção/truncamento;
 *   - a ASSINATURA DIGITAL (campo dsig) é verificada pelo próprio clamscan ao carregar a base
 *     (arquivo inválido → clamscan falha → veredito "sem antivírus", nunca "limpo").
 */
'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');

const BASE_URL = 'https://database.clamav.net/';
const CVD_FILES = ['bytecode.cvd', 'daily.cvd', 'main.cvd'];   // menor primeiro: falha cedo e barato
const MAX_BYTES = { 'main.cvd': 400 * 1024 * 1024, 'daily.cvd': 300 * 1024 * 1024, 'bytecode.cvd': 16 * 1024 * 1024 };
const HEADER = 512;

/** "ClamAV-VDB:<data>:<versão>:<assinaturas>:<f-level>:<md5>:<dsig>:<builder>:<stime>" */
function parseCvdHeader(buf) {
  const text = Buffer.from(buf.subarray(0, HEADER)).toString('latin1').replace(/\0+$/, '').trim();
  if (!text.startsWith('ClamAV-VDB:')) return null;
  const f = text.split(':');
  if (f.length < 7) return null;
  const md5 = f[5];
  if (!/^[a-f0-9]{32}$/i.test(md5)) return null;
  const version = parseInt(f[2], 10); const sigs = parseInt(f[3], 10);
  if (!Number.isFinite(version) || !Number.isFinite(sigs) || sigs <= 0) return null;
  return { created: f[1], version, sigs, flevel: parseInt(f[4], 10) || 0, md5: md5.toLowerCase(), builder: f[7] || '', stime: parseInt(f[8], 10) || 0 };
}

/** Verifica um .cvd no disco: cabeçalho + MD5 do conteúdo. */
async function verifyCvdFile(file) {
  const fh = await fsp.open(file, 'r');
  try {
    const st = await fh.stat();
    if (st.size <= HEADER) return { ok: false, reason: 'arquivo curto demais' };
    const hb = Buffer.alloc(HEADER);
    await fh.read(hb, 0, HEADER, 0);
    const hdr = parseCvdHeader(hb);
    if (!hdr) return { ok: false, reason: 'cabeçalho ClamAV inválido' };
    const h = crypto.createHash('md5');
    const buf = Buffer.alloc(1024 * 1024);
    let pos = HEADER;
    while (pos < st.size) {
      const { bytesRead } = await fh.read(buf, 0, buf.length, pos);
      if (!bytesRead) break;
      h.update(buf.subarray(0, bytesRead)); pos += bytesRead;
    }
    if (h.digest('hex') !== hdr.md5) return { ok: false, reason: 'MD5 do conteúdo não confere (arquivo corrompido ou adulterado)' };
    return { ok: true, header: hdr };
  } finally { await fh.close(); }
}

/**
 * Baixa UM arquivo em streaming → dest.part → verifica → renomeia. Nunca deixa arquivo parcial/inválido.
 * @param {{fetchFn:Function, url:string, dest:string, maxBytes:number, onProgress?:Function, signal?:AbortSignal}} o
 */
async function downloadCvd(o) {
  const part = o.dest + '.part';
  await fsp.mkdir(path.dirname(o.dest), { recursive: true });
  let out = null;
  try {
    const res = await o.fetchFn(o.url, o.signal ? { signal: o.signal } : undefined);
    if (!res || !res.ok) throw new Error('HTTP ' + (res ? res.status : 'sem resposta'));
    const declared = Number(res.headers && res.headers.get && res.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > o.maxBytes) throw new Error('arquivo maior que o limite');
    if (!res.body || typeof res.body.getReader !== 'function') throw new Error('resposta sem corpo em fluxo');
    const reader = res.body.getReader();
    out = await fsp.open(part, 'w');
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > o.maxBytes) { try { await reader.cancel(); } catch (_) { /* ignorado */ } throw new Error('arquivo maior que o limite'); }
      await out.write(value);
      if (o.onProgress) o.onProgress({ file: path.basename(o.dest), bytes: total, total: Number.isFinite(declared) ? declared : 0 });
    }
    await out.close(); out = null;
    const v = await verifyCvdFile(part);
    if (!v.ok) throw new Error(v.reason);
    await fsp.rename(part, o.dest);
    return { ok: true, header: v.header, bytes: total };
  } catch (e) {
    try { if (out) await out.close(); } catch (_) { /* ignorado */ }
    try { await fsp.unlink(part); } catch (_) { /* ignorado */ }
    return { ok: false, reason: String(e && e.message ? e.message : e).slice(0, 120) };
  }
}

/** Estado da base: arquivos presentes, idade (dias) da mais antiga e se está completa. */
function dbStatus(dir, now) {
  const t = now || Date.now();
  const found = {};
  try {
    for (const f of fs.readdirSync(dir)) {
      const m = /^(main|daily|bytecode)\.(cvd|cld)$/i.exec(f);
      if (m) found[m[1].toLowerCase()] = { file: f, mtime: fs.statSync(path.join(dir, f)).mtimeMs };
    }
  } catch (_) { /* sem pasta */ }
  const have = Object.keys(found);
  const complete = have.includes('main') && have.includes('daily');
  const oldest = have.length ? Math.min(...have.map((k) => found[k].mtime)) : 0;
  return { complete, files: have, ageDays: oldest ? (t - oldest) / 86400000 : Infinity };
}

/** Baixa main/daily/bytecode via `fetchFn`. Para no primeiro erro (sem deixar base pela metade). */
async function updateViaFetch(dir, fetchFn, opts) {
  const o = opts || {};
  const results = [];
  for (const name of CVD_FILES) {
    const r = await downloadCvd({ fetchFn, url: (o.baseUrl || BASE_URL) + name, dest: path.join(dir, name), maxBytes: (o.maxBytes && o.maxBytes[name]) || MAX_BYTES[name], onProgress: o.onProgress, signal: o.signal });
    results.push(Object.assign({ file: name }, r));
    if (!r.ok) return { ok: false, results, reason: name + ': ' + r.reason };
  }
  return { ok: true, results };
}

module.exports = { BASE_URL, CVD_FILES, MAX_BYTES, parseCvdHeader, verifyCvdFile, downloadCvd, dbStatus, updateViaFetch };

#!/usr/bin/env node
/**
 * NanoDesk — Gerador/verificador de SHA256SUMS.txt (1.9.6)
 * ==================================================================
 * REESCRITO na auditoria de cadeia de suprimentos (2026-11-26) — o
 * script original (tools/make-sha256sums.js) não foi encontrado no
 * repositório nem em backups do workspace. O FORMATO foi replicado
 * fielmente do SHA256SUMS.txt real do build 1.9.6 (estilo sha256sum do
 * GNU coreutils: "<hash hex minúsculo>␠␠<caminho relativo com barras
 * normais>", sem cabeçalho, ordenado alfabeticamente case-insensitive)
 * e validado com --check contra o dist existente.
 *
 * Uso (contrato do package.json → scripts verify:sums / postdist:win):
 *   node tools/make-sha256sums.js <pasta-do-build>
 *     → grava <pasta>/SHA256SUMS.txt com o hash de TODOS os arquivos da
 *       pasta (recursivo), sobrescrevendo o arquivo anterior.
 *   node tools/make-sha256sums.js --check <pasta-do-build>
 *     → verifica cada linha de <pasta>/SHA256SUMS.txt contra o disco;
 *       sai com código 1 se algum arquivo faltar ou divergir.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function sha256File(p) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    const s = fs.createReadStream(p);
    s.on('data', (d) => h.update(d));
    s.on('end', () => resolve(h.digest('hex')));
    s.on('error', reject);
  });
}

function walk(dir, root, out) {
  const entries = fs.readdirSync(dir, { withFileTypes: true })
    .sort((a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }));
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, root, out);
    else out.push(path.relative(root, p).split(path.sep).join('/'));
  }
  return out;
}

async function main() {
  const args = process.argv.slice(2);
  const check = args[0] === '--check';
  const dir = args[check ? 1 : 0] || '.';
  const root = path.resolve(dir);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    console.error(`pasta não encontrada: ${root}`);
    process.exit(2);
  }
  const sumsPath = path.join(root, 'SHA256SUMS.txt');

  if (!check) {
    // SHA256SUMS.txt é excluído — o original não se autolista (autoreferência nunca conferiria)
    const files = walk(root, root, []).filter((f) => f !== 'SHA256SUMS.txt');
    const lines = [];
    for (const rel of files) {
      lines.push(`${await sha256File(path.join(root, rel))}  ${rel}`);
    }
    fs.writeFileSync(sumsPath, lines.join('\n') + '\n', 'utf8');
    console.log(`SHA256SUMS.txt gravado: ${lines.length} arquivos em ${root}`);
    return;
  }

  if (!fs.existsSync(sumsPath)) {
    console.error(`sem SHA256SUMS.txt em ${root}`);
    process.exit(2);
  }
  const lines = fs.readFileSync(sumsPath, 'utf8').split('\n').filter((l) => l.trim() !== '');
  let ok = 0;
  let fail = 0;
  for (const line of lines) {
    const m = line.match(/^([0-9a-f]{64})  (.+)$/);
    if (!m) { console.error(`FORMATO INESPERADO: ${line}`); fail++; continue; }
    const [, hash, rel] = m;
    const p = path.join(root, rel);
    if (!fs.existsSync(p)) { console.error(`FALTANDO: ${rel}`); fail++; continue; }
    const real = await sha256File(p);
    if (real !== hash) { console.error(`DIVERGENTE: ${rel}`); fail++; continue; }
    ok++;
  }
  console.log(`${ok} OK, ${fail} falha(s), ${lines.length} linha(s) — ${root}`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });

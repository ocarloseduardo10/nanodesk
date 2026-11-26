#!/usr/bin/env node
/**
 * NanoDesk — Grava a versão do package.json nos metadados PE (1.9.6)
 * ==================================================================
 * REESCRITO na auditoria de cadeia de suprimentos (2026-11-26) — o
 * script original não foi encontrado no repositório nem em backups do
 * workspace. Contrato documentado (package.json → scripts):
 *   node tools/set-pe-version.js            (chamado por postdist:win)
 * Aplica FileVersion/ProductVersion = "X.Y.Z.0" e ProductName =
 * "NanoDesk" ao executável do build (release/NanoDesk-win32-x64/
 * NanoDesk.exe) usando o rcedit (devDependency do app-src). NÃO assina
 * o binário e NÃO altera binários embutidos de terceiros (aria2,
 * ClamAV, FFmpeg, Tor, yt-dlp mantêm a assinatura/origem original).
 */
'use strict';
const fs = require('fs');
const path = require('path');

async function loadRcedit() {
  try {
    const m = require('rcedit');
    return typeof m === 'function' ? m : (m.default || (m.set ? m.set.bind(m) : null));
  } catch (e) {
    // rcedit 4.x é ESM-only — cai para import dinâmico
    return (await import('rcedit')).default;
  }
}

async function main() {
  const pkg = require(path.join(__dirname, '..', 'package.json'));
  const peVersion = `${pkg.version}.0`;
  const exePath = path.resolve(__dirname, '..', 'release', 'NanoDesk-win32-x64', 'NanoDesk.exe');
  if (!fs.existsSync(exePath)) {
    console.error(`executável não encontrado: ${exePath}`);
    console.error('rode `npm run dist:win` antes de `npm run postdist:win`.');
    process.exit(2);
  }
  let rcedit;
  try {
    rcedit = await loadRcedit();
  } catch (e) {
    console.error('rcedit não instalado — rode `npm install` no app-src antes do pós-build.');
    process.exit(2);
  }
  await rcedit(exePath, {
    'file-version': peVersion,
    'product-version': peVersion,
    'version-string': {
      ProductName: pkg.productName || 'NanoDesk',
      FileDescription: (pkg.description || '').slice(0, 240),
      CompanyName: pkg.author || '',
      LegalCopyright: 'MIT License — Projeto acadêmico NanoDesk',
    },
  });
  console.log(`PE version gravada: ${peVersion} → ${path.relative(process.cwd(), exePath)}`);
}

main().catch((e) => { console.error(e); process.exit(1); });

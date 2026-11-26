/**
 * NanoDesk — Security Gateway de downloads (1.6.0, FASE 6)
 * ==================================================================
 * Referências estudadas (sem copiar código):
 *  - ClamAV (github.com/Cisco-Talos/clamav, GPL-3.0): antivírus —
 *    usado SOMENTE como processo externo, se estiver instalado na
 *    máquina do usuário (clamscan/clamdscan no PATH ou caminho
 *    padrão do Windows). Nenhum binário é distribuído junto.
 *  - YARA (github.com/VirusTotal/yara, BSD-3): regras próprias —
 *    idem: binário externo + arquivo de regras informado pelo usuário.
 *  - URLCheck (TrianguloY): ideia de checagem antes de abrir.
 *
 * O que é implementado SEM ferramentas externas (funciona sempre):
 *  - tipo REAL do arquivo por magic bytes (PE MZ, ELF, ZIP, PDF,
 *    PNG/JPG, script) — pega executável disfarçado de .pdf;
 *  - inspeção de ZIP/CBZ/EPUB (mesmo formato ZIP): lista entradas do
 *    central directory SEM extrair nada, detecta executáveis dentro,
 *    zip bomb (razão de compressão absurda/total gigantesco) e
 *    path traversal nos nomes;
 *  - SHA-256 (já existia) registrado no resultado;
 *  - veredito conservador: "limpo" significa apenas "nada encontrado
 *    pelos scanners disponíveis" — JAMAIS afirmamos segurança
 *    absoluta (mensagem explícita na interface).
 *
 * Fila de análise: sequencial, no processo principal (processo
 * separado do renderer); scanners externos rodam como subprocesso
 * com timeout — permissões mínimas, nenhum dado sai do PC.
 */
'use strict';

const { spawn } = require('child_process');

/* ---------------- tipo real por magic bytes ---------------- */

const MAGIC = [
  // CORREÇÃO 1.6.7: "MZ" sozinho não é PE — texto/asset exótico começando com
  // MZ era classificado como executável e ia para a quarentena. Agora valida
  // e_lfanew + assinatura "PE\0\0" antes de afirmar que é um PE real.
  { test: b => isPeBinary(b), family: 'pe', mime: 'application/x-msdownload', label: 'Executável Windows (PE)' },
  { test: b => b.length >= 4 && b[0] === 0x7F && b[1] === 0x45 && b[2] === 0x4C && b[3] === 0x46, family: 'elf', mime: 'application/x-elf', label: 'Executável Linux (ELF)' },
  { test: b => b.length >= 4 && b[0] === 0x50 && b[1] === 0x4B && (b[2] === 3 || b[2] === 5 || b[2] === 7), family: 'zip', mime: 'application/zip', label: 'Arquivo compactado (ZIP)' },
  { test: b => b.length >= 4 && b[0] === 0x52 && b[1] === 0x61 && b[2] === 0x72 && b[3] === 0x21, family: 'rar', mime: 'application/vnd.rar', label: 'Arquivo compactado (RAR)' },
  { test: b => b.length >= 3 && b[0] === 0x37 && b[1] === 0x7A && b[2] === 0xBC, family: '7z', mime: 'application/x-7z-compressed', label: 'Arquivo compactado (7-Zip)' },
  { test: b => b.length >= 5 && b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46, family: 'pdf', mime: 'application/pdf', label: 'PDF' },
  { test: b => b.length >= 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47, family: 'png', mime: 'image/png', label: 'Imagem PNG' },
  { test: b => b.length >= 3 && b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF, family: 'jpeg', mime: 'image/jpeg', label: 'Imagem JPEG' },
  { test: b => b.length >= 4 && b[0] === 0x1F && b[1] === 0x8B, family: 'gzip', mime: 'application/gzip', label: 'Arquivo compactado (GZip)' }
];

/**
 * PE real = "MZ" + e_lfanew apontando para a assinatura "PE\0\0"
 * (especificação PE/COFF da Microsoft). Puro e testável.
 */
function isPeBinary(b) {
  if (!Buffer.isBuffer(b) || b.length < 64 || b[0] !== 0x4D || b[1] !== 0x5A) return false;
  try {
    const lfa = b.readUInt32LE(0x3C);
    if (lfa < 0x40 || lfa + 4 > b.length) return false;
    return b[lfa] === 0x50 && b[lfa + 1] === 0x45 && b[lfa + 2] === 0x00 && b[lfa + 3] === 0x00;
  } catch (_) { return false; }
}

/** Classifica os primeiros bytes do arquivo. */
function magicType(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf || []);
  for (const m of MAGIC) {
    try { if (m.test(b)) return { family: m.family, mime: m.mime, label: m.label }; } catch (_) { /* continua */ }
  }
  const printable = b.slice(0, 512).every(c => c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 128);
  if (printable) return { family: 'text', mime: 'text/plain', label: 'Texto' };
  return { family: 'other', mime: 'application/octet-stream', label: 'Dados binários' };
}

/* ---------------- inspeção de ZIP (sem extrair) ---------------- */

/** Procura o EOCD (fim do central directory) a partir do final. */
function findEocd(buf) {
  const min = Math.max(0, buf.length - 66000);
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf[i] === 0x50 && buf[i + 1] === 0x4B && buf[i + 2] === 0x05 && buf[i + 3] === 0x06) {
      const count = buf.readUInt16LE(i + 10);
      const cdSize = buf.readUInt32LE(i + 12);
      const cdOfs = buf.readUInt32LE(i + 16);
      return { offset: i, count, cdSize, cdOfs };
    }
  }
  return null;
}

/**
 * Lista entradas do central directory a partir de um buffer que COMEÇA no
 * início do central directory (usado por scanZipFile, que lê o mínimo do
 * arquivo em vez de carregá-lo inteiro).
 * @param {Buffer} cdBuf  buffer começando no primeiro registro do central directory
 * @param {number} count  quantidade declarada de entradas no EOCD
 * @param {object} [opts] { maxEntries?: number }
 */
function listZipFromCentral(cdBuf, count, opts = {}) {
  const maxEntries = Math.min(20000, Math.max(1, Number(opts.maxEntries) || 5000));
  if (!Buffer.isBuffer(cdBuf) || cdBuf.length < 46) return { ok: false, error: 'central directory ilegível' };
  const total = Math.max(0, Math.min(Number(count) || 0, maxEntries));
  let p = 0;
  const entries = [];
  for (let i = 0; i < total; i++) {
    if (p + 46 > cdBuf.length || cdBuf[p] !== 0x50 || cdBuf[p + 1] !== 0x4B || cdBuf[p + 2] !== 0x01 || cdBuf[p + 3] !== 0x02) {
      return { ok: false, error: 'central directory corrompido', entries };
    }
    const method = cdBuf.readUInt16LE(p + 10);
    const compressed = cdBuf.readUInt32LE(p + 20);
    const size = cdBuf.readUInt32LE(p + 24);
    const nameLen = cdBuf.readUInt16LE(p + 28);
    const extraLen = cdBuf.readUInt16LE(p + 30);
    const commentLen = cdBuf.readUInt16LE(p + 32);
    const nameStart = p + 46;
    if (nameStart + nameLen > cdBuf.length) return { ok: false, error: 'central directory truncado', entries };
    const name = cdBuf.toString('utf8', nameStart, nameStart + nameLen);
    entries.push({ name, size, compressed, method });
    p = nameStart + nameLen + extraLen + commentLen;
  }
  return { ok: true, entries, count: total };
}

/**
 * CORREÇÃO 1.6.7 (performance): a varredura de ZIP lia o ARQUIVO INTEIRO
 * (fs.readFileSync, até 2 GB) de forma síncrona no processo principal — a
 * interface congelava durante a análise. Agora lê posicionalmente APENAS o
 * fim do arquivo (EOCD) e o trecho do central directory (normalmente < 1 MB).
 * @param {string} filePath
 * @param {object} [deps] { openSync, readSync, closeSync, fstatSync } (testes)
 * @param {object} [opts] { maxEntries?: number }
 * @returns {{ ok:boolean, entries?:Array, error?:string, zip64?:boolean, count?:number }}
 */
function scanZipFile(filePath, deps = {}, opts = {}) {
  const fsx = require('fs');
  const openSync = deps.openSync || fsx.openSync.bind(fsx);
  const readSync = deps.readSync || fsx.readSync.bind(fsx);
  const closeSync = deps.closeSync || fsx.closeSync.bind(fsx);
  const fstatSync = deps.fstatSync || fsx.fstatSync.bind(fsx);
  let fd = null;
  try {
    fd = openSync(filePath, 'r');
    const size = fstatSync(fd).size;
    if (size < 22) return { ok: false, error: 'arquivo pequeno demais' };
    // 1) tail com EOCD (padrão ZIP: EOCD pode ter comentário de até 65535 bytes)
    const tailLen = Math.min(size, 22 + 65535 + 22);
    const tail = Buffer.alloc(tailLen);
    readSync(fd, tail, 0, tailLen, size - tailLen);
    const eocd = findEocd(tail);
    if (!eocd) return { ok: false, error: 'central directory não encontrado' };
    if (eocd.count === 0xFFFF || eocd.cdOfs === 0xFFFFFFFF) {
      return { ok: true, zip64: true, entries: [], error: 'zip64 — inspeção superficial apenas' };
    }
    // 2) central directory por leitura posicional
    const cdSize = Math.min(eocd.cdSize + 66, 64 * 1024 * 1024, size);
    const cdOfs = Math.max(0, Math.min(eocd.cdOfs, size - cdSize));
    const cd = Buffer.alloc(Math.min(cdSize, size - cdOfs));
    readSync(fd, cd, 0, cd.length, cdOfs);
    const listed = listZipFromCentral(cd, eocd.count, opts);
    if (listed.ok) listed.count = eocd.count;
    return listed;
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e).slice(0, 120) };
  } finally {
    if (fd !== null) { try { closeSync(fd); } catch (_) { /* ignorado */ } }
  }
}

/**
 * Lista entradas do central directory de um ZIP (EPUB/CBZ/XLSX são ZIP).
 * @param {Buffer} buf
 * @param {object} [opts] { maxEntries?: number }
 * @returns {{ ok:boolean, entries?: Array<{name:string,size:number,compressed:number}>,
 *             error?: string, zip64?: boolean }}
 */
function listZip(buf, opts = {}) {
  const maxEntries = Math.min(20000, Math.max(1, Number(opts.maxEntries) || 5000));
  if (!Buffer.isBuffer(buf) || buf.length < 22) return { ok: false, error: 'arquivo pequeno demais' };
  const eocd = findEocd(buf);
  if (!eocd) return { ok: false, error: 'central directory não encontrado' };
  if (eocd.count === 0xFFFF || eocd.cdOfs === 0xFFFFFFFF) {
    return { ok: true, zip64: true, entries: [], error: 'zip64 — inspeção superficial apenas' };
  }
  let p = eocd.cdOfs;
  const entries = [];
  for (let i = 0; i < Math.min(eocd.count, maxEntries); i++) {
    if (p + 46 > buf.length || buf[p] !== 0x50 || buf[p + 1] !== 0x4B || buf[p + 2] !== 0x01 || buf[p + 3] !== 0x02) {
      return { ok: false, error: 'central directory corrompido', entries };
    }
    const method = buf.readUInt16LE(p + 10);
    const compressed = buf.readUInt32LE(p + 20);
    const size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const nameStart = p + 46;
    if (nameStart + nameLen > buf.length) return { ok: false, error: 'central directory truncado', entries };
    const name = buf.toString('utf8', nameStart, nameStart + nameLen);
    entries.push({ name, size, compressed, method });
    p = nameStart + nameLen + extraLen + commentLen;
  }
  return { ok: true, entries, count: eocd.count };
}

/**
 * Riscos em um conteúdo compactado (puro, testável).
 * @param {Array<{name:string,size:number,compressed:number}>} entries
 * @param {number} archiveBytes tamanho do arquivo compactado
 */
function archiveRisk(entries, archiveBytes) {
  const reasons = [];
  if (!Array.isArray(entries)) return reasons;
  let totalUncompressed = 0;
  let totalCompressed = 0;
  for (const e of entries) {
    const name = String(e.name || '');
    totalUncompressed += Number(e.size) || 0;
    totalCompressed += Number(e.compressed) || 0;
    // executáveis/scripts dentro do pacote
    if (/\.(exe|msi|bat|cmd|ps1|vbs|js|jse|wsf|scr|com|pif|hta|jar|lnk)$/i.test(name)) {
      reasons.push('Executável/script dentro do pacote: ' + name.slice(0, 80));
    }
    // path traversal / caminho absoluto
    if (name.includes('..') || /^[a-zA-Z]:[\\/]/.test(name) || name.startsWith('/')) {
      reasons.push('Caminho perigoso dentro do pacote: ' + name.slice(0, 80));
    }
  }
  if (totalUncompressed > 2 * 1024 * 1024 * 1024) {
    reasons.push('Conteúdo descompactado excede 2 GB (possível zip bomb)');
  }
  if (archiveBytes > 1024 * 1024 && totalCompressed > 0) {
    const ratio = totalUncompressed / Math.max(1, archiveBytes);
    if (ratio > 500) reasons.push('Razão de compressão suspeita (' + Math.round(ratio) + 'x)');
  }
  return reasons.slice(0, 10);
}

/* ---------------- adaptadores externos (ClamAV / YARA) ---------------- */

/**
 * Executa um scanner externo com timeout. Injetável para testes.
 * @param {object} cfg { cmd: string, args: string[], timeoutMs?: number }
 * @returns {Promise<{ran:boolean, clean:boolean|null, output:string, engine:string}>}
 */
function runExternal(cfg) {
  // 1.9.3 — a saída era acumulada SEM LIMITE (out += String(d)) e só cortada em 4000 caracteres depois que o
  // processo terminava: um scanner/subprocesso que despeja dados gastava memória sem teto (e String(chunk)
  // ainda podia partir caracteres multibyte). Agora: guarda só o INÍCIO (HEAD_KEEP) e o FIM (TAIL_KEEP) dos
  // bytes, conta o total e, ao passar do teto (maxOutputBytes), ENCERRA o subprocesso (resultado inconclusivo).
  const HEAD_KEEP = 16 * 1024, TAIL_KEEP = 4 * 1024;
  const maxOut = Math.max(HEAD_KEEP + TAIL_KEEP, Number(cfg.maxOutputBytes) || 4 * 1024 * 1024);
  return new Promise((resolve) => {
    let done = false;
    const finish = (r) => { if (!done) { done = true; resolve(r); } };
    let child;
    try {
      child = spawn(cfg.cmd, cfg.args, { windowsHide: true, timeout: cfg.timeoutMs || 60000 });
    } catch (e) {
      return finish({ ran: false, clean: null, output: e.message, engine: cfg.cmd });
    }
    let head = Buffer.alloc(0); let tail = Buffer.alloc(0);
    let total = 0; let overflow = false;
    const t = setTimeout(() => { try { child.kill(); } catch (_) {} }, cfg.timeoutMs || 60000);
    const onData = (d) => {
      const b = Buffer.isBuffer(d) ? d : Buffer.from(String(d));
      total += b.length;
      if (head.length < HEAD_KEEP) { head = Buffer.concat([head, b.subarray(0, HEAD_KEEP - head.length)]); }
      tail = Buffer.concat([tail, b]); if (tail.length > TAIL_KEEP) tail = tail.subarray(tail.length - TAIL_KEEP);
      if (total > maxOut && !overflow) { overflow = true; try { child.kill(); } catch (_) { /* ignorado */ } }
    };
    child.stdout && child.stdout.on('data', onData);
    child.stderr && child.stderr.on('data', onData);
    child.on('error', (e) => { clearTimeout(t); finish({ ran: false, clean: null, output: e.message, engine: cfg.cmd }); });
    child.on('close', (code) => {
      clearTimeout(t);
      // juntar início + fim sem duplicar quando a saída inteira coube no início
      const text = total <= HEAD_KEEP ? head.toString('utf8') : head.toString('utf8') + '\n[...]\n' + tail.toString('utf8');
      // ClamAV: 0 = limpo, 1 = vírus, 2 = erro. YARA: 0 = sem match, 1 = match. Estouro de saída = inconclusivo.
      finish({ ran: true, clean: overflow ? null : code === 0 ? true : code === 1 ? false : null, output: text.slice(0, 4000), engine: cfg.cmd, overflow, totalBytes: total });
    });
  });
}

/**
 * Procura clamscan/clamdscan no sistema (Windows/Linux/macOS).
 * 1.8.8: também consulta o binário EMBUTIDO em resources/clamav/ (o NanoDesk
 * agora distribui o ClamAV portable junto, sem precisar de instalação).
 * @param {Function} existsSync injetável
 * @param {object} [opts] { bundledPath?: string } (caminho embutido do main.js)
 */
function findClamAV(existsSync = require('fs').existsSync, env = process.env, opts = {}) {
  // 1.8.8: binário EMBUTIDO primeiro (resources/clamav/clamscan.exe)
  if (opts && opts.bundledPath && existsSync(opts.bundledPath)) return opts.bundledPath;
  const cands = [];
  if (process.platform === 'win32') {
    const pf = env['ProgramFiles'] || 'C:\\Program Files';
    // CORREÇÃO 1.6.7: clamdscan (daemon) primeiro — clamscan recarrega a base
    // inteira de assinaturas A CADA download (centenas de MB, CPU perceptível).
    // 1.8.8: como a base vive em SESSION_TMP, clamdscan (que lê config fixa)
    // NÃO serve — priorizamos clamscan.exe (suporta --database=<dir>).
    cands.push(
      `${pf}\\ClamAV\\clamscan.exe`,
      `${pf}\\ClamAV\\clamdscan.exe`,
      'C:\\Program Files (x86)\\ClamAV\\clamscan.exe',
      'C:\\Program Files (x86)\\ClamAV\\clamdscan.exe'
    );
  }
  cands.push('/usr/bin/clamdscan', '/usr/bin/clamscan', '/usr/local/bin/clamdscan', '/usr/local/bin/clamscan', '/opt/homebrew/bin/clamscan');
  for (const c of cands) if (existsSync(c)) return c;
  return null;
}

/**
 * Procura o binário do YARA + regras (env NANODESK_YARA_RULES).
 */
function findYara(existsSync = require('fs').existsSync, env = process.env) {
  const rules = env['NANODESK_YARA_RULES'] || '';
  if (!rules || !existsSync(rules)) return null;
  const cands = [];
  if (process.platform === 'win32') {
    const pf = env['ProgramFiles'] || 'C:\\Program Files';
    cands.push(`${pf}\\YARA\\yara64.exe`, `${pf}\\yara\\yara.exe`);
  }
  cands.push('/usr/bin/yara', '/usr/local/bin/yara', '/opt/homebrew/bin/yara');
  for (const c of cands) if (existsSync(c)) return c;
  return null;
}

/* ---------------- veredito ---------------- */

/**
 * Consolidado (puro). "limpo" NUNCA é garantia — é o texto que a
 * interface mostra: "nenhuma ameaça encontrada pelos scanners
 * disponíveis; mantenha o hábito de conferir a origem".
 * 1.8.8: o SCANNER NATIVO (SHA-256 base embutida + PE + strings + entropia)
 *        pode afirmar "infectado" quando o hash bate — veredito acompanha.
 */
function verdict(scan) {
  if (!scan) return { level: 'indisponivel', label: 'Não verificado' };
  // 1.8.8: SCANNER NATIVO com hash correspondendo a malware conhecido.
  if (scan.nativeScanner && scan.nativeScanner.level === 'infectado') {
    return { level: 'infectado', label: 'Malware conhecido detectado (hash SHA-256 está na lista de malware fornecida)' };
  }
  // 1.6.2: só um antivírus de verdade (ClamAV) pode afirmar "ameaça detectada". Achados
  // heurísticos (executável disfarçado, pacote com executável/zip bomb, YARA) são
  // "suspeito" — avisam o usuário, mas NÃO são removidos automaticamente (1.6.7).
  const avFound = (scan.clamav && scan.clamav.ran && scan.clamav.clean === false) ||
    (scan.findings || []).some(f => /^ClamAV:/i.test(String(f)));
  if (avFound) return { level: 'infectado', label: 'ClamAV detectou ameaça — arquivo em quarentena' };
  // CORREÇÃO 1.6.7: scanner interrompido por timeout NÃO é "limpo" — era o
  // veredito antigo (close com code=null). Agora é "inconclusivo", sem
  // quarentena e com orientação para verificar a origem.
  const scanTimedOut = (scan.clamav && scan.clamav.ran && scan.clamav.clean === null) ||
    (scan.yara && scan.yara.ran && scan.yara.clean === null);
  if (scanTimedOut) return { level: 'inconclusivo', label: 'Varredura interrompida por tempo esgotado — resultado inconclusivo' };
  if (scan.yara && scan.yara.ran && scan.yara.clean === false) return { level: 'suspeito', label: 'Regra YARA correspondeu' };
  // 1.8.8: SCANNER NATIVO nível 'suspeito' (imports PE suspeitos + strings + entropia)
  if (scan.nativeScanner && scan.nativeScanner.level === 'suspeito') {
    return { level: 'suspeito', label: 'Heurística do scanner nativo (estrutura PE/strings/entropia) — indício, não prova' };
  }
  if (scan.magic && (scan.magic.family === 'pe' || scan.magic.family === 'elf')) return { level: 'suspeito', label: 'Executável disfarçado detectado' };
  if (scan.archive && scan.archive.risks && scan.archive.risks.length) return { level: 'suspeito', label: 'Conteúdo compactado suspeito' };
  if (scan.findings && scan.findings.length) return { level: 'suspeito', label: 'Achado suspeito na análise local' };
  const anyRan = (scan.clamav && scan.clamav.ran) || (scan.yara && scan.yara.ran);
  if (anyRan) return { level: 'limpo', label: 'Nenhuma ameaça detectada pelo antivírus (ClamAV/YARA) — isso não é garantia de segurança' };
  // 1.9.2: SEM antivírus. A análise local é heurística e limitada; o texto diz isso e POR QUE o ClamAV não rodou
  // (ex.: Tor em uso → a base de assinaturas não é baixada pela rede direta para não expor o IP).
  const why = scan.clamav && scan.clamav.reason ? String(scan.clamav.reason) : '';
  return { level: 'limpo-local', label: 'SEM varredura antivírus — só análise local limitada (não é garantia de segurança)', note: why };
}

/**
 * 1.8.8 — Baixa a base de assinaturas do ClamAV para uma pasta de destino
 * usando freshclam.exe (binário externo ou embutido em resources/clamav/).
 * Roda UMA vez por sessão; a base vive na pasta temporária da sessão
 * (morre junto com o app). Falha de rede = silenciosa.
 * @param {string} dataDir pasta onde main.cvd/daily.cvd serão gravados
 * @param {string} freshclamBin caminho do freshclam.exe (embutido ou externo)
 * @returns {Promise<boolean>} true se a base está pronta
 */
async function downloadClamAVDatabase(dataDir, freshclamBin) {
  if (!dataDir || !freshclamBin) return false;
  const fsx = require('fs');
  try { fsx.mkdirSync(String(dataDir), { recursive: true }); } catch (_) { /* já existe */ }
  try {
    const files = fsx.readdirSync(String(dataDir)).filter(f => /^(main|daily|bytecode)\./i.test(f));
    if (files.length >= 2) return true;
  } catch (_) { /* sem pasta — segue */ }
  try {
    const r = await runExternal({
      cmd: freshclamBin,
      args: ['--datadir=' + String(dataDir), '--no-dns'],
      timeoutMs: 120000
    });
    if (r.ran) {
      try {
        const files = fsx.readdirSync(String(dataDir)).filter(f => /^(main|daily|bytecode)\./i.test(f));
        return files.length >= 2;
      } catch (_) { return false; }
    }
  } catch (_) { /* melhor esforço */ }
  return false;
}

module.exports = {
  magicType, listZip, listZipFromCentral, scanZipFile, archiveRisk, runExternal,
  findClamAV, findYara, verdict,
  downloadClamAVDatabase,
  MAGIC, isPeBinary
};

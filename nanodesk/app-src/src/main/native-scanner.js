/**
 * NanoDesk — Scanner NATIVO (heurístico) — reescrito na 1.9.2
 * ==================================================================
 * ISTO NÃO É UM ANTIVÍRUS. É uma análise local, sem rede, que procura SINAIS de risco:
 *   - hashes SHA-256 de uma lista que VOCÊ fornece (a lista embutida é vazia de propósito: a anterior
 *     tinha hashes fabricados; não há como o projeto verificar amostras reais sozinho);
 *   - estrutura PE real: tabela de seções, imports RESOLVIDOS (RVA→offset), seções gravável+executável,
 *     nomes de packers, ponto de entrada fora do código, importações mínimas;
 *   - combinações de APIs (injeção de processo, keylogger, downloader+execução, escalada de privilégio)
 *     — uma API isolada (LoadLibrary, CreateProcess…) NÃO conta, pois é comum em software legítimo;
 *   - strings suspeitas no ARQUIVO INTEIRO (ASCII e UTF-16), em fluxo, com teto de bytes;
 *   - entropia por seção (packer/criptografia).
 * Quem pode afirmar "ameaça detectada" é o ClamAV. Quando ele não roda (ex.: Tor em uso), o veredito
 * diz claramente "SEM varredura antivírus".
 *
 * Núcleo testável sem Electron/rede. API antiga (`scan({sha256, head, magic})`) preservada.
 */
'use strict';

/* ---------------- base de hashes SHA-256 ---------------- */
/* 1.8.11: a tabela anterior tinha 8 hashes FABRICADOS (padrões hex repetidos, não eram
 * amostras reais) — nunca detectavam nada e o comentário dizia o contrário. Removidos.
 * A detecção por hash real fica a cargo do ClamAV; esta Set existe para receber hashes
 * REAIS e verificados (ex.: de um feed próprio) sem mudar a API do scanner. */
const MALWARE_HASHES = new Set([]);

/**
 * Carrega hashes SHA-256 de um TEXTO (um por linha; # comentário). Use para uma lista que você
 * mesmo verificou (feed próprio, IOC de um incidente). Devolve quantos hashes novos entraram.
 */
function loadHashList(text) {
  let n = 0;
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim().toLowerCase();
    const m = /^([a-f0-9]{64})(?:\s|$)/.exec(line);
    if (m && !MALWARE_HASHES.has(m[1])) { MALWARE_HASHES.add(m[1]); n++; }
  }
  return n;
}

/* ---------------- imports PE suspeitos ---------------- */
const SUSPICIOUS_PE_IMPORTS = [
  'CreateRemoteThread',       // injeção clássica
  'CreateRemoteThreadEx',     // variante
  'WriteProcessMemory',       // escrever em outro processo
  'VirtualAllocEx',           // alocar memória remota
  'VirtualProtect',           // mudar proteção de página (RWX)
  'VirtualProtectEx',         // idem remoto
  'SetWindowsHookEx',         // keylogger global
  'GetAsyncKeyState',         // keylogger
  'GetKeyState',              // keylogger
  'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW',
  'GetProcAddress',           // resolver API dinamicamente
  'WinExec',                  // executar comando
  'CreateProcessA', 'CreateProcessW', 'CreateProcessAsUserA', 'CreateProcessAsUserW',
  'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA', 'ShellExecuteExW',
  'URLDownloadToFileA', 'URLDownloadToFileW',  // download remoto
  'InternetOpenA', 'InternetOpenW', 'InternetOpenUrlA', 'InternetOpenUrlW',
  'HttpSendRequestA', 'HttpSendRequestW',
  'AdjustTokenPrivileges',    // escalonar privilégios
  'OpenProcessToken',         // acessar token de processo
  'LookupPrivilegeValueA', 'LookupPrivilegeValueW',
  'RegSetValueExA', 'RegSetValueExW',  // persistência
  'RegCreateKeyExA', 'RegCreateKeyExW',
  'CreateServiceA', 'CreateServiceW', 'StartServiceA', 'StartServiceW',  // serviço
  'WNetAddConnection2A', 'WNetAddConnection2W'  // spread por rede
];

/* ---------------- strings/regex suspeitas ---------------- */
const SUSPICIOUS_STRING_RX = [
  { rx: /cmd\.exe\s+\/c\s/i, label: 'cmd.exe /c (execução de comando)', w: 1 },
  { rx: /powershell\s+-e(?:ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}/i, label: 'PowerShell base64 (ofuscação)', w: 2 },
  { rx: /powershell\s.{0,200}-w(?:indowstyle)?\s+hidden/i, label: 'PowerShell oculto (-w hidden)', w: 2 },
  { rx: /IEX\s*\(\s*(?:New-Object|Net\.WebClient|Invoke-WebRequest)/i, label: 'PowerShell IEX (download/exec)', w: 2 },
  { rx: /HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/i, label: 'chave de persistência Run', w: 1 },
  { rx: /\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce/i, label: 'chave de persistência RunOnce', w: 1 },
  { rx: /rundll32\.exe\s+/i, label: 'rundll32 (carregador DLL)', w: 1 },
  { rx: /regsvr32\.exe\s+\/s\s+\/u\s+\/i:/i, label: 'regsvr32 squiblydoo (fileless)', w: 2 },
  { rx: /mshta\s+http/i, label: 'mshta remoto (fileless)', w: 2 },
  { rx: /schtasks\s+\/create/i, label: 'agendador de tarefas (persistência)', w: 1 },
  { rx: /wscript\.shell|vbscript\.regexp/i, label: 'activeX scripting (ofuscação)', w: 1 },
  { rx: /\bbitcoins?:\s*(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{20,40})\b/i, label: 'endereço bitcoin (ransomware)', w: 1 },
  { rx: /\bTOR\b.{0,100}\.onion/i, label: 'referência C2 .onion', w: 1 },
  { rx: /SeDebugPrivilege/, label: 'SeDebugPrivilege (escalada de privilégio)', w: 0 },   // peso 0: comum em antivírus/depuradores; só informativo
  { rx: /(?:base64|b64)\s*:?\s*[A-Za-z0-9+/]{200,}={0,2}/i, label: 'blob base64 grande (payload ofuscado)', w: 1 }
];

/* ---------------- entropia de Shannon ---------------- */

/** Calcula entropia de Shannon (0..8) de um buffer/string. (puro) */
function shannonEntropy(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(String(buf || ''), 'utf8');
  if (b.length < 2) return 0;
  const counts = new Array(256).fill(0);
  for (let i = 0; i < b.length; i++) counts[b[i]]++;
  let H = 0;
  for (let i = 0; i < 256; i++) {
    if (counts[i] === 0) continue;
    const p = counts[i] / b.length;
    H -= p * Math.log2(p);
  }
  return H;
}

/** Extrai strings ASCII imprimíveis de um buffer (puro). */
function extractStrings(buf, minLen = 5, maxLen = 64) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(String(buf || ''), 'utf8');
  const out = [];
  let cur = '';
  for (let i = 0; i < b.length; i++) {
    const c = b[i];
    if (c >= 0x20 && c < 0x7F) {
      cur += String.fromCharCode(c);
      if (cur.length >= maxLen) { out.push(cur); cur = ''; }
    } else {
      if (cur.length >= minLen) out.push(cur);
      cur = '';
    }
  }
  if (cur.length >= minLen) out.push(cur);
  return out;
}

/** Lê a import table de um PE a partir do cabeçalho (puro). */
function readPeImports(head) {
  const b = Buffer.isBuffer(head) ? head : Buffer.from(head || []);
  if (!b || b.length < 64 || b[0] !== 0x4D || b[1] !== 0x5A) return [];
  try {
    const e_lfanew = b.readUInt32LE(0x3C);
    if (e_lfanew < 0x40 || e_lfanew + 4 > b.length) return [];
    if (b[e_lfanew] !== 0x50 || b[e_lfanew + 1] !== 0x45) return [];
    // Optional header comes right after PE signature (4) + COFF header (20)
    const optHdr = e_lfanew + 4 + 20;
    const magic = b.readUInt16LE(optHdr);
    const is64 = (magic === 0x20B);
    // DataDirectory[1] = Import Table (RVA + size)
    const importDirOffset = is64 ? optHdr + 112 + (8 * 1) : optHdr + 96 + (8 * 1);
    if (importDirOffset + 8 > b.length) return [];
    const importRva = b.readUInt32LE(importDirOffset);
    const importSize = b.readUInt32LE(importDirOffset + 4);
    if (!importRva || !importSize) return [];
    // Não tentamos resolver o RVA para offset sem section table (precisaria
    // varrer o arquivo); em vez disso, procuramos nomes de API diretamente
    // nas strings do cabeçalho (1ª tabela de DLL imports costuma aparecer
    // como string ASCII "CreateRemoteThread", etc.).
    return [];
  } catch (_) { return []; }
}

/** Procura imports suspeitos por string-match no cabeçalho. (puro) */
function suspiciousImportsFromHead(head) {
  const strings = extractStrings(head, 4, 64);
  const found = [];
  const seen = new Set();
  for (const s of strings) {
    for (const imp of SUSPICIOUS_PE_IMPORTS) {
      if (s === imp && !seen.has(imp)) {
        found.push(imp);
        seen.add(imp);
      }
    }
  }
  return found;
}

/** Procura strings suspeitas no cabeçalho. (puro) */
function suspiciousStringsFromHead(head) {
  const strings = extractStrings(head, 6, 256);
  const found = [];
  for (const s of strings) {
    for (const rule of SUSPICIOUS_STRING_RX) {
      if (rule.rx.test(s) && !found.includes(rule.label)) {
        found.push(rule.label);
      }
    }
  }
  return found;
}

/**
 * Análise principal — devolve {level, findings, details}.
 * @param {object} arg { sha256?: string, head?: Buffer, magic?: object }
 * @returns {{level:'limpo'|'suspeito'|'infectado', findings:string[], details:object}}
 */
function scan(arg) {
  const a = arg || {};
  const findings = [];
  const details = {};
  const head = Buffer.isBuffer(a.head) ? a.head : Buffer.from(a.head || []);
  const magic = a.magic || { family: 'other' };
  details.magicFamily = magic.family || 'other';

  // 1) hash SHA-256 na base embutida
  if (a.sha256 && MALWARE_HASHES.has(String(a.sha256).toLowerCase())) {
    findings.push('Hash SHA-256 corresponde a malware conhecido (base embutida)');
    return { level: 'infectado', findings, details };
  }

  // 2) imports PE suspeitos (somente para PE)
  if (magic.family === 'pe' || magic.family === 'elf') {
    const imps = suspiciousImportsFromHead(head);
    if (imps.length) {
      details.suspiciousImports = imps;
      findings.push('Imports PE suspeitos: ' + imps.slice(0, 5).join(', ') +
        (imps.length > 5 ? ' (+' + (imps.length - 5) + ' outros)' : ''));
    }
  }

  // 3) strings suspeitas (qualquer família)
  const ss = suspiciousStringsFromHead(head);
  if (ss.length) {
    details.suspiciousStrings = ss;
    findings.push('Strings suspeitas: ' + ss.slice(0, 3).join('; ') +
      (ss.length > 3 ? ' (+' + (ss.length - 3) + ' outras)' : ''));
  }

  // 4) entropia alta (packer/criptografia) — só para PE/ELF binários
  if (magic.family === 'pe' || magic.family === 'elf' || magic.family === 'other') {
    const H = shannonEntropy(head);
    details.entropy = Math.round(H * 100) / 100;
    if (H >= 7.0 && head.length >= 1024) {
      findings.push('Entropia muito alta (' + details.entropy + '/8 — possível packer/criptografia)');
    }
  }

  // 5) MZ sem PE real (já coberto pelo magicType do security-gateway)
  if (head.length >= 2 && head[0] === 0x4D && head[1] === 0x5A && magic.family !== 'pe') {
    findings.push('Cabeçalho MZ sem assinatura PE válida (executável malformado)');
  }

  // Veredito
  let level = 'limpo';
  if (findings.length >= 2) level = 'suspeito';
  else if (findings.length === 1) level = 'suspeito';
  return { level, findings, details };
}

/* =================================================================================
 * 1.9.2 — Análise de ARQUIVO (parser PE real + strings no arquivo inteiro)
 * ================================================================================= */

const fsp = require('fs').promises;

const INJECTION_APIS = ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'CreateRemoteThreadEx',
  'NtCreateThreadEx', 'QueueUserAPC', 'SetThreadContext', 'NtWriteVirtualMemory', 'NtMapViewOfSection', 'RtlCreateUserThread'];
const KEYLOG_HOOK = ['SetWindowsHookExA', 'SetWindowsHookExW', 'SetWindowsHookEx'];
const KEYLOG_READ = ['GetAsyncKeyState', 'GetKeyboardState', 'GetRawInputData', 'RegisterRawInputDevices'];
const DOWNLOAD_APIS = ['URLDownloadToFileA', 'URLDownloadToFileW', 'URLDownloadToCacheFileA', 'URLDownloadToCacheFileW', 'InternetOpenUrlA', 'InternetOpenUrlW', 'WinHttpReadData', 'InternetReadFile'];
const EXEC_APIS = ['ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA', 'ShellExecuteExW', 'WinExec', 'CreateProcessA', 'CreateProcessW'];
const PRIV_APIS = ['AdjustTokenPrivileges', 'OpenProcessToken', 'LookupPrivilegeValueA', 'LookupPrivilegeValueW'];
const PACKER_SECTIONS = ['upx0', 'upx1', 'upx2', '.aspack', '.adata', '.petite', '.themida', '.vmp0', '.vmp1', '.vmp2', 'mpress1', 'mpress2', '.nsp0', '.nsp1', '.nsp2', '.enigma1', '.enigma2', '.perplex', 'pec1', 'pec2', '.yp', '.boom', '.packed'];

function readCString(buf, off, max) {
  if (off < 0 || off >= buf.length) return '';
  let e = off;
  const lim = Math.min(buf.length, off + max);
  while (e < lim && buf[e] !== 0) e++;
  return buf.toString('latin1', off, e);
}

/** Lê `len` bytes na posição `pos` (menos, se o arquivo acabar). */
async function readAt(fh, pos, len) {
  const b = Buffer.alloc(len);
  const { bytesRead } = await fh.read(b, 0, len, pos);
  return b.subarray(0, bytesRead);
}

/**
 * Parser PE por leitura posicional (não carrega o arquivo na memória).
 * @returns {Promise<null|object>} null se não for um PE válido.
 */
async function parsePeFile(fh, size, opts) {
  const o = opts || {};
  const head = await readAt(fh, 0, Math.min(size, 64));
  if (head.length < 64 || head[0] !== 0x4D || head[1] !== 0x5A) return null;
  const pe = head.readUInt32LE(0x3C);
  if (pe < 0x40 || pe + 24 > size) return null;
  let h = await readAt(fh, pe, Math.min(size - pe, 4096 + 24 + 1024));
  if (h.length < 24 || h.readUInt32LE(0) !== 0x00004550) return null;       // "PE\0\0"
  const machine = h.readUInt16LE(4);
  const nSec = h.readUInt16LE(6);
  const optSize = h.readUInt16LE(20);
  if (nSec === 0 || nSec > 96 || optSize < 96) return null;
  const need = 24 + optSize + nSec * 40;
  if (h.length < need) h = await readAt(fh, pe, need);
  if (h.length < need) return null;
  const opt = 24;
  const magic = h.readUInt16LE(opt);
  const is64 = magic === 0x20B;
  if (!is64 && magic !== 0x10B) return null;
  const entryRva = h.readUInt32LE(opt + 16);
  const ddBase = opt + (is64 ? 112 : 96);
  const nDd = h.readUInt32LE(opt + (is64 ? 108 : 92));
  const dd = (i) => (i < nDd && ddBase + i * 8 + 8 <= opt + optSize) ? { rva: h.readUInt32LE(ddBase + i * 8), size: h.readUInt32LE(ddBase + i * 8 + 4) } : { rva: 0, size: 0 };
  const sections = [];
  for (let i = 0; i < nSec; i++) {
    const so = 24 + optSize + i * 40;
    sections.push({
      name: h.toString('latin1', so, so + 8).replace(/\0+$/, ''),
      vsize: h.readUInt32LE(so + 8), va: h.readUInt32LE(so + 12),
      rawSize: h.readUInt32LE(so + 16), rawPtr: h.readUInt32LE(so + 20),
      chars: h.readUInt32LE(so + 36)
    });
  }
  const secOf = (rva) => sections.find((s) => rva >= s.va && rva < s.va + Math.max(s.vsize, s.rawSize));
  const info = { is64, machine, sections: [], imports: {}, importCount: 0, unresolved: 0, entrySection: '', overlay: 0, signed: dd(4).size > 0 };

  // entropia por seção (amostra) — orçamento total de leitura limitado
  let budget = o.entropyBudget || 16 * 1024 * 1024;
  let end = 0;
  for (const s of sections) {
    let H = null;
    if (s.rawSize > 0 && s.rawPtr < size && budget > 0) {
      const take = Math.min(s.rawSize, 256 * 1024, budget, size - s.rawPtr);
      if (take > 1024) { H = shannonEntropy(await readAt(fh, s.rawPtr, take)); budget -= take; }
    }
    end = Math.max(end, s.rawPtr + s.rawSize);
    info.sections.push({ name: s.name, entropy: H === null ? null : Math.round(H * 100) / 100, exec: !!(s.chars & 0x20000000), write: !!(s.chars & 0x80000000), rawSize: s.rawSize });
  }
  info.overlay = Math.max(0, size - end);
  const es = secOf(entryRva);
  info.entrySection = es ? es.name : '';
  info.entryExec = es ? !!(es.chars & 0x20000000) : false;
  info.entryWritable = es ? !!(es.chars & 0x80000000) : false;
  info.entryIsLastSection = es ? sections[sections.length - 1] === es : false;

  // imports: resolve QUALQUER RVA (descritores, thunks e nomes podem estar em seções diferentes — comum em
  // binários grandes como o Chromium/Electron) lendo páginas de 64 KB com cache (sem carregar o arquivo todo)
  const imp = dd(1);
  const PG = 64 * 1024;
  const pages = new Map();
  const raw = async (off, len) => {
    const out = Buffer.alloc(len); let got = 0;
    while (got < len) {
      const pn = Math.floor((off + got) / PG);
      let pg = pages.get(pn);
      if (!pg) { pg = await readAt(fh, pn * PG, PG); pages.set(pn, pg); if (pages.size > 256) pages.delete(pages.keys().next().value); }
      const within = off + got - pn * PG;
      if (within >= pg.length) break;
      const n = Math.min(len - got, pg.length - within);
      pg.copy(out, got, within, within + n); got += n;
    }
    return out.subarray(0, got);
  };
  const atRva = async (rva, len) => {
    const sec = secOf(rva);
    if (!sec) return null;
    const rel = rva - sec.va;
    if (rel >= sec.rawSize || sec.rawPtr + rel >= size) return null;
    return raw(sec.rawPtr + rel, Math.min(len, sec.rawSize - rel));
  };
  if (imp.rva) {
    const dir = await atRva(imp.rva, Math.min(Math.max(imp.size, 20), 20 * 512 + 20));
    if (!dir) info.unresolved++;
    else {
      const step = is64 ? 8 : 4;
      const maxImports = o.maxImports || 20000;
      for (let d = 0, n = 0; d + 20 <= dir.length && n < 512; d += 20, n++) {
        const oft = dir.readUInt32LE(d), nameRva = dir.readUInt32LE(d + 12), ft = dir.readUInt32LE(d + 16);
        if (!oft && !nameRva && !ft) break;
        const nm = nameRva ? await atRva(nameRva, 64) : null;
        const dll = nm ? readCString(nm, 0, 64).toLowerCase() : '?';
        const funcs = info.imports[dll] || (info.imports[dll] = []);
        const thunks = await atRva(oft || ft, step * 4096);
        if (!thunks) { info.unresolved++; continue; }
        for (let t = 0; t + step <= thunks.length && info.importCount < maxImports; t += step) {
          const lo = thunks.readUInt32LE(t);
          const hi = is64 ? thunks.readUInt32LE(t + 4) : 0;
          if (!lo && !hi) break;
          const byOrdinal = is64 ? (hi & 0x80000000) !== 0 : (lo & 0x80000000) !== 0;
          if (byOrdinal) { funcs.push('#' + (lo & 0xFFFF)); info.importCount++; continue; }
          const hn = await atRva(lo & 0x7FFFFFFF, 130);
          if (!hn || hn.length < 3) { info.unresolved++; continue; }
          funcs.push(readCString(hn, 2, 128));
          info.importCount++;
        }
      }
    }
  }
  return info;
}

/** Avalia o resultado do parser: devolve achados com PESO (>=2 no total => suspeito). */
function assessPe(info) {
  const findings = [];      // {text, w}
  if (!info) return findings;
  const all = new Set();
  for (const fns of Object.values(info.imports)) for (const f of fns) all.add(f);
  const has = (list) => list.filter((a) => all.has(a));
  // CALIBRAÇÃO (medida em binários reais): navegadores Chromium/Electron importam VirtualAllocEx+WriteProcessMemory+
  // CreateRemoteThread (sandbox/crashpad) e antivírus/depuradores usam privilégios de depuração. O MESMO conjunto
  // de APIs pesa menos num programa GRANDE (>=200 imports em >=8 DLLs) do que num executável pequeno.
  const nDll = Object.keys(info.imports).length;
  const big = info.importCount >= 300 || (info.importCount >= 200 && nDll >= 8);
  const bigNote = big ? ' (programa grande: comum em navegadores/depuradores)' : '';
  const inj = has(INJECTION_APIS);
  const injCore = all.has('VirtualAllocEx') || all.has('NtWriteVirtualMemory') || all.has('NtMapViewOfSection');
  if (inj.length >= 3 && injCore) findings.push({ text: 'Combinação de injeção de processo: ' + inj.slice(0, 5).join(', ') + bigNote, w: big ? 1 : 2 });
  if (has(KEYLOG_HOOK).length && has(KEYLOG_READ).length) findings.push({ text: 'Combinação de keylogger: ' + has(KEYLOG_HOOK).concat(has(KEYLOG_READ)).slice(0, 4).join(', ') + bigNote, w: big ? 1 : 2 });
  if (has(DOWNLOAD_APIS).length && has(EXEC_APIS).length) findings.push({ text: 'Baixa da internet e executa: ' + has(DOWNLOAD_APIS)[0] + ' + ' + has(EXEC_APIS)[0], w: 1 });
  if (has(PRIV_APIS).length >= 3) findings.push({ text: 'Ajuste de privilégios do processo (' + has(PRIV_APIS).length + ' APIs)', w: 1 });
  const packer = info.sections.filter((s) => PACKER_SECTIONS.includes(s.name.toLowerCase()));
  if (packer.length) findings.push({ text: 'Seções típicas de packer: ' + packer.map((s) => s.name).join(', '), w: 1 });
  const wx = info.sections.filter((s) => s.exec && s.write);
  if (wx.length) findings.push({ text: 'Seção executável E gravável: ' + wx.map((s) => s.name || '(sem nome)').join(', '), w: 1 });
  if (info.entrySection && (info.entryWritable || (info.entryIsLastSection && info.sections.length > 2 && !/^\.?(text|code)$/i.test(info.entrySection)))) {
    findings.push({ text: 'Ponto de entrada em seção atípica (' + info.entrySection + ')', w: 1 });
  }
  const hot = info.sections.some((s) => s.entropy !== null && s.entropy >= 7.2 && s.rawSize > 8192);
  if (info.importCount > 0 && info.importCount <= 4 && hot) findings.push({ text: 'Poucas importações (' + info.importCount + ') e seção cifrada/compactada (entropia alta): típico de packer', w: 1 });
  return findings;
}

/** Varre o ARQUIVO INTEIRO (até maxBytes) por strings suspeitas, ASCII e UTF-16LE, em blocos. */
async function scanStringsFile(fh, size, maxBytes) {
  const CH = 1024 * 1024, OVER = 1024;
  const limit = Math.min(size, maxBytes || 96 * 1024 * 1024);
  const hits = new Map();       // label -> peso
  let pos = 0; let scanned = 0; let carry = Buffer.alloc(0);
  const test = (text) => { for (const r of SUSPICIOUS_STRING_RX) if (!hits.has(r.label) && r.rx.test(text)) hits.set(r.label, r.w === undefined ? 1 : r.w); };
  while (pos < limit) {
    const chunk = await readAt(fh, pos, Math.min(CH, limit - pos));
    if (!chunk.length) break;
    const buf = carry.length ? Buffer.concat([carry, chunk]) : chunk;
    test(buf.toString('latin1'));                                   // ASCII / bytes
    test(buf.toString('utf16le'));                                  // UTF-16LE alinhado
    test(buf.subarray(1).toString('utf16le'));                      // UTF-16LE deslocado
    scanned += chunk.length; pos += chunk.length;
    carry = chunk.subarray(Math.max(0, chunk.length - OVER));
  }
  return { hits, scanned, truncated: size > limit };
}

/**
 * Análise completa de um arquivo no disco. NÃO é antivírus (ver cabeçalho).
 * @param {string} filePath
 * @param {{sha256?:string, magic?:{family?:string}, maxBytes?:number}} arg
 * @returns {Promise<{level:'limpo'|'suspeito'|'infectado', findings:string[], details:object}>}
 */
async function scanFile(filePath, arg) {
  const a = arg || {};
  const findings = []; const details = { kind: 'heuristica-local' };
  if (a.sha256 && MALWARE_HASHES.has(String(a.sha256).toLowerCase())) {
    return { level: 'infectado', findings: ['Hash SHA-256 está na lista de malware fornecida'], details: Object.assign(details, { hashList: MALWARE_HASHES.size }) };
  }
  const fh = await fsp.open(filePath, 'r');
  try {
    const st = await fh.stat();
    const size = st.size;
    let weight = 0;
    let peInfo = null;
    if (size >= 64) { try { peInfo = await parsePeFile(fh, size); } catch (_) { peInfo = null; } }
    const head2 = size >= 2 ? await readAt(fh, 0, 2) : Buffer.alloc(0);
    const looksMz = head2.length === 2 && head2[0] === 0x4D && head2[1] === 0x5A;
    if (peInfo) {
      details.pe = { is64: peInfo.is64, sections: peInfo.sections.length, imports: peInfo.importCount, dlls: Object.keys(peInfo.imports).length, entrySection: peInfo.entrySection, overlay: peInfo.overlay, signed: peInfo.signed, unresolved: peInfo.unresolved };
      for (const f of assessPe(peInfo)) { findings.push(f.text); weight += f.w; }
    } else if (looksMz) {
      findings.push('Cabeçalho MZ sem estrutura PE válida (executável malformado)'); weight += 1;
    }
    const ss = await scanStringsFile(fh, size, a.maxBytes);
    details.coverage = { bytesScanned: ss.scanned, fileSize: size, truncated: ss.truncated, pe: !!peInfo };
    if (ss.hits.size) {
      const counted = [...ss.hits.entries()].filter(([, w]) => w > 0).map(([l]) => l);
      const info0 = [...ss.hits.entries()].filter(([, w]) => w === 0).map(([l]) => l);
      if (counted.length) findings.push('Strings suspeitas: ' + counted.slice(0, 3).join('; ') + (counted.length > 3 ? ' (+' + (counted.length - 3) + ' outras)' : ''));
      if (info0.length) findings.push('Informativo: ' + info0.join('; '));
      for (const w of ss.hits.values()) weight += w;
      details.suspiciousStrings = counted;
    }
    const level = weight >= 2 ? 'suspeito' : 'limpo';
    details.notes = findings.slice();             // registra tudo, mesmo o que não chegou a alerta
    if (level === 'limpo') findings.length = 0;   // um indício isolado de peso 1 não vira alerta (evita falso positivo)
    details.weight = weight;
    return { level, findings, details };
  } finally {
    await fh.close();
  }
}

module.exports = {
  loadHashList, parsePeFile, assessPe, scanStringsFile, scanFile,
  MALWARE_HASHES, SUSPICIOUS_PE_IMPORTS, SUSPICIOUS_STRING_RX,
  shannonEntropy, extractStrings, readPeImports,
  suspiciousImportsFromHead, suspiciousStringsFromHead, scan
};

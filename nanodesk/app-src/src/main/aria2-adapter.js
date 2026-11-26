/**
 * NanoDesk — Adaptador aria2 (1.9.5)
 * ==================================================================
 * Cliente JSON-RPC sobre HTTP para o aria2c (binário C++ embutido em
 * resources/aria2/ ou no PATH). Segurança (especificação 9.1):
 *
 *  - RPC escuta SOMENTE em 127.0.0.1 (loopback) — nunca 0.0.0.0.
 *  - Token secreto gerado por crypto.randomBytes(32) a cada sessão.
 *  - CORS desabilitado (aria2 não envia Access-Control-Allow-Origin).
 *  - O renderer NÃO conhece o token — só o processo principal.
 *  - Binário verificado por PE header + (opcional) SHA-256 conhecido.
 *
 *  Operações suportadas (especificação 9):
 *    aria2.addUri, aria2.tellStatus, aria2.tellActive, aria2.tellWaiting,
 *    aria2.tellStopped, aria2.pause, aria2.unpause, aria2.forceRemove,
 *    aria2.removeDownloadResult, aria2.getVersion, aria2.shutdown
 *
 *  Distribuição (9.2): o binário aria2c.exe (Windows) é buscado em:
 *    1. resources/aria2/aria2c.exe (extra-resource pattern)
 *    2. app.getAppPath()/../aria2/aria2c.exe (legacy)
 *    3. PATH (findTool do video.js)
 *  Se não encontrado, isAvailable()=false e o manager cai no Electron.
 */
'use strict';

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const { STATES, validateTask } = require('./download-engine-interface');
const dlsec = require('./download-security');

/** Porta fixa em range local alto — evita conflito comuns (9050=Tor, 9051=control). */
const ARIA2_PORT = 16801;

function createAria2Adapter(deps) {
  const d = deps || {};
  // d = { app, fetch, findTool, process, isPeBinary, sha256sums (opcional), log }
  const app = d.app;
  const fetchFn = d.fetch;
  const findTool = d.findTool || (() => null);
  const isPeBinary = d.isPeBinary || (() => true);
  const log = d.log || (() => {});

  let proc = null;
  let rpcUrl = '';
  let token = '';
  let bootPromise = null;
  let availableCache = null;
  let ready = false;
  let nextRpcId = 1;
  const inflightRpc = new Map();

  /* ---------------- descoberta do binário ---------------- */

  function binCandidates() {
    if (!app) return [];
    const isWin = process.platform === 'win32';
    const exe = isWin ? 'aria2c.exe' : 'aria2c';
    const out = [];
    if (app.isPackaged) {
      try {
        const p = path.join(process.resourcesPath, 'aria2', exe);
        if (fs.existsSync(p)) out.push(p);
      } catch (_) { /* sem resourcesPath */ }
      out.push(path.join(app.getAppPath(), '..', 'aria2', exe));
    }
    out.push(path.join(app.getAppPath(), 'resources', 'aria2', exe));
    const fromPath = findTool('aria2c');
    if (fromPath) out.push(fromPath);
    return out;
  }

  function resolveBinary() {
    const cands = binCandidates();
    for (const c of cands) {
      try {
        if (!c || !fs.existsSync(c)) continue;
        // Verificação de integridade: PE real (Windows) ou ELF (Linux).
        const head = Buffer.alloc(4096);
        const fd = fs.openSync(c, 'r');
        try { fs.readSync(fd, head, 0, head.length, 0); }
        finally { fs.closeSync(fd); }
        if (!isPeBinary(head.slice(0, 4096))) {
          log('warn', '[aria2] binário não é PE válido: ' + c);
          continue;
        }
        return c;
      } catch (_) { /* segue */ }
    }
    return null;
  }

  function isAvailable() {
    if (availableCache === null) availableCache = !!resolveBinary();
    return availableCache;
  }

  /* ---------------- inicialização do processo ---------------- */

  async function boot() {
    if (bootPromise) return bootPromise;
    if (ready) return true;
    bootPromise = (async () => {
      const bin = resolveBinary();
      if (!bin) {
        log('warn', '[aria2] binário não encontrado — adaptador indisponível');
        bootPromise = null;
        return false;
      }
      token = crypto.randomBytes(32).toString('hex');
      rpcUrl = 'http://127.0.0.1:' + ARIA2_PORT + '/jsonrpc';
      const args = [
        '--enable-rpc',
        '--rpc-listen-all=false',          // só 127.0.0.1 (default já é false)
        '--rpc-listen-port=' + ARIA2_PORT,
        '--rpc-secret=' + token,
        '--rpc-allow-origin-all=false',    // SEM CORS (default false)
        '--continue=true',                 // retoma downloads parcialmente baixados
        '--max-concurrent-downloads=5',
        '--split=4',                       // 4 conexões por arquivo (conservador)
        '--min-split-size=1M',
        '--max-connection-per-server=4',   // teto razoável (especificação 4.1)
        '--file-allocation=none',          // não reserva espaço no disco
        '--allow-overwrite=false',
        '--auto-file-renaming=true',
        '--console-log-level=warn',
        '--log-level=warn',
        // Diretório padrão: Downloads. O manager passa outDir por tarefa (aria2.addUri option dir).
        '--dir=' + (app ? app.getPath('downloads') : process.cwd()),
        // Não carregar sessão anterior (NanoDesk não persiste fila entre reinícios)
        '--input-file='
      ];
      try {
        proc = spawn(bin, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
      } catch (e) {
        log('error', '[aria2] falha ao spawnar: ' + e.message);
        bootPromise = null;
        return false;
      }
      proc.on('error', (e) => {
        log('error', '[aria2] erro do processo: ' + e.message);
        ready = false; bootPromise = null;
      });
      proc.on('exit', (code) => {
        log('info', '[aria2] processo saiu (code=' + code + ')');
        ready = false; bootPromise = null; proc = null;
        // rejeita RPCs pendentes
        for (const [, p] of inflightRpc) {
          try { p.reject(new Error('aria2 encerrou')); } catch (_) {}
        }
        inflightRpc.clear();
      });
      // stderr → log (não derruba nada; aria2 é verboso só em warn/error)
      if (proc.stderr) proc.stderr.on('data', (buf) => {
        const s = String(buf).trim();
        if (s) log('info', '[aria2:stderr] ' + s.slice(0, 240));
      });
      // Espera o RPC aceitar conexões (até 5 s)
      const ok = await waitForRpc(5000);
      if (!ok) {
        try { proc && proc.kill('SIGKILL'); } catch (_) {}
        proc = null; bootPromise = null;
        log('error', '[aria2] RPC não respondeu em 5s');
        return false;
      }
      ready = true;
      log('info', '[aria2] pronto em ' + rpcUrl);
      return true;
    })();
    return bootPromise;
  }

  function waitForRpc(timeoutMs) {
    return new Promise((resolve) => {
      const t0 = Date.now();
      function probe() {
        if (Date.now() - t0 > timeoutMs) return resolve(false);
        call('aria2.getVersion', [], 1000)
          .then(() => resolve(true))
          .catch(() => setTimeout(probe, 300));
      }
      probe();
    });
  }

  /* ---------------- JSON-RPC sobre HTTP ---------------- */

  /**
   * Faz uma chamada JSON-RPC. POST em http://127.0.0.1:port/jsonrpc.
   * Token vai no params[0] como 'token:<secret>' (convenção aria2).
   */
  function call(method, params, timeoutMs) {
    return new Promise((resolve, reject) => {
      if (!ready && method !== 'aria2.getVersion') {
        return reject(new Error('aria2 não está pronto'));
      }
      const id = String(nextRpcId++);
      const body = JSON.stringify({
        jsonrpc: '2.0', id, method,
        params: ['token:' + token, ...(params || [])]
      });
      const data = Buffer.from(body, 'utf8');
      const req = http.request({
        hostname: '127.0.0.1',
        port: ARIA2_PORT,
        path: '/jsonrpc',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': data.length,
          // Sem Origin/Access-Control headers — aria2 rejeita qualquer origin externo.
        },
        timeout: timeoutMs || 8000
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const txt = Buffer.concat(chunks).toString('utf8');
          try {
            const j = JSON.parse(txt);
            if (j.error) return reject(new Error(j.error.message || JSON.stringify(j.error)));
            resolve(j.result);
          } catch (e) { reject(new Error('RPC JSON inválido: ' + e.message)); }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(new Error('timeout')); });
      req.write(data);
      req.end();
    });
  }

  /* ---------------- interface do engine ---------------- */

  function name() { return 'aria2'; }

  /**
   * Inicia um download. Devolve o GID (16 chars hex) do aria2.
   * @param {Task} task
   */
  async function start(task) {
    const err = validateTask(task);
    if (err) throw new Error(err);
    // 1.9.6 (ERRO 1): regra de proxy fail-closed. Tarefa de aba Tor (torRequired)
    // SEM proxy Tor validado → RECUSA (nada de conexão direta). Proxy presente
    // precisa ser socks5://127.0.0.1:<porta> (daemon Tor embutido do NanoDesk).
    const proxyErr = dlsec.validateTaskProxy(task);
    if (proxyErr) throw new Error(proxyErr);
    if (!ready) {
      const ok = await boot();
      if (!ok) throw new Error('aria2 indisponível');
    }
    const opts = {
      dir: task.outDir,
      out: task.fileName,
      'user-agent': task.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/156.0.0.0 Safari/537.36',
      'max-connection-per-server': '4',
      split: '4',
      'min-split-size': '1M',
      'allow-overwrite': 'false',
      'auto-file-renaming': 'true'
    };
    // 1.9.6 (ERRO 1): TODO o tráfego desta tarefa sai pelo proxy Tor validado
    // (todas as conexões segmentadas incluídas — all-proxy é global por tarefa).
    if (task.proxy) {
      opts['all-proxy'] = task.proxy;
      // loopback nunca deve ser roteado pelo proxy (RPC é local, não afeta)
      opts['no-proxy'] = '127.0.0.1,localhost';
    }
    if (task.headers) {
      opts.header = Object.entries(task.headers).map(([k, v]) => k + ': ' + v);
    }
    if (task.referrer) opts.referer = task.referrer;
    if (task.cookies && task.cookies.length) {
      // aria2 aceita cookies como array de strings "name=value" no header Cookie,
      // ou --load-cookies com arquivo Netscape. Aqui usamos o header Cookie.
      const ck = task.cookies.map(c => c.name + '=' + c.value).join('; ');
      opts.header = (opts.header || []).concat(['Cookie: ' + ck]);
    }
    const gid = await call('aria2.addUri', [[task.url], opts], 10000);
    return String(gid);
  }

  async function pause(gid) {
    try { await call('aria2.pause', [gid], 5000); return true; }
    catch (_) { try { await call('aria2.forcePause', [gid], 5000); return true; } catch (e) { return false; } }
  }

  async function resume(gid) {
    try { await call('aria2.unpause', [gid], 5000); return true; }
    catch (_) { return false; }
  }

  async function cancel(gid) {
    try {
      await call('aria2.forceRemove', [gid], 5000);
      // limpa o resultado da memória do aria2
      try { await call('aria2.removeDownloadResult', [gid], 2000); } catch (_) {}
      return true;
    } catch (_) { return false; }
  }

  /**
   * Status de um download. Mapeia os códigos do aria2 para STATES.
   * @returns {EngineStatus}
   */
  async function status(gid) {
    try {
      const st = await call('aria2.tellStatus', [gid, [
        'status', 'totalLength', 'completedLength', 'downloadSpeed',
        'files', 'errorCode', 'errorMessage', 'bittorrent'
      ]], 4000);
      const state = mapStatus(st.status);
      const total = parseInt(st.totalLength || '0', 10);
      const received = parseInt(st.completedLength || '0', 10);
      const speed = parseInt(st.downloadSpeed || '0', 10);
      const file = (st.files && st.files[0]);
      return {
        state,
        received, total, speed,
        path: file ? file.path : '',
        etaSec: speed > 0 ? Math.ceil((total - received) / speed) : undefined,
        error: st.errorMessage ? String(st.errorMessage).slice(0, 240) : undefined
      };
    } catch (e) {
      return { state: STATES.ERROR, received: 0, total: 0, speed: 0, error: String(e && e.message || e).slice(0, 240) };
    }
  }

  function mapStatus(s) {
    switch (s) {
      case 'active': return STATES.DOWNLOADING;
      case 'waiting': case 'paused': return STATES.PAUSED;
      case 'complete': return STATES.COMPLETED;
      case 'removed': return STATES.CANCELLED;
      case 'error': return STATES.ERROR;
      default: return STATES.WAITING;
    }
  }

  /** Lista GIDs ativos (para sincronização periódica). */
  async function activeGids() {
    try {
      const list = await call('aria2.tellActive', [[]], 3000);
      return Array.isArray(list) ? list.map(o => o.gid) : [];
    } catch (_) { return []; }
  }

  /** Tarefas paradas (completas/com erro) para recover().
   *  1.9.6-d (B): inclui o dir da tarefa — o manager só retoma quando a
   *  pasta de destino é confiável (dentro de Downloads do app). */
  async function recover() {
    if (!ready) return [];
    try {
      const stopped = await call('aria2.tellStopped', [0, 100, [['gid', 'status', 'files', 'dir']]], 4000);
      return (stopped || []).map(o => ({
        gid: o.gid,
        state: mapStatus(o.status),
        path: (o.files && o.files[0] && o.files[0].path) || '',
        dir: String(o.dir || '')
      }));
    } catch (_) { return []; }
  }

  /** Encerra o aria2c gracefully (aria2.shutdown). */
  async function shutdown() {
    if (!proc) return;
    try {
      if (ready) await call('aria2.shutdown', [], 2000);
    } catch (_) {
      try { proc.kill('SIGTERM'); } catch (_) {}
    }
    // espera o processo sair (até 3s)
    const p = proc;
    await new Promise((resolve) => {
      const t = setTimeout(() => { try { p.kill('SIGKILL'); } catch (_) {} resolve(); }, 3000);
      p.on('exit', () => { clearTimeout(t); resolve(); });
    });
    proc = null; ready = false; bootPromise = null;
  }

  return {
    name, isAvailable, boot,
    start, pause, resume, cancel, status,
    activeGids, recover, shutdown,
    // expostos para testes/integração
    _call: call, _rpcUrl: () => rpcUrl, _ready: () => ready
  };
}

module.exports = { createAria2Adapter, ARIA2_PORT };

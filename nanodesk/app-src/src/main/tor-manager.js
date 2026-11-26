/**
 * NanoDesk — Gerenciador do Tor NATIVO (1.5.3)
 * ==================================================================
 * O Tor passa a rodar SEM cliente externo: o pacote oficial
 * "Tor Expert Bundle" (dist.torproject.org, licença BSD-3 + GPL para
 * o tor) é embarcado em resources/tor/<plataforma>/ e o NanoDesk
 * controla o processo `tor` diretamente — exatamente como o próprio
 * Tor Browser faz internamente. Nada de VPN fictícia: é o daemon
 * real, com SOCKS5 + ControlPort + cookie de autenticação.
 *
 * Fluxo:
 *  1. start(): escolhe portas livres (preferência 9050/9051), grava um
 *     torrc minimalista no diretório do app e faz spawn do binário;
 *  2. O stdout do tor é analisado ("Bootstrapped N% (tag): resumo" e
 *     as portas efetivamente abertas) e vira eventos para a interface;
 *  3. No 100% o estado fica "connected" — as abas Tor passam a usar a
 *     sessão isolada com proxy socks5://127.0.0.1:<porta> (SEM fallback
 *     direto: com o Tor fora do ar, a aba Tor FALHA — nunca vaza);
 *  4. newIdentity(): SIGNAL NEWNYM pelo ControlPort (autenticado com o
 *     cookie que o próprio tor grava);
 *  5. stop(): SIGNAL SHUTDOWN e, se necessário, kill.
 *
 * O núcleo de análise (torrc, linhas de bootstrap, respostas do
 * protocolo de controle, resolução do binário) é puro e testável.
 */
'use strict';

const { spawn } = require('child_process');
const net = require('net');
const fs = require('fs');
const path = require('path');

/* ------------------------------ puros ------------------------------ */

const TOR_SUBDIR = { win32: 'win', darwin: 'mac', linux: 'linux' };
const TOR_BINARY = { win32: 'tor.exe', darwin: 'tor', linux: 'tor' };

/**
 * Localiza o binário do Tor embarcado.
 * @param {object} opts { platform, resourcesDir, envOverride? }
 *   resourcesDir: pasta "tor" (fora do app.asar no pacote Windows).
 *   envOverride:  NANODESK_TOR_DIR (para desenvolvimento/testes).
 * @returns {string|null} caminho do binário ou null (pacote ausente)
 */
function resolveTorBinary(opts = {}) {
  const platform = opts.platform || process.platform;
  const envDir = opts.envOverride ||
    (typeof process !== 'undefined' && process.env ? process.env.NANODESK_TOR_DIR : '');
  const base = envDir ? String(envDir) : path.join(String(opts.resourcesDir || ''), TOR_SUBDIR[platform] || platform);
  if (!base) return null;
  const binName = TOR_BINARY[platform] || 'tor';
  // O Expert Bundle vem com o binário dentro de uma subpasta "tor"
  // (tor/tor.exe); aceitamos também o binário direto na pasta.
  const candidates = [path.join(base, binName), path.join(base, 'tor', binName)];
  for (const bin of candidates) {
    try {
      if (fs.existsSync(bin) && fs.statSync(bin).isFile()) return bin;
    } catch (_) { /* tenta o próximo */ }
  }
  return null;
}

/**
 * torrc minimalista e documentado. ClientOnly garante que a máquina
 * NUNCA vira retransmissor/saída; IsolateDestAddr/IsolateDestPort dão
 * isolamento de circuito por destino (mesmo critério de isolamento do
 * Tor Browser para destinos distintos).
 */
function buildTorrc(o = {}) {
  const dataDir = String(o.dataDir || '.');
  // 1.6.2: com o processo rodando COM cwd = pasta de dados, usamos caminhos RELATIVOS.
  // O tor.exe lê o torrc na página de código ANSI do Windows: um caminho absoluto com
  // acento (C:\\Users\\João\\...) quebraria a partida. Relativo = só ASCII.
  const cookieFile = o.relative ? 'control-auth-cookie' : path.join(dataDir, 'control-auth-cookie');
  const dataSub = o.relative ? 'data' : path.join(dataDir, 'data');
  return [
    '# Gerado pelo NanoDesk em ' + new Date().toISOString(),
    '# Controla apenas o daemon embutido — arquivos em pasta exclusiva.',
    'SocksPort 127.0.0.1:' + (o.socksPort || 9050) + ' IsolateDestAddr IsolateDestPort',
    'ControlPort 127.0.0.1:' + (o.controlPort || 9051),
    'CookieAuthentication 1',
    'CookieAuthFile ' + cookieFile,
    'DataDirectory ' + dataSub,
    'ClientOnly 1',
    'AvoidDiskWrites 1',
    'SafeLogging 1',
    'Log notice stdout'
  ].join('\n') + '\n';
}

/**
 * "Nov 07 14:39:31.000 [notice] Bootstrapped 100% (done): Done"
 *   -> { progress: 100, tag: 'done', summary: 'Done' }
 */
function parseBootstrapLine(line) {
  const m = /Bootstrapped (\d{1,3})% \(([^)]+)\): (.+)/.exec(String(line || ''));
  if (!m) return null;
  const progress = Number(m[1]);
  if (!Number.isInteger(progress) || progress < 0 || progress > 100) return null;
  return { progress, tag: m[2].trim(), summary: m[3].trim() };
}

/** "Socks listener listening on port 40287." -> 40287 (formato do SocksPort auto) */
function parseListenerPort(line, kind) {
  let m = new RegExp(kind + ' listener listening on port (\\d+)', 'i').exec(String(line || ''));
  if (m) return Number(m[1]);
  // formato com porta explícita: "Opened Socks listener connection (ready) on 127.0.0.1:9050"
  m = new RegExp('Opened ' + kind + ' listener connection \\(ready\\) on [\\d.]+:(\\d+)', 'i').exec(String(line || ''));
  return m ? Number(m[1]) : null;
}

/**
 * Analisa uma resposta do protocolo de controle (line-based, CRLF):
 *  "250 OK"                     -> { ok: true, lines: ['250 OK'] }
 *  "250-circuit-established=1"  -> { ok: true, lines: [...] }  (última "250 OK")
 *  "513 Unrecognized command"   -> { ok: false, error: '513 ...', lines: [...] }
 * Aceita também linhas de evento 650 (SIGNAL NEWNYM gera "650 NS..."? —
 * são ignoradas na contagem da resposta atual).
 */
function parseControlReply(text) {
  const lines = String(text || '').split(/\r?\n/).filter(l => l.length);
  const out = { ok: false, done: false, error: '', lines: [] };
  for (const line of lines) {
    out.lines.push(line);
    const m = /^(\d{3})([- ])\s?(.*)$/.exec(line);
    if (!m) continue;
    const code = Number(m[1]);
    if (code === 650) continue;              // evento assíncrono — não encerra
    if (m[2] === ' ') {                      // última linha da resposta
      out.done = true;
      out.ok = code >= 200 && code < 300;
      if (!out.ok) out.error = line;
    }
  }
  return out;
}

/**
 * Porta livre a partir de uma preferida (o teste determina se a porta
 * está realmente utilizável antes de gravar no torrc).
 * @param {number} preferred  porta desejada (0 = já pede aleatória)
 * @param {function} [probe]  (port, cb) => cb(free:boolean) — injetável p/ testes
 * @returns {Promise<number>}
 */
/**
 * 1.8.10: findFreePort retorna a porta REAL alocada pelo SO.
 * Antes: realProbe chamava cb(true/false) sem devolver o número da porta
 * quando p===0 — findFreePort devolvia 0 e applyTorProxy podia apontar
 * para uma porta inválida (1) durante a janela antes de o Tor anunciar
 * sua porta de listener.
 */
function findFreePort(preferred, probe) {
  const realProbe = probe || ((port, cb) => {
    const srv = net.createServer();
    const done = (free, boundPort) => {
      try { srv.close(() => cb(free, boundPort)); } catch (_) { cb(free, boundPort); }
    };
    srv.once('error', () => done(false, 0));
    srv.listen(port, '127.0.0.1', () => done(true, srv.address() ? srv.address().port : 0));
  });
  return new Promise((resolve) => {
    const tryPort = (p) => {
      realProbe(p, (free, boundPort) => {
        if (free) {
          // Preferência: a porta REAL alocada (importante quando p===0)
          // caindo para p só se o probe não devolver a porta.
          resolve(Number(boundPort) > 0 ? Number(boundPort) : p);
        } else if (p === 0) {
          resolve(0); // não deveria acontecer — porta 0 sempre livre
        } else {
          tryPort(0); // preferida ocupada: deixa o sistema escolher
        }
      });
    };
    tryPort(Number(preferred) > 0 ? Number(preferred) : 0);
  });
}

/* ---------------------------- gerenciador ---------------------------- */

/**
 * Cria o gerenciador do Tor.
 * @param {object} opts { resourcesDir, dataDir, onEvent(ev), locale }
 *   onEvent recebe { state, progress?, tag?, summary?, error?, socksPort?, controlPort? }
 */
function createTorManager(opts = {}) {
  const dataDir = String(opts.dataDir || '.');
  const emit = (ev) => { if (typeof opts.onEvent === 'function') { try { opts.onEvent(ev); } catch (_) {} } };

  const state = {
    phase: 'off',        // off | starting | bootstrapping | connected | stopping | error
    progress: 0,
    tag: '',
    summary: '',
    error: '',
    socksPort: 0,
    controlPort: 0,
    proc: null,
    ctrl: null,          // socket de controle autenticado
    ctrlReady: false,
    ctrlBuf: '',
    ctrlQueue: [],
    ctrlBusy: false,
    ownershipDone: false, // 1.6.7: TAKEOWNERSHIP + __OwningControllerProcess
    stopping: false,
    tail: []             // últimas linhas para diagnóstico de falha
  };

  function setPhase(phase, extra) {
    state.phase = phase;
    emit(Object.assign({ state: phase, progress: state.progress, tag: state.tag,
      summary: state.summary, error: state.error }, extra || {}));
  }

  function noteLine(line) {
    state.tail.push(String(line).slice(0, 300));
    if (state.tail.length > 12) state.tail.shift();
  }

  function clearRuntimeFiles() {
    // cookie de controle e torrc ficam na pasta do runtime; o DataDirectory
    // (consenso público) é recriado pelo tor a cada partida.
    try { for (const f of ['control-auth-cookie', 'torrc']) {
      fs.rmSync(path.join(dataDir, f), { force: true });
    } } catch (_) {}
  }

  /* ---- protocolo de controle (mínimo: AUTHENTICATE/SIGNAL/GETINFO) ---- */

  function controlSend(line) {
    return new Promise((resolve, reject) => {
      if (!state.ctrl || state.ctrl.destroyed) return reject(new Error('Controle do Tor indisponível.'));
      const job = { line, resolve, reject, timer: null };
      // CORREÇÃO 1.6.7: comando sem timeout podía ficar pendente PARA SEMPRE
      // (tor travado no meio de SIGNAL NEWNYM travava a fila inteira).
      job.timer = setTimeout(() => {
        const i = state.ctrlQueue.indexOf(job);
        if (i >= 0) state.ctrlQueue.splice(i, 1);
        if (state.ctrlBusy && job === state.currentJob) {
          try { state.ctrl.removeListener('data', state.currentOnData); } catch (_) {}
          state.ctrlBusy = false;
          state.currentJob = null;
          pumpControl();
        }
        reject(new Error('Tempo esgotado no comando de controle do Tor.'));
      }, 10000);
      state.ctrlQueue.push(job);
      pumpControl();
    });
  }

  function pumpControl() {
    if (state.ctrlBusy || !state.ctrlQueue.length) return;
    if (!state.ctrl || state.ctrl.destroyed) {
      for (const j of state.ctrlQueue) { clearTimeout(j.timer); j.reject(new Error('Controle do Tor indisponível.')); }
      state.ctrlQueue = [];
      return;
    }
    state.ctrlBusy = true;
    const job = state.ctrlQueue.shift();
    state.currentJob = job;
    state.ctrlBuf = '';
    state.ctrl.write(job.line + '\r\n');
    const onData = (chunk) => {
      state.ctrlBuf += chunk.toString('utf8');
      const reply = parseControlReply(state.ctrlBuf);
      if (!reply.done) return;
      state.ctrl.removeListener('data', onData);
      state.currentOnData = null;
      state.ctrlBusy = false;
      state.currentJob = null;
      clearTimeout(job.timer);
      if (reply.ok) job.resolve(reply);
      else job.reject(new Error(reply.error || 'Comando de controle recusado.'));
      pumpControl();
    };
    state.currentOnData = onData;
    state.ctrl.on('data', onData);
  }

  async function ensureControl() {
    if (state.ctrl && !state.ctrl.destroyed && state.ctrlQueue.length === 0 && state.ctrlReady) {
      return state.ctrl;
    }
    if (!state.controlPort) throw new Error('Porta de controle ainda não informada pelo tor.');
    const cookie = fs.readFileSync(path.join(dataDir, 'control-auth-cookie'));
    await new Promise((resolve, reject) => {
      const sock = net.connect({ host: '127.0.0.1', port: state.controlPort });
      const to = setTimeout(() => { sock.destroy(); reject(new Error('Tempo esgotado no ControlPort.')); }, 5000);
      sock.once('error', (e) => { clearTimeout(to); reject(e); });
      sock.once('connect', () => {
        clearTimeout(to);
        state.ctrl = sock;
        state.ctrlBuf = '';
        // respostas dos comandos são consumidas pelo listener próprio do
        // pumpControl; este socket não tem listener permanente aqui.
        resolve();
      });
    });
    await controlSend('AUTHENTICATE ' + cookie.toString('hex'));
    state.ctrlReady = true;
    // CORREÇÃO 1.6.7 (privacidade): o daemon podia ficar ÓRFÃO se o NanoDesk
    // crashasse ou fosse morto — o SOCKS continuava aberto indefinidamente.
    // Com TAKEOWNERSHIP o tor sai quando ESTA conexão de controle fechar (o
    // SO fecha o socket em qualquer morte do processo); __OwningControllerProcess
    // é a segunda rede de segurança (o tor monitora o PID do dono).
    if (!state.ownershipDone) {
      try { await controlSend('TAKEOWNERSHIP'); state.ownershipDone = true; } catch (_) { /* tor antigo */ }
      try { await controlSend('SETCONF __OwningControllerProcess=' + process.pid); } catch (_) { /* idem */ }
    }
    state.ctrl.on('close', () => {
      state.ctrlReady = false;
      state.ctrl = null;
      // CORREÇÃO 1.6.7: a fila pendente é REJEITADA (antes ficava pendurada
      // para sempre e ctrlBusy travava o canal de controle).
      for (const j of state.ctrlQueue) { clearTimeout(j.timer); j.reject(new Error('Conexão de controle do Tor encerrada.')); }
      state.ctrlQueue = [];
      // 1.8.10: rejeitar também o job EM ANDAMENTO (currentJob) — antes, o close
      // só zerava a referência mas o Promise do job continuava pendente até o
      // setTimeout de 10s disparar (10s de silêncio na UI).
      if (state.currentJob) {
        try { clearTimeout(state.currentJob.timer); state.currentJob.reject(new Error('Conexão de controle do Tor encerrada.')); }
        catch (_) { /* best-effort */ }
      }
      state.ctrlBusy = false;
      state.currentJob = null;
    });
    return state.ctrl;
  }

  /* ------------------------------ start ------------------------------ */

  async function start() {
    if (state.phase === 'starting' || state.phase === 'bootstrapping') {
      return { ok: false, reason: 'já está conectando' };
    }
    if (state.phase === 'connected') return { ok: false, reason: 'já está conectado' };
    await stopInternal(true); // encerra instância anterior com erro, se houver

    const binary = resolveTorBinary({ resourcesDir: opts.resourcesDir });
    if (!binary) {
      const dir = path.join(String(opts.resourcesDir || ''), TOR_SUBDIR[process.platform] || '');
      setPhase('error', { error: 'Pacote do Tor não encontrado (esperado: ' + dir + ').' });
      return { ok: false, reason: 'sem binário' };
    }

    state.error = '';
    state.progress = 0;
    state.tag = '';
    state.summary = '';
    state.tail = [];
    setPhase('starting');

    try { fs.mkdirSync(path.join(dataDir, 'data'), { recursive: true }); } catch (_) {}
    const socksPort = await findFreePort(9050);
    const controlPort = await findFreePort(9051);
    fs.writeFileSync(path.join(dataDir, 'torrc'), buildTorrc({ socksPort, controlPort, dataDir, relative: true }), 'utf8');
    // As portas já são conhecidas (escolhidas acima e gravadas no torrc);
    // o parser do log serve de confirmação/refino (caso de porta 0/auto).
    state.socksPort = socksPort;
    state.controlPort = controlPort;

    let proc;
    try {
      proc = spawn(binary, ['-f', 'torrc', '--ignore-missing-torrc'], {
        cwd: dataDir,   // 1.6.2: caminhos relativos (ver buildTorrc)
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true
      });
    } catch (e) {
      setPhase('error', { error: 'Não foi possível iniciar o tor: ' + e.message });
      return { ok: false, reason: 'spawn falhou' };
    }
    state.proc = proc;

    const onLine = (line) => {
      noteLine(line);
      const boot = parseBootstrapLine(line);
      if (boot) {
        state.progress = boot.progress;
        state.tag = boot.tag;
        state.summary = boot.summary;
        if (state.phase !== 'connected') {
          if (boot.progress >= 100) finalizeConnected();
          else setPhase('bootstrapping');
        }
        return;
      }
      const sp = parseListenerPort(line, 'Socks');
      if (sp) state.socksPort = sp;
      const cp = parseListenerPort(line, 'Control');
      if (cp) state.controlPort = cp;
    };
    const feed = (buf) => String(buf).split(/\r?\n/).forEach(l => { if (l.trim()) onLine(l); });
    proc.stdout.on('data', feed);
    proc.stderr.on('data', feed);

    proc.once('exit', (code, signal) => {
      proc.removeAllListeners('exit');
      state.proc = null;
      try { if (state.ctrl) state.ctrl.destroy(); } catch (_) {}
      state.ctrl = null; state.ctrlReady = false; state.ctrlQueue = [];
      clearRuntimeFiles();
      if (state.stopping) {
        state.stopping = false;
        state.socksPort = 0; state.controlPort = 0;
        setPhase('off');
      } else {
        const last = state.tail.filter(l => /err|fail|could not bind/i.test(l)).pop() ||
          state.tail[state.tail.length - 1] || ('código ' + code);
        state.progress = 0;
        setPhase('error', { error: 'O tor foi encerrado: ' + String(last).slice(0, 220) });
      }
    });

    return { ok: true, socksPort, controlPort };
  }

  function finalizeConnected() {
    if (state.phase === 'connected') return;
    setPhase('connected');
  }

  /* ---------------------------- identidade ---------------------------- */

  async function newIdentity() {
    if (state.phase !== 'connected') throw new Error('O Tor não está conectado.');
    await ensureControl();
    await controlSend('SIGNAL NEWNYM');
    return true;
  }

  /* ------------------------------- stop ------------------------------- */

  let stoppingPromise = null;
  function stop() {
    if (stoppingPromise) return stoppingPromise;
    stoppingPromise = stopInternal(false).finally(() => { stoppingPromise = null; });
    return stoppingPromise;
  }

  function stopInternal(silent) {
    const proc = state.proc;
    if (!proc) {
      if (!silent && state.phase !== 'off') setPhase('off');
      return Promise.resolve();
    }
    if (!silent) state.stopping = true;
    return new Promise((resolve) => {
      const killHard = setTimeout(() => {
        try { proc.kill('SIGKILL'); } catch (_) {}
      }, 2500);
      const done = setTimeout(() => resolve(), 3000);
      proc.once('exit', () => { clearTimeout(killHard); clearTimeout(done); resolve(); });
      (async () => {
        try { await ensureControl(); await controlSend('SIGNAL SHUTDOWN'); }
        catch (_) { try { proc.kill(); } catch (_) {} }
      })();
    });
  }

  function killNow() {
    state.stopping = true;
    try { if (state.proc) state.proc.kill('SIGKILL'); } catch (_) {}
    try { if (state.ctrl) state.ctrl.destroy(); } catch (_) {}
  }

  function status() {
    return {
      state: state.phase,
      progress: state.progress,
      tag: state.tag,
      summary: state.summary,
      error: state.error,
      socksPort: state.socksPort,
      controlPort: state.controlPort
    };
  }

  return {
    start, stop, stopInternal, newIdentity, killNow, status,
    get socksPort() { return state.socksPort; },
    get controlPort() { return state.controlPort; },
    get phase() { return state.phase; }
  };
}

module.exports = {
  TOR_SUBDIR,
  TOR_BINARY,
  resolveTorBinary,
  buildTorrc,
  parseBootstrapLine,
  parseListenerPort,
  parseControlReply,
  findFreePort,
  createTorManager
};

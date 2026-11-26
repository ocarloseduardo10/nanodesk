/**
 * NanoDesk — Gerenciador central de downloads (1.9.5)
 * ==================================================================
 * Ponto ÚNICO de entrada para todos os downloads do NanoDesk (especificação
 * 5 + 4.3): renderer pede → manager escolhe engine → adapta ao DownloadStore
 * existente → emite eventos 'downloads:update'.
 *
 *  Engine selection (especificação 4.3):
 *    - task.engine explícito            → usa esse engine
 *    - task.sessionPartition exigida    → Electron (sessão autenticada da aba)
 *    - tarefa direta HTTP/HTTPS >= 5MB  → aria2 (segmentação)
 *    - tarefa direta HTTP/HTTPS < 5MB   → Electron (overhead de aria2 não vale)
 *    - Gopeed                            → só se task.engine='gopeed' explicitamente
 *
 *  Anti-duplicata: mesma URL no mesmo tab não cria dois downloads — devolve
 *  o download existente.
 *
 *  Lifecycle: pause/resume/cancel repassados ao engine que criou a tarefa.
 *  Recuperação: recover() no boot (aria2/Gopeed) — lista tarefas persistidas
 *  e recria registros no DownloadStore.
 *
 *  Não persiste fila no disco (compatível com "nada gravado" do NanoDesk):
 *  recover() só vale para a sessão atual do aria2 (continue=true).
 */
'use strict';

const { STATES, validateTask } = require('./download-engine-interface');
const dlsec = require('./download-security');

function createDownloadManager(deps) {
  // deps = {
  //   electronAdapter, aria2Adapter, gopeedAdapter,
  //   downloads: módulo downloads.js (safeFileName, uniquePath, isRiskyFile, sha256File, LIMITS),
  //   downloadStore,   // MemoryStore com .get('items', []), .set('items', ...)
  //   pushDownloads,   // fn que envia 'downloads:update' ao renderer
  //   toast, pushSecurityEvent,
  //   app (Electron app), fs, path, hostOf,
  //   torPartition?:  string — nome da partição da sessão Tor ('tor-nanodesk');
  //   torProxy?:      () => 'socks5://127.0.0.1:<porta>' | null — proxy Tor VALIDADO
  //                   (só quando o daemon embutido está conectado);
  //   security?:      { limits: LIMITS, onComplete(rec) } — ERRO 2 (1.9.6): gate
  //                   CENTRAL de segurança. onComplete roda para TODO engine no
  //                   finalize (no main.js: magic bytes, ZIP, scanner nativo,
  //                   ClamAV/YARA, veredito, quarentena — a mesma fila queueScan).
  //   log
  // }
  const d = deps || {};
  const electronAd = d.electronAdapter;
  const aria2Ad = d.aria2Adapter;
  const gopeedAd = d.gopeedAdapter;
  const dl = d.downloads;
  const store = d.downloadStore;
  const pushDownloads = d.pushDownloads || (() => {});
  const toast = d.toast || (() => {});
  const pushSecurityEvent = d.pushSecurityEvent || (() => {});
  const app = d.app;
  const fs = d.fs || require('fs');
  const path = d.path || require('path');
  const hostOf = d.hostOf || ((u) => { try { return new URL(u).hostname.toLowerCase(); } catch (_) { return ''; } });
  const log = d.log || (() => {});
  // 1.9.6 — dependências de privacidade (ERRO 1) e segurança central (ERRO 2).
  const torPartition = d.torPartition || '';
  const torProxy = d.torProxy || (() => null);
  const security = d.security || { limits: null, onComplete: null };
  // 1.9.6-b (P4): função de quarentena injetada pelo main.js (fail-closed).
  const quarantineMove = typeof d.quarantineMove === 'function' ? d.quarantineMove : null;
  const limits = security.limits || d.downloads && d.downloads.LIMITS || null;

  // gid externo (aria2/Gopeed) -> rec.id (NanoDesk) para rotear pause/resume/cancel
  const gidToRecId = new Map();
  // (tabId, urlNormalizada) -> recId ativo/não-finalizado, anti-duplicata
  const activeByKey = new Map();
  // gid -> intervalId para status polling (aria2/Gopeed não têm push, só poll)
  const pollTimers = new Map();

  /* 1.9.6-b (P3) — ADOÇÃO ELECTRON: o engine Electron é fire-and-forget
   * (downloadURL); o registro REAL nasce no 'will-download' (handleNewDownload).
   * Para NÃO existirem dois registros para o mesmo download (o do manager
   * preso em "downloading" + o real do main), o manager registra o rec como
   * PENDENTE DE ADOÇÃO e o handleNewDownload o adota: mesmo id, mesmos
   * controles, um único registro. Se o onStarted não chegar no prazo, o rec
   * vira ERRO honesto (não fica eternamente "downloading"). */
  const pendingElectron = new Map();   // pendingKey(tabId, urlKey) -> { recId, urlKey, timer }
  const PENDING_ELECTRON_TTL_MS = Math.max(250, Number(d.pendingElectronTtlMs) || 60000);

  /* 1.9.6-d (A): chave COMPOSTA aba+URL. A versão anterior usava SÓ a URL
   * normalizada: duas abas baixando a MESMA URL sobrescreviam a pendência da
   * primeira (o anti-duplicata permite downloads iguais em abas distintas) —
   * um dos dois adotava o registro ERRADO e o outro ficava pendente até
   * expirar. Agora cada aba tem a sua pendência; quando a aba do DownloadItem
   * não é identificável, só adota por URL se houver EXATAMENTE UMA pendência
   * com essa URL (fallback inequívoco — nunca adota a errada). */
  function pendingKey(tabId, url) {
    const urlKey = normalizeUrl(url);
    if (!urlKey) return '';
    return String(tabId == null || tabId === '' ? '*' : tabId) + '::' + urlKey;
  }

  function registerPendingElectron(url, recId, tabId) {
    const key = pendingKey(tabId, url);
    if (!key) return;
    const timer = setTimeout(() => {
      const pend = pendingElectron.get(key);
      if (!pend || pend.recId !== recId) return;
      pendingElectron.delete(key);
      const rec = findRec(recId);
      if (rec && (rec.state === STATES.RESOLVING || rec.state === STATES.DOWNLOADING)) {
        rec.state = STATES.ERROR;
        rec.error = 'O download não iniciou (nenhum retorno do navegador).';
        toast('Download não iniciou: ' + rec.name);
        finalizeRec(rec, STATES.ERROR);
      }
    }, PENDING_ELECTRON_TTL_MS);
    if (timer.unref) timer.unref();
    pendingElectron.set(key, { recId, urlKey: normalizeUrl(url), timer });
  }

  /** Chamado pelo handleNewDownload (main.js): devolve o rec pendente para
   *  adoção (e limpa o prazo). tabId = aba de origem do DownloadItem
   *  (item.getWebContents → tabByWebContents). Sem pendente → null. */
  function takePendingElectron(rawUrl, tabId) {
    const urlKey = normalizeUrl(rawUrl);
    if (!urlKey) return null;
    let pend = pendingElectron.get(pendingKey(tabId, urlKey));
    if (!pend) {
      // Fallback inequívoco: aba desconhecida — adota por URL SOMENTE se
      // existir exatamente UMA pendência com essa URL. Com duas abas na
      // mesma URL não há como saber qual é: não adota NENHUMA (cada uma
      // cria seu próprio registro — nunca se adota o registro errado).
      const cands = [];
      for (const p of pendingElectron.values()) if (p.urlKey === urlKey) cands.push(p);
      if (cands.length !== 1) return null;
      pend = cands[0];
    }
    clearTimeout(pend.timer);
    for (const [k, p] of pendingElectron) { if (p === pend) { pendingElectron.delete(k); break; } }
    const rec = findRec(pend.recId);
    return rec ? { rec } : null;
  }

  /** Solta o anti-duplicata quando o DownloadItem termina (via main.js). */
  function clearActiveKey(recId) {
    for (const [k, id] of activeByKey) {
      if (id === recId) { activeByKey.delete(k); break; }
    }
  }

  // 1.9.6: intervalo de poll injetável (testes usam um valor pequeno)
  const POLL_INTERVAL_MS = Math.max(20, Number(d.pollIntervalMs) || 800);

  /* ---------------- registros (compatíveis com o existente) ---------------- */

  function records() { return store.get('items', []); }
  function setRecords(arr) {
    if (arr.length > 200) arr.length = 200;
    store.set('items', arr);
    pushDownloads();
  }
  function findRec(id) { return records().find(r => r.id === id); }
  function findRecByGid(gid) { const id = gidToRecId.get(gid); return id ? findRec(id) : null; }
  function upsertRec(rec) {
    const items = records();
    const i = items.findIndex(r => r.id === rec.id);
    if (i >= 0) items[i] = rec;
    else { items.unshift(rec); if (items.length > 200) items.length = 200; }
    setRecords(items);
  }

  /* ---------------- escolha de engine ---------------- */

  /**
   * Decide qual engine usar para uma tarefa.
   * @returns {object} engine + reason
   */
  function pickEngine(task) {
    // 1.9.6 (ERRO 1): aba Tor — motores EXTERNOS só com proxy Tor VALIDADO.
    // Um motor externo sem proxy faria conexão DIRETA e vazaria o IP real
    // exatamente quando o usuário escolheu não expô-lo. Fail-closed.
    const torRequired = dlsec.isTorTask(task);
    // 1) Preferência explícita do caller (renderer/yt-dlp path)
    if (task.engine === 'gopeed' && gopeedAd && gopeedAd.isAvailable()) {
      // Gopeed é um serviço EXTERNO (env do usuário): não há como validar que
      // ele honrará um proxy Tor → em aba Tor NUNCA é permitido.
      if (torRequired) {
        return { engine: null, name: 'bloqueado', reason: 'tor-gopeed-sem-proxy-validado' };
      }
      return { engine: gopeedAd, name: 'gopeed', reason: 'engine explícito' };
    }
    if (task.engine === 'aria2' && aria2Ad && aria2Ad.isAvailable()) {
      if (torRequired) {
        const proxy = torProxy();
        if (!dlsec.isValidTorProxy(proxy)) {
          return { engine: null, name: 'bloqueado', reason: 'tor-sem-proxy' };
        }
        task.proxy = proxy;   // o adaptador valida de novo (defesa em profundidade)
        return { engine: aria2Ad, name: 'aria2', reason: 'engine explícito com proxy Tor validado' };
      }
      return { engine: aria2Ad, name: 'aria2', reason: 'engine explícito' };
    }
    if (task.engine === 'electron') {
      return { engine: electronAd, name: 'electron', reason: 'engine explícito' };
    }
    // 2) Sessão autenticada da aba (Tor/contêiner/login) → Electron
    //    aria2/Gopeed não têm como herdar a Session do Electron sem exportar
    //    cookies (decisão 8: "não exporte cookies para arquivos temporários
    //    desnecessários" — exceto yt-dlp que já faz isso).
    //    1.9.6: em aba Tor SEM engine explícito, Electron é o padrão — ele usa
    //    a própria sessão Tor (proxy fixo, fail-closed com porta morta se o
    //    daemon cair), nunca conexão direta.
    if (task.sessionPartition) {
      return { engine: electronAd, name: 'electron', reason: 'sessão autenticada' };
    }
    // 3) Stream (HLS/DASH) — Electron não sabe baixar manifesto; aria2 também não
    //    diretamente (não é HTTP simples). Exige yt-dlp (já existente) ou FFmpeg.
    if (task.mediaType === 'stream') {
      return { engine: null, name: 'stream', reason: 'streaming exige yt-dlp ou ffmpeg' };
    }
    // 4) HTTP direto grande → aria2 (se disponível)
    if (aria2Ad && aria2Ad.isAvailable() && task.totalExpected >= 5 * 1024 * 1024) {
      return { engine: aria2Ad, name: 'aria2', reason: 'arquivo >= 5MB, segmentação vale' };
    }
    // 5) Padrão: Electron (sempre disponível)
    return { engine: electronAd, name: 'electron', reason: 'padrão' };
  }

  /* ---------------- download público ---------------- */

  /**
   * Cria um download a partir de uma MediaResource detectada.
   * @param {MediaResource} media
   * @param {object} opts { tabId, sessionPartition?, engine?, outDir?, fileName?, cookies?, headers? }
   * @returns {Promise<{ok:boolean, id?:string, reason?:string, engine?:string}>}
   */
  async function downloadMedia(media, opts) {
    if (!media || !media.url) return { ok: false, reason: 'mídia inválida' };
    const tabId = String((opts && opts.tabId) || media.tabId || '');
    if (!tabId) return { ok: false, reason: 'tabId ausente' };

    // anti-duplicata: mesma URL ativa no mesmo tab. Inclui TODOS os estados
    // não-finalizados (resolving, downloading, paused, waiting).
    const key = tabId + '|' + normalizeUrl(media.url);
    const existing = activeByKey.get(key);
    if (existing) {
      const r = findRec(existing);
      if (r && r.state !== STATES.COMPLETED && r.state !== STATES.CANCELLED && r.state !== STATES.ERROR) {
        toast('Download já em andamento: ' + (r.name || 'arquivo'));
        return { ok: false, reason: 'duplicado', id: r.id };
      }
    }

    const url = media.url;
    const host = hostOf(url);
    const fileName = (opts && opts.fileName) || deriveFileName(media, url);
    const safeName = dl.safeFileName(fileName);
    const outDir = (opts && opts.outDir) || (app ? app.getPath('downloads') : process.cwd());

    // 1.9.6 (ERRO 2): gate CENTRAL de segurança ANTES de qualquer engine tocar
    // a rede — limite de tamanho e de simultaneidade. O fluxo Electron já
    // aplicava isso em handleNewDownload; agora vale para TODO engine.
    if (limits) {
      const activeCount = records().filter(r =>
        r.state === STATES.RESOLVING || r.state === STATES.DOWNLOADING ||
        r.state === STATES.WAITING || r.state === 'progressing' || r.state === 'confirming'
      ).length;
      const startErr = dlsec.validateStart(null, {
        maxMB: limits.maxMB,
        maxConcurrent: limits.maxConcurrent,
        activeCount,
        totalExpected: media.fileSize
      });
      if (startErr) {
        toast(startErr, 6000);
        return { ok: false, reason: startErr };
      }
    }

    // arquivo arriscado: NÃO passa para aria2/Gopeed (eles não pausam item.cancel()
    // do Electron antes de tocar o disco — decisão de segurança). Cai no Electron
    // que tem o diálogo de confirmação de executável (handleNewDownload no main).
    if (dl.isRiskyFile(safeName)) {
      // Electron path cuida disso
      return startViaElectron({ url, tabId, fileName: safeName, outDir,
        sessionPartition: opts && opts.sessionPartition, media });
    }

    // 1.9.6 (ERRO 1): a tarefa marca torRequired quando vem da partição Tor.
    // Adaptadores também recusam tarefa torRequired sem proxy (defesa em
    // profundidade — ver download-security.validateTaskProxy).
    const torRequired = !!torPartition &&
      (opts && opts.sessionPartition) === torPartition;
    const task = {
      url, tabId,
      outDir, fileName: safeName,
      sessionPartition: opts && opts.sessionPartition,
      torRequired,
      engine: opts && opts.engine,
      headers: opts && opts.headers,
      cookies: opts && opts.cookies,
      referrer: opts && opts.referrer,
      userAgent: opts && opts.userAgent,
      mediaType: media.mediaType,
      totalExpected: media.fileSize
    };
    const err = validateTask(task);
    if (err) return { ok: false, reason: err };

    const { engine, name: engineName, reason } = pickEngine(task);
    if (!engine) {
      // Stream: encaminha para yt-dlp/ffmpeg (já existente no main.js)
      if (reason && reason.startsWith('streaming')) {
        toast('Streaming detectado — use o menu "Baixar com yt-dlp" ou encaminhe para o FFmpeg.', 8000);
        return { ok: false, reason: 'streaming-not-supported-here' };
      }
      // 1.9.6 (ERRO 1): aba Tor sem proxy Tor validado → RECUSA. Não há
      // fallback para conexão direta: se o proxy está indisponível o download
      // é INTERROMPIDO e o usuário é informado do motivo (fail-closed).
      if (reason === 'tor-sem-proxy' || reason === 'tor-gopeed-sem-proxy-validado') {
        const msg = 'Download interrompido: o proxy Tor não está disponível. ' +
          'Nenhuma conexão direta foi feita (proteção de privacidade).';
        toast(msg, 8000);
        pushSecurityEvent({ kind: 'download', host: host || 'origem desconhecida', level: 'aviso',
          detail: 'Download bloqueado em aba Tor sem proxy Tor validado: ' + safeName });
        return { ok: false, reason: msg };
      }
      return { ok: false, reason: 'nenhum engine disponível' };
    }

    // registra o download ANTES de chamar o engine (estado "resolving")
    const recId = 'dl-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
    const rec = {
      id: recId,
      name: safeName,
      path: '',
      url: String(url).slice(0, 500),
      origin: host || 'origem desconhecida',
      total: media.fileSize || 0,
      received: 0,
      state: STATES.RESOLVING,
      risky: dl.isRiskyFile(safeName),
      sha256: '',
      ts: Date.now(),
      engine: engineName,
      // 1.9.6 (ERRO 2): pasta de destino acordada — o finalize valida que o
      // arquivo concluído está DENTRO dela (anti path traversal).
      outDir,
      mediaType: media.mediaType || 'unknown',
      mediaSource: media.source || 'manual'
    };
    upsertRec(rec);
    activeByKey.set(key, recId);

    try {
      const gid = await engine.start(task);
      rec.engineGid = String(gid);
      rec.state = STATES.DOWNLOADING;
      upsertRec(rec);
      gidToRecId.set(String(gid), recId);
      // 1.9.6-b (P3): engine Electron = fire-and-forget; registra o rec para
      // ser ADOTADO pelo handleNewDownload (um único registro por download).
      if (engineName === 'electron') {
        rec.awaitingElectron = true;
        registerPendingElectron(url, recId, tabId);   // 1.9.6-d (A): por aba+URL
      }
      // Para aria2/Gopeed: poll de status (Electron usa eventos do DownloadItem)
      if (engineName !== 'electron') startPolling(String(gid), engine, engineName);
      pushSecurityEvent({ kind: 'download', host: rec.origin, level: 'info',
        detail: rec.name + ' via ' + engineName + ' (' + reason + ')' });
      return { ok: true, id: recId, engine: engineName, gid: String(gid) };
    } catch (e) {
      rec.state = STATES.ERROR;
      rec.error = String(e && e.message || e).slice(0, 240);
      upsertRec(rec);
      activeByKey.delete(key);
      // Fallback gracioso: se aria2/Gopeed falharam e a tarefa NÃO exige sessão,
      // tenta Electron (que sempre existe).
      // 1.9.6 (ERRO 1): aba Tor/contêiner (sessionPartition presente) NUNCA tem
      // fallback — cair para Electron via navSession faria conexão DIRETA (ou
      // fora da sessão isolada). O download permanece em ERROR, sem vazamento.
      if (engineName !== 'electron' && !task.sessionPartition) {
        log('warn', '[dl-manager] ' + engineName + ' falhou (' + rec.error + ') — tentando Electron');
        toast(engineName + ' falhou — tentando download padrão.', 5000);
        return startViaElectron({ url, tabId, fileName: safeName, outDir, media });
      }
      return { ok: false, reason: rec.error };
    }
  }

  /** Atalho: inicia via Electron (usado quando engine escolhido ou fallback). */
  async function startViaElectron({ url, tabId, fileName, outDir, media, sessionPartition }) {
    // Electron: handleNewDownload no main cria o rec quando onStarted dispara.
    // Aqui só disparamos downloadURL na sessão certa. O rec real terá id diferente
    // do que criamos aqui — anti-duplicata usa key por URL, então não há conflito.
    const task = {
      url, tabId, fileName, outDir,
      sessionPartition,
      mediaType: media && media.mediaType,
      engine: 'electron'
    };
    try {
      const gid = await electronAd.start(task);
      // rec não é criado aqui — handleNewDownload cuida. Devolvemos ok.
      return { ok: true, id: 'electron-pending', engine: 'electron', gid };
    } catch (e) {
      return { ok: false, reason: String(e && e.message || e) };
    }
  }

  /* ---------------- polling de status (aria2/Gopeed) ---------------- */

  function startPolling(gid, engine, engineName) {
    if (pollTimers.has(gid)) return;
    const timer = setInterval(async () => {
      try {
        const st = await engine.status(gid);
        const recId = gidToRecId.get(gid);
        if (!recId) { stopPolling(gid); return; }
        const rec = findRec(recId);
        if (!rec) { stopPolling(gid); return; }
        rec.state = st.state;
        rec.received = st.received;
        rec.total = st.total || rec.total;
        rec.speed = st.speed;
        if (st.path && !rec.path) rec.path = st.path;
        if (st.error) rec.error = st.error;
        // 1.9.6 (ERRO 2): limite de tamanho para engines externos — o fluxo
        // Electron cancela em item.on('updated'); aqui o teto é imposto NO
        // engine (cancel) e o arquivo parcial não vira download concluído.
        if (limits && rec.state === STATES.DOWNLOADING &&
            (dlsec.sizeExceedsLimit(rec.received, limits.maxMB) ||
             dlsec.sizeExceedsLimit(rec.total, limits.maxMB))) {
          try { await engine.cancel(gid); } catch (_) { /* já parou */ }
          stopPolling(gid);
          rec.state = STATES.ERROR;
          rec.error = 'Download cancelado: passou do limite de ' + limits.maxMB + ' MB.';
          pushSecurityEvent({ kind: 'download', host: rec.origin, level: 'aviso',
            detail: rec.name + ': ' + rec.error });
          toast(rec.error, 6000);
          finalizeRec(rec, STATES.ERROR);
          return;
        }
        // push throttled: a cada 2 ticks (~1.6s) para não inundar o renderer
        if (Math.random() < 0.5 || st.state !== STATES.DOWNLOADING) upsertRec(rec);
        if (st.state === STATES.COMPLETED || st.state === STATES.ERROR || st.state === STATES.CANCELLED) {
          stopPolling(gid);
          finalizeRec(rec, st.state);
        }
      } catch (_) { /* segue pollando até cancel explícito */ }
    }, POLL_INTERVAL_MS);
    pollTimers.set(gid, timer);
  }

  function stopPolling(gid) {
    const t = pollTimers.get(gid);
    if (t) { clearInterval(t); pollTimers.delete(gid); }
  }

  function finalizeRec(rec, finalState) {
    rec.state = finalState;
    // 1.9.6 (ERRO 2): validação do CAMINHO DE DESTINO para TODO engine —
    // o arquivo concluído tem de estar dentro da pasta acordada (rec.outDir).
    // aria2/Gopeed auto-renomeiam, mas nunca podem gravar fora dela.
    // 1.9.6-d (B): registro recuperado SEM pasta confiável também é bloqueado
    // (antes a checagem era pulada quando outDir não existia).
    if (finalState === STATES.COMPLETED && rec.path &&
        (rec.recoveredNoDir ||
         (rec.outDir && !dlsec.isInsideDir(rec.path, rec.outDir)))) {
      rec.state = STATES.ERROR;
      rec.error = rec.recoveredNoDir
        ? 'Caminho de destino não confirmado (download recuperado) — bloqueado pelo Security Gateway.'
        : 'Caminho de destino fora da pasta acordada — download bloqueado pelo Security Gateway.';
      pushSecurityEvent({ kind: 'download', host: rec.origin, level: 'aviso',
        detail: rec.name + ': ' + rec.error });
      toast(rec.error, 8000);
    }
    if (rec.state === STATES.COMPLETED) {
      // sha-256 do arquivo (igual ao fluxo do electron-dl)
      if (rec.path && fs.existsSync(rec.path)) {
        dl.sha256File(rec.path).then(hash => {
          rec.sha256 = hash;
          upsertRec(rec);
        }).catch(() => { /* arquivo pode ter sido movido */ }).finally(() => {
          runSecurityGate(rec);
        });
        // 1.9.6-b (P4): a política de segurança AINDA NÃO passou — a mensagem
        // não pode ser um "concluído" seco sem ressalva.
        toast('Download concluído — analisando segurança…');
      } else {
        runSecurityGate(rec);
        if (rec.state === STATES.COMPLETED) toast('Download concluído: ' + rec.name);
      }
    }
    // limpa anti-duplicata
    for (const [k, id] of activeByKey) if (id === rec.id) { activeByKey.delete(k); break; }
    upsertRec(rec);
  }

  /**
   * 1.9.6 (ERRO 2) — camada CENTRAL de segurança, injetada pelo main.js.
   * Roda para TODO engine que conclui (aria2/Gopeed incluídos) e aplica a
   * MESMA análise do fluxo Electron: revalidação de limite, tipo real por
   * magic bytes, inspeção de ZIP, scanner nativo, ClamAV/YARA, veredito e
   * quarentena (queueScan no processo principal).
   */
  function runSecurityGate(rec) {
    try {
      if (typeof security.onComplete === 'function') security.onComplete(rec);
    } catch (e) {
      // 1.9.6-b (P4): FAIL-CLOSED — uma falha inesperada no gate NUNCA deixa
      // o arquivo como concluído/seguro: estado security_error, sem abertura
      // automática, quarentena quando possível e mensagem clara ao usuário.
      log('warn', '[dl-manager] gate de segurança falhou: ' + String(e && e.message || e));
      rec.state = 'security_error';
      rec.error = 'Análise de segurança FALHOU — arquivo NÃO liberado. (' + String(e && e.message || e).slice(0, 120) + ')';
      let q = null;
      try { if (quarantineMove) q = quarantineMove(rec); } catch (_) { /* sem quarentena */ }
      if (q) rec.quarantine = q;
      pushSecurityEvent({ kind: 'download', host: rec.origin || 'origem desconhecida', level: 'aviso',
        detail: rec.name + ' (' + rec.engine + '): análise de segurança falhou — não liberado' + (q ? ' (quarentena)' : '') });
      toast('Segurança: análise FALHOU — ' + rec.name + ' NÃO foi liberado' + (q ? ' (em quarentena).' : '.'), 9000);
      upsertRec(rec);
    }
  }

  /* ---------------- ações: pause / resume / cancel ---------------- */

  async function pause(id) {
    const rec = findRec(id);
    if (!rec) return false;
    if (rec.engine === 'electron') return electronAd.pause(id);
    if (rec.engineGid && (rec.engine === 'aria2' || rec.engine === 'gopeed')) {
      const ad = rec.engine === 'aria2' ? aria2Ad : gopeedAd;
      const ok = await ad.pause(rec.engineGid);
      if (ok) { rec.state = STATES.PAUSED; upsertRec(rec); }
      return ok;
    }
    return false;
  }

  async function resume(id) {
    const rec = findRec(id);
    if (!rec) return false;
    if (rec.engine === 'electron') return electronAd.resume(id);
    if (rec.engineGid && (rec.engine === 'aria2' || rec.engine === 'gopeed')) {
      const ad = rec.engine === 'aria2' ? aria2Ad : gopeedAd;
      const ok = await ad.resume(rec.engineGid);
      if (ok) { rec.state = STATES.DOWNLOADING; upsertRec(rec); }
      return ok;
    }
    return false;
  }

  async function cancel(id) {
    const rec = findRec(id);
    if (!rec) return false;
    if (rec.engine === 'electron') return electronAd.cancel(id);
    if (rec.engineGid && (rec.engine === 'aria2' || rec.engine === 'gopeed')) {
      const ad = rec.engine === 'aria2' ? aria2Ad : gopeedAd;
      const ok = await ad.cancel(rec.engineGid);
      stopPolling(rec.engineGid);
      if (ok) { rec.state = STATES.CANCELLED; finalizeRec(rec, STATES.CANCELLED); }
      return ok;
    }
    return false;
  }

  /* ---------------- recover no boot ---------------- */

  /* 1.9.6-d (B): a validação do caminho concluído (finalizeRec) precisa da
   * pasta de destino CONFIÁVEL (rec.outDir). Registros recuperados de
   * aria2/Gopeed vinham SEM outDir — para eles a checagem isInsideDir era
   * simplesmente PULADA. Agora o adapter informa o dir da tarefa e o manager
   * SÓ confia se estiver DENTRO da pasta Downloads do app; sem dir confiável
   * a retomada é BLOQUEADA (fail-closed: estado ERROR com motivo claro e sem
   * polling → pause/resume nunca concluem). Nada é apagado — o usuário
   * decide cancelar e baixar de novo. */
  async function recover() {
    let recovered = [];
    let defaultOut = '';
    try { defaultOut = app ? app.getPath('downloads') : process.cwd(); }
    catch (_) { defaultOut = process.cwd(); }
    const trustedOutDir = (dir) => {
      try {
        if (!dir) return '';
        const d = path.resolve(String(dir));
        // a própria pasta Downloads é o destino padrão — confiável;
        // subpasta dela também; fora dela (ou caminho estranho) → ''
        if (d === path.resolve(defaultOut)) return d;
        return dlsec.isInsideDir(d, defaultOut) ? d : '';
      } catch (_) { return ''; }
    };
    if (aria2Ad && aria2Ad.isAvailable()) {
      try {
        const ok = await aria2Ad.boot();
        if (ok) {
          const list = await aria2Ad.recover();
          for (const t of list) {
            if (t.state === STATES.COMPLETED || t.state === STATES.CANCELLED) continue;
            const outDir = trustedOutDir(t.dir);
            const r = {
              id: 'dl-rec-' + Math.random().toString(36).slice(2, 10),
              name: t.path ? path.basename(t.path) : 'aria2-recover',
              path: t.path, url: '', origin: '',
              total: 0, received: 0,
              state: t.state, ts: Date.now(),
              engine: 'aria2', engineGid: t.gid,
              outDir,
              recoveredNoDir: !outDir
            };
            if (!outDir) {
              // FAIL-CLOSED: pasta de destino original não confirmável.
              r.state = STATES.ERROR;
              r.error = 'Retomada bloqueada: a pasta de destino original não pôde ser confirmada pelo Security Gateway. Cancele e baixe novamente.';
              pushSecurityEvent({ kind: 'download', host: 'local', level: 'aviso',
                detail: 'Download recuperado sem pasta de destino confiável (' + r.name + '): retomada bloqueada. Nada foi apagado.' });
              toast('Download recuperado bloqueado (pasta de destino não confirmada): ' + r.name, 8000);
              upsertRec(r);
              recovered.push(r.id);
              continue;   // SEM polling — a retomada nunca chega a concluir
            }
            upsertRec(r);
            gidToRecId.set(t.gid, r.id);
            recovered.push(r.id);
            startPolling(t.gid, aria2Ad, 'aria2');
          }
        }
      } catch (_) { /* aria2 indisponível no boot — segue */ }
    }
    if (gopeedAd && gopeedAd.isAvailable()) {
      try {
        const list = await gopeedAd.recover();
        for (const t of list) {
          if (t.state === STATES.COMPLETED || t.state === STATES.CANCELLED) continue;
          const outDir = trustedOutDir(t.dir);
          const r = {
            id: 'dl-rec-' + Math.random().toString(36).slice(2, 10),
            name: t.path ? path.basename(t.path) : 'gopeed-recover',
            path: t.path, url: '', origin: '',
            total: 0, received: 0,
            state: t.state, ts: Date.now(),
            engine: 'gopeed', engineGid: t.gid,
            outDir,
            recoveredNoDir: !outDir
          };
          if (!outDir) {
            r.state = STATES.ERROR;
            r.error = 'Retomada bloqueada: a pasta de destino original não pôde ser confirmada pelo Security Gateway. Cancele e baixe novamente.';
            pushSecurityEvent({ kind: 'download', host: 'local', level: 'aviso',
              detail: 'Download recuperado sem pasta de destino confiável (' + r.name + '): retomada bloqueada. Nada foi apagado.' });
            toast('Download recuperado bloqueado (pasta de destino não confirmada): ' + r.name, 8000);
            upsertRec(r);
            recovered.push(r.id);
            continue;
          }
          upsertRec(r);
          gidToRecId.set(t.gid, r.id);
          recovered.push(r.id);
          startPolling(t.gid, gopeedAd, 'gopeed');
        }
      } catch (_) { /* Gopeed indisponível — segue */ }
    }
    if (recovered.length) log('info', '[dl-manager] recover: ' + recovered.length + ' tarefas');
    return recovered;
  }

  async function shutdown() {
    for (const [gid] of pollTimers) stopPolling(gid);
    try { aria2Ad && aria2Ad.shutdown && await aria2Ad.shutdown(); } catch (_) {}
    try { gopeedAd && gopeedAd.shutdown && await gopeedAd.shutdown(); } catch (_) {}
  }

  /* ---------------- utilitários ---------------- */

  function normalizeUrl(u) {
    try {
      const url = new URL(u);
      // remove query params de rastreamento (compatível com ClearURLs já no projeto)
      return url.origin + url.pathname;
    } catch (_) { return String(u); }
  }

  function deriveFileName(media, url) {
    if (media && media.title && /\.\w{2,5}$/.test(media.title)) return media.title;
    try {
      const u = new URL(url);
      const last = u.pathname.split('/').filter(Boolean).pop();
      if (last && /\.\w{2,5}$/.test(last)) return decodeURIComponent(last);
    } catch (_) {}
    const ext = media && media.extension ? '.' + media.extension : '';
    return (media && media.title ? media.title : 'media-' + Date.now().toString(36)) + ext;
  }

  return {
    downloadMedia,
    pause, resume, cancel,
    recover, shutdown,
    pickEngine,        // exposto para testes
    _records: records, // exposto para testes
    _findRec: findRec,
    // 1.9.6-b (P3): adoção do rec Electron criado pelo manager
    registerPendingElectron, takePendingElectron, clearActiveKey
  };
}

module.exports = { createDownloadManager };

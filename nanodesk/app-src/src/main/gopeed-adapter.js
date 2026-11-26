/**
 * NanoDesk — Adaptador Gopeed (1.9.5) — OPCIONAL
 * ==================================================================
 * DECISÃO TÉCNICA (especificação 4.3 + 10):
 *
 *  O Gopeed é um downloader em Go (binário ~15-25 MB) com API REST.
 *  Comparado ao aria2 (binário C++ ~6 MB, RPC JSON maduro, amplamente
 *  empacotado, com mesma capacidade de multi-conexão/segmentação/retoma),
 *  o Gopeed adicionaria:
 *
 *    + ~15-25 MB ao pacote (já temos Tor/ClamAV/yt-dlp/FFmpeg = ~150 MB)
 *    + Outro serviço REST local para gerenciar (porta, token, lifecycle)
 *    + Funcionalidade duplicada com aria2 (HTTP/HTTPS segmentado, retoma)
 *    - Único diferencial: BitTorrent/Magnet/ed2k — que o NanoDesk não
 *      usa no fluxo "detecção de mídia de página" (não há <video> BT).
 *
 *  CONCLUSÃO: implementar Gopeed como engine OPCIONAL — o contrato é
 *  respeitado, o manager sabe quando ativá-lo, mas o binário NÃO é
 *  embutido por padrão. Quem quiser BitTorrent/Magnet instala o Gopeed
 *  standalone e aponta NANODESK_GOPEED_URL (env) para a API REST.
 *
 *  Segurança (10): REST em localhost + Bearer token; o renderer nunca
 *  conhece a URL/token; todas as chamadas são validadas pelo manager.
 */
'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const { STATES, validateTask } = require('./download-engine-interface');
const dlsec = require('./download-security');

const DEFAULT_PORT = 16802;
const DEFAULT_HOST = '127.0.0.1';

function createGopeedAdapter(deps) {
  const d = deps || {};
  // d = { log, env (process.env), httpClient?, httpsClient? }
  const log = d.log || (() => {});
  const env = d.env || process.env;
  /* 1.9.6-c (CRÍTICO): cliente POR PROTOCOLO. A versão anterior usava o
   * módulo http para TODAS as chamadas — uma URL https:// disparava um
   * HTTP PLAINTEXT contra a porta 443 e o Bearer token ia SEM criptografia
   * (a porta não liga TLS; o módulo que liga). Agora: https ⇒ módulo
   * https (TLS real); http ⇒ módulo http (SÓ loopback, validação abaixo).
   * Injeção para testes: httpClient (aplica aos dois esquemas) ou
   * httpsClient (só https) — em produção usa os módulos reais. */
  const clients = {
    http: d.httpClient || http,
    https: d.httpsClient || d.httpClient || https
  };
  // CA personalizada (opcional) para https com CA própria/self-signed:
  // NANODESK_GOPEED_TLS_CA=/caminho/ca.pem — ADICIONA uma âncora de confiança
  // (ca) e NÃO desliga a verificação (rejectUnauthorized continua true).
  let tlsCaPem = null;
  const tlsCaPath = String(env.NANODESK_GOPEED_TLS_CA || '').trim();
  if (tlsCaPath) {
    try {
      tlsCaPem = fs.readFileSync(tlsCaPath, 'utf8');
      log('info', '[gopeed] CA TLS personalizada carregada (verificação do certificado continua ATIVA).');
    } catch (e) {
      log('warn', '[gopeed] NANODESK_GOPEED_TLS_CA ilegível — https usará só as CAs do sistema: ' + String(e && e.message || e).slice(0, 120));
    }
  }

  // Configuração via env (setado pelo usuário no lançador do NanoDesk):
  //   NANODESK_GOPEED_URL=http://127.0.0.1:16802   (loopback; http SÓ em loopback)
  //   NANODESK_GOPEED_TOKEN=<bearer>
  //   NANODESK_GOPEED_ALLOW_REMOTE=1  (opt-in EXPLÍCITO p/ host remoto — e mesmo
  //     assim SOMENTE https; http remoto é sempre recusado)
  //   NANODESK_GOPEED_TLS_CA=/caminho/ca.pem (CA própria p/ https — opcional)
  const baseUrl = (env.NANODESK_GOPEED_URL || '').replace(/\/+$/, '');
  const token = env.NANODESK_GOPEED_TOKEN || '';

  /* 1.9.6-b (P2) — validação FAIL-CLOSED do endpoint:
   *   - protocolo: SOMENTE http/https;
   *   - padrão: apenas LOOPBACK (127.0.0.0/8, localhost, [::1]);
   *   - host remoto: RECUSADO, a menos que NANODESK_GOPEED_ALLOW_REMOTE=1 —
   *     e mesmo autorizado, SOMENTE https (http remoto nunca);
   *   - porta: 1-65535, default POR ESQUEMA (a versão antiga fazia
   *     "url.port || 80", que mandava https para a porta 80).
   * O token NUNCA aparece em mensagens de erro nem em logs. */
  function validateEndpoint(raw) {
    try {
      const u = new URL(String(raw || ''));
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        return { ok: false, reason: 'protocolo inválido (só http/https)' };
      }
      const host = String(u.hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
      const isLoop = host === 'localhost' || host === '::1' || /^127\.\d+\.\d+\.\d+$/.test(host);
      if (!host) return { ok: false, reason: 'host ausente' };
      if (u.port) {
        const p = Number(u.port);
        if (!Number.isInteger(p) || p < 1 || p > 65535) return { ok: false, reason: 'porta inválida' };
      }
      if (!isLoop) {
        const allowRemote = env.NANODESK_GOPEED_ALLOW_REMOTE === '1' ||
                            env.NANODESK_GOPEED_ALLOW_REMOTE === 'true';
        if (!allowRemote) return { ok: false, reason: 'host remoto recusado — padrão: só localhost/127.0.0.1 (NANODESK_GOPEED_ALLOW_REMOTE=1 para autorizar com https)' };
        if (u.protocol !== 'https:') return { ok: false, reason: 'host remoto exige https' };
      }
      const port = u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80);
      return { ok: true, host: u.hostname, port, https: u.protocol === 'https:', path: u.pathname + (u.search || '') };
    } catch (_) {
      return { ok: false, reason: 'URL inválida' };
    }
  }

  const endpoint = validateEndpoint(baseUrl);
  if (baseUrl && !endpoint.ok) {
    // razão NUNCA contém o token (só protocolo/host/porta)
    log('warn', '[gopeed] NANODESK_GOPEED_URL recusada: ' + endpoint.reason);
  }
  function name() { return 'gopeed'; }
  function isAvailable() { return !!(baseUrl && token && endpoint.ok); }

  function restCall(method, reqPath, body, timeoutMs) {
    return new Promise((resolve, reject) => {
      if (!isAvailable()) return reject(new Error('Gopeed não configurado ou endpoint inválido'));
      // revalida o endpoint COMPLETO a cada chamada (defesa no ponto que monta
      // a requisição — nada escapa para host/porta não autorizados)
      const ep = validateEndpoint(baseUrl + reqPath);
      if (!ep.ok) return reject(new Error('endpoint recusado: ' + ep.reason));
      const data = body ? Buffer.from(JSON.stringify(body), 'utf8') : null;
      const opts = {
        hostname: ep.host,
        port: ep.port,
        path: ep.path,   // caminho NORMALIZADO da URL validada (sem traversal)
        method,
        headers: {
          'Authorization': 'Bearer ' + token,
          'Accept': 'application/json'
        },
        timeout: timeoutMs || 8000
      };
      if (data) {
        opts.headers['Content-Type'] = 'application/json';
        opts.headers['Content-Length'] = data.length;
      }
      // 1.9.6-c: CA própria opcional (quando presente, ACRESCENTADA às CAs do
      // sistema; a verificação do certificado NUNCA é desligada).
      if (ep.https && tlsCaPem) opts.ca = tlsCaPem;
      // 1.9.6-c (CRÍTICO): https ⇒ módulo https (TLS real); http ⇒ módulo http.
      // A porta não liga TLS — o MÓDULO que liga; a versão anterior mandava
      // o Bearer token em plaintext mesmo com URL https://.
      const client = ep.https ? clients.https : clients.http;
      const req = client.request(opts, (res) => {
        // 1.9.6-b (P2): redirect NUNCA é seguido — o Bearer token não pode
        // ser reenviado a outro host/esquema (3xx = erro imediato).
        if (res.statusCode >= 300 && res.statusCode < 400) {
          res.resume();
          return reject(new Error('redirect recusado (token não é reenviado): HTTP ' + res.statusCode));
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const txt = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode >= 400) {
            return reject(new Error('Gopeed HTTP ' + res.statusCode + ': ' + txt.slice(0, 200)));
          }
          if (!txt) return resolve(null);
          try { resolve(JSON.parse(txt)); } catch (_) { resolve(txt); }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => req.destroy(new Error('timeout')));
      if (data) req.write(data);
      req.end();
    });
  }

  /**
   * Cria uma tarefa no Gopeed. Schema simplificado da API REST v1.
   * @see https://gopeed.com/docs/dev-api
   */
  async function start(task) {
    const err = validateTask(task);
    if (err) throw new Error(err);
    // 1.9.6 (ERRO 1): fail-closed. O Gopeed é um serviço EXTERNO do usuário —
    // o NanoDesk não controla o spawn nem pode VALIDAR que um proxy Tor foi
    // honrado pelo processo externo. Tarefa de aba Tor (torRequired) é sempre
    // recusada, mesmo que um proxy venha na tarefa.
    if (dlsec.isTorTask(task)) {
      throw new Error('download interrompido: o Gopeed não pode validar proxy Tor (serviço externo) — falha segura, nenhuma conexão direta foi feita');
    }
    const proxyErr = dlsec.validateTaskProxy(task);
    if (proxyErr) throw new Error(proxyErr);
    if (!isAvailable()) throw new Error('Gopeed não configurado (NANODESK_GOPEED_URL/TOKEN)');
    const body = {
      req: {
        url: task.url,
        dir: task.outDir,
        name: task.fileName,
        extra: {
          headers: task.headers || {},
          connections: 4,
          userAgent: task.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/156.0.0.0'
        }
      }
    };
    if (task.referrer) body.req.extra.headers.Referer = task.referrer;
    if (task.cookies && task.cookies.length) {
      body.req.extra.headers.Cookie = task.cookies.map(c => c.name + '=' + c.value).join('; ');
    }
    const res = await restCall('POST', '/api/v1/tasks', body, 10000);
    // API devolve { id: "..." }
    const id = res && (res.id || res.data && res.data.id);
    if (!id) throw new Error('Gopeed não devolveu id de tarefa');
    return String(id);
  }

  async function pause(id) {
    try { await restCall('POST', '/api/v1/tasks/' + id + '/pause', null, 5000); return true; }
    catch (_) { return false; }
  }
  async function resume(id) {
    try { await restCall('POST', '/api/v1/tasks/' + id + '/continue', null, 5000); return true; }
    catch (_) { return false; }
  }
  async function cancel(id) {
    try {
      await restCall('POST', '/api/v1/tasks/' + id + '/pause', null, 3000);
      await restCall('DELETE', '/api/v1/tasks/' + id, null, 5000);
      return true;
    } catch (_) { return false; }
  }

  async function status(id) {
    try {
      const res = await restCall('GET', '/api/v1/tasks/' + id, null, 4000);
      const t = res && (res.data || res);
      if (!t) return { state: STATES.ERROR, error: 'sem resposta' };
      const state = mapGopeedStatus(t.status);
      const progress = Number(t.progress || 0);   // 0..1
      const total = parseInt(t.size || t.total || '0', 10);
      const received = total > 0 ? Math.round(total * progress) : parseInt(t.downloaded || '0', 10);
      const speed = parseInt(t.speed || '0', 10);
      return {
        state,
        received, total, speed,
        path: t.filePath || '',
        etaSec: speed > 0 ? Math.ceil((total - received) / speed) : undefined,
        error: t.errMsg ? String(t.errMsg).slice(0, 240) : undefined
      };
    } catch (e) {
      return { state: STATES.ERROR, error: String(e && e.message || e).slice(0, 240) };
    }
  }

  function mapGopeedStatus(s) {
    // Gopeed usa int 0..3
    switch (Number(s)) {
      case 0: return STATES.WAITING;   // ready
      case 1: return STATES.DOWNLOADING;   // running
      case 2: return STATES.PAUSED;    // pause
      case 3: return STATES.ERROR;     // error
      case 4: return STATES.COMPLETED; // finish
      default: return STATES.WAITING;
    }
  }

  async function recover() {
    if (!isAvailable()) return [];
    try {
      const res = await restCall('GET', '/api/v1/tasks?page=1&pageSize=100', null, 5000);
      const arr = (res && (res.data || res)) || [];
      // 1.9.6-d (B): dir (se a API informar) vai para o manager — sem dir
      // confiável, o manager BLOQUEIA a retomada (fail-closed).
      return Array.isArray(arr) ? arr.map(t => ({ gid: String(t.id), state: mapGopeedStatus(t.status), path: t.filePath || '', dir: t.dir || '' })) : [];
    } catch (_) { return []; }
  }

  async function shutdown() {
    // Gopeed standalone: NÃO encerramos o processo do usuário — ele é externo.
    log('info', '[gopeed] shutdown: processo é externo (standalone), não encerrado');
  }

  return { name, isAvailable, start, pause, resume, cancel, status, recover, shutdown,
           _restCall: restCall, _baseUrl: () => baseUrl };
}

module.exports = { createGopeedAdapter, DEFAULT_PORT };

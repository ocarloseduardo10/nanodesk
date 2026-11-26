/**
 * NanoDesk — Processo principal (1.5.0)
 * ==================================================================
 * ARQUITETURA NOVA — sem a tag <webview> (desaconselhada pelo Electron):
 *  - Cada aba é uma WebContentsView gerenciada pelo processo principal;
 *  - A janela da interface roda com sandbox: true e sem webviewTag;
 *  - O renderer é um "cliente fino": envia comandos e recebe o estado
 *    das abas; o conteúdo das páginas vive em views nativas.
 *
 * NOVO 1.5.0 — LEITORES INTERNOS DE DOCUMENTOS:
 *  - PDF: viewer oficial do mozilla/pdf.js (Apache-2.0), servido em
 *    ndr://readers/pdf/web/viewer.html;
 *  - Ebooks (EPUB, MOBI, AZW3, FB2, CBZ): foliate-js (John Factotum,
 *    MIT), servido em ndr://readers/epub/epub.html;
 *  - Alvos .pdf/.epub/… (links, digitação, pop-ups, redirecionamentos
 *    e content-type da resposta) abrem como ABAS-LEITOR; os bytes são
 *    buscados pela sessão anônima ou lidos do disco e ficam SÓ EM RAM;
 *  - A CSP dos leitores bloqueia scripts externos (livros maliciosos
 *    não executam código).
 *
 * NOVO 1.5.1 — PROTEÇÕES ATIVAS (pop-ups e redirecionamentos):
 *  - Bloqueador de pop-ups (conceitos de madjeek-web/Popup-Blocker-Pro):
 *    window.open/target=_blank SEM gesto do usuário é cortado no
 *    setWindowOpenHandler; allowlist por site e contadores (só RAM);
 *  - Guardião de redirecionamentos (conceitos de dikshanagvekar/
 *    RedirectGuard): alvos para redes de redirecionamento conhecidas
 *    são cortados em will-navigate/will-redirect; cadeias com origens
 *    demais em poucos segundos são travadas; overlays-armadilha
 *    invisíveis ganham pointer-events:none (camada DOM);
 *  - Painel "Proteções" com estatísticas, eventos recentes e
 *    allowlists — tudo em memória, nada persistido.
 *
 * MODO ANÔNIMO TOTAL — nada é gravado no PC:
 *  - Sessão de navegação EM MEMÓRIA (partição sem persistência em disco);
 *  - sessionData e crashDumps apontados para uma pasta temporária
 *    exclusiva, criada antes do uso e apagada ao fechar;
 *  - Histórico, favoritos, configurações e lista de downloads: só RAM;
 *  - Resíduos de versões anteriores são apagados na inicialização.
 *
 * NOVO 1.6.0 — PROJETO PRIVACIDADE E SEGURANÇA (9 FASES):
 *  - FASE 2: sessões isoladas por contêiner + perfil local OPCIONAL
 *    (desligado por padrão — coerente com "zero dados gravados");
 *  - FASE 3: HTTPS-first com fallback, certificado sempre negado,
 *    proteção WebRTC (disable_non_proxied_udp), cookies de terceiros;
 *  - FASE 4: limpeza de parâmetros de rastreamento (ClearURLs),
 *    anti-fingerprinting canvas/WebGL/áudio (CanvasBlocker, redução
 *    sem randomização), StevenBlack hosts na camada de bloqueio;
 *  - FASE 5: Network Manager — detecção de VPN (interfaces do SO),
 *    Tor SOCKS5 em sessão isolada, DNS seguro (DoH), verificação de IP;
 *  - FASE 6: Security Gateway — análise heurística de URLs (URLCheck)
 *    antes de navegar, quarentena de downloads com tipo real (magic
 *    bytes), inspeção de ZIP e adaptadores externos ClamAV/YARA;
 *  - FASE 7: SearXNG/Brave na busca, favoritos com pastas/etiquetas,
 *    histórico pesquisável (só RAM), Bitwarden via CLI oficial,
 *    LibreTranslate com consentimento, import/export de favoritos;
 *  - FASE 8 / 1.8.8: vídeo — apenas yt-dlp (FreeTube/Invidious/Piped removidos).
 *
 * Segurança:
 *  - contextIsolation + sandbox em TODAS as janelas e abas;
 *  - Sem Node.js nas páginas; IPC validado por origem;
 *  - Somente HTTP/HTTPS (e ndr:// interno dos leitores); pop-ups viram
 *    abas internas;
 *  - Permissões negadas por padrão; DNT + GPC;
 *  - Bloqueador de anúncios nativo + motor Ghostery (EasyList/EasyPrivacy)
 *    integrados em UM único listener de webRequest (limitação do Electron);
 *  - Downloads via electron-dl com diálogos, limites e avisos.
 */
'use strict';

const {
  app, BrowserWindow, WebContentsView, ipcMain, session, Menu, screen,
  shell, clipboard, dialog, crashReporter, protocol, nativeImage
} = require('electron');

/* --------------- FASE 3 — nenhum serviço do Chromium pela rede ---------------
 * O Electron não desliga TUDO do Chromium por padrão: alguns componentes ainda
 * fazem consultas automáticas (telemetria/otimização) ou salvam dados sensíveis
 * (senhas no Login Data, autofill local). FASE 3 exige: sem salvamento de
 * senhas, sem preenchimento automático, sem telemetria, sem sincronização e
 * sem consultas automáticas. Recursos desligados por nome de feature:
 *   PasswordSaving / PasswordGeneration / PasswordLeakDetection → o Chromium
 *     NÃO grava credenciais (Login Data) nem consulta o servidor de vazamentos;
 *     o cofre de senhas é o NATIVO do NanoDesk (AES-256-GCM, na RAM);
 *   AutofillServerCommunication / AutofillEnableAccountStorageCreation /
 *     AutofillAddressProfileSaving / AutofillCreditCardSaving /
 *     ContactInfoSuggestions → preenchimento automático desligado e nada vai
 *     ao servidor de autofill do Google;
 *   Translate → o tradutor interno do Chromium (fala com Google) fica fora;
 *     o NanoDesk usa LibreTranslate da instância do usuário;
 *   MediaRouter → descoberta Chromecast (broadcast na rede local) fora;
 *   OptimizationHints → download de "hints" do servidor do Google fora;
 *   ChromeVariations → experimentos/variações do Chromium fora.
 * Switches de rede em segundo plano:
 *   --disable-background-networking → desliga serviços silenciosos (variations,
 *     Safe Browsing remoto, atualização de componentes) — o bloqueio de
 *     rastreadores continua local (listas embutidas; atualização vira MANUAL);
 *   --disable-component-update / --disable-domain-reliability / --no-pings →
 *     sem component updater, sem envio de falhas de domínio, sem pings de
 *     hyperlinks; --disable-sync → sem sincronização de conta;
 *   --disable-client-side-phishing-detection → o anti-phishing continua pelo
 *     Security Gateway LOCAL (URLGate + PageSecurity), não pelo cliente Google.
 * Nota honesta: com isso o CRLSet (revogação por componente) também para de
 * atualizar — a validação de certificados continua íntegra; revogação pontual
 * é coberta pelo rejeite de certificado inválido (certificate-error: SEMPRE negado).
 */
app.commandLine.appendSwitch('disable-features', [
  'PasswordSaving',
  'PasswordGeneration',
  'PasswordLeakDetection',
  'AutofillServerCommunication',
  'AutofillEnableAccountStorageCreation',
  'AutofillAddressProfileSaving',
  'AutofillCreditCardSaving',
  'ContactInfoSuggestions',
  'Translate',
  'MediaRouter',
  'OptimizationHints',
  'ChromeVariations',
  // 1.9.6 (ciclo de dados): o Chromium baixa o dicionário de spellcheck do
  // locale do SO (~en-US.bdic) para a sessão DEFAULT mesmo com spellcheck:false
  // nas janelas — é uma consulta automática e cria Cache/Dictionaries em disco.
  // O NanoDesk não usa spellcheck em nenhuma janela → serviço desligado
  // (reforço por sessão: ses.spellCheckerEnabled = false no engineFor e no
  // defaultSession no arranque; spellCheckerDictionaryDownloadURL nunca é
  // definido, então não há CDN de dicionário para o app).
  'SpellcheckService',
  'SpellcheckOfflineDictionaryDownload'
].join(','));
app.commandLine.appendSwitch('disable-component-update');
app.commandLine.appendSwitch('disable-background-networking');
app.commandLine.appendSwitch('disable-domain-reliability');
app.commandLine.appendSwitch('disable-client-side-phishing-detection');
app.commandLine.appendSwitch('disable-sync');
app.commandLine.appendSwitch('no-pings');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');
const { fileURLToPath } = require('url');
const validation = require('../shared/validation');   // 1.9.2: isSameOrigin
const { isHttpUrl, isTopLevelFrame, validateSetting, normalizeHostname } = validation;
const { MemoryStore } = require('./store');
const adblock = require('./adblock');
const ytguard = require('./ytguard');        // 1.6.8: anti-adblock base do YouTube (embutido)
const dl = require('./downloads');
const { updates } = require('./updates');
const ctxmenu = require('./context-menu');
const filtersBundle = require('./filters-bundle');
const perms = require('./permissions');
const reader = require('./reader');
const readerMode = require('./reader-mode');
const archiveMod = require('./archive');          // 1.9.0: arquivar página (arquivo único, nativo e privado)
const archiveUtil = require('./archive-util');
const netLimits = require('./net-limits');
const cookiePolicy = require('./cookie-policy');
const enginesStatus = require('./engines-status');  // 1.9.3: painel de motores de varredura
const clamavDb = require('./clamav-db');            // 1.9.2: base do ClamAV por qualquer rota (inclusive Tor), verificada   // 1.9.2: cookies de terceiros (requisição + Set-Cookie)        // 1.9.2: leitura de respostas HTTP com teto de bytes (streaming)
const readers = require('./readers');
const popupBlocker = require('./popup-blocker');
const redirectGuardMod = require('./redirect-guard');
const { OVERLAY_SCRIPT } = require('./overlay-neutralizer');
const urlclean = require('./urlclean');
const urlgate = require('./urlgate');
const netmgr = require('./network');
const { HistoryStore } = require('./history');
const securityGateway = require('./security-gateway');
const hostsEngine = require('./hosts-engine');
const fingerprint = require('./fingerprint');
const persistence = require('./persistence');
const bitwarden = require('./bitwarden');
const translate = require('./translate');
const video = require('./video');
const sponsorblock = require('./sponsorblock');          // 1.7.0: SponsorBlock nativo (YouTube — API pública)
const authhosts = require('./authhosts');                // 1.7.2: páginas de login (nada injetado) + grupos de SSO
const consentomatic = require('./consentomatic');        // 1.7.0: nega rastreadores nos popups de cookies
const languagetool = require('./languagetool');          // 1.7.0: correção gramatical (API oficial)
const librarytranslate = require('./librarytranslate');  // 1.7.0: biblioteca de traduções
const identity = require('./identity');       // 1.6.1 (vindo do 1.5.3): identidade Chrome coerente
const torMod = require('./tor-manager');      // 1.6.1 (vindo do 1.5.3): Tor nativo (daemon embutido)
const crypto = require('crypto');             // 1.8.8: SHA-256 para o scanner nativo
const htmlutil = require('./htmlutil');       // 1.8.11: sanitização do HTML traduzido
const noredirect = require('./noredirect');               // 1.8.8: resolvedor de redirects (Google/Bing/DDG/Reddit…)
const cosmeticCleanup = require('./cosmetic-cleanup');    // 1.8.8: limpeza cosmética (barras cinzentas de anúncio)
const popupBlockerStrictMod = require('./popup-blocker-strict'); // 1.8.8: popup-blocker strict (schomery-style)
const pageSecurityMod = require('./page-security');      // 1.8.8: segurança in-page (miners/hidden iframes/phishing)
const nativeScanner = require('./native-scanner');        // 1.8.8: scanner nativo (SHA-256 + PE + strings + entropia)
const mediaDetector = require('./media-detector');         // 1.9.5: detector de mídia (áudio/vídeo/streaming)
const { createDownloadManager } = require('./download-manager');   // 1.9.5: gerenciador central
const { createElectronAdapter } = require('./electron-download-adapter'); // 1.9.5
const { createAria2Adapter } = require('./aria2-adapter');  // 1.9.5
const { createGopeedAdapter } = require('./gopeed-adapter'); // 1.9.5 (opcional)

const SELFTEST = process.argv.includes('--selftest');

// Partição de navegação EM MEMÓRIA (SEM o prefixo de persistência do Electron).
const MEM_PARTITION = 'anon-nanodesk';
// 1.6.1: partição das abas Tor nativas — SEPARADA de tudo (cookies/cache/storage
// próprios, sempre em memória, proxy SOCKS5 do daemon e NENHUMA rota direta).
const TOR_PARTITION = 'tor-nanodesk';

// Esquema privilegiado das páginas dos LEITORES (padrão + seguro + fetch).
// Precisa ser registrado ANTES de o app ficar pronto.
protocol.registerSchemesAsPrivileged([
  {
    scheme: 'ndr',
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: true,
      corsEnabled: true,
      stream: true
    }
  }
]);

/** Pasta dos arquivos estáticos dos leitores (dentro do app.asar). */
const READERS_DIR = path.normalize(path.join(__dirname, '..', 'readers'));

const READER_MIME = {
  '.html': 'text/html; charset=utf-8',
  '.htm': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json',
  '.txt': 'text/plain; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.gif': 'image/gif',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.properties': 'text/plain; charset=utf-8',
  '.ftl': 'text/plain; charset=utf-8',
  '.bcmap': 'application/octet-stream',
  '.pfb': 'application/octet-stream',
  '.pfm': 'application/octet-stream',
  '.ttf': 'font/ttf',
  '.otf': 'font/otf',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2'
};

/**
 * Servidor estático do esquema ndr:// — só entrega arquivos da pasta
 * src/readers, com lista branca de extensões (sem travessia de caminho).
 * CORREÇÃO 1.6.7 (velocidade): os assets dos leitores são estáticos DENTRO
 * do próprio pacote — agora podem ser cacheados pela sessão (em memória,
 * morre com o app) e arquivos grandes (pdf.js ≈ 3 MB) são entregues por
 * STREAM em vez de readFileSync no processo principal.
 */
function serveReaders(request) {
  try {
    const u = new URL(request.url);
    if (u.protocol !== 'ndr:' || u.host !== 'readers') {
      return new Response('Forbidden', { status: 403 });
    }
    const rel = decodeURIComponent(u.pathname).replace(/^\/+/, '');
    const file = path.normalize(path.join(READERS_DIR, rel));
    if (file !== READERS_DIR && !file.startsWith(READERS_DIR + path.sep)) {
      return new Response('Forbidden', { status: 403 });
    }
    const ext = path.extname(file).toLowerCase();
    const mime = READER_MIME[ext];
    if (!mime) return new Response('Forbidden', { status: 403 });
    const st = fs.statSync(file);
    if (!st.isFile()) return new Response('Not found', { status: 404 });
    const headers = { 'content-type': mime };
    if (ext === '.html' || ext === '.htm') {
      headers['cache-control'] = 'no-store';            // página do leitor: sempre fresca
    } else {
      // 1.6.7: assets estáticos DENTRO do pacote podem viver no cache da
      // sessão (em memória, morre com o app) — pdf.js/viewer.js deixa de ser
      // re-lido a cada aba-leitor aberta.
      headers['cache-control'] = 'private, max-age=86400';
    }
    const data = fs.readFileSync(file);
    return new Response(data, { status: 200, headers });
  } catch (_) {
    return new Response('Not found', { status: 404 });
  }
}

/**
 * Pasta temporária exclusiva da sessão. Criada ANTES de qualquer uso:
 *  - sessionData (cache de rede, shaders, DevTools...) aponta para cá;
 *  - crashDumps também (após mkdir);
 *  - cache do motor de filtros (EasyList/EasyPrivacy) vive aqui;
 *  - tudo é apagado quando o NanoDesk fecha.
 */
const SESSION_TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'nanodesk-session-'));
// Precisa ser definido ANTES do app ficar pronto.
try { app.setPath('sessionData', SESSION_TMP); } catch (_) { /* opcional */ }

/* CORREÇÃO 1.6.7: o bloco applyDohEarly foi REMOVIDO. Ele aplicava switches
 * (dns-over-https-mode/-templates) que NÃO são switches reais do Chromium/
 * Electron (a 1.6.2 já documentava isso) e, pior: com "DNS seguro: off" e
 * perfil local desligado, o app consultava a Cloudflare contra a escolha do
 * usuário entre a partida e o whenReady. O DoH REAL (e único) continua sendo
 * o app.configureHostResolver do whenReady (applyDohRuntime). */

/**
 * 1.6.2: DNS seguro em TEMPO DE EXECUÇÃO pela API oficial do Electron
 * (app.configureHostResolver). Os switches de linha de comando usados antes
 * (dns-over-https-mode/-templates) não são switches reais do Chromium, então o DoH
 * nunca era aplicado — e, sem perfil local, a configuração nem sobrevivia ao reinício.
 */
function applyDohRuntime() {
  try {
    if (!settings) return;
    const cfg = {
      provider: settings.get('secureDns', 'cloudflare'),
      customUrl: settings.get('secureDnsCustom', ''),
      strict: settings.get('secureDnsStrict', false) === true
    };
    const sw = netmgr.dohSwitches(cfg);
    const tpl = (sw.find(x => x[0] === 'dns-over-https-templates') || [])[1];
    if (!tpl) { app.configureHostResolver({ secureDnsMode: 'off' }); return; }
    app.configureHostResolver({ secureDnsMode: cfg.strict ? 'secure' : 'automatic', secureDnsServers: [tpl] });
  } catch (_) { /* mantém o DNS do sistema */ }
}

let win = null;
let engine = null;               // motor da sessão PADRÃO (compatibilidade)
const engines = new Map();       // partição -> motor (contêineres 1.6.0)
let navSession = null;
let browserIdentity = null; // 1.6.1: identidade Chrome coerente (UA + client hints)
let torIdentity = null;     // 1.6.7: identidade das abas Tor (en-US — não reduzir o conjunto de anonimato)
let torMgr = null;          // 1.6.1: gerenciador do daemon Tor embutido
let torSession = null;      // 1.6.1: sessão isolada das abas Tor (criada só conectada)
let torEngine = null;       // 1.6.1: bloqueador acoplado à sessão Tor
const downloadSessions = new Map(); // url -> sessão de origem (reemissão de executáveis)
let settings, favorites, allowStore, downloadStore;
let library = null;         // 1.7.0: biblioteca de traduções (LibraryTranslate) — só RAM
const nativeStats = { sbSkips: 0, sbSecs: 0, cmDenies: 0 }; // 1.7.0: contadores nativos (só RAM)
let readerStore = null, readerSvc = null;
let popupGuard = null;      // 1.5.1 bloqueador de pop-ups
let redirectGuard = null;   // 1.5.1 guardião de redirecionamentos
let sharedDlOptions = null; // opções compartilhadas com o electron-dl
const activeDownloadItems = new Map(); // rec.id -> DownloadItem (electron-dl)

/* ---------------- 1.9.5 — detector de mídia + gerenciador central de downloads ----------------
 * Cada aba tem um mediaDetector.createDetectorState() próprio (Map<id, MediaResource>).
 * O hook onBeforeRequest (instalado em applySessionSettings) classifica cada requisição
 * de rede via mediaDetector.classifyNetwork; recursos de mídia entram no estado da aba.
 * O gerenciador central (dlManager) escolhe engine (Electron/aria2/Gopeed) e mantém o
 * DownloadStore existente como fonte única de verdade para o painel de Downloads. */
const mediaStateByTab = new Map();   // tabId -> { state: createDetectorState(), wcId }
let dlManager = null;                 // createDownloadManager() — inicializado depois de initStores()
let aria2Adapter = null;
let gopeedAdapter = null;
let electronAdapter = null;
let mediaPollTimer = null;            // setInterval de prune + push de mídia detectada

// 1.6.0 — perfil local OPCIONAL + histórico da sessão + estado de rede
let profile = null;
let history = null;
let netState = {
  vpn: { connected: false, kind: '', interfaces: [] },
  tor: { active: false, isolated: true, port: 9050 },
  webrtcProtected: true,
  doh: { provider: 'cloudflare' }
};
let securityLog = [];            // eventos do Security Gateway (só RAM)
const urlGateTrusted = new Set(); // hosts nos quais o usuário confiou nesta sessão
const scanQueue = [];
let scanRunning = false;

/* ---------------------- armazenamento volátil ---------------------- */

const DEFAULT_SETTINGS = {
  homepage: '',               // vazio = Nova Aba interna
  searchEngine: 'duckduckgo', // duckduckgo | bing | google | startpage | brave | searxng
  adblockEnabled: true,
  adblockScriptlets: true,    // 1.6.6: scriptlets do uBlock (YouTube etc.) — desligue se um site quebrar
  popupBlockerEnabled: true,  // 1.5.1 (Popup-Blocker-Pro)
  redirectGuardEnabled: true, // 1.5.1 (RedirectGuard)
  hibernateTabs: true,
  hibernateMinutes: 15,
  doNotTrack: true,
  askWhereToSave: true,       // janela "salvar como" para cada download
  // ---- 1.6.0 ----
  persistentData: false,      // perfil local OPCIONAL (FASE 2)
  httpsFirst: true,           // FASE 3
  blockThirdPartyCookies: true, // FASE 3
  webrtcProtect: true,        // FASE 3/5
  clearUrls: true,            // FASE 4 (ClearURLs)
  fingerprintProtect: true,   // FASE 4 (CanvasBlocker)
  urlGateEnabled: true,       // FASE 6 (URLCheck)
  downloadScan: true,         // FASE 6 (Security Gateway)
  quarantineDownloads: true,  // FASE 6 (quarentena)
  secureDns: 'cloudflare',    // FASE 5 (DoH)
  secureDnsCustom: '',
  secureDnsStrict: false,
  torMode: false,             // FASE 5 (SOCKS 127.0.0.1:9050)
  torPort: 9050,
  searxngUrl: '',             // FASE 7 (instância própria)
  // ---- 1.8.8: VÍDEO — sem Piped/Invidious/FreeTube (removidos). ----
  // Apenas yt-dlp para download sob demanda. SponsorBlock/ytguard continuam
  // protegendo o YouTube comum dentro do NanoDesk.
  videoQuality: 'best',          // FASE 8: best | 1080 | 720 | audio
  ytdlpSubtitles: false,         // 1.8.8: embutir legendas (.srt) no .mp4 baixado
  ytdlpThumbnail: false,         // 1.8.8: embutir capa (.jpg) no .mp4 baixado
  // ---- 1.8.8: PROTEÇÕES ATIVAS NOVAS ----
  noredirectEnabled: true,       // resolve redirects de Google/Bing/DDG/Reddit/Steam/Facebook/YouTube
  adCleanupEnabled: true,        // remove barras cinzentas de anúncio (.bstn-ad, gib-ad, ...)
  pageSecurityScan: true,        // detecta miners/hidden iframes/phishing HTTP/auto-download
  malwareSiteBlock: true,        // bloqueia hosts na StevenBlack (malware) ANTES de navegar
  popupBlockerStrict: true,      // 1.8.8: popup-blocker strict (bloqueia TODOS, schomery-style)
  popupBlockerAggressive: false, // 1.8.8: modo agressivo (bloqueia até same-origin em alguns casos)
  // ---- 1.8.9: cofre de senhas NATIVO (substitui CLI bw) ----
  // 1.9.6-b (P1): modo de PRIVACIDADE RIGOROSA por padrão — o cofre vem
  // DESLIGADO e, quando o usuário liga explicitamente, nasce EFÊMERO (só
  // RAM; nada em disco). Persistir um cofre cifrado em userData
  // (nanodesk-vault.json) é opt-in explícito do usuário (voltar o modo
  // efêmero para off), nunca o comportamento padrão.
  vaultEnabled: false,           // cofre embutido DESLIGADO por padrão (1.9.6-b)
  vaultAutolockMinutes: 15,      // bloqueia a chave em RAM após N minutos de inatividade
  vaultSavePrompt: false,        // 1.9.6-b: NÃO oferece salvar credenciais por padrão
  // 1.9.1 — proteção de teclado e de captura
  thirdPartyCookiesStrict: false, // 1.9.3: contexto DESCONHECIDO (service worker, sem aba/Referer) também perde cookies (fail-closed)
  clamavPersistDb: false,        // 1.9.2: guarda a base do ClamAV em userData (~300 MB) em vez de baixar a cada sessão
  keyboardGuard: true,           // corta eventos de tecla com caractere em campos de senha antes do site (anti-keylogger de página)
  keyboardGuardAuthSites: false, // também em páginas de login/banco (pode atrapalhar antifraude por dinâmica de digitação)
  contentProtection: false,      // impede captura de tela/gravação da janela do NanoDesk (Windows/macOS)
  // 1.9.0 — Arquivar página (arquivo único). Tudo roda localmente; nada vai a serviço externo.
  archiveBlockNetwork: true,     // o arquivo salvo leva CSP que bloqueia rede e scripts (não "liga para casa")
  archiveRemoveHidden: false,    // remove elementos ocultos (display:none) do arquivo
  archiveRemoveUnused: true,     // remove regras de CSS e fontes que a página não usa (arquivo menor)
  archiveLoadLazy: true,         // rola a página antes para carregar imagens "lazy"
  archiveSkipTrackers: true,     // não baixa recursos de rastreadores (lista do bloqueador)
  archiveAskWhere: true,         // pergunta onde salvar (desligado: Downloads\Páginas salvas)
  archiveKeepForm: false,        // 1.9.6-b (P5): NÃO preserva valores digitados em formulários no arquivo (senhas e ocultos nunca foram salvos; agora NADA digitado é salvo por padrão)
  // 1.9.6-b (P1): efêmero é o padrão — cofre SÓ na RAM (nada em disco; some
  // ao fechar). Cores existente em disco (upgrade de versão antiga) é
  // respeitado — ver initStores — e a persistência cifrada vira opt-in.
  vaultEphemeral: true,
  filtersCacheOnDisk: false,     // 1.9.6-b (P5): cache do motor vai para a pasta temporária da sessão (apagada ao fechar). Ligar grava em userData para acelerar o arranque
  // ---- 1.7.0: SponsorBlock nativo (pula patrocínios automaticamente) ----
  // 1.8.11: DESLIGADO por padrão (P-02 da auditoria): cada vídeo consulta sponsor.ajay.app.
  // Quando ligado, só o PREFIXO do hash do ID é enviado (k-anonimato), via sessão do app.
  sponsorBlockEnabled: false,
  sponsorBlockToast: true,
  sbCategories: ['sponsor', 'selfpromo', 'interaction', 'intro', 'outro', 'preview', 'filler'],
  // ---- 1.7.0: Consent-O-Matic nativo (sempre NEGAR rastreadores, nível máximo) ----
  consentomaticEnabled: true,
  consentomaticLevel: 'max',
  cmCooldownHours: 24,
  cmWhitelist: [],
  fpExempt: [],               // 1.7.2: domínios extras de login/banco onde NADA é injetado na página
  // ---- 1.7.0: LanguageTool + LibraryTranslate ----
  languagetoolEnabled: true,
  languagetoolApi: 'https://api.languagetool.org',
  languagetoolLang: 'auto',
  translateUrl: '',           // FASE 7 (vazio = tradução desligada — LibraryTranslate usa MyMemory)
  translateTarget: 'pt',
  // 1.8.10: videoQuality removido daqui (estava duplicado na linha 314 da
  // seção "1.8.8: VÍDEO"). Mantém o definido acima para evitar chave
  // duplicada silenciosa em DEFAULT_SETTINGS.
  linkwardenUrl: '',          // FASE 7: instância própria (token via env)
  // ---- 1.6.7: OPT-IN (privacidade) — a checagem automática de atualizações
  // (endoflife.date) só roda se o usuário ligar. O menu continua manual.
  updateCheck: false,
  // ---- 1.9.6 (FASE 3): OPT-IN — sem consulta automática às listas de filtros.
  // O bloqueio de rastreadores usa o pacote EMBUTIDO + cache; a renovação
  // "listas do dia" (easylist.to / uAssetsCDN) só acontece quando o usuário
  // pede: menu Ferramentas > "Atualizar listas de filtros". 
  filterAutoRefresh: false
};

const SETTING_KEYS = [
  'homepage', 'searchEngine', 'adblockEnabled', 'adblockScriptlets', 'popupBlockerEnabled',
  'redirectGuardEnabled', 'hibernateTabs',
  'hibernateMinutes', 'doNotTrack', 'askWhereToSave',
  // 1.6.0
  'persistentData', 'httpsFirst', 'blockThirdPartyCookies', 'webrtcProtect',
  'clearUrls', 'fingerprintProtect', 'urlGateEnabled', 'downloadScan',
  'quarantineDownloads', 'secureDns', 'secureDnsCustom', 'secureDnsStrict',
  'torMode', 'torPort', 'searxngUrl',
  'translateUrl', 'translateTarget',
  'videoQuality', 'ytdlpSubtitles', 'ytdlpThumbnail', 'linkwardenUrl',
  // 1.8.8 — nativo: redirect/cosmetic/security/popup-strict
  'noredirectEnabled', 'adCleanupEnabled', 'pageSecurityScan',
  'malwareSiteBlock', 'popupBlockerStrict', 'popupBlockerAggressive',
  // 1.8.9 — cofre nativo
  'vaultEnabled', 'vaultAutolockMinutes', 'vaultSavePrompt', 'vaultEphemeral', 'filtersCacheOnDisk',
  'keyboardGuard', 'keyboardGuardAuthSites', 'contentProtection', 'clamavPersistDb', 'thirdPartyCookiesStrict',
  'archiveBlockNetwork', 'archiveRemoveHidden', 'archiveRemoveUnused', 'archiveLoadLazy', 'archiveSkipTrackers', 'archiveAskWhere', 'archiveKeepForm',
  // 1.7.0 (nativo)
  'sponsorBlockEnabled', 'sponsorBlockToast', 'sbCategories',
  'consentomaticEnabled', 'consentomaticLevel', 'cmCooldownHours', 'cmWhitelist', 'fpExempt',
  'languagetoolEnabled', 'languagetoolApi', 'languagetoolLang',
  // 1.6.7
  'updateCheck',
  // 1.9.6 (FASE 3): renovação de listas de filtros é OPT-IN (ação manual no menu)
  'filterAutoRefresh'
];

function initStores() {
  // Nenhum arquivo é lido ou escrito POR PADRÃO: ao fechar o NanoDesk,
  // tudo some. O perfil local (1.6.0, OPCIONAL e desligado por padrão)
  // restaura apenas configurações e favoritos de dois arquivos pequenos;
  // histórico/cookies/dados de sites NUNCA são persistidos.
  settings      = new MemoryStore('settings', DEFAULT_SETTINGS);
  favorites     = new MemoryStore('favorites', { items: [] });
  allowStore    = new MemoryStore('allow', { items: [] });
  downloadStore = new MemoryStore('downloads', { items: [] });
  library      = new MemoryStore('library', { items: [] });  // 1.7.0 (LibraryTranslate)
  readerStore   = new MemoryStore('feeds', { items: [] });   // leitor 1.4.0
  history       = new HistoryStore();                        // 1.6.0 (só RAM)

  profile = new persistence.ProfileStore(app.getPath('userData'));
  const loaded = profile.load();

  // 1.8.9 — inicializa o cofre de senhas NATIVO (criptografia embutida).
  // 1.9.6-b (P1): modo de privacidade rigorosa — o cofre fica DESLIGADO por
  // padrão e, quando o usuário liga, é EFÊMERO (só RAM). O arquivo
  // nanodesk-vault.json só volta a existir se o usuário explicitamente
  // desligar o modo efêmero. UPGRADE: se já existe um cofre legado em disco
  // de versão anterior, ele é RESPEITADO (não apagamos dado do usuário) —
  // nesse caso o modo efêmero não é aplicado e o refletimos no setting.
  try {
    bitwarden.init({
      userDataDir: app.getPath('userData'),
      autolockMinutes: settings.get('vaultAutolockMinutes', 15),
      enabled: settings.get('vaultEnabled', false),
      onChange: (ev) => {
        if (ev && ev.event === 'locked') sendToWin('vault:state', bitwarden.status());
      }
    });
    if (settings.get('vaultEphemeral', true)) {
      const hasDiskVault = (() => { try { return bitwarden.exists(); } catch (_) { return false; } })();
      if (!hasDiskVault) {
        try { bitwarden.setEphemeral(true); } catch (_) { /* segue em disco */ }
      } else {
        settings.set('vaultEphemeral', false);   // realidade: cofre legado em disco
      }
    }
  } catch (_) { /* cofre ilegível: não bloqueia o arranque */ }

  if (loaded.enabled) {
    if (loaded.settings && typeof loaded.settings === 'object') {
      for (const k of SETTING_KEYS) {
        if (k in loaded.settings) {
          try { settings.set(k, validateSetting(k, loaded.settings[k])); }
          catch (_) { /* valor salvo inválido: usa o padrão */ }
        }
      }
    }
    // 1.8.10: APLICA ao módulo do cofre os valores que vieram do perfil.
    // Antes: bitwarden.init() acima lia defaults (15 min / enabled=true)
    // e nunca re-aplicava → quem desligou o cofre ou mudou o autolock
    // via UI e reiniciava perdia a configuração até re-togglar no painel.
    // 1.9.6-b (P1): fallbacks agora são false/false/true (rigoroso).
    try { bitwarden.setEnabled(settings.get('vaultEnabled', false)); } catch (_) { /* ignorado */ }
    try { bitwarden.setAutolockMinutes(settings.get('vaultAutolockMinutes', 15)); } catch (_) { /* ignorado */ }
    try {
      if (settings.get('vaultEphemeral', true) && !bitwarden.setEphemeral(true).ok) settings.set('vaultEphemeral', false);
    } catch (_) { /* ignorado */ }
    if (loaded.favorites && Array.isArray(loaded.favorites.items)) {
      const ok = loaded.favorites.items
        .filter(i => i && typeof i.url === 'string' && isHttpUrl(i.url))
        .slice(0, 500)
        .map(i => ({ id: validId(i.id) || nowId(), url: i.url,
          title: safeTitle(i.title, i.url), ts: Number(i.ts) || Date.now(),
          folder: typeof i.folder === 'string' ? i.folder.slice(0, 60) : '',
          tags: Array.isArray(i.tags) ? i.tags.map(t => String(t).slice(0, 24)).slice(0, 8) : [] }));
      favorites.set('items', ok);
    }
  }
}

/** Persiste o perfil local (somente quando o usuário o ligou). */
function persistProfile() {
  if (!profile || !profile.enabled) return;
  profile.saveSettings(settings.data);
  profile.saveFavorites(favorites.get('items', []));
}

/**
 * Apaga do PC QUALQUER resíduo que versões anteriores do NanoDesk
 * possam ter deixado — EXCETO quando o perfil local está ligado
 * (settings/favorites são dados do usuário e precisam sobreviver).
 */
function wipeLegacyData() {
  let dir = '';
  try { dir = app.getPath('userData'); } catch (_) { return; }
  // 1.9.3: NÃO depende de `profile` (ainda nulo nesta altura do arranque) — lê prefs.json direto
  persistence.wipeLegacyData(dir, { keepProfileFiles: persistence.isProfileEnabled(dir) });
  try { fs.rmSync(path.join(os.tmpdir(), 'nanodesk-crashdumps'), { recursive: true, force: true }); }
  catch (_) { /* ignorado */ }
}

/* ---------------------- utilitários ---------------------- */

/* 1.8.8 — REMOVIDOS os blocos de vídeo NATIVO Piped/Invidious/FreeTube.
 *   O YouTube abre comum (protegido por ytguard + bloqueador + SponsorBlock).
 *   Apenas o yt-dlp baixa vídeos sob demanda do usuário (menu / context-menu). */
const hintOrigins = new Map();   // 1.7.3: host -> Set de client hints pedidos (Accept-CH)

/* 1.8.8 — StevenBlack hosts como SET para O(1) lookup (malwareSiteBlock).
 *   hostsDomains continua sendo o ARRAY usado pelo adblock.js (não tocar).
 *   hostsDomainSet é uma cópia em Set para checagem de malware ANTES de navegar. */
let hostsDomainSet = new Set();

/**
 * 1.8.10: checagem de host contra a lista StevenBlack CAMINHANDO SUFIXOS.
 * Antes: hostsDomainSet.has(hh) só batia host EXATO — `www.evil.com` não
 * era bloqueado mesmo que `evil.com` estivesse na lista. Agora testa o
 * host e cada ancestral (`www.evil.com` → `evil.com` → `com`).
 */
function isInHostsBlocklist(host) {
  if (!host || !hostsDomainSet.size) return false;
  let h = String(host).toLowerCase().replace(/\.$/, '');
  while (h) {
    if (hostsDomainSet.has(h)) return true;
    const i = h.indexOf('.');
    if (i < 0) break;
    h = h.slice(i + 1);
  }
  return false;
}

const pendingToasts = [];
function sendToWin(channel, payload) {
  if (win && !win.isDestroyed()) win.webContents.send(channel, payload);
}
function toast(msg, ms) {
  if (win && !win.isDestroyed()) sendToWin('status:toast', { msg, ms });
  else pendingToasts.push({ msg, ms });
}
function flushPendingToasts() {
  while (pendingToasts.length) {
    const t = pendingToasts.shift();
    sendToWin('status:toast', t);
  }
}

function isNavigable(url) { return isHttpUrl(url); }

function isTrustedIpc(event) {
  if (!win || win.isDestroyed() || event.sender !== win.webContents) return false;
  const frame = event.senderFrame;
  if (!isTopLevelFrame(frame)) return false;
  try {
    const actual = path.resolve(fileURLToPath(frame.url));
    const expected = path.resolve(path.join(__dirname, '..', 'renderer', 'index.html'));
    return process.platform === 'win32'
      ? actual.toLowerCase() === expected.toLowerCase()
      : actual === expected;
  } catch (_) {
    return false;
  }
}

/** Localiza a aba pela WebContents (views-leitor e views normais). */
function tabByWebContents(wc) {
  if (!wc) return null;
  return tabList.find(t => t.view && t.view.webContents === wc) || null;
}
function tabByWebContentsId(id) {
  if (!Number.isInteger(id)) return null;
  return tabList.find(t => t.view && t.view.webContents.id === id) || null;
}

/**
 * Confiança de IPC vinda das páginas-leitor: o frame superior tem que
 * ser uma página servida em ndr://readers/ E pertencer a uma aba-leitor
 * real do gerenciador de abas.
 */
function isTrustedReaderIpc(event) {
  const url = String(event.senderFrame && event.senderFrame.url || '');
  if (!url.startsWith(readers.READER_BASE)) return false;
  const t = tabByWebContents(event.sender);
  return !!(t && t.kind);
}

function safeTitle(value, fallback) {
  return typeof value === 'string' && value.trim()
    ? value.trim().slice(0, 300)
    : String(fallback || '').slice(0, 300);
}

function nowId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch (e) { return ''; }
}

/* ------------- sessões isoladas por contêiner (1.6.0, FASE 2) ------------- */

const containers = [{ id: 'padrao', name: 'Padrão', color: '#4f8cff' }];
let containerSeq = 0;

function containerById(id) {
  return containers.find(c => c.id === id) || null;
}

/** Partição da sessão de uma aba (contêineres usam partições distintas). */
function partitionOf(t) {
  if (t && t.tor) return TOR_PARTITION;   // 1.6.1
  return (t && t.sessionId && t.sessionId !== 'padrao')
    ? MEM_PARTITION + '-' + String(t.sessionId)
    : MEM_PARTITION;
}

/**
 * 1.9.3 — descobre o SITE DE TOPO de uma requisição, em ordem: aba dona (webContentsId/webContents) →
 * frame principal da requisição (service workers e iframes) → Referer → desconhecido.
 */
function cookieTopContext(details) {
  try {
    let owner = tabByWebContentsId(details.webContentsId);
    if (!owner && details.webContents) owner = tabByWebContents(details.webContents);
    if (owner && owner.url) return { url: owner.url, via: 'aba' };
  } catch (_) { /* tenta o próximo */ }
  try {
    const top = details.frame && details.frame.top;
    if (top && top.url) return { url: top.url, via: 'frame' };
  } catch (_) { /* frame destruído */ }
  if (details.referrer) return { url: details.referrer, via: 'referrer' };
  return { url: '', via: 'desconhecido' };
}

const cookieStats = { blocked: 0, unknown: 0, unknownStrictBlocked: 0 };
const cookieUnknownReported = new Set();

/**
 * 1.9.2/1.9.3 — esta requisição/resposta é de TERCEIRO em relação ao site de topo? Contextos
 * desconhecidos são CONTADOS e registrados (a proteção não pôde ser aplicada); no modo estrito
 * (thirdPartyCookiesStrict) são bloqueados (fail-closed).
 */
function thirdPartyCookie(details) {
  try {
    const ctx = cookieTopContext(details);
    const fpEx = settings.get('fpExempt', []);
    const reqHost = hostOf(details.url);
    const d = cookiePolicy.decide(
      { reqHost, topHost: cookiePolicy.topSiteHost({ tabUrl: ctx.url }), resourceType: details.resourceType },
      { sameSite: sameSiteHost, sameSso: authhosts.sameSsoGroup, isAuth: (h) => authhosts.isAuthHost(h, fpEx) },
      { strict: settings.get('thirdPartyCookiesStrict', false) }
    );
    if (d.unknown) {
      cookieStats.unknown++;
      if (d.action === 'block') cookieStats.unknownStrictBlocked++;
      if (reqHost && !cookieUnknownReported.has(reqHost) && cookieUnknownReported.size < 50) {
        cookieUnknownReported.add(reqHost);
        pushSecurityEvent({ kind: 'cookies', host: reqHost, level: 'info',
          detail: 'Cookies de terceiros: contexto desconhecido (service worker ou requisição sem aba/Referer). ' +
            (d.action === 'block' ? 'Bloqueado (modo estrito).' : 'Proteção NÃO aplicada a esta requisição — ative o modo estrito em Configurações para bloquear.') });
      }
    }
    if (d.action === 'block') cookieStats.blocked++;
    return d.action === 'block';
  } catch (_) { return false; }
}

/** Mesmo "site" registrado (eTLD+1) — p/ cookies de terceiros. */
let _tldtsSameSite = null;
function sameSiteHost(a, b) {
  const x = String(a || '').toLowerCase().replace(/\.$/, '');
  const y = String(b || '').toLowerCase().replace(/\.$/, '');
  if (!x || !y) return true;          // sem referência: não decide
  if (x === y) return true;
  if (_tldtsSameSite === null) {
    try { _tldtsSameSite = require('tldts-experimental').parse; }
    catch (_) { _tldtsSameSite = false; }
  }
  if (_tldtsSameSite) {
    const dx = (_tldtsSameSite(x) || {}).domain || x;
    const dy = (_tldtsSameSite(y) || {}).domain || y;
    return dx === dy;
  }
  const lx = x.split('.'), ly = y.split('.');
  return lx.slice(-2).join('.') === ly.slice(-2).join('.');
}

/* ------------- motores de bloqueio por sessão (1.6.0) ------------- */

let ghosteryBlocker = null;   // matcher compartilhado entre sessões
let hostsDomains = null;      // StevenBlack (lista atual da sessão)

/**
 * CORREÇÃO 1.6.7: estado do motor Ghostery VISÍVEL (antes, uma falha de rede
 * no arranque deixava o bloqueio só no modo nativo — SEM os scriptlets
 * json-prune que matam os anúncios do YouTube — e NINGUÉM ficava sabendo:
 * a única saída era um console.warn).
 */
const ghosteryState = {
  ready: false,        // motor carregado e aplicado às sessões
  source: '',          // 'cache' | 'online' | 'embutido'
  updatedAt: 0,        // idade da fonte usada (ms)
  lastError: ''
};
let ghosteryRetryTimer = null;

/** Cache das listas do motor FORA da pasta temporária: a 1.6.x guardava o
 * motor serializado em SESSION_TMP (apagada a cada fechamento) — todo start
 * re-baixava 14 listas de raw.githubusercontent.com e re-parseava ~130 mil
 * filtros no processo principal (startup lento, até ~45 s de espera com o
 * GitHub instável). O binário de listas públicas NÃO é dado do usuário. */
function filtersCacheDir() {
  try {
    // 1.8.11: filtersCacheOnDisk=false → cache só na pasta temporária da sessão
    // (apagada ao fechar) e o cache antigo em userData é removido.
    if (settings && settings.get('filtersCacheOnDisk', true) === false) {
      try { fs.rmSync(path.join(app.getPath('userData'), 'cache-filtros'), { recursive: true, force: true }); } catch (_) { /* ignorado */ }
      return SESSION_TMP;
    }
    const dir = path.join(app.getPath('userData'), 'cache-filtros');
    fs.mkdirSync(dir, { recursive: true });
    return dir;
  } catch (_) {
    return SESSION_TMP; // melhor esforço: volta ao comportamento antigo
  }
}

/** CORREÇÃO 1.6.8: schema do cache do motor — troque para invalidar caches antigos. */
const ENGINE_CACHE_SCHEMA = 'v3'; // 1.8.8: bumpado de v2 — cache v2 foi construido com filtros template (%timestamp%)
function engineCacheFile() {
  return path.join(filtersCacheDir(), 'filters-engine-' + ENGINE_CACHE_SCHEMA + '.bin');
}
/** Remove caches de schemas anteriores (uma tentativa por partida, silencioso). */
function cleanupLegacyEngineCaches() {
  try {
    const dir = filtersCacheDir();
    if (dir === SESSION_TMP) return;   // pasta temporária: nada legado lá dentro para limpar
    const current = 'filters-engine-' + ENGINE_CACHE_SCHEMA;
    for (const f of fs.readdirSync(dir)) {
      if (/^filters-engine.*\.bin(\.tmp)?$/.test(f) && f !== current && f !== current + '.bin.tmp') {
        try { fs.rmSync(path.join(dir, f), { force: true }); } catch (_) { /* melhor esforço */ }
      }
    }
  } catch (_) { /* melhor esforço */ }
}

function engineFor(partition) {
  if (engines.has(partition)) return engines.get(partition);
  const ses = session.fromPartition(partition);
  // 1.9.6 (ciclo de dados): downloads de dicionário de spellcheck SÓ ocorrem
  // com o verificador ortográfico ativo na sessão — o NanoDesk não usa
  // spellcheck em nenhuma janela/aba; desliga por sessão para NADA buscar
  // dicionário no CDN do Chromium (en-US.bdic etc.).
  try { ses.spellCheckerEnabled = false; } catch (_) { /* Electron antigo: segue */ }
  const eng = adblock.createEngine(ses, { onBlock: () => pushStatsThrottled() });
  // 1.7.3: login/SSO nunca tem requisição bloqueada
  eng.setBypass((srcHost, reqHost) => {
    const extra = settings ? settings.get('fpExempt', []) : [];
    return authhosts.isAuthHost(srcHost, extra) || authhosts.isAuthHost(reqHost, extra);
  });
  eng.setEnabled(settings ? settings.get('adblockEnabled', true) : true);
  if (ghosteryBlocker) eng.setGhostery(ghosteryBlocker);
  if (hostsDomains && hostsDomains.length) eng.setHosts(hostsDomains);
  // 1.8.10: herda allowlist do motor default — antes, um novo contêiner
  // nascia SEM as exceções que o usuário já tinha adicionado em abas
  // anteriores (allowStore gravava mas nunca era relido).
  try {
    if (engine && engine !== eng && typeof engine.allowlist === 'function') {
      const inherited = engine.allowlist();
      if (Array.isArray(inherited)) {
        for (const h of inherited) { try { eng.allow(h); } catch (_) { /* segue */ } }
      }
    }
  } catch (_) { /* best-effort: motor novo funciona sem allowlist herdada */ }
  engines.set(partition, eng);
  applySessionSettings(ses);
  return eng;
}

function allEngines() { return [...engines.values()]; }

/** Estatísticas agregadas de todos os contêineres (só RAM). */
function aggregatedAdblockStats() {
  const list = allEngines();
  if (!list.length) {
    return { enabled: true, session: 0, total: 0, native: 0, ghostery: 0, hosts: 0, hostsCount: 0, lists: 'nativas',
      ghosteryReady: false, ghosterySource: '', truncated: 0 };
  }
  const out = { enabled: false, session: 0, total: 0, native: 0, ghostery: 0, hosts: 0, hostsCount: 0, lists: list[0].stats().lists };
  for (const e of list) {
    const s = e.stats();
    out.enabled = out.enabled || s.enabled;
    out.session += s.session; out.total += s.total;
    out.native += s.native; out.ghostery += s.ghostery;
    out.hosts += s.hosts || 0;
    out.truncated = (out.truncated || 0) + (s.truncated || 0);
    out.hostsCount = Math.max(out.hostsCount, s.hostsCount || 0);
  }
  // CORREÇÃO 1.6.7: estado do motor exposto (o painel e os testes de regressão
  // conseguem ver "motor carregado" de verdade — antes só havia console.warn).
  out.ghosteryReady = ghosteryState.ready;
  out.ghosterySource = ghosteryState.source;
  return out;
}

/** Motor da partição da aba (cria sob demanda — contêineres). */
function engineForTab(t) {
  if (t && t.tor) { getTorSession(); return torEngine; }   // 1.6.1
  return engineFor(partitionOf(t));
}

/**
 * 1.7.2 / 1.8.8 — Hosts onde NADA é injetado no mundo principal da página:
 *  - páginas de LOGIN (Google/Microsoft/Apple/gov.br/bancos) e a lista do
 *    usuário (fpExempt). Seus desafios anti-bot verificam se o navegador
 *    foi adulterado — os hooks de fingerprint são detectáveis (toString
 *    não nativo) e o login é recusado.
 *  (1.8.8: Piped/Invidious foram REMOVIDOS — sem lista de instâncias.)
 */
function noInjectionHost(host) {
  try {
    const h = String(host || '').toLowerCase();
    if (!h) return false;
    if (authhosts.isAuthHost(h, settings ? settings.get('fpExempt', []) : [])) return true;
    return false;
  } catch (_) { return false; }
}

/**
 * 1.7.3 — Diagnóstico de compatibilidade: copia para a área de transferência o que a PÁGINA ATIVA
 * enxerga do navegador (UA, client hints, window.chrome, webdriver, funções nativas…) e o que o
 * NanoDesk está aplicando. Serve para entender por que um site de login recusa o navegador.
 * Não envia nada para a rede — só copia texto; nenhuma senha/cookie é lido.
 */
async function runCompatDiagnostic() {
  const t = activeTab();
  if (!t || !t.view || !/^https?:\/\//i.test(String(t.url || ''))) {
    toast('Abra a página de login (http/https) numa aba e rode o diagnóstico de novo.', 6000);
    return;
  }
  const wc = t.view.webContents;
  const code = `(async()=>{const o={};try{
    o.ua=navigator.userAgent; o.webdriver=navigator.webdriver; o.vendor=navigator.vendor; o.platform=navigator.platform;
    o.langs=navigator.languages.join(','); o.hw=navigator.hardwareConcurrency; o.mem=navigator.deviceMemory;
    o.plugins=navigator.plugins.length; o.secure=window.isSecureContext;
    const u=navigator.userAgentData; o.brands=u?u.brands.map(b=>b.brand+'/'+b.version).join('|'):'sem userAgentData';
    try{const h=await u.getHighEntropyValues(['fullVersionList','platformVersion','architecture','bitness']);o.fullVersionList=(h.fullVersionList||[]).map(b=>b.brand+'/'+b.version).join('|');o.platformVersion=h.platformVersion;o.arch=h.architecture+'/'+h.bitness;}catch(e){o.hev='ERR '+e.message}
    o.chromeKeys=window.chrome?Object.keys(window.chrome).join(','):'SEM window.chrome';
    o.inner=innerWidth+'x'+innerHeight; o.outer=outerWidth+'x'+outerHeight; o.screen=screen.width+'x'+screen.height;
    o.notif=(typeof Notification!=='undefined')?Notification.permission:'sem';
    o.node=[typeof process,typeof require,typeof Buffer].join(','); o.sw=('serviceWorker' in navigator);
    const ts=(f)=>{try{return Function.prototype.toString.call(f).slice(0,38)}catch(e){return 'ERR'}};
    o.native={toDataURL:ts(HTMLCanvasElement.prototype.toDataURL),getParameter:ts(WebGLRenderingContext.prototype.getParameter),fnToString:ts(Function.prototype.toString),permQuery:ts(navigator.permissions&&navigator.permissions.query)};
    o.fpHook=typeof window.__nanodeskFp!=='undefined';
    try{const c=document.createElement('canvas');const g=c.getContext('webgl');const e=g&&g.getExtension('WEBGL_debug_renderer_info');o.gl=e?g.getParameter(e.UNMASKED_VENDOR_WEBGL)+' | '+g.getParameter(e.UNMASKED_RENDERER_WEBGL):'sem';}catch(e){o.gl='ERR'}
  }catch(e){o.erro=String(e&&e.message)}return JSON.stringify(o,null,1)})()`;
  let page = '';
  try { page = await wc.executeJavaScript(code, false); } catch (e) { page = 'FALHA ao ler a página: ' + (e && e.message); }
  let host = '';
  try { host = new URL(t.url).hostname; } catch (_) { /* ignorado */ }
  const lines = [
    '=== Diagnóstico NanoDesk ' + app.getVersion() + ' ===',
    'Electron ' + process.versions.electron + ' / Chromium ' + process.versions.chrome + ' / ' + process.platform + ' ' + process.arch,
    'Host da aba: ' + host,
    'Página de login isenta (sem injeção)? ' + (authhosts.isAuthHost(host, settings.get('fpExempt', [])) ? 'SIM' : 'não'),
    'Anti-fingerprint ligado: ' + settings.get('fingerprintProtect', true) + ' | Bloqueador: ' + settings.get('adblockEnabled', true) + ' | DNT: ' + settings.get('doNotTrack', true),
    'UA enviado: ' + (browserIdentity ? browserIdentity.userAgent : '?'),
    'Sec-CH-UA enviado: ' + (browserIdentity ? browserIdentity.secChUa : '?'),
    'Hints de alta entropia disponíveis: ' + !!(browserIdentity && browserIdentity.high) + ' | hosts que pediram Accept-CH: ' + hintOrigins.size,
    '--- O que a página enxerga ---',
    page
  ];
  clipboard.writeText(lines.join('\n'));
  toast('Diagnóstico copiado — cole na conversa (não contém senhas nem cookies).', 7000);
}

/** Opções que uma aba nova herda da aba de origem (Tor e contêiner). */
function inheritOpts(t) {
  if (!t) return {};
  if (t.tor === true) return { tor: true };
  return t.sessionId && t.sessionId !== 'padrao' ? { sessionId: t.sessionId } : {};
}

/**
 * Sessão correta para pedidos feitos PELO PROCESSO PRINCIPAL em nome de uma
 * aba (leitor de documentos, Modo Leitura, tradução). Aba Tor => sessão Tor
 * (fail-closed: sem sessão Tor o pedido FALHA, nunca cai na rota direta).
 */
function sessionForTab(t) {
  if (t && t.tor) {
    if (!torSession) throw new Error('A sessão Tor não está disponível.');
    return torSession;
  }
  if (t && t.sessionId && t.sessionId !== 'padrao') return session.fromPartition(partitionOf(t));
  return navSession;
}

/* ------------- configuração comum de uma sessão (1.6.0) ------------- */

const SHARED_UA = () => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/' + process.versions.chrome + ' Safari/537.36';

/** Tor SOCKS5 (FASE 5): aplica (ou remove) o proxy da sessão. */
function applyTorProxy(ses) {
  try {
    // 1.6.1: a sessão do Tor NATIVO só usa o SOCKS5 do daemon embutido — sem
    // rota alternativa. Sem porta conhecida, aponta para um destino morto
    // (a aba falha em vez de vazar tráfego direto).
    if (torSession && ses === torSession) {
      const port = torMgr && torMgr.socksPort ? Number(torMgr.socksPort) : 1;
      ses.setProxy({
        mode: 'fixed_servers',
        proxyRules: 'socks5://127.0.0.1:' + port,
        proxyBypassRules: '<-loopback>'   // nem a rede local escapa pelo lado direto
      });
      return true;
    }
    if (settings && settings.get('torMode', false)) {
      // 1.8.10: quando o daemon embutido está conectado, usar a porta REAL
      // dele (findFreePort pode cair em porta != 9050 se 9050 ocupado).
      // Antes: usava settings.get('torPort', 9050), o que apontava para uma
      // porta fechada e fazia o tráfego de navSession/contêineres falhar.
      const embeddedPort = (torMgr && torMgr.phase === 'connected' && torMgr.socksPort)
        ? Number(torMgr.socksPort)
        : Number(settings.get('torPort', 9050));
      ses.setProxy({
        mode: 'fixed_servers',
        proxyRules: netmgr.torProxyRules(embeddedPort)
      });
      return true;
    }
    ses.setProxy({ mode: 'direct' });
  } catch (_) { /* sessão pode estar fechando */ }
  return false;
}

/**
 * Identidade aplicável a uma sessão.
 * CORREÇÃO 1.6.7 (privacidade): as abas Tor usavam a MESMA identidade da
 * navegação normal (UA + Accept-Language do sistema, ex.: pt-BR). O idioma
 * reduz drasticamente o conjunto de anonimato na rede Tor e permite que um
 * site presente nos dois mundos ligue as sessões à mesma pessoa. O Tor
 * Browser normaliza para en-US; fazemos o mesmo aqui.
 */
function identityFor(ses) {
  if (torSession && ses === torSession && torIdentity) return torIdentity;
  return browserIdentity;
}

/**
 * Pré-carga de anti-fingerprinting (FASE 4) — toda frame da sessão.
 */
function registerFramePreloads(ses) {
  const fpPath = path.join(__dirname, '..', 'preload', 'fingerprint-preload.js');
  try {
    if (typeof ses.registerPreloadScript === 'function') {
      ses.registerPreloadScript({ id: 'nanodesk-fingerprint', type: 'frame', filePath: fpPath });
      return true;
    }
    if (typeof ses.setPreloads === 'function') {
      ses.setPreloads([fpPath]); // API antiga (Electron <35): substitui a lista
      return true;
    }
  } catch (_) { /* best-effort */ }
  return false;
}

/**
 * 1.6.3 — Entrega ao preload de frame (síncrono, ANTES dos scripts da página):
 * hooks de fingerprint completos, scriptlets do uBlock Origin e CSS cosmético.
 * Só responde a frames de ABAS reais (a janela da interface e páginas internas não recebem).
 */
let _fpScriptCache = null;
function fingerprintScript() {
  if (_fpScriptCache === null) {
    try { _fpScriptCache = fingerprint.buildHookScript({ platform: process.platform }); } catch (_) { _fpScriptCache = ''; }
  }
  return _fpScriptCache;
}

/**
 * CORREÇÃO 1.6.7: script de fingerprint das ABAS TOR — fuso UTC, idioma en-US
 * e WebRTC desativado (a política disable_non_proxied_udp ainda deixava TURN
 * sobre TCP escapar pela rota direta: o IP real vazava).
 */
let _torFpScriptCache = null;
function torFingerprintScript() {
  if (_torFpScriptCache === null) {
    try {
      _torFpScriptCache = fingerprint.buildHookScript({
        platform: process.platform,
        timezone: 'UTC',
        locale: 'en-US',
        blockWebRtc: true
      });
    } catch (_) { _torFpScriptCache = ''; }
  }
  return _torFpScriptCache;
}

/**
 * CORREÇÃO 1.6.7 (velocidade): nd:frame-init é sendSync e getCosmeticsFilters
 * varria o motor PARA CADA FRAME de cada página — com o motor ainda parseando
 * no arranque, TODAS as frames congelavam. Resposta por HOST é cacheada (os
 * scriptlets/CSS de base dependem do host, não da URL completa) e o cache é
 * invalidado quando o motor troca (geração).
 */
let cosmeticsGen = 0;           // sobe quando o motor Ghostery é (re)carregado
const cosmeticsCache = new Map(); // 'gen|host' -> {scripts, styles, dom}
const COSMETICS_CACHE_MAX = 200;
function cachedCosmetics(eng, url) {
  const key = cosmeticsGen + '|' + hostOf(url);
  if (cosmeticsCache.has(key)) return cosmeticsCache.get(key);
  const val = eng.cosmetics(url);
  if (cosmeticsCache.size >= COSMETICS_CACHE_MAX) cosmeticsCache.clear();
  cosmeticsCache.set(key, val);
  return val;
}

/**
 * 1.6.5: URL efetiva da frame. iframes about:blank/srcdoc/blob:/data: (vazio ou sem http)
 * herdam a origem de quem os criou — antes ficavam SEM hooks de fingerprint, e bastava a
 * página criar um iframe about:blank para ler canvas/áudio/WebGL sem proteção.
 */
function effectiveFrameUrl(frame) {
  let f = frame;
  for (let hops = 0; f && hops < 8; hops++) {
    let u = '';
    try { u = String(f.url || ''); } catch (_) { u = ''; }
    if (/^blob:/i.test(u)) u = u.slice(5);
    if (/^https?:\/\//i.test(u)) return u;
    if (u && !/^(about:blank|about:srcdoc|data:)/i.test(u)) return u; // página interna/outro esquema
    try { f = f.parent; } catch (_) { f = null; }
  }
  return '';
}

function registerFrameInitIpc() {
  ipcMain.on('nd:frame-init', (event) => {
    const out = { fp: '', scripts: [], styles: '', dom: false, kg: false, cc: false };
    try {
      const t = tabByWebContents(event.sender);
      const frame = event.senderFrame;
      const url = effectiveFrameUrl(frame);
      // 1.7.2: páginas de LOGIN (Google/Microsoft/Apple/gov.br/bancos…) recebem ZERO injeção no
      // mundo principal — os hooks são detectáveis (toString não nativo) e o login é recusado.
      const authSafe = noInjectionHost(hostOf(url));
      // 1.9.1: proteção de teclado (campos de senha) e captura segura do login — ambas rodam no
      // mundo ISOLADO do preload (invisíveis ao site). Em páginas de login/banco (authSafe) o
      // guarda de teclado fica DESLIGADO por padrão: bancos usam a dinâmica de digitação como
      // sinal antifraude. Para forçar: keyboardGuardAuthSites.
      if (t && !t.kind && /^https?:\/\//i.test(url) && settings) {
        if (settings.get('keyboardGuard', true) && (!authSafe || settings.get('keyboardGuardAuthSites', false))) out.kg = true;
        if (frame === event.sender.mainFrame && !authSafe &&
            settings.get('vaultEnabled', true) && settings.get('vaultSavePrompt', true)) out.cc = true;
      }
      // 1.7.3: em página de LOGIN só se completa o objeto window.chrome (vem VAZIO no Electron)
      if (t && !t.kind && authSafe && /^https?:\/\//i.test(url)) out.fp = fingerprint.buildChromeObjectScript();
      if (t && !t.kind && /^https?:\/\//i.test(url) && !authSafe) {
        if (settings && settings.get('fingerprintProtect', true)) {
          // 1.6.7: abas Tor recebem os hooks com fuso/idioma/WebRTC tratados
          out.fp = t.tor ? torFingerprintScript() : fingerprintScript();
        }
        const eng = engineForTab(t);
        if (eng && eng.isEnabled()) {
          // 1.6.7: resposta por host vem do cache (frame-init é sendSync)
          const c = cachedCosmetics(eng, url);
          // CORREÇÃO 1.6.8: scriptlets anti-adblock BASE do YouTube (embutidos,
          // independentes de listas/rede) entram ANTES dos scriptlets das listas.
          // Sem isso, primeira partida/offline/GitHub falho = YouTube em loop
          // ("Está enfrentando interrupções?") porque as listas quick-fixes
          // ainda não chegaram.
          let scripts = (settings && settings.get('adblockScriptlets', true) === false) ? [] : c.scripts.slice();
          if (settings && settings.get('adblockScriptlets', true) !== false &&
              ytguard.isYoutubeGuardHost(hostOf(url))) {
            const yg = ytguard.buildScript();
            if (yg) scripts.unshift(yg);
          }
          out.scripts = scripts;
          out.styles = c.styles;
          out.dom = eng.hasGhostery();
        }
        // ---- 1.7.0 / 1.8.8: SponsorBlock NATIVO (YouTube apenas) ----
        // Piped/Invidious foram REMOVIDOS — o SB agora só roda no YouTube.
        if (settings && settings.get('sponsorBlockEnabled', false)) {
          if (sponsorblock.isSponsorBlockHost(hostOf(url), '')) {
            const sb = sponsorblock.buildScript({
              cats: settings.get('sbCategories', []),
              toast: settings.get('sponsorBlockToast', true)
            });
            if (sb) out.scripts.push(sb);
          }
        }
        // ---- 1.8.8: LIMPEZA COSMÉTICA (barras cinzentas de anúncio) ----
        if (settings && settings.get('adCleanupEnabled', true) &&
            !authhosts.isAuthHost(hostOf(url), settings.get('fpExempt', []))) {
          const css = cosmeticCleanup.buildCss();
          if (css) {
            out.styles = (out.styles || '') + '\n' + css;
          }
          const script = cosmeticCleanup.buildScript();
          if (script) out.scripts.push(script);
        }
        // ---- 1.8.8: POPUP BLOCKER STRICT (schomery-style) ----
        if (settings && settings.get('popupBlockerStrict', true) &&
            !authhosts.isAuthHost(hostOf(url), settings.get('fpExempt', []))) {
          const script = popupBlockerStrictMod.buildScript({
            aggressive: settings.get('popupBlockerAggressive', false)
          });
          if (script) out.scripts.push(script);
        }
        // ---- 1.8.8: SEGURANÇA DA PÁGINA (miners/hidden iframes/phishing) ----
        if (settings && settings.get('pageSecurityScan', true) &&
            !authhosts.isAuthHost(hostOf(url), settings.get('fpExempt', []))) {
          const script = pageSecurityMod.buildScript();
          if (script) out.scripts.push(script);
        }
        // ---- 1.7.0: Consent-O-Matic NATIVO (todas as frames http(s)) ----
        // SEMPRE recusa rastreadores, no nível máximo de privacidade.
        if (settings && settings.get('consentomaticEnabled', true) &&
            !consentomatic.isWhitelisted(hostOf(url), settings.get('cmWhitelist', []))) {
          const cm = consentomatic.buildScript({
            level: settings.get('consentomaticLevel', 'max'),
            cooldownHours: settings.get('cmCooldownHours', 24),
            whitelist: settings.get('cmWhitelist', [])
          });
          if (cm) out.scripts.push(cm);
        }
      }
    } catch (_) { /* resposta vazia: página abre sem as proteções extras */ }
    event.returnValue = out;
  });

  // 1.7.0 — contadores dos módulos nativos (eventos do mundo principal
  // encaminhados pelo preload de frame). Só RAM.
  // 1.8.11 — ENDURECIDO: o evento vem do MUNDO PRINCIPAL da página (qualquer script pode
  // emiti-lo). Antes: host/URL dos toasts e do painel vinham do que a página DECLARAVA
  // (spoof da UI do navegador, ex.: "bancoxyz.com pediu senha em HTTP") e secs/contadores
  // aceitavam qualquer número. Agora: host = URL REAL do frame remetente, tipos só valem
  // quando o módulo está ligado e o site é elegível, números são limitados e há limite de taxa.
  const nativeEventRate = new Map();   // webContents.id -> { start, n }
  ipcMain.on('nd:native-event', (event, msg) => {
    try {
      if (!msg || typeof msg !== 'object') return;
      const t = tabByWebContents(event.sender);
      if (!t || t.kind) return;
      const senderUrl = effectiveFrameUrl(event.senderFrame);
      if (!/^https?:\/\//i.test(senderUrl)) return;
      const host = hostOf(senderUrl) || '—';
      const now = Date.now();
      const rk = event.sender.id;
      let r = nativeEventRate.get(rk);
      if (!r || now - r.start > 10000) { r = { start: now, n: 0 }; nativeEventRate.set(rk, r); }
      if (++r.n > 40) return;                         // anti-flood: 40 eventos / 10 s por aba
      if (nativeEventRate.size > 200) nativeEventRate.clear();
      const type = String(msg.type || '');
      if (type === 'sb') {
        if (!settings.get('sponsorBlockEnabled', false) || !sponsorblock.isSponsorBlockHost(host, '')) return;
        const secs = Number(msg.secs);
        nativeStats.sbSkips += 1;
        if (Number.isFinite(secs) && secs > 0 && secs <= 7200) nativeStats.sbSecs += secs;
      } else if (type === 'cm') {
        if (!settings.get('consentomaticEnabled', true)) return;
        nativeStats.cmDenies += 1;
      } else if (type === 'page-sec') {
        if (!settings.get('pageSecurityScan', true)) return;
        const kind = ['crypto-miner', 'http-password', 'hidden-iframe'].includes(msg.kind) ? msg.kind : 'info';
        const level = kind === 'crypto-miner' ? 'critico' : kind === 'info' ? 'info' : 'suspeito';
        const detail = String(msg.detail || '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 200);
        pushSecurityEvent({ kind: 'page-sec:' + kind, host, level, detail });
        if (kind === 'crypto-miner') {
          guardToast('pagesec:miner:' + host, 'Miner de criptomoeda bloqueado em ' + host + ' — detalhes no painel Segurança.', 7000);
        } else if (kind === 'http-password') {
          guardToast('pagesec:httppw:' + host, 'Aviso: ' + host + ' pediu senha em HTTP (sem criptografia) — possível phishing.', 8000);
        }
      } else if (type === 'popup-strict') {
        if (!settings.get('popupBlockerStrict', true)) return;
        const target = hostOf(String(msg.url || '')).slice(0, 60);
        guardToast('pp-strict:' + host, 'Pop-up bloqueado em ' + host + (target ? ' (destino: ' + target + ')' : '') + '.');
        pushProtectionStatsThrottled();
      } else {
        return;
      }
      pushProtectionStatsThrottled();
    } catch (_) { /* ignorado */ }
  });

  ipcMain.handle('nd:cosmetic-dom', (event, msg) => {
    try {
      const t = tabByWebContents(event.sender);
      const url = effectiveFrameUrl(event.senderFrame);
      if (!t || t.kind || !/^https?:\/\//i.test(url) || !msg || typeof msg !== 'object') return '';
      if (noInjectionHost(hostOf(url))) return '';   // 1.7.2
      const cap = (arr, n) => (Array.isArray(arr) ? arr.slice(0, n).map(x => String(x).slice(0, 300)) : undefined);
      const eng = engineForTab(t);
      if (!eng || !eng.isEnabled()) return '';
      return eng.cosmetics(url, { classes: cap(msg.classes, 1500), ids: cap(msg.ids, 800), hrefs: cap(msg.hrefs, 800) }).styles;
    } catch (_) { return ''; }
  });
}

/** Permissões (política 1.3.1) — mesma decisão para todos os contêineres. */
function attachPermissionHandlers(ses) {
  const permSession = new perms.PermissionSession(async ({ origin, permission }) => {
    const w = BrowserWindow.getAllWindows()[0];
    if (!w) return false;
    const host = perms.hostOf(origin) || 'este site';
    const r = await dialog.showMessageBox(w, {
      type: 'question',
      buttons: ['Permitir nesta sessão', 'Negar'],
      defaultId: 1,
      cancelId: 1,
      noLink: true,
      title: 'Permissão do site',
      message: `"${host}" quer ${perms.labelFor(permission)}.`,
      detail: 'A decisão vale apenas enquanto o NanoDesk estiver aberto — nada é lembrado depois.'
    });
    return r.response === 0;
  });
  ses.setPermissionRequestHandler((wc, permission, cb, details) => {
    const origin = perms.originOf(details && details.requestingUrl) || '';
    const policy = perms.policyFor(permission);
    permSession.request(origin, permission).then((ok) => {
      cb(ok);
      if (!ok && policy === 'deny') {
        toast('Permissão "' + permission + '" negada pela política do NanoDesk.');
      }
    }).catch(() => cb(false));
  });
  ses.setPermissionCheckHandler((wc, permission, requestingOrigin) =>
    permSession.check(requestingOrigin || '', permission));
}

/**
 * Proteções comuns de QUALQUER sessão de navegação (FASE 3/4/5):
 * UA limpa, DNT+GPC, cookies de terceiros, proxy Tor, permissões e
 * pré-carga de fingerprinting.
 */
function applySessionSettings(ses) {
  try {
    // CORREÇÃO 1.6.7: a sessão Tor usa a identidade normalizada (en-US)
    const id = identityFor(ses);
    if (id) ses.setUserAgent(id.userAgent, id.acceptLanguage || undefined);
    else ses.setUserAgent(SHARED_UA());
  } catch (_) { /* ignorado */ }
  applyTorProxy(ses);

  // DNT + GPC + bloqueio de cookies de terceiros em UM listener.
  ses.webRequest.onBeforeSendHeaders((details, callback) => {
    try {
      // 1.6.1: identidade Chrome completa (Sec-CH-UA*) e sem X-Client-Data
      // 1.6.7: identidade da PRÓPRIA sessão (Tor ≠ normal)
      const id = identityFor(ses);
      if (id) identity.applyIdentityHeaders(details.requestHeaders, id);
      // 1.7.3: hints de ALTA entropia pedidos pelo servidor via Accept-CH (valores = os da engine)
      try {
        const reqH = hintOrigins.get(hostOf(details.url));
        if (reqH && id && id.high) Object.assign(details.requestHeaders, identity.buildHintHeaders(reqH, id.high));
      } catch (_) { /* ignorado */ }
      // 1.7.3: Chrome real não envia DNT/Sec-GPC por padrão — nas páginas de login não enviamos
      const authReq = authhosts.isAuthHost(hostOf(details.url), settings.get('fpExempt', []));
      if (settings.get('doNotTrack', true) && !authReq) {
        details.requestHeaders['DNT'] = '1';
        details.requestHeaders['Sec-GPC'] = '1';
      }
      if (settings.get('blockThirdPartyCookies', true) && thirdPartyCookie(details)) {
        cookiePolicy.stripRequestCookie(details.requestHeaders);   // 1.9.2: qualquer caixa; decisão pelo site de topo da ABA
      }
    } catch (_) { /* nunca derrubar o tráfego aqui */ }
    callback({ requestHeaders: details.requestHeaders });
  });

  // 1.6.1: abas Tor NUNCA recebem prompt — câmera/microfone/localização são
  // sempre negados (um prompt seria convite a expor dados pela rede Tor).
  if (torSession && ses === torSession) denyAllPermissions(ses);
  else attachPermissionHandlers(ses);
  registerFramePreloads(ses);
  installReaderContentTypeSniffer(ses);   // 1.6.1: PDF/ebook por Content-Type em TODAS as sessões
  installMediaDetectorSniffer(ses);       // 1.9.5: detector de mídia em TODAS as sessões
  // 1.6.1: lembra a sessão de origem de cada download (reemissão de executáveis
  // confirmados precisa sair pela MESMA sessão — Tor/contêiner).
  try {
    ses.on('will-download', (_e, item) => {
      try {
        downloadSessions.set(String(item.getURL() || ''), ses);
        if (downloadSessions.size > 60) downloadSessions.delete(downloadSessions.keys().next().value);
      } catch (_) { /* ignorado */ }
    });
  } catch (_) { /* ignorado */ }
}

/** Política WebRTC (FASE 3/5): bloqueia UDP fora do proxy (vazamento). */
function applyWebRtcPolicy(wc, tab) {
  try {
    // 1.6.1: em aba Tor a proteção é SEMPRE ligada (não depende da configuração)
    if (tab && tab.tor) { wc.setWebRTCIPHandlingPolicy('disable_non_proxied_udp'); return; }
    const protect = settings ? settings.get('webrtcProtect', true) : true;
    netState.webrtcProtected = protect;
    wc.setWebRTCIPHandlingPolicy(protect ? 'disable_non_proxied_udp' : 'default');
  } catch (_) { /* best-effort */ }
}


/* ---------------------- Tor nativo + identidade (1.5.3 → 1.6.1) ----------------------
 * Tor nativo: o daemon oficial (Tor Expert Bundle) é iniciado pelo app (ação
 * explícita do usuário). As abas Tor usam a partição TOR_PARTITION, em memória,
 * com proxy SOCKS5 do daemon — SEM rota alternativa (fail-closed).
 * Identidade: UA do Chrome da engine + Accept-Language + client hints Sec-CH-UA*.
 */

/** Pasta do binário do Tor. No pacote Windows fica FORA do app.asar
 *  (o Windows não executa executáveis de dentro do asar).
 *  1.8.10: prefere process.resourcesPath/tor (idiomático Electron) antes
 *  de app.getAppPath()/../tor — o último só funciona se o build pipeline
 *  alinhar tor/ como irmão de app.asar, o que nem sempre acontece. */
function torResourcesDir() {
  if (app.isPackaged) {
    try {
      const p = path.join(process.resourcesPath, 'tor');
      if (require('fs').existsSync(p)) return p;
    } catch (_) { /* sem resourcesPath? cai abaixo */ }
    return path.join(app.getAppPath(), '..', 'tor');
  }
  return path.join(app.getAppPath(), 'resources', 'tor');
}

/** Permissões SEMPRE negadas (sessão Tor). */
function denyAllPermissions(ses) {
  ses.setPermissionRequestHandler((wc, permission, cb) => {
    cb(false);
    guardToast('tor-perm', 'Permissão "' + permission + '" é sempre negada em abas Tor.');
  });
  ses.setPermissionCheckHandler(() => false);
}

/**
 * Sessão isolada das abas Tor — criada APENAS quando o usuário conecta.
 * engineFor() aplica as proteções comuns (identidade, DNT/GPC, cookies de
 * terceiros, anti-fingerprinting, bloqueador) e applyTorProxy() fixa o SOCKS5.
 */
function getTorSession() {
  if (torSession && torEngine) return torSession;
  torSession = session.fromPartition(TOR_PARTITION);
  try { torSession.clearCache(); } catch (_) { /* ignorado */ }
  try { torSession.clearStorageData(); } catch (_) { /* ignorado */ }
  torEngine = engineFor(TOR_PARTITION);
  applyTorProxy(torSession);
  return torSession;
}

/** Eventos do gerenciador Tor → interface. */
function onTorEvent(ev) {
  sendToWin('tor:state', Object.assign({}, ev, { supported: true }));
  if (ev.state === 'connected') {
    try {
      const ses = getTorSession();
      applyTorProxy(ses);
      toast('Tor conectado — use "Abrir aba Tor" no painel da conexão.', 7000);
    } catch (_) { /* ignorado */ }
  }
  if (ev.state === 'error') {
    toast('Tor: ' + String(ev.error || 'falha desconhecida').slice(0, 180), 8000);
  }
}

/** Aba Tor — só existe com o circuito estabelecido (fail-closed por desenho). */
function createTorTab(url) {
  if (!torMgr || torMgr.phase !== 'connected' || !torMgr.socksPort) {
    throw new Error('O Tor não está conectado. Conecte no painel da conexão.');
  }
  getTorSession();
  return createTab(url || null, { tor: true });
}

/**
 * Leitores 1.5.0: detecção de PDF/ebook pelo CONTENT-TYPE da resposta
 * (pega também links sem extensão .pdf/.epub). A conversão da aba
 * acontece fora do callback de webRequest (evita reentrância).
 * 1.6.1: instalado em TODAS as sessões (padrão, contêineres e Tor).
 */
function installReaderContentTypeSniffer(ses) {
  // 1.9.5: CORREÇÃO CRÍTICA — fundimos a detecção de mídia AQUI dentro do
  // ÚNICO onHeadersReceived da sessão. Antes tínhamos dois onHeadersReceived
  // com o mesmo filtro (este + installMediaDetectorSniffer) e o Electron só
  // permite UM listener por filtro — o segundo substituía o primeiro e a
  // detecção de mídia não funcionava. Agora há um único listener que faz
  // as duas coisas: (a) detecta PDF/ebook para o leitor interno, (b)
  // classifica mídia (áudio/vídeo/stream) pelo MIME/Content-Length.
  ses.webRequest.onHeadersReceived({ urls: ['http://*/*', 'https://*/*'] }, (details, callback) => {
    try {
      // 1.7.3: lembra os client hints que o servidor PEDE (Accept-CH) para respondê-los depois
      try {
        const rh = details.responseHeaders || {};
        const k = Object.keys(rh).find(x => x.toLowerCase() === 'accept-ch');
        if (k && (details.resourceType === 'mainFrame' || details.resourceType === 'subFrame')) {
          const want = identity.parseAcceptCh(Array.isArray(rh[k]) ? rh[k].join(',') : String(rh[k]));
          const hh = hostOf(details.url);
          if (hh && want.size) {
            hintOrigins.set(hh, want);
            if (hintOrigins.size > 300) hintOrigins.delete(hintOrigins.keys().next().value);
          }
        }
      } catch (_) { /* ignorado */ }

      // 1.9.5 — DETECÇÃO DE MÍDIA: classifica áudio/vídeo/stream pelo MIME +
      // Content-Length + Content-Disposition. Roda para TODAS as respostas
      // (mainFrame incluído — um MP3 aberto direto na URL é mainFrame).
      try {
        if (details.webContentsId && details.url && details.responseHeaders) {
          const mediaTab = tabByWebContentsId(details.webContentsId);
          if (mediaTab && mediaTab.id) {
            const mediaRes = mediaDetector.classifyNetwork({
              url: details.url, tabId: mediaTab.id,
              webContentsId: details.webContentsId,
              resourceType: details.resourceType, method: details.method || 'GET',
              headers: details.responseHeaders
            });
            if (mediaRes) {
              const st = ensureMediaState(mediaTab.id, details.webContentsId);
              if (st && st.state) st.state.add(mediaRes);
            }
          }
        }
      } catch (_) { /* nunca bloquear a detecção de mídia por erro aqui */ }

      if (details.resourceType === 'mainFrame') {
        const headers = details.responseHeaders || {};
        const ctKey = Object.keys(headers).find(k => k.toLowerCase() === 'content-type');
        const ctVal = ctKey ? headers[ctKey][0] : '';
        const dispKey = Object.keys(headers).find(k => k.toLowerCase() === 'content-disposition');
        const disp = dispKey ? String(headers[dispKey][0] || '') : '';
        const isAttachment = /attachment/i.test(disp);
        if (!isAttachment) {
          const target = readers.classifyContentType(ctVal, details.url);
          if (target) {
            const t = tabByWebContentsId(details.webContentsId);
            if (t && !t.kind) {
              callback({}); // deixa a resposta terminar o handshake
              setImmediate(() => {
                try { openReaderInTab(t, target); } catch (_) { /* ignorado */ }
              });
              return;
            }
          }
        }
      }
    } catch (_) { /* nunca bloquear o tráfego por erro aqui */ }
    // 1.9.2: Set-Cookie de TERCEIROS é descartado (antes só o Cookie das requisições era removido,
    // então o terceiro ainda GRAVAVA cookies no navegador).
    try {
      if (settings.get('blockThirdPartyCookies', true) && details.resourceType !== 'mainFrame' && thirdPartyCookie(details)) {
        const hdrs = details.responseHeaders || {};
        if (cookiePolicy.stripSetCookie(hdrs) > 0) { callback({ responseHeaders: hdrs }); return; }
      }
    } catch (_) { /* nunca bloquear o tráfego por erro aqui */ }
    callback({});
  });
}

/* ------------- 1.9.5 — Detector de mídia: hook onBeforeRequest (early stream detection) -------------
 * CORREÇÃO: o onHeadersReceived foi MERGEADO dentro de installReaderContentTypeSniffer
 * (acima) porque o Electron só permite UM listener por filtro. Aqui só mantemos
 * onBeforeRequest — não conflita com nenhum outro listener e permite detectar
 * streams (.m3u8/.mpd) pela URL ANTES mesmo da resposta chegar.
 */
function installMediaDetectorSniffer(ses) {
  if (!ses || !ses.webRequest) return;
  // onBeforeRequest: detecta streams por URL (.m3u8/.mpd) antes do response.
  // Não modifica o request — só classifica e adiciona ao estado da aba.
  try {
    ses.webRequest.onBeforeRequest({ urls: ['http://*/*', 'https://*/*'] }, (details, callback) => {
      try {
        if (details && details.webContentsId && details.url) {
          const tab = tabByWebContentsId(details.webContentsId);
          if (tab && tab.id && /^https?:\/\//i.test(details.url)) {
            // Classifica só pelo URL neste estágio (sem headers ainda).
            // Stream por .m3u8/.mpd na URL é detectado aqui; arquivos por MIME
            // entram no onHeadersReceived (mergeado no reader sniffer).
            const r = mediaDetector.classifyNetwork({
              url: details.url, tabId: tab.id,
              webContentsId: details.webContentsId,
              resourceType: details.resourceType, method: details.method || 'GET'
            });
            if (r) {
              const st = ensureMediaState(tab.id, details.webContentsId);
              if (st && st.state) st.state.add(r);
            }
          }
        }
      } catch (_) { /* nunca bloquear */ }
      callback({});
    });
  } catch (_) { /* sessão pode estar fechando */ }
}

/** Devolve (ou cria) o estado de mídia da aba. Throttled por wcId. */
function ensureMediaState(tabId, wcId) {
  let entry = mediaStateByTab.get(tabId);
  if (!entry) {
    entry = { state: mediaDetector.createDetectorState(), wcId };
    mediaStateByTab.set(tabId, entry);
  }
  return entry;
}

/** Remove o estado de mídia quando a aba fecha. */
function clearMediaState(tabId) {
  mediaStateByTab.delete(tabId);
}

/**
 * Executa o probe DOM na aba ativa (chamado por IPC 'media:detect').
 * Combina recursos de rede já acumulados com o que o DOM revela.
 * @returns {Promise<Array<MediaResource>>}
 */
async function detectMediaInTab(tabId) {
  const t = tabList.find(x => x.id === tabId);
  if (!t || !t.view) return [];
  const wc = t.view.webContents;
  const entry = ensureMediaState(tabId, wc.id);

  // 1.9.5 FIX CRÍTICO — FALLBACK 1: a URL DA PRÓPRIA ABA.
  // Se o usuário navegou DIRETO para um arquivo de mídia (ex.: .mp3), o
  // Chromium mostra um player interno. O webRequest hook DEVE pegar isso,
  // mas se falhar (timing, shadow DOM, página interna do Chromium bloqueando
  // executeJavaScript, etc.), este fallback garante que a mídia seja detectada.
  // A URL da aba é a fonte MAIS confiável — não depende de hooks nem de DOM.
  try {
    const tabUrl = String(t.url || wc.getURL() || '');
    if (/^https?:\/\//i.test(tabUrl)) {
      const r = mediaDetector.classifyNetwork({
        url: tabUrl, tabId, method: 'GET'
      });
      if (r) {
        r.source = 'page-url';   // marcado: veio da URL da aba, não da rede
        entry.state.add(r);
      }
    }
  } catch (_) { /* ignorado */ }

  // 2) Probe DOM (uma vez por chamada — sem MutationObserver contínuo).
  //    Tenta acessar <audio>, <video>, <source>, <a[href]> e
  //    performance.getEntriesByType('resource'). Se a página for interna
  //    do Chromium (media viewer), executeJavaScript pode falhar — o
  //    fallback 1 acima já garantiu a detecção pela URL da aba.
  let domList = [];
  try {
    const code = mediaDetector.DOM_PROBE_SCRIPT;
    const result = await wc.executeJavaScript(code, true);
    if (Array.isArray(result)) domList = result;
  } catch (_) { /* página interna do Chromium ou em transição — fallback 1 cobre */ }

  // 3) Merge DOM + rede (a rede/page-url tem prioridade — DOM só enriquece)
  entry.state.mergeDom(domList, tabId);

  // 4) Devolve a lista consolidada (pode incluir recursos novos do DOM)
  return entry.state.list().map(r => {
    // Não expõe o campo webContentsId ao renderer (info interna)
    const { webContentsId, ...rest } = r;
    return rest;
  });
}

/* ------------- Security Gateway: log + eventos (FASE 6) ------------- */

function pushSecurityEvent(ev) {
  securityLog.unshift({
    kind: String(ev.kind || 'info').slice(0, 20),
    host: String(ev.host || '').slice(0, 120),
    detail: String(ev.detail || '').slice(0, 240),
    level: ev.level === 'infectado' || ev.level === 'suspeito' || ev.level === 'critico' ? ev.level : 'info',
    ts: Date.now()
  });
  if (securityLog.length > 200) securityLog.length = 200;
  if (win && !win.isDestroyed()) sendToWin('security:update', securityLog.slice(0, 60));
}


/* ---------------------- página de erro (dentro da aba) ---------------------- */

const ERR_MSG = {
  '-105': 'Não foi possível encontrar o servidor. Verifique o endereço digitado ou sua conexão.',
  '-106': 'Sem conexão com a Internet. Verifique o cabo, o Wi-Fi ou o roteador.',
  '-102': 'O servidor recusou a conexão.',
  '-109': 'O servidor está inacessível a partir desta rede.',
  '-7': 'A conexão demorou demais e foi interrompida (tempo esgotado).',
  '-118': 'A conexão demorou demais e foi interrompida (tempo esgotado).',
  '-20': 'Este acesso foi impedido por uma política de filtragem da rede.',
  '-21': 'Este acesso foi bloqueado pela política de segurança da sua organização ou rede.',
  '-22': 'Este acesso foi bloqueado por uma regra de segurança do ambiente.',
  '-120': 'A rede Tor/proxy SOCKS não conseguiu alcançar o destino (serviço fora do ar, sem circuito ou porta recusada).',
  '-130': 'Não foi possível falar com o proxy (o Tor está desconectado ou o cliente Tor externo não está rodando).',
  '-501': 'A conexão segura falhou (certificado ou resposta HTTPS inválidos).',
  '-300': 'O endereço digitado é inválido.',
  'crash': 'A página travou durante a execução.'
};

function isPolicyCode(code) {
  const text = String(code == null ? '' : code).toUpperCase();
  if (/^ERR_BLOCKED_BY_(CLIENT|ADMINISTRATOR|EXTENSION)$/.test(text)) return true;
  return [-20, -21, -22].includes(Number(text));
}

/**
 * Página de erro interna exibida DENTRO da própria aba (WebContentsView
 * não permite overlay DOM do renderer por cima do conteúdo).
 */
/** 1.6.1: URL de serviço onion (host termina em .onion). */
function isOnionUrl(u) {
  try { return /\.onion$/i.test(new URL(String(u || '')).hostname); } catch (_) { return false; }
}

function errorPageUrl(code, desc, retryUrl) {
  const known = ERR_MSG[String(code)] ||
    ('Falha na navegação' + (desc ? ' (' + String(desc).slice(0, 200) + ')' : ''));
  const policy = isPolicyCode(code);
  const html =
    '<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8">' +
    '<title>Erro</title><style>' +
    ':root{color-scheme:light dark}' +
    'body{margin:0;min-height:100vh;display:grid;place-items:center;' +
    'font-family:system-ui,Segoe UI,sans-serif;background:#0b0e13;color:#e8eaf0}' +
    '.box{max-width:520px;padding:40px;text-align:center;background:#12161f;' +
    'border:1px solid #262c3a;border-radius:16px}' +
    'h2{margin:0 0 12px;font-size:19px}p{margin:8px 0;line-height:1.5;color:#aab2c5;font-size:14px}' +
    '.note{font-size:12.5px;color:#7f8899}.code{font-family:monospace;font-size:12px;color:#5f6878}' +
    '.btns{margin-top:22px;display:flex;gap:10px;justify-content:center}' +
    'button{padding:9px 18px;border-radius:9px;border:1px solid #2c3444;' +
    'background:#1a2030;color:#e8eaf0;font-size:13.5px;cursor:pointer}' +
    'button:hover{background:#232b3d}' +
    '</style></head><body><div class="box">' +
    '<h2>Não foi possível carregar esta página</h2>' +
    '<p>' + known.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])) + '</p>' +
    (isOnionUrl(retryUrl) ? '<p class="note">Endereços .onion só abrem pela rede Tor: conecte em Conexão Tor (Ctrl+Shift+T) e use "Abrir aba Tor". Se já está numa aba Tor, o serviço pode estar fora do ar ou ainda sem circuito — aguarde um pouco e tente de novo.</p>' : '') +
    (policy ? '<p class="note">O NanoDesk respeita os controles de navegação da organização e não tenta contorná-los.</p>' : '') +
    '<p class="code">Código: ' + String(code).replace(/[&<>"]/g, '') + '</p>' +
    '<div class="btns">' +
    '<button id="retry">Tentar novamente</button>' +
    '<button id="back">Voltar</button>' +
    '</div></div>' +
    '<script>' +
    'var RETRY=' + JSON.stringify(String(retryUrl || '')) + ';' +
    'document.getElementById("retry").onclick=function(){location.replace(RETRY)};' +
    'document.getElementById("back").onclick=function(){history.back()};' +
    '</script></body></html>';
  return 'data:text/html;charset=utf-8,' + encodeURIComponent(html);
}

/* ---------------------- gerenciador de abas (WebContentsView) ---------------------- */

const tabList = [];   // registros das abas (fonte da verdade fica no main)
let tabSeq = 0;
let activeTabId = null;
let lastBounds = null; // { x, y, width, height } retângulo de #view-area
let boundsTimer = null;
let vaultSavePromptSkip = []; // 1.8.9: hosts silenciados (sessão) para o prompt "salvar credenciais"

function activeTab() {
  return tabList.find(t => t.id === activeTabId) || null;
}

/** 1.8.11 — a ação em curso DEVE sair pelo Tor? (modo Tor global OU aba ativa Tor). */
function torRequiredNow() {
  const t = activeTab();
  return !!((t && t.tor) || (settings && settings.get('torMode', false)));
}
/** 1.8.11 — existe QUALQUER uso de Tor agora (modo global ou alguma aba Tor aberta)? */
function torInUse() {
  return !!((settings && settings.get('torMode', false)) || tabList.some(t => t && t.tor));
}

/**
 * 1.8.9 — Pega credenciais do host da aba ativa no cofre nativo, escolhe
 * (menu nativo se várias) e injeta fillScript no mundo principal da página.
 * Definida no escopo do módulo para ser chamada tanto pelo IPC
 * bitwarden:fill / vault:fill-now quanto pelo listener console-message
 * do botão flutuante nas páginas.
 * @returns {Promise<boolean>}
 */
async function vaultFillActiveTab() {
  const t = activeTab();
  if (!t || !t.view) throw new Error('Nenhuma aba ativa.');
  const host = hostOf(t.url);
  let logins;
  try { logins = bitwarden.getByHost(host); }
  catch (e) { throw new Error(e && e.message ? e.message : 'Cofre bloqueado.'); }
  if (!logins || !logins.length) {
    toast('Nenhuma credencial do cofre para ' + host + '.');
    return false;
  }
  const applyOne = (login) => {
    try {
      // 1.8.11: o menu (vários logins) é assíncrono — se a aba navegou enquanto o menu
      // estava aberto, a senha seria injetada NO NOVO SITE. Revalida aba + host agora.
      const cur = activeTab();
      const liveWc = cur && cur.id === t.id && cur.view ? cur.view.webContents : null;
      let liveHost = '';
      try { liveHost = liveWc && !liveWc.isDestroyed() ? hostOf(liveWc.getURL()) : ''; } catch (_) { liveHost = ''; }
      if (!liveWc || liveHost !== host) {
        toast('O site mudou antes do preenchimento — cancelado por segurança.', 6000);
        return;
      }
      t.view.webContents.executeJavaScript(bitwarden.fillScript(login.username, login.password), false)
        .then(res => {
          if (res && res.ok) toast('Login preenchido: ' + (login.name || login.username || host) + '.');
          else toast('Não encontrei campos de login: ' + ((res && res.reason) || '?'));
        })
        .catch(() => toast('Não foi possível preencher na página.'));
    } catch (_) { toast('Aba não disponível.'); }
  };
  if (logins.length === 1) { applyOne(logins[0]); return true; }
  const menu = Menu.buildFromTemplate(logins.map(l => ({
    label: (l.name || '(sem nome)') + ' — ' + (l.username || '(sem usuário)'),
    click: () => applyOne(l)
  })));
  menu.popup({ window: win });
  return true;
}

/**
 * 1.9.1 — Após um submit de login, oferece salvar a credencial no cofre. A credencial vem da
 * MEMÓRIA do processo principal (tab.pendingCred, preenchida pelo IPC 'nd:cred-capture' a partir
 * do preload no mundo isolado) — nunca do sessionStorage da página. Funciona também quando o
 * login redireciona para outra origem (o sessionStorage antigo era por origem) e expira em 2 min.
 * Se o cofre estiver bloqueado, avisa e aborta (não pede a senha-mestra de um gatilho automático).
 */
function maybePromptSaveCredentials(tab) {
  if (!tab || !tab.view) return;
  const rec = tab.pendingCred;
  tab.pendingCred = null;                                   // consumida (uma vez)
  if (!rec || Date.now() - rec.ts > 120000) return;
  const host = rec.host;
  if (!host || noInjectionHost(host)) return;               // 1.7.2: páginas de login/banco: não capturar
  if (vaultSavePromptSkip && vaultSavePromptSkip.includes(host)) return;
  if (!rec.u && !rec.p) return;
  const st = bitwarden.status();
  if (!st.enabled) return;
  if (!st.unlocked) {
    toast('Cofre bloqueado — credenciais de ' + host + ' não foram salvas (desbloqueie no painel do cofre).', 8000);
    return;
  }
  let existing = [];
  try { existing = bitwarden.getByHost(host); } catch (_) { return; }
  if (existing.some(it => String(it.username || '') === String(rec.u || ''))) return;   // já salvo
  const userPreview = String(rec.u || '(sem usuário)').slice(0, 60);
  dialog.showMessageBox(win, {
    type: 'question',
    buttons: ['Salvar no cofre', 'Agora não', 'Nunca para este site'],
    defaultId: 0,
    cancelId: 1,
    title: 'Salvar credenciais?',
    message: 'Salvar estas credenciais no cofre NanoDesk?',
    detail: 'Site: ' + host + '\nUsuário: ' + userPreview +
      (bitwarden.status().ephemeral
        ? '\n\nCofre temporário: as credenciais ficam só na memória e somem ao fechar o NanoDesk.'
        : '\n\nAs credenciais serão cifradas com AES-256-GCM e gravadas no seu computador (nanodesk-vault.json).')
  }).then((res) => {
    if (res.response === 0) {
      try {
        bitwarden.add({
          name: host + ' · ' + userPreview,
          username: String(rec.u || ''),
          password: String(rec.p || ''),
          uris: [rec.origin || ('https://' + host)],       // só a origem (sem query/tokens)
          notes: ''
        });
        toast('Credenciais salvas no cofre NanoDesk (' + host + ').', 6000);
        sendToWin('vault:state', bitwarden.status());
      } catch (e) {
        toast('Não foi possível salvar: ' + (e && e.message || 'erro.'), 6000);
      }
    } else if (res.response === 2) {
      try {
        if (!Array.isArray(vaultSavePromptSkip)) vaultSavePromptSkip = [];
        if (!vaultSavePromptSkip.includes(host)) vaultSavePromptSkip.push(host);
      } catch (_) { /* ignorado */ }
    }
  }).catch(() => { /* janela pode ter sido destruída */ }).finally(() => { rec.p = ''; });
}

function serializeTab(t) {
  let canBack = false, canFwd = false;
  if (t.view) {
    try {
      canBack = t.view.webContents.navigationHistory.canGoBack();
      canFwd = t.view.webContents.navigationHistory.canGoForward();
    } catch (_) { /* view pode estar sendo destruída */ }
  }
  return {
    id: t.id,
    url: t.url,
    title: t.title,
    favicon: t.favicon,
    audio: t.audio,
    loading: t.loading,
    sleeping: t.state === 'sleeping',
    state: t.state,
    zoom: t.zoom,
    canBack, canFwd,
    active: t.id === activeTabId,
    lastSiteUrl: t.lastSiteUrl || null,
    sessionId: t.sessionId || 'padrao',  // 1.6.0 — contêiner
    tor: t.tor === true                  // 1.6.1 — aba Tor nativa
  };
}

function pushState() {
  sendToWin('tabs:state', tabList.map(serializeTab));
}
function pushStateThrottled() {
  if (boundsTimer) return;
  boundsTimer = setTimeout(() => { boundsTimer = null; pushState(); }, 120);
}

/** Aplica o último retângulo conhecido a uma view. */
function applyBoundsTo(t) {
  if (!t || !t.view || !lastBounds) return;
  try {
    t.view.setBounds({
      x: Math.max(0, Math.round(lastBounds.x)),
      y: Math.max(0, Math.round(lastBounds.y)),
      width: Math.max(1, Math.round(lastBounds.width)),
      height: Math.max(1, Math.round(lastBounds.height))
    });
  } catch (_) { /* janela pode ter fechado */ }
}

function reapplyBounds() {
  const t = activeTab();
  if (t && t.view) applyBoundsTo(t);
}

function createTab(url, opts = {}) {
  const t = {
    id: ++tabSeq,
    url: null,
    title: 'Nova aba',
    favicon: null,
    audio: false,
    loading: false,
    state: 'ntp',          // ntp | loading | ready | sleeping
    zoom: 1,
    view: null,
    active: false,
    lastActive: Date.now(),
    lastSiteUrl: null,
    googleHinted: false,
    allowDataOnce: false,
    errCode: null,
    tor: opts.tor === true,   // 1.6.1: aba roteada pela sessão Tor isolada
    sessionId: (opts.tor !== true && containerById(opts.sessionId)) ? opts.sessionId : 'padrao', // 1.6.0
    httpsFallback: null    // 1.6.0 FASE 3: http original no fallback HTTPS-first
  };
  tabList.push(t);
  if (url) navigateRecord(t, url, { quiet: true });
  if (opts.activate !== false) activateTab(t.id);
  else pushState();
  return t;
}

/**
 * Prepara o registro para uma URL (sem criar view — a view nasce sob demanda).
 * Retorna a aba que deve ficar ativa depois da navegação (ou null = a própria).
 */
function navigateRecord(t, url, opts = {}) {
  // Aba-leitor não navega para endereços: links externos viram nova aba
  // (que se torna a ativa — devolvida ao chamador).
  if (t.kind) {
    if (isHttpUrl(url)) return createTab(url, inheritOpts(t));
    return null;
  }
  // 1.5.0: alvos de leitor (PDF/ebook) viram aba-leitor na própria aba.
  const target = readers.classifyReaderTarget(String(url || ''));
  if (target) {
    openReaderInTab(t, target);
    return t;
  }
  // 1.6.0 FASE 4 (ClearURLs): destino digitado entra limpo de rastreadores.
  if (settings && settings.get('clearUrls', true) && /^https?:\/\//i.test(url)) {
    const skip = engine ? engine.allowlist() : [];
    const cleaned = urlclean.cleanUrl(url, { skipHosts: skip });
    if (cleaned.removed.length) {
      url = cleaned.url;
      toast('Parâmetros de rastreamento removidos (' + cleaned.removed.length + ').', 2200);
    }
  }
  // 1.6.0 FASE 3: HTTPS-first — tenta https://; erro de TLS volta ao http.
  // 1.6.1: .onion NÃO sobe para https (serviços onion costumam só falar HTTP;
  // o próprio Tor já criptografa de ponta a ponta) — antes dava ERR_SOCKS_CONNECTION_FAILED.
  if (settings && settings.get('httpsFirst', true) && /^http:\/\//i.test(url) && !isOnionUrl(url) &&
      !/^http:\/\/(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i.test(url)) {
    t.httpsFallback = url;
    url = 'https://' + url.slice(7);
  }
  // 1.6.0 FASE 8 / 1.7.0: política de vídeo NATIVO (URL digitada).
  // 1.8.8: Piped/Invidious/FreeTube REMOVIDOS — o YouTube abre comum.
  // 1.8.8: resolve redirects de trackers (Google url?q=, Bing base64,
  // DuckDuckGo uddg, Reddit r., Steam, Facebook l.php, YouTube redirect)
  // ANTES de carregar — evita expor a URL "real" via tracker de redirect.
  if (settings && settings.get('noredirectEnabled', true) && /^https?:\/\//i.test(url)) {
    const resolved = noredirect.resolveRedirect(url);
    if (resolved && resolved !== url) {
      guardToast('noredirect:' + hostOf(url), 'Redirect de tracker resolvido -> ' + hostOf(resolved) + '.', 2000);
      url = resolved;
    }
  }
  // 1.8.8: bloqueio de sites de MALWARE (StevenBlack hosts) ANTES de navegar.
  //   Usa o hostsDomainSet (Set) — NÃO o array hostsDomains, senão .has() crasha.
  if (settings && settings.get('malwareSiteBlock', true) && /^https?:\/\//i.test(url)) {
    const hh = hostOf(url);
    if (hh && isInHostsBlocklist(hh)) {
      pushSecurityEvent({ kind: 'malware', host: hh, level: 'critico',
        detail: 'host na lista StevenBlack (malware) — navegação cancelada' });
      toast('Acesso bloqueado: "' + hh + '" é conhecido por distribuir malware.', 8000);
      return null;
    }
  }
  t.onionHttpTried = false;   // 1.6.1: nova navegação libera o fallback .onion
  t.url = url;
  t.title = hostOf(url) || 'Carregando…';
  t.state = opts.lazy ? 'sleeping' : 'loading';
  t.favicon = null;
  t.errCode = null;
  if (opts.lazy) return;
  if (t.view) {
    // CORREÇÃO 1.4.0: a aba JÁ tem view (navegação seguinte na mesma aba —
    // endereço digitado de novo). Antes o loadURL só acontecia na CRIAÇÃO
    // da view: digitar um novo endereço não navegava.
    t.loading = true;
    try { t.view.webContents.loadURL(url).catch(() => { /* did-fail-load trata */ }); }
    catch (_) { /* view pode estar sendo destruída */ }
  } else if (t.active || opts.activateNow) {
    t.loading = true;
    ensureView(t);
  }
}

function ensureView(t) {
  if (t.view || !t.url) return;
  let wc = null;
  try {
    // 1.9.4 — defesa em profundidade das abas (WebContentsView):
    //   - navigateOnDragDrop: false — arrastar-soltar um arquivo .html/.svg
    //     sobre a aba NÃO dispara navegação (vetor de XSS/sequestro via DOM).
    //   - enableWebSQL: false — WebSQL está deprecated/removido em Chromium
    //     156+, mas deixamos explícito para nunca ressuscitar o armazenamento
    //     SQLite legacy (vetor de persistência não-sanitizada).
    //   - safeBrowsing: false — a lista remota do Google não é consultada
    //     (o NanoDesk usa StevenBlack + URL Gate + Security Gateway). Manter
    //     ligado vazar URLs ao Safe Browsing e criar telemetria indesejada.
    //   - enablePreferredSizeMode: false — não há razão para a aba reportar
    //     o tamanho preferido do conteúdo (superfície mínima).
    t.view = new WebContentsView({
      webPreferences: {
        partition: partitionOf(t),     // sessão EM MEMÓRIA (contêiner 1.6.0)
        contextIsolation: true,
        sandbox: true,
        nodeIntegration: false,
        nodeIntegrationInSubFrames: false,
        nodeIntegrationInWorker: false,
        webSecurity: true,
        allowRunningInsecureContent: false,
        experimentalFeatures: false,
        plugins: true,                 // leitor de PDF integrado (PDFium)
        spellcheck: false,
        navigateOnDragDrop: false,     // 1.9.4 — sem navegação por drag-drop
        enableWebSQL: false,           // 1.9.4 — WebSQL legacy desligado
        safeBrowsing: false,           // 1.9.4 — não consulta Safe Browsing remoto
        enablePreferredSizeMode: false // 1.9.4 — superfície mínima de callbacks
      }
    });
    t.view.setBackgroundColor('#ffffff');
    wc = t.view.webContents;
    applyWebRtcPolicy(wc, t);        // 1.6.0 FASE 3/5 — WebRTC sem vazamento
    try { wc.setZoomFactor(t.zoom); } catch (_) { /* ignorado */ }
    bindTabWebContents(t, wc);
    if (win && !win.isDestroyed()) {
      win.contentView.addChildView(t.view);
      t.view.setVisible(t.active);
      applyBoundsTo(t);
    }
    wc.loadURL(t.url).catch(() => { /* did-fail-load cuida do erro */ });
  } catch (error) {
    t.view = null;
    console.warn('[nanodesk:tabs] não foi possível criar a aba:', error.message);
  }
}

function destroyView(t) {
  const v = t.view;
  t.view = null;
  if (!v) return;
  // 1.5.1: limpa contadores/cadeias ligados à view que está saindo.
  try { popupGuard && popupGuard.resetTab(t.id); } catch (_) { /* ignorado */ }
  try { redirectGuard && redirectGuard.endChain(v.webContents.id); } catch (_) { /* ignorado */ }
  try {
    if (win && !win.isDestroyed()) win.contentView.removeChildView(v);
  } catch (_) { /* ignorado */ }
  try { v.webContents.stop(); } catch (_) { /* ignorado */ }
  try { v.webContents.close(); } catch (_) { /* pode já ter fechado */ }
}

/* ---------------- abas-leitor (PDF / ebook — 1.5.0) ---------------- */

/**
 * Converte a aba em ABA-LEITOR: destrói a view atual e carrega a página
 * do leitor interno (pdf.js ou foliate-js) servida em ndr://readers/.
 * Os bytes do documento não ficam gravados — a página os recebe por IPC.
 */
function openReaderInTab(t, target) {
  if (!t || !target || !target.kind) return;
  destroyView(t);
  t.kind = target.kind;              // 'pdf' | 'ebook'
  t.readerSrc = String(target.source || '');
  t.url = t.readerSrc;               // a barra mostra a origem real
  t.title = safeTitle(target.title, t.kind === 'pdf' ? 'PDF' : 'Livro');
  t.readerTitle = t.title;           // título original (env do leitor)
  t.favicon = null;
  t.errCode = null;
  t.zoom = 1;
  t.audio = false;
  t.state = 'loading';
  t.loading = true;
  if (t.active) ensureReaderView(t);
  pushState();
}

/** Aba nova direto no leitor (diálogo "abrir arquivo"). */
function createReaderTab(target) {
  const t = createTab(null);
  openReaderInTab(t, target);
  return t;
}

function ensureReaderView(t) {
  if (t.view || !t.readerSrc) return;
  try {
    // 1.9.4 — mesmo endurecimento das abas de navegação (navigateOnDragDrop,
    // enableWebSQL, safeBrowsing, enablePreferredSizeMode). O leitor é
    // tão exposto ao conteúdo remoto quanto a aba: um PDF malicioso com
    // links/action scripts pode disparar navegação. plugins:true para PDF.
    t.view = new WebContentsView({
      webPreferences: {
        preload: path.join(__dirname, '..', 'readers', 'reader-preload.js'),
        partition: MEM_PARTITION,      // sessão EM MEMÓRIA
        contextIsolation: true,
        sandbox: true,
        nodeIntegration: false,
        nodeIntegrationInSubFrames: false,
        nodeIntegrationInWorker: false,
        webSecurity: true,
        allowRunningInsecureContent: false,
        experimentalFeatures: false,
        plugins: false,
        spellcheck: false,
        navigateOnDragDrop: false,     // 1.9.4
        enableWebSQL: false,           // 1.9.4
        safeBrowsing: false,           // 1.9.4
        enablePreferredSizeMode: false // 1.9.4
      }
    });
    t.view.setBackgroundColor('#0b0e13');
    const wc = t.view.webContents;
    bindReaderWebContents(t, wc);
    if (win && !win.isDestroyed()) {
      win.contentView.addChildView(t.view);
      t.view.setVisible(t.active);
      applyBoundsTo(t);
    }
    wc.loadURL(readers.readerPageUrl(t.kind))
      .catch(() => { /* did-fail-load avisa */ });
  } catch (error) {
    t.view = null;
    console.warn('[nanodesk:readers] não foi possível criar o leitor:', error.message);
  }
}

function bindReaderWebContents(t, wc) {
  const isCurrent = () => t.view && t.view.webContents === wc;

  wc.on('did-start-loading', () => {
    if (!isCurrent()) return;
    t.loading = true;
    pushStateThrottled();
  });
  wc.on('did-stop-loading', () => {
    if (!isCurrent()) return;
    t.loading = false;
    t.state = 'ready';
    pushState();
  });
  wc.on('page-title-updated', (e, title) => {
    if (!isCurrent()) return;
    t.title = safeTitle(title, t.title);
    pushStateThrottled();
  });
  wc.on('did-fail-load', (e, code, desc, url, isMainFrame) => {
    if (!isCurrent() || !isMainFrame || code === -3 || code === 0) return;
    t.loading = false;
    t.state = 'ready';
    toast('Não foi possível carregar o leitor (código ' + code + ').');
    pushState();
  });
  wc.on('context-menu', (e, params) => {
    if (!isCurrent()) return;
    showPageContextMenu(wc, params);
  });

  // Pop-ups (links externos dentro de PDFs/livros) viram abas internas.
  wc.setWindowOpenHandler(({ url }) => {
    if (isNavigable(url)) createTab(url, inheritOpts(t));
    else toast('Destino de pop-up bloqueado (somente HTTP/HTTPS).');
    return { action: 'deny' };
  });

  // Navegação de páginas-leitor: nada substitui a página do leitor.
  // Links http/https abrem em NOVA aba; ndr só é permitido se for a
  // própria página; o resto é bloqueado.
  wc.on('will-navigate', (ev, url) => {
    ev.preventDefault();
    const u = String(url || '');
    if (u.startsWith(readers.READER_BASE)) {
      const page = readers.readerPageUrl(t.kind);
      if (u === page || u.startsWith(page + '?')) {
        try { wc.loadURL(page).catch(() => {}); } catch (_) { /* ignorado */ }
      }
      return;
    }
    if (isHttpUrl(u)) createTab(u, inheritOpts(t));
    else toast('Navegação bloqueada: o leitor só abre links http/HTTPS em nova aba.');
  });
}

function activateTab(id) {
  const t = tabList.find(x => x.id === id);
  if (!t) return;
  closeFindIfNeeded();
  activeTabId = id;
  t.active = true;
  t.lastActive = Date.now();
  if (t.state === 'sleeping') {
    t.state = 'loading';
    t.loading = true;
    ensureView(t);
  } else if (!t.view && t.state !== 'ntp' && t.url) {
    t.loading = true;
    if (t.kind) ensureReaderView(t); // 1.5.0: aba-leitor em segundo plano
    else ensureView(t);
  }
  for (const other of tabList) {
    other.active = other.id === id;   // 1.6.2: antes só ligava a flag — nenhuma aba voltava a 'inativa'
    if (other.view) {
      try { other.view.setVisible(other.id === id); } catch (_) { /* ignorado */ }
    }
  }
  reapplyBounds();
  pushState();
}

function closeFindIfNeeded() { /* renderer fecha a findbar ao trocar de aba via onState */ }

/**
 * Economia de memória: destrói a WebContentsView da aba e guarda apenas
 * a URL. A aba volta ao ser reativada (recarrega do site — nada é
 * restaurado do disco).
 */
function hibernateTab(t) {
  if (!t || !t.view || t.active || t.kind) return; // leitores nunca dormem
  try {
    const u = t.view.webContents.getURL();
    if (u && u !== 'about:blank' && isHttpUrl(u)) t.url = u;
  } catch (_) { /* ignorado */ }
  destroyView(t);
  t.audio = false;
  t.loading = false;
  t.state = 'sleeping';
  pushState();
}

/* Suspensão automática de abas inativas (economia de RAM). */
setInterval(() => {
  if (!settings) return;
  if (!settings.get('hibernateTabs', true)) return;
  // CORREÇÃO 1.6.7: clamp — hibernateMinutes=0 suspendia TODA aba inativa no
  // primeiro tick de 20 s (a validação já impede 0, mas o valor legado/restaurado
  // não passava por aqui com garantia).
  const ms = Math.max(1, (settings.get('hibernateMinutes', 15) || 15)) * 60000;
  const now = Date.now();
  for (const t of tabList.slice()) {
    if (t.kind) continue;           // abas-leitor não são suspensas
    if (t.view && !t.active && !t.audio && now - t.lastActive > ms) hibernateTab(t);
  }
}, 20000);

function closeTab(id) {
  const idx = tabList.findIndex(t => t.id === id);
  if (idx < 0) return;
  const t = tabList[idx];
  destroyView(t);
  tabList.splice(idx, 1);
  clearMediaState(id);   // 1.9.5: limpa estado de mídia da aba fechada
  if (activeTabId === id) {
    activeTabId = null;
    const next = tabList[Math.min(idx, tabList.length - 1)];
    if (next) activateTab(next.id);
    else createTab(null);
  } else {
    pushState();
  }
}

function bindTabWebContents(t, wc) {
  const isCurrent = () => t.view && t.view.webContents === wc;

  wc.on('did-start-loading', () => {
    if (!isCurrent()) return;
    t.loading = true;
    if (t.state === 'sleeping') t.state = 'loading';
    pushStateThrottled();
  });

  wc.on('did-stop-loading', () => {
    if (!isCurrent()) return;
    t.loading = false;
    if (t.state !== 'sleeping') t.state = 'ready';
    if (!t.errCode && t.title === 'Carregando…') t.title = hostOf(t.url) || 'Sem título';
    pushState();
  });

  wc.on('did-navigate', (e, url) => {
    if (!isCurrent()) return;
    // 1.5.1: navegação confirmada — a cadeia de redirecionamentos antiga
    // termina aqui (a próxima navegação começa uma cadeia limpa).
    try { redirectGuard && redirectGuard.endChain(wc.id); } catch (_) { /* ignorado */ }
    injectedStyles = new Set(); // 1.6.7: nova página, CSS de base pode ser injetado de novo
    // data: é a página de erro interna — não é a URL real da aba.
    // CORREÇÃO 1.5.2: a exceção "data: uma vez" é consumida AQUI (loadURL do
    // main não dispara will-navigate, então a flag antiga ficava ligada).
    if (String(url || '').startsWith('data:')) t.allowDataOnce = false;
    if (url && url !== 'about:blank' && !String(url).startsWith('data:')) {
      t.url = url;
      t.errCode = null;
      // 1.6.0 FASE 7: histórico pesquisável — só RAM, some ao fechar.
      if (history && !t.tor) history.add(url, t.title);   // 1.6.1: abas Tor não entram no histórico
      const host = hostOf(url);
      if (host && host !== 'accounts.google.com') t.lastSiteUrl = url;
      if (host === 'accounts.google.com' && !t.googleHinted) {
        t.googleHinted = true;
        toast('Login no Google: funciona normalmente nesta sessão, mas a conta desconecta quando o NanoDesk fechar (nada fica gravado).', 10000);
      }
      // 1.8.8: watchdog de vídeo REMOVIDO (Piped/Invidious/FreeTube fora).
      // 1.8.9: cofre — após navegação pós-submit de login, tenta ler a
      // credencial capturada (sessionStorage) e oferece salvar no cofre.
      if (host && settings.get('vaultEnabled', true) && settings.get('vaultSavePrompt', true)) {
        setTimeout(() => { try { maybePromptSaveCredentials(t); } catch (_) { /* ignorado */ } }, 1300);
      }
    }
    pushState();
  });

  wc.on('did-navigate-in-page', (e, url, isMainFrame) => {
    if (!isCurrent() || !isMainFrame || !url) return;
    t.url = url;
    pushState();
    // 1.8.8: watchdog SPA REMOVIDO (Piped/Invidious/FreeTube fora).
  });

  wc.on('page-title-updated', (e, title) => {
    if (!isCurrent()) return;
    if (t.errCode) return; // não sobrescrever o título do erro
    t.title = safeTitle(title, 'Sem título');
    pushStateThrottled();
  });

  wc.on('page-favicon-updated', (e, icons) => {
    if (!isCurrent()) return;
    // CORREÇÃO 1.6.7 (vazamento grave): o favicon de abas Tor era uma URL
    // remota que a INTERFACE baixava pela sessão PADRÃO (rota direta, IP
    // real) minutos depois da navegação anonima — correlação temporal que
    // liga o IP real ao conteúdo visitado via Tor. Abas Tor não têm favicon
    // remoto (a UI mostra o ícone de letra do host).
    if (t.tor) { if (t.favicon) { t.favicon = null; pushStateThrottled(); } return; }
    t.favicon = (icons && icons[0]) || null;
    pushStateThrottled();
  });

  wc.on('media-started-playing', () => { if (isCurrent()) { t.audio = true; pushState(); } });
  wc.on('media-paused', () => { if (isCurrent()) { t.audio = false; pushState(); } });

  wc.on('found-in-page', (e, result) => {
    if (!isCurrent()) return;
    sendToWin('tabs:found', { id: t.id, result });
  });

  // 1.6.7: hashes dos CSS de base já injetados nesta página (evita que o
  // dom-ready reinjete o que o frame-init já pôs — insertCSS acumula folhas
  // e deixa a resolução de estilo cada vez mais cara em sessões longas).
  let injectedStyles = new Set();
  const styleHash = (s) => {
    const str = String(s || '');
    let h = 5381;
    for (let i = 0; i < str.length; i += 97) { h = ((h << 5) + h + str.charCodeAt(i)) | 0; }
    return str.length + ':' + h;
  };

  wc.on('dom-ready', () => {
    if (!isCurrent()) return;
    // Filtros cosméticos (Ghostery) — injeção de CSS silenciosa.
    // CORREÇÃO 1.6.7: só injeta CSS ainda não injetado nesta página (o
    // preload de frame já injeta o CSS de base no frame-init); se o motor
    // não estava pronto naquela hora, aqui é a segunda chance.
    try {
      const eng = engineForTab(t);
      if (eng && eng.isEnabled() && /^https?:\/\//i.test(String(t.url || '')) &&
          !noInjectionHost(hostOf(t.url))) {   // 1.7.2
        const c = cachedCosmetics(eng, t.url);
        const key = styleHash(c.styles);
        if (c.styles && !injectedStyles.has(key)) {
          injectedStyles.add(key);
          wc.insertCSS(c.styles, { cssOrigin: 'author' }).catch(() => {});
        }
      }
    } catch (_) { /* melhor esforço */ }
    // 1.5.1 RedirectGuard: neutraliza overlays-armadilha invisíveis
    // (click hijacking). Falha é silenciosa — é uma melhoria.
    runOverlayGuard(wc, t);
    // 1.5.2: armadilhas costumam ser inseridas por script DEPOIS do
    // dom-ready — CORREÇÃO 1.6.7: duas passadas em vez de três
    // (dom-ready + 2,5 s captura armadilha tardia; 6 s pega as minutos depois).
    const navUrl = t.url;
    for (const delay of [2500, 6000]) {
      setTimeout(() => {
        if (isCurrent() && t.url === navUrl) runOverlayGuard(wc, t);
      }, delay);
    }
    // 1.8.9 — cofre de senhas: injeta o detector de formulário de login e,
    // se houver credenciais do host no cofre (desbloqueado), injeta o
    // botão flutuante "Cofre: preencher".
    runVaultAutofill(wc, t);
    setTimeout(() => { if (isCurrent() && t.url === navUrl) runVaultAutofill(wc, t); }, 2500);
  });

  function runOverlayGuard(contents, tab) {
    if (!redirectGuard || !redirectGuard.isEnabled()) return;
    if (!/^https?:\/\//i.test(String(tab.url || ''))) return;
    if (noInjectionHost(hostOf(tab.url))) return;   // 1.7.2: nunca mexe em páginas de login
    try {
      contents.executeJavaScript(OVERLAY_SCRIPT, false)
        .then((hits) => {
          const n = Number(hits) || 0;
          if (n > 0) {
            redirectGuard.noteClickTraps(n);
            pushProtectionStatsThrottled();
          }
        })
        .catch(() => { /* best-effort */ });
    } catch (_) { /* webContents pode estar sendo destruída */ }
  }

  // 1.8.9 — cofre de senhas: injeta detector de login + botão flutuante
  function runVaultAutofill(contents, tab) {
    if (!settings.get('vaultEnabled', true)) return;
    if (!/^https?:\/\//i.test(String(tab.url || ''))) return;
    if (noInjectionHost(hostOf(tab.url))) return;   // páginas de login/banco: não injetar
    try {
      // (A) REMOVIDO na 1.9.1: a captura de credenciais agora é feita no preload (mundo isolado).
      // (B) botão flutuante só se cofre desbloqueado E com credenciais do host
      const st = bitwarden.status();
      if (!st.unlocked) return;
      const host = hostOf(tab.url);
      let matches = [];
      try { matches = bitwarden.getByHost(host); } catch (_) { matches = []; }
      if (!matches.length) return;
      // 1.9.2: oferta registrada no processo principal; o botão é criado pelo PRELOAD (mundo isolado)
      tab.fillOffer = { host, ts: Date.now() };
      try { contents.mainFrame.send('nd:vault-button', { label: host }); } catch (_) { /* best-effort */ }
    } catch (_) { /* webContents pode estar sendo destruída */ }
  }

  // 1.9.2 — o preenchimento do cofre NÃO é mais disparado por console.log (qualquer script da página podia
  // emitir a mesma mensagem): ver ipcMain 'nd:vault-fill' (clique REAL no botão do preload isolado).
  // O console-message abaixo atende apenas ao SponsorBlock.
  wc.on('console-message', (event, level, message) => {
    if (!isCurrent()) return;
    // Electron 45+: se level for um objeto (details), extrair message dele
    const details = (level && typeof level === 'object') ? level : null;
    const msg = String(details ? (details.message || '') : (message || ''));
    // 1.8.9 — SponsorBlock CSP bypass: o script na página sinaliza o ID do
    // vídeo via console.log('__nanodesk_sb_request__<id>'); o main process
    // (Node.js, não sofre CSP do YouTube) busca os segmentos e os injeta de
    // volta chamando window.__nanodeskSbSet(id, segments).
    // 1.8.10: NÃO dispara em abas Tor — fetchSegments usa https.get do Node,
    // que ignora o proxy SOCKS5 da sessão e VAZARIA o IP real para
    // sponsor.ajay.app. Mesmo padrão já adotado por translate/LanguageTool.
    if (msg.indexOf('__nanodesk_sb_request__') !== -1) {
      try {
        if (t && t.tor) return; // guarda Tor: não vaza IP real
        const token = '__nanodesk_sb_request__';
        const videoId = msg.slice(msg.indexOf(token) + token.length).trim();
        if (/^[A-Za-z0-9_-]{6,20}$/.test(videoId) && settings.get('sponsorBlockEnabled', false)) {
          const cats = settings.get('sbCategories', []);
          sponsorblock.fetchSegments(videoId, cats, sessionFetch()).then((segments) => {
            const code = 'window.__nanodeskSbSet && window.__nanodeskSbSet(' +
              JSON.stringify(videoId) + ', ' + JSON.stringify(segments) + ');';
            try { wc.executeJavaScript(code, false).catch(() => {}); } catch (_) {}
          }).catch(() => {});
        }
      } catch (_) {}
    }
  });

  wc.on('did-fail-load', (e, code, desc, url, isMainFrame) => {
    if (!isCurrent() || !isMainFrame || code === -3 || code === 0) return;
    // 1.6.0 FASE 3: HTTPS-first — TLS falhou, tenta o HTTP original UMA vez.
    // 1.6.3: o fallback só cobria erros de certificado. Site que só serve HTTP (porta 443 fechada,
    // servidor HTTP puro na porta, timeout, conexão resetada) ficava INACESSÍVEL com HTTPS-first.
    const HTTPS_FALLBACK_CODES = new Set([-100, -101, -102, -107, -109, -111, -113, -118, -324, -501]);
    if (t.httpsFallback && (HTTPS_FALLBACK_CODES.has(code) || (code <= -200 && code >= -230))) {
      const fb = t.httpsFallback;
      t.httpsFallback = null;
      toast('HTTPS indisponível: página aberta em HTTP (SEM criptografia).', 6000);
      try { wc.loadURL(fb).catch(() => { /* did-fail-load trata */ }); } catch (_) { /* ignorado */ }
      return;
    }
    // 1.6.1: serviço .onion sem HTTPS — o Tor responde falha de SOCKS (-120) à porta 443.
    // Tenta o http:// equivalente UMA vez (seguro: o trajeto onion é criptografado pelo Tor).
    const failed = url || t.url;
    if (!t.onionHttpTried && /^https:\/\//i.test(failed) && isOnionUrl(failed) &&
        (code === -120 || code === -130 || code === -100 || code === -101 || code === -102 || code === -109)) {
      t.onionHttpTried = true;
      toast('Serviço .onion sem HTTPS: aberto em HTTP (o Tor já criptografa o trajeto).', 6000);
      try { wc.loadURL('http://' + failed.slice(8)).catch(() => { /* did-fail-load trata */ }); } catch (_) { /* ignorado */ }
      return;
    }
    // 1.8.8: FAILOVER da instância nativa (Piped/Invidious) REMOVIDO.
    showErrorPage(t, code, desc, failed);
  });

  wc.on('render-process-gone', (e, details) => {
    if (!isCurrent()) return;
    if (details && details.reason === 'clean-exit') return;
    showErrorPage(t, 'crash', 'O processo da página parou inesperadamente.', t.url);
  });

  wc.on('context-menu', (e, params) => {
    if (!isCurrent()) return;
    showPageContextMenu(wc, params);
  });

  // Pop-ups (1.5.1 — conceitos de Popup-Blocker-Pro): aberturas SEM
  // interação do usuário (window.open automático, pop-under, tab-under)
  // são BLOQUEADAS; com clique/tecla real viram abas internas, como
  // antes. Sites na allowlist podem abrir pop-ups livremente.
  //
  // "Gesto do usuário" no Electron 45: o HandlerDetails do
  // setWindowOpenHandler NÃO traz mais o campo userGesture, então a
  // interação real é detectada aqui — qualquer clique/tecla que chegue
  // à aba (input-event) deixa a aba "ativa" por uma janela curta de
  // 1000 ms, tempo mais que suficiente para o window.open de um
  // handler de clique; aberturas fora disso são automáticas.
  let lastUserInputAt = 0;
  const USER_INPUT_WINDOW_MS = 1000;
  wc.on('input-event', (e, input) => {
    const tpe = input && input.type;
    if (tpe === 'mouseDown' || tpe === 'mouseUp' ||
        tpe === 'keyDown' || tpe === 'rawKeyDown') {
      lastUserInputAt = Date.now();
    }
  });

  wc.setWindowOpenHandler((details) => {
    // 1.8.8: popupBlockerStrict — bloqueia TODOS os pop-ups (COM ou SEM gesto),
    //   exceto same-origin e about:blank. Conceito schomery/popup-blocker.
    //   O script injetado (popup-blocker-strict.js) já intercepta window.open
    //   na página; AQUI é a camada extra do processo principal.
    if (settings && settings.get('popupBlockerStrict', true)) {
      const u = String(details.url || '');
      const dest = hostOf(u);
      const srcHost = hostOf(t.url);
      // 1.9.2: origem COMPLETA (protocolo + host + porta). Antes: só o host, com subdomínios nos dois
      // sentidos, e URL sem host (data:, etc.) contava como "mesma origem". Exceções EXPLÍCITAS:
      // about:blank/javascript: (herdam a origem de quem abre) e fluxos de login legítimos (SSO/OAuth).
      const sameOrigin = validation.isSameOrigin(u, t.url);
      const isAboutBlank = u === '' || u === 'about:blank' || /^javascript:/i.test(u);
      const authFlow = !!dest && (authhosts.isAuthHost(dest, settings.get('fpExempt', [])) || authhosts.sameSsoGroup(dest, srcHost));
      if (!sameOrigin && !isAboutBlank && !authFlow) {
        guardToast('popup-strict:' + dest, 'Pop-up bloqueado (modo estrito): ' + dest);
        pushProtectionStatsThrottled();
        return { action: 'deny' };
      }
    }
    const userActive = details.userGesture === true ||
      (Date.now() - lastUserInputAt) <= USER_INPUT_WINDOW_MS;
    const dec = popupGuard
      ? popupGuard.decide({
          url: details.url,
          userGesture: userActive,
          sourceHost: hostOf(t.url),
          sourceTabId: t.id
        })
      : { allow: true, reason: 'indisponivel' };
    if (!dec.allow) {
      guardToast('popup:' + dec.host, 'Pop-up bloqueado (sem interação): ' + dec.host);
      pushProtectionStatsThrottled();
      return { action: 'deny' };
    }
    if (isNavigable(details.url)) createTab(details.url, inheritOpts(t));   // 1.6.1: herda Tor/contêiner
    else toast('Destino de pop-up bloqueado (somente HTTP/HTTPS).');
    return { action: 'deny' }; // pop-ups nunca viram janelas nativas
  });

  // Guardas de navegação: somente HTTP/HTTPS (data: apenas para páginas de
  // erro internas e para o auto-teste do build). Alvos de leitor (PDF/
  // ebook) viram aba-leitor na PRÓPRIA aba (1.5.0). NOVO 1.5.1: alvos
  // para redes de redirecionamento conhecidas (RedirectGuard) são
  // cortados antes de sair da página.
  const guardNavigation = (ev, url) => {
    const u = String(url || '');
    const target = readers.classifyReaderTarget(u);
    if (target && isHttpUrl(u)) {
      ev.preventDefault();
      openReaderInTab(t, target);
      return;
    }
    if (/^https?:\/\//i.test(u)) {
      // RedirectGuard (1.5.1): sequestro de clique para rede de anúncios.
      if (redirectGuard) {
        const dec = redirectGuard.checkTarget(u);
        if (!dec.allow) {
          ev.preventDefault();
          guardToast('rd:' + dec.host, 'Redirecionamento bloqueado: ' + dec.host + ' (' + dec.rule + ').');
          pushProtectionStatsThrottled();
          return;
        }
      }
      // 1.6.0 FASE 4 (ClearURLs): links clicados entram sem rastreadores.
      if (settings && settings.get('clearUrls', true)) {
        const skip = engine ? engine.allowlist() : [];
        const cleaned = urlclean.cleanUrl(u, { skipHosts: skip });
        if (cleaned.removed.length) {
          ev.preventDefault();
          try { wc.loadURL(cleaned.url).catch(() => { /* ignora */ }); } catch (_) { /* ignorado */ }
          guardToast('clean', 'Parâmetros de rastreamento removidos do link.', 2000);
          return;
        }
      }
      // 1.6.0 FASE 6 (Security Gateway): análise heurística ANTES de navegar.
      if (settings && settings.get('urlGateEnabled', true)) {
        const gate = urlgate.analyze(u, { trustedHosts: [...urlGateTrusted] });
        if (gate.level !== 'ok') {
          ev.preventDefault();
          confirmUrlGate(wc, u, gate);
          return;
        }
      }
      // 1.8.8: vídeo NATIVO (Piped/Invidious/FreeTube) REMOVIDO.
      // 1.8.8: noredirect (resolve Google/Bing/DDG/Reddit/Steam/FB/YT redirects).
      if (settings && settings.get('noredirectEnabled', true) && /^https?:\/\//i.test(u)) {
        const resolved = noredirect.resolveRedirect(u);
        if (resolved && resolved !== u) {
          ev.preventDefault();
          try { wc.loadURL(resolved).catch(() => { /* ignora */ }); } catch (_) { /* ignorado */ }
          guardToast('noredirect:' + hostOf(u), 'Redirect de tracker resolvido -> ' + hostOf(resolved) + '.', 2000);
          return;
        }
      }
      // 1.8.8: malware site block (StevenBlack) — isInHostsBlocklist caminha sufixos.
      if (settings && settings.get('malwareSiteBlock', true) && /^https?:\/\//i.test(u)) {
        const hh = hostOf(u);
        if (hh && isInHostsBlocklist(hh)) {
          ev.preventDefault();
          guardToast('malware:' + hh, 'Acesso bloqueado: \"' + hh + '\" é conhecido por distribuir malware.', 5000);
          pushSecurityEvent({ kind: 'malware', host: hh, level: 'critico',
            detail: 'host na lista StevenBlack (malware) — link bloqueado' });
          return;
        }
      }
      return;
    }
    if (t.allowDataOnce && /^data:text\/html/i.test(u)) {
      t.allowDataOnce = false;
      return;
    }
    if (SELFTEST && /^data:text\/html/i.test(u)) return;
    ev.preventDefault();
    toast('Navegação bloqueada: o NanoDesk permite apenas HTTP/HTTPS.');
  };
  wc.on('will-navigate', guardNavigation);

  // Redirects de servidor (1.5.1): além das guardas acima, mantém a
  // CADEIA de redirecionamentos da aba — farms de redirect (5–10
  // domínios em segundos) são travadas; iframe mandando para rede de
  // anúncios também é cortado.
  //
  // CORREÇÃO 1.6.7 (logins quebrados): will-redirect NÃO pode passar pelo
  // guardNavigation completo — o URL Gate abria diálogo MODAL no meio de um
  // redirect de servidor e o "navegar mesmo assim" reemitia a navegação como
  // GET, PERDENDO o método POST/headers (SSO/banco quebravam). Em redirect
  // o máximo possível é REGISTRAR a suspeita: o destino suspeito será
  // analisado normalmente quando a navegação dele partir (will-navigate).
  wc.on('will-redirect', (ev, url, isInPlace, isMainFrameArg) => {
    if (ev.defaultPrevented) return;
    const mainFrame = (ev && typeof ev.isMainFrame === 'boolean')
      ? ev.isMainFrame
      : (isMainFrameArg !== false);
    const u = String(url || '');
    if (!/^https?:\/\//i.test(u)) return;
    // RedirectGuard: cadeias e redes de anúncio continuam cortadas aqui.
    if (redirectGuard) {
      const dec = mainFrame
        ? redirectGuard.checkRedirect({ key: wc.id, fromUrl: t.url, toUrl: u })
        : redirectGuard.checkTarget(u);
      if (!dec.allow) {
        ev.preventDefault();
        guardToast('rd:' + dec.host,
          dec.reason === 'cadeia'
            ? 'Cadeia de redirecionamentos travada (' + dec.rule + '): ' + dec.host + '.'
            : 'Redirecionamento bloqueado: ' + dec.host + ' (' + dec.rule + ').');
        pushProtectionStatsThrottled();
        return;
      }
    }
    // URL Gate em redirect: apenas REGISTRA (sem diálogo, sem reemissão).
    if (settings && settings.get('urlGateEnabled', true) && mainFrame) {
      try {
        const gate = urlgate.analyze(u, { trustedHosts: [...urlGateTrusted] });
        if (gate.level !== 'ok') {
          pushSecurityEvent({ kind: 'urlgate', host: gate.host, level: gate.level,
            detail: 'suspeita em REDIRECT (navegação permitida): ' + gate.reasons.join('; ') });
        }
      } catch (_) { /* nunca travar o tráfego por erro aqui */ }
    }
    // 1.8.8: vídeo NATIVO no redirect do SERVIDOR (Piped/Invidious/FreeTube) REMOVIDO.
    // 1.8.8: noredirect também vale no redirect de servidor (Google/Bing/DDG/...).
    if (mainFrame && settings && settings.get('noredirectEnabled', true) &&
        noredirect.isRedirectHost(u) && !t.allowDataOnce) {
      const resolved = noredirect.resolveRedirect(u);
      if (resolved && resolved !== u) {
        ev.preventDefault();
        try { wc.loadURL(resolved).catch(() => { /* ignora */ }); } catch (_) { /* ignorado */ }
        guardToast('noredirect:' + hostOf(u), 'Redirect de tracker resolvido -> ' + hostOf(resolved) + '.', 2000);
        return;
      }
    }
    // 1.8.8: malware site block no redirect de servidor.
    if (mainFrame && settings && settings.get('malwareSiteBlock', true)) {
      const hh = hostOf(u);
      if (hh && isInHostsBlocklist(hh)) {
        ev.preventDefault();
        guardToast('malware:' + hh, 'Acesso bloqueado: \"' + hh + '\" é conhecido por distribuir malware.', 5000);
        pushSecurityEvent({ kind: 'malware', host: hh, level: 'critico',
          detail: 'host na lista StevenBlack (malware) — redirect bloqueado' });
        return;
      }
    }
  });

  if (SELFTEST) {
    wc.on('did-finish-load', () => {
      console.log('SELFTEST-WEBVIEW-OK ' + wc.getURL());
      setTimeout(() => app.exit(0), 500);
    });
  }
}

function showErrorPage(t, code, desc, url) {
  t.errCode = code;
  t.title = (hostOf(url) || 'Página') + ' (erro)';
  t.loading = false;
  t.state = 'ready';
  const target = t.view;
  if (!target) return;
  t.allowDataOnce = true;
  try {
    target.webContents.loadURL(errorPageUrl(code, desc, url))
      .catch(() => { /* página de erro é best-effort */ });
  } catch (_) { /* ignorado */ }
  toast('Não foi possível carregar ' + (hostOf(url) || 'a página') + ' (código ' + code + ').');
  pushState();
}

/* ---------------------- menu de contexto das páginas ---------------------- */

function showPageContextMenu(wc, params) {
  const nav = wc.navigationHistory;
  const inherit = inheritOpts(tabByWebContents(wc));   // 1.6.1: herda Tor/contêiner da aba de origem
  const act = {
    openTab: (u) => { if (isNavigable(u)) createTab(u, inherit); },
    openReader: (u) => { if (isNavigable(u)) createTab(u, inherit); }, // classify abre o leitor
    openExternal: (url) => { if (isNavigable(url)) shell.openExternal(url).catch(() => {}); },
    copyText: (t) => clipboard.writeText(String(t)),
    download: (u) => { if (isNavigable(u)) wc.downloadURL(u); },
    copyImageAt: (x, y) => wc.copyImageAt(x, y),
    search: (text) => sendToWin('tabs:search', String(text).slice(0, 500)),
    // 1.6.0 FASE 7 — tradução privada (consentimento no diálogo)
    translate: (text) => { translateSelection(String(text).slice(0, translate.MAX_TEXT)).catch(() => {}); },
    // 1.7.0 — LanguageTool (gramática) + LibraryTranslate (biblioteca)
    grammarCheck: (text, fromField) => { runGrammarCheck(wc, String(text || ''), !!fromField).catch(() => {}); },
    libraryTranslate: (text) => { libraryTranslateSelection(String(text || '').slice(0, translate.MAX_TEXT)).catch(() => {}); },
    // 1.8.8 — vídeo: yt-dlp apenas (FreeTube/Invidious/Piped REMOVIDOS)
    videoDownload: (u) => startYtDlpDownload(u),
    // 1.9.5 — detector de mídia (abre o painel no renderer)
    detectMedia: () => sendToWin('cmd', 'media'),
    saveLinkwarden: (u) => { saveToLinkwarden(u).catch(() => {}); },
    // 1.9.0 — arquivar página (arquivo único, nativo e privado)
    archivePage: (selectionOnly) => { archiveTab(tabByWebContents(wc) || activeTab(), { selectionOnly: !!selectionOnly }); },
    edit: (name) => { if (typeof wc[name] === 'function') wc[name](); },
    replaceMisspelling: (w) => wc.replaceMisspelling(w),
    canGoBack: () => { try { return nav.canGoBack(); } catch (_) { return false; } },
    canGoForward: () => { try { return nav.canGoForward(); } catch (_) { return false; } },
    back: () => { try { nav.goBack(); } catch (_) {} },
    forward: () => { try { nav.goForward(); } catch (_) {} },
    reload: () => wc.reload(),
    print: () => wc.print(),
    inspect: (x, y) => wc.inspectElement(x, y)
  };
  const tpl = ctxmenu.buildTemplate(params, act);
  Menu.buildFromTemplate(tpl).popup({ window: win });
}

/* ---------------------- downloads (electron-dl) ---------------------- */

function downloadRecords() { return downloadStore.get('items', []); }
function pushDownloads() { sendToWin('downloads:update', downloadRecords()); }
/** CORREÇÃO 1.6.7 (velocidade): o evento 'updated' de download dispara a cada
 * tick de progresso e enviava a LISTA COMPLETA (até 200 registros) por IPC —
 * agora o push em massa é limitado a 1x/250 ms; transições de estado usam o
 * push imediato. */
let dlTimer = null;
function pushDownloadsThrottled() {
  if (dlTimer) return;
  dlTimer = setTimeout(() => { dlTimer = null; pushDownloads(); }, 250);
}
function findRecByPath(p) {
  return downloadRecords().find(r => r.path === p);
}

/* ------------- Security Gateway: varredura de downloads (1.6.0) -------------
 * Fila sequencial no processo principal; scanners externos (ClamAV/YARA)
 * só rodam se existirem na máquina; inspeção de ZIP SEM extrair nada.
 * "Limpo" NUNCA é garantia — mensagem conservadora na interface. */

const QUARANTINE_DIRNAME = 'NanoDesk-Quarantine';

function scanToolPaths() {
  // 1.8.8: prioridade — binário EMBUTIDO (resources/clamav/) primeiro;
  //       depois o ClamAV instalado na máquina (clamdscan/clamscan no PATH).
  const bundled = bundledClamAvPath();
  return {
    clamav: bundled || securityGateway.findClamAV(),
    clamavBundled: bundled,
    yara: securityGateway.findYara()
  };
}

function queueScan(rec) {
  if (!rec || rec.state !== 'completed' || !rec.path) return;
  scanQueue.push(rec.id);
  processScanQueue();
}

/**
 * CORREÇÃO 1.9.6 (ERRO 2) — gate CENTRAL de segurança para TODO engine
 * (aria2/Gopeed incluídos). O DownloadManager chama esta função no finalize de
 * cada download concluído; antes, o fluxo externo terminava num SHA-256 solto
 * e NUNCA passava pelo Security Gateway. Aqui o download externo recebe a
 * MESMA análise do fluxo Electron:
 *   1) revalidação do limite de tamanho (o motor externo pode relatar total
 *      errado ou crescer além do esperado);
 *   2) validação do caminho de destino (anti path traversal — o manager já
 *      valida, esta é a segunda linha);
 *   3) Security Gateway completo via queueScan(): tipo REAL por magic bytes,
 *      inspeção de ZIP sem extrair, scanner nativo (PE/strings/entropia),
 *      ClamAV/YARA se disponíveis, veredito conservador, quarentena,
 *      eventos de segurança e toasts — a MESMA fila do fluxo electron-dl.
 */
/** 1.9.6-b (P4): move o arquivo do rec para a quarentena (Downloads/NanoDesk-
 *  Quarantine). Usado nos caminhos FAIL-CLOSED (gate/scan falharam): o arquivo
 *  fica fora do alcance do "abrir". Retorna o destino ou '' (sem quarentena). */
function moveToQuarantine(rec) {
  try {
    if (!rec || !rec.path || !fs.existsSync(rec.path)) return '';
    const qdir = path.join(app.getPath('downloads'), QUARANTINE_DIRNAME);
    try { fs.mkdirSync(qdir, { recursive: true }); } catch (_) { /* já existe */ }
    const target = dl.uniquePath(qdir, rec.name || 'arquivo', fs.existsSync, reservedDownloadPaths);
    fs.renameSync(rec.path, target);
    rec.quarantine = target;
    pushDownloads();
    return target;
  } catch (_) { return ''; }
}

function managerDownloadGate(rec) {
  try {
    if (!rec || rec.state !== 'completed') return;
    // 1) Limite de tamanho (mesmo teto do fluxo Electron: dl.LIMITS.maxMB)
    if (rec.total && rec.total > dl.LIMITS.maxMB * 1024 * 1024) {
      rec.state = 'error';
      rec.error = 'arquivo excede o limite de ' + dl.LIMITS.maxMB + ' MB — bloqueado pelo Security Gateway';
      pushSecurityEvent({ kind: 'download', host: rec.origin, level: 'aviso',
        detail: rec.name + ' (' + rec.engine + '): ' + rec.error });
      toast(rec.error, 8000);
      pushDownloads();
      return;
    }
    // 2) Caminho de destino dentro da pasta acordada (defesa extra)
    if (rec.path && rec.outDir) {
      try {
        const resolvedPath = path.resolve(rec.path);
        const resolvedDir = path.resolve(rec.outDir);
        if (!resolvedPath.startsWith(resolvedDir + path.sep) && resolvedPath !== resolvedDir) {
          rec.state = 'error';
          rec.error = 'caminho de destino fora da pasta acordada — bloqueado pelo Security Gateway';
          pushSecurityEvent({ kind: 'download', host: rec.origin, level: 'aviso',
            detail: rec.name + ' (' + rec.engine + '): ' + rec.error });
          toast(rec.error, 8000);
          pushDownloads();
          return;
        }
      } catch (_) { /* segue para a varredura normal */ }
    }
    // 3) Security Gateway (mesma fila do fluxo Electron; hash SHA-256 já feito
    //    pelo manager é reutilizado por scanDownloadRecord).
    if (settings.get('downloadScan', true)) queueScan(rec);
  } catch (e) {
    // 1.9.6-b (P4): FAIL-CLOSED — o gate NUNCA deixa o download como
    // concluído quando a própria política de segurança falha.
    console.warn('[nanodesk:downloads] gate de segurança do manager falhou:', e.message);
    try {
      rec.state = 'security_error';
      rec.error = 'Análise de segurança FALHOU — arquivo NÃO liberado. (' + String(e.message || e).slice(0, 120) + ')';
      const q = moveToQuarantine(rec);
      pushSecurityEvent({ kind: 'download', host: rec.origin || 'origem desconhecida', level: 'aviso',
        detail: rec.name + ' (' + rec.engine + '): análise de segurança falhou — não liberado' + (q ? ' (quarentena)' : '') });
      toast('Segurança: análise FALHOU — ' + rec.name + ' NÃO foi liberado' + (q ? ' (em quarentena).' : '.'), 9000);
      pushDownloads();
    } catch (_) { /* melhor esforço */ }
  }
}

function processScanQueue() {
  if (scanRunning || !scanQueue.length) return;
  scanRunning = true;
  (async () => {
    try {
      while (scanQueue.length) {
        const id = scanQueue.shift();
        const rec = downloadRecords().find(r => r.id === id);
        if (!rec || rec.state !== 'completed' || !rec.path || !fs.existsSync(rec.path)) continue;
        try { await scanDownloadRecord(rec); }
        catch (e) {
          // 1.9.6-b (P4): FAIL-CLOSED — erro na análise = arquivo NÃO
          // verificado ⇒ NUNCA permanece 'completed' (sem abrir automaticamente).
          try {
            rec.state = 'security_error';
            rec.error = 'Análise de segurança FALHOU — arquivo NÃO liberado. (' + String(e.message || e).slice(0, 120) + ')';
            const q = moveToQuarantine(rec);
            rec.scan = { status: 'erro', findings: [String(e.message || e).slice(0, 160)], ts: Date.now() };
            pushSecurityEvent({ kind: 'download', host: rec.origin || 'origem desconhecida', level: 'aviso',
              detail: rec.name + ': análise de segurança falhou — não liberado' + (q ? ' (quarentena)' : '') });
            toast('Segurança: análise FALHOU — ' + rec.name + ' NÃO foi liberado' + (q ? ' (em quarentena).' : '.'), 9000);
            pushDownloads();
          } catch (_) { pushDownloads(); }
        }
      }
    } finally { scanRunning = false; }
  })();
}

async function scanDownloadRecord(rec) {
  rec.scan = { status: 'analisando', findings: [], ts: Date.now() };
  pushDownloads();
  const scan = { status: 'ok', findings: [], ts: Date.now() };

  // 1) Tipo REAL por magic bytes — pega executável disfarçado
  const head = Buffer.alloc(4096);
  let fd = null;
  try {
    fd = fs.openSync(rec.path, 'r');
    fs.readSync(fd, head, 0, head.length, 0);
  } catch (_) { /* arquivo sumiu */ }
  finally { if (fd !== null) { try { fs.closeSync(fd); } catch (_) { /* ignorado */ } } }
  const magic = securityGateway.magicType(head);
  scan.magic = magic;

  // 2) Compactados (ZIP/CBZ/EPUB): inspeção SEM extrair.
  //    CORREÇÃO 1.6.7: lia o ARQUIVO INTEIRO (readFileSync, até 2 GB) de forma
  //    síncrona no processo principal — a interface CONGELAVA durante a análise.
  //    Agora lê posicionalmente só o fim do arquivo + central directory.
  if (magic.family === 'zip') {
    try {
      const listed = securityGateway.scanZipFile(rec.path, {}, { maxEntries: 5000 });
      const archive = listed.ok
        ? { risks: securityGateway.archiveRisk(listed.entries || [], rec.total || 0), entries: (listed.entries || []).length }
        : { risks: ['Pacote compactado ilegível/corrompido — inspeção impossível'], entries: 0 };
      scan.archive = archive;
      if (archive.risks.length) scan.findings.push(...archive.risks.slice(0, 5));
    } catch (e) {
      scan.archive = { risks: ['Falha ao ler o pacote: ' + String(e.message || e).slice(0, 80)], entries: 0 };
    }
  }

  // 3) Executável disfarçado (extensão boa, conteúdo PE/ELF)
  if (magic.family === 'pe' || magic.family === 'elf') {
    scan.findings.push('O conteúdo REAL é ' + magic.label + ' (a extensão pode estar enganando)');
  }

  // 3.5) 1.8.8 — SCANNER NATIVO (SHA-256 + PE imports + strings + entropia)
  //   Roda SEMPRE (mesmo sem ClamAV/YARA instalados): 100% local, sem rede.
  //   Hashes: só os da lista fornecida pelo usuário (hashes-malware.txt / NANODESK_HASHLIST); a embutida é vazia.
  try {
    // SHA-256 do arquivo (ou reutiliza o hash que o electron-dl já calculou)
    let sha256 = String(rec.sha256 || '').toLowerCase();
    if (!sha256 || !/^[a-f0-9]{64}$/.test(sha256)) {
      const hash = crypto.createHash('sha256');
      const rf = fs.createReadStream(rec.path, { highWaterMark: 64 * 1024 });
      for await (const chunk of rf) hash.update(chunk);
      sha256 = hash.digest('hex');
      rec.sha256 = sha256;
    }
    // 1.9.2: análise do ARQUIVO (parser PE real + strings no arquivo inteiro), não mais só 4 KB do cabeçalho.
    //        Continua sendo HEURÍSTICA local — não substitui antivírus (ver veredito 'limpo-local').
    const ns = await nativeScanner.scanFile(rec.path, { sha256, magic });
    scan.nativeScanner = {
      level: ns.level,
      findings: ns.findings.slice(0, 6),
      details: ns.details
    };
    if (ns.findings.length) {
      scan.findings.push(...ns.findings.slice(0, 5));
      if (ns.level === 'infectado') {
        pushSecurityEvent({ kind: 'malware', host: rec.origin, level: 'critico',
          detail: rec.name + ': hash SHA-256 está na lista de malware fornecida' });
      }
    }
  } catch (e) {
    scan.nativeScanner = { level: 'limpo', findings: [], error: String(e.message || e).slice(0, 80) };
  }

  // 4) ClamAV — binário EMBUTIDO (resources/clamav/) ou instalado na máquina.
  //    1.8.8: se a base de assinaturas não existir em SESSION_TMP/clamav-db/,
  //    baixa com freshclam.exe embutido (uma vez por sessão; falha de rede =
  //    silenciosa — o scanner nativo continua funcionando).
  const tools = scanToolPaths();
  if (tools.clamav) {
    // garante a base antes de chamar o clamscan (sem base, ele falha)
    let dbReady = false;
    try { dbReady = await ensureClamavDatabase(); } catch (_) { dbReady = false; }
    if (dbReady) {
      const r = await securityGateway.runExternal({
        cmd: tools.clamav,
        args: ['--database=' + clamavDatabaseDir(), '--no-summary', rec.path],
        timeoutMs: 120000
      });
      scan.clamav = { ran: r.ran, clean: r.clean, output: r.output.slice(0, 300), bundled: !!tools.clamavBundled };
      if (r.ran && r.clean === false) {
        const line = r.output.split('\n').find(l => l.includes('FOUND'));
        scan.findings.push('ClamAV: ' + (line || 'ameaça detectada').trim().slice(0, 160));
      }
    } else {
      scan.clamav = { ran: false, available: true, bundled: !!tools.clamavBundled,
        reason: 'ClamAV não executou: ' + clamavSkipMessage(clamavDbSkipReason) + ' O scanner nativo (heurístico) continua ativo.' };
    }
  } else scan.clamav = { ran: false, available: false };

  // 5) YARA — só se binário + regras (NANODESK_YARA_RULES) existirem
  if (tools.yara) {
    const r = await securityGateway.runExternal({ cmd: tools.yara, args: [process.env.NANODESK_YARA_RULES, rec.path], timeoutMs: 90000 });
    scan.yara = { ran: r.ran, clean: r.clean, output: r.output.slice(0, 300) };
    if (r.ran && r.clean === false) {
      scan.findings.push('YARA: regra correspondeu — ' + r.output.split('\n')[0].slice(0, 120));
    }
  } else scan.yara = { ran: false, available: false };

  // 6) Veredito conservador
  const v = securityGateway.verdict(scan);
  scan.verdict = v.level;
  scan.verdictLabel = v.label;
  scan.status = 'pronto';

  // 7) Quarentena (FASE 6).
  //    CORREÇÃO 1.6.7: SÓ a detecção de antivírus REAL (ClamAV) move o arquivo
  //    — antes o nível "suspeito" (heurística: PE disfarçado, .js dentro de ZIP,
  //    razão de compressão) TAMBÉM movia o arquivo do usuário sem ele pedir,
  //    e "o arquivo sumiu" era lido como "o antivírus deletou meu download".
  //    Suspeito/inconclusivo continuam no lugar, com aviso e ação manual.
  if (v.level === 'infectado' && settings.get('quarantineDownloads', true)) {
    try {
      const qdir = path.join(app.getPath('downloads'), QUARANTINE_DIRNAME);
      try { fs.mkdirSync(qdir, { recursive: true }); } catch (_) { /* já existe */ }
      const target = dl.uniquePath(qdir, rec.name || 'arquivo', fs.existsSync, reservedDownloadPaths);
      fs.renameSync(rec.path, target);
      rec.quarantine = target;
      scan.quarantined = true;
      pushSecurityEvent({ kind: 'quarentena', host: rec.origin, level: v.level, detail: rec.name + ' movido para a quarentena' });
    } catch (e) {
      scan.findings.push('Não foi possível mover para a quarentena: ' + String(e.message || e).slice(0, 100));
    }
  }

  rec.scan = scan;
  pushDownloads();
  pushSecurityEvent({
    kind: 'download', host: rec.origin,
    level: v.level === 'limpo-local' || v.level === 'limpo' || v.level === 'inconclusivo' ? 'info' : v.level,
    detail: rec.name + ': ' + v.label + (scan.findings.length ? ' — ' + scan.findings[0] : '')
  });
  if (v.level === 'infectado' || v.level === 'suspeito') {
    toast('ATENÇÃO no download ' + rec.name + ': ' + v.label);
  } else if (v.level === 'inconclusivo') {
    toast('Análise de ' + rec.name + ' inconclusiva (tempo esgotado) — confira a origem do arquivo.');
  } else if (v.level === 'limpo-local' && /\.(exe|msi|dll|scr|bat|cmd|ps1|js|jse|vbs|vbe|wsf|hta|jar|lnk|zip|rar|7z|iso)$/i.test(rec.name || '')) {
    // 1.9.2: nunca deixa o usuário confundir a heurística local com uma varredura antivírus
    toast('SEM varredura antivírus em ' + rec.name + (v.note ? ' — ' + v.note : '') + '. Só houve análise local limitada: NÃO é garantia de que o arquivo é seguro.', 9000);
  }
}

/**
 * Inicializa o electron-dl como gerenciador de downloads.
 * As opções são um objeto compartilhado: mudanças de configuração
 * (ex.: "perguntar onde salvar") valem para os próximos downloads.
 */
async function initDownloads() {
  const mod = await import('electron-dl');
  const electronDl = mod.default;

  // CORREÇÃO 1.5.2: o electron-dl COPIA estas opções ao registrar a sessão —
  // mudar `saveAs` depois (configuração "Perguntar onde salvar") não tinha
  // efeito. O electron-dl sempre prepara o diálogo (saveAs: true) e
  // handleNewDownload() aplica a escolha atual do usuário por download.
  sharedDlOptions = {
    directory: app.getPath('downloads'),
    saveAs: true,
    overwrite: false,
    showProgressBar: true,
    openFolderWhenDone: false,
    errorTitle: 'Falha no download',

    onStarted(item) {
      try { handleNewDownload(item); } catch (error) {
        console.warn('[nanodesk:downloads] onStarted:', error.message);
      }
    },
    onError(error) {
      toast('Falha no download: ' + String(error && error.message ? error.message : error).slice(0, 160));
    }
  };
  electronDl(sharedDlOptions);
}

// caminhos reservados por downloads em andamento (evita dois arquivos com o
// mesmo nome nas gravações simultâneas — o arquivo final só aparece no fim)
const reservedDownloadPaths = new Set();

// URLs de executáveis reemitidas APÓS confirmação do usuário (proteção
// contra laço: a reemissão segue o fluxo normal e consome a flag).
const riskyReissue = new Map(); // url -> ts da reemissão

/** "Perguntar onde salvar" desligado: grava direto na pasta Downloads. */
function applySaveChoice(item) {
  if (settings.get('askWhereToSave', true) === true) return; // diálogo do electron-dl
  try {
    const dir = app.getPath('downloads');
    const target = dl.uniquePath(dir, dl.safeFileName(item.getFilename()), fs.existsSync, reservedDownloadPaths);
    const key = dl.pathKey(target);
    reservedDownloadPaths.add(key);
    item.setSavePath(target); // com caminho definido o Electron não abre o diálogo
    item.once('done', () => reservedDownloadPaths.delete(key));
  } catch (error) {
    console.warn('[nanodesk:downloads] não foi possível definir o destino:', error.message);
  }
}

function handleNewDownload(item) {
  // 1) Limite de downloads simultâneos (proteção contra downloads repetitivos)
  const activeCount = downloadRecords().filter(r => r.state === 'progressing' || r.state === 'confirming').length;
  if (activeCount >= dl.LIMITS.maxConcurrent) {
    item.cancel();
    toast('Limite de ' + dl.LIMITS.maxConcurrent + ' downloads simultâneos atingido. Download cancelado.');
    return;
  }
  // 2) Limite de tamanho (quando o servidor informa)
  const total = item.getTotalBytes();
  if (total > dl.LIMITS.maxMB * 1024 * 1024) {
    item.cancel();
    toast('Download cancelado: arquivo maior que o limite de ' + dl.LIMITS.maxMB + ' MB.');
    return;
  }

  const fileName = item.getFilename();
  const fullUrl = String(item.getURL() || '');

  // 3) Executável/script: NUNCA toca o disco antes da confirmação.
  //    CORREÇÃO 1.5.2: item.pause() não segura arquivos pequenos — o corpo
  //    já pode ter chegado inteiro e o item completa MESMO pausado (o .exe
  //    era salvo antes do usuário responder). Agora o item é CANCELADO na
  //    origem e a URL só é reemitida se o usuário confirmar.
  if (dl.isRiskyFile(fileName) && !riskyReissue.has(fullUrl)) {
    try { item.cancel(); } catch (_) { /* já cancelado/completo */ }
    const origin = hostOf(item.getURLChain()[0] || fullUrl) || 'origem desconhecida';
    const rec = {
      id: nowId(),
      name: fileName,
      path: '',
      url: fullUrl.slice(0, 500),
      origin,
      total,
      received: 0,
      state: 'confirming',
      risky: true,
      sha256: '',
      ts: Date.now()
    };
    const items = downloadRecords();
    items.unshift(rec);
    if (items.length > 200) items.length = 200;
    downloadStore.set('items', items);
    pushDownloads();
    toast('Executável detectado: ' + fileName + ' (de ' + origin + '). Nada foi salvo ainda — confirme para baixar.');
    confirmRiskyDownload(rec, fullUrl);
    return;
  }
  riskyReissue.delete(fullUrl); // reemissão confirmada: segue fluxo normal

  applySaveChoice(item);

  const origin = hostOf(item.getURLChain()[0] || fullUrl) || 'origem desconhecida';

  // 1.9.6-b (P3): ADOÇÃO — se este download foi iniciado pelo gerenciador
  // central (downloadMedia → engine Electron), NÃO criar um segundo registro.
  // O rec "downloading" do manager é ADOTADO aqui: mesmo id, eventos ligados
  // nele, activeDownloadItems com o MESMO id → pause/resume do painel
  // funcionam, o anti-duplicata não trava a URL e o painel mostra um único
  // registro consistente (antes: dois registros, um preso em "downloading").
  let rec = null;
  let adopted = false;
  const pend = (dlManager && typeof dlManager.takePendingElectron === 'function')
    ? dlManager.takePendingElectron(fullUrl) : null;
  if (pend && pend.rec) {
    rec = pend.rec;
    adopted = true;
    rec.awaitingElectron = false;
    rec.state = 'progressing';
    rec.received = 0;
    rec.total = total || rec.total;
    try { rec.path = item.getSavePath() || rec.path || ''; } catch (_) { /* sem caminho ainda */ }
  } else {
    rec = {
      id: nowId(),
      name: fileName,
      path: '',
      url: fullUrl.slice(0, 500),
      origin,
      total,
      received: 0,
      state: 'progressing',
      risky: dl.isRiskyFile(fileName),
      sha256: '',
      ts: Date.now()
    };
  }
  const items = downloadRecords();
  if (adopted) {
    const i = items.findIndex(r => r.id === rec.id);
    if (i >= 0) items[i] = rec; else items.unshift(rec);
  } else {
    items.unshift(rec);
  }
  if (items.length > 200) items.length = 200;
  downloadStore.set('items', items);
  pushDownloads();
  if (!adopted) toast('Baixando: ' + rec.name + ' (de ' + origin + ')');

  activeDownloadItems.set(rec.id, item);

  item.on('updated', (_e, state) => {
    rec.received = item.getReceivedBytes();
    rec.total = item.getTotalBytes() || rec.total;
    if (rec.state !== 'confirming') {
      if (state === 'interrupted') rec.state = 'interrupted';
      else if (rec.state !== 'confirming') rec.state = 'progressing';
      // 4) Limite de tamanho quando o total não é conhecido
      if (rec.received > dl.LIMITS.maxMB * 1024 * 1024) {
        item.cancel();
        toast('Download cancelado: passou do limite de ' + dl.LIMITS.maxMB + ' MB.');
      }
    }
    if (!rec.path) {
      try { rec.path = item.getSavePath() || ''; } catch (_) { /* sem caminho ainda */ }
    }
    pushDownloadsThrottled();   // 1.6.7: lista completa no máximo 1x/250 ms
  });

  item.once('done', (_e, state) => {
    activeDownloadItems.delete(rec.id);
    rec.received = item.getReceivedBytes();
    rec.total = item.getTotalBytes() || rec.received;
    rec.state = state; // completed | cancelled | interrupted
    try { rec.path = item.getSavePath() || rec.path; } catch (_) { /* ignorado */ }
    pushDownloads();
    // 1.9.6-b (P3): solta o anti-duplicata do gerenciador central
    try { if (dlManager && dlManager.clearActiveKey) dlManager.clearActiveKey(rec.id); } catch (_) { /* ignorado */ }
    if (state === 'completed') {
      // 1.9.6-b (P4): 'concluído' só sem análise ativa; com o Security
      // Gateway ligado, a mensagem não afirma segurança antes da política.
      sendToWin('status:toast', { msg: settings.get('downloadScan', true)
        ? 'Download concluído — analisando segurança…'
        : 'Download concluído: ' + rec.name });
      // Verificação de integridade: hash SHA-256 do arquivo salvo.
      dl.sha256File(rec.path).then(hash => {
        rec.sha256 = hash;
        pushDownloads();
      }).catch(() => { /* arquivo pode ter sido movido */ });
      // 1.6.0 FASE 6: Security Gateway — tipo real, ZIP, ClamAV/YARA, quarentena.
      if (settings.get('downloadScan', true)) queueScan(rec);
    } else if (state === 'interrupted') {
      sendToWin('status:toast', { msg: 'Download interrompido: ' + rec.name });
    }
  });
}

/**
 * Confirmação de executável. O item original JÁ FOI CANCELADO (nada tocou
 * o disco); confirmar reemite a URL pelo fluxo normal da sessão anônima.
 */
async function confirmRiskyDownload(rec, fullUrl) {
  let keep = false;
  try {
    const r = await dialog.showMessageBox(win, {
      type: 'warning',
      buttons: ['Cancelar download', 'Baixar mesmo assim'],
      defaultId: 0,
      cancelId: 0,
      message: 'Arquivo potencialmente perigoso',
      detail: rec.name + ' (de ' + rec.origin + ') é um arquivo executável ou de script.\n' +
        'Arquivos assim podem conter malware. Verifique a origem antes de continuar.\n' +
        'Nada foi salvo no disco: o download só começa se você confirmar.'
    });
    keep = r.response === 1;
  } catch (_) { keep = false; }

  if (!downloadRecords().some(r => r.id === rec.id && r.state === 'confirming')) return;
  if (keep) {
    downloadStore.set('items', downloadRecords().filter(r => r.id !== rec.id));
    pushDownloads();
    riskyReissue.set(fullUrl, Date.now());
    setTimeout(() => riskyReissue.delete(fullUrl), 60000); // sem laço nem vazamento
    try { (downloadSessions.get(fullUrl) || navSession).downloadURL(fullUrl); }   // 1.6.1: mesma sessão (Tor/contêiner)
    catch (error) {
      toast('Não foi possível reiniciar o download: ' + String(error.message || error).slice(0, 120));
    }
  } else {
    rec.state = 'cancelled';
    pushDownloads();
  }
}

/* ---------------------- estatísticas ---------------------- */

let statsTimer = null;
function pushStatsThrottled() {
  if (statsTimer) return;
  statsTimer = setTimeout(() => {
    statsTimer = null;
    sendToWin('adblock:stats', aggregatedAdblockStats());
  }, 250);
}

/* 1.5.1 — estatísticas das PROTEÇÕES (pop-ups + redirects) para o painel. */
let protTimer = null;
function pushProtectionStatsThrottled() {
  if (protTimer) return;
  protTimer = setTimeout(() => {
    protTimer = null;
    if (popupGuard && redirectGuard) {
      sendToWin('protection:stats', protectionStatsPayload());
    }
  }, 300);
}
function protectionStatsPayload() {
  return {
    popup: popupGuard.stats(),
    redirect: redirectGuard.stats(),
    native: {
      sbSkips: nativeStats.sbSkips,
      sbSecs: Math.round(nativeStats.sbSecs),
      cmDenies: nativeStats.cmDenies
    }
  };
}

/* Avisos das proteções com dedupe por chave (farms de redirect e
 * pop-unders em série não podem inundar a interface de toasts). */
const guardToastTimes = new Map();
function guardToast(key, msg, ms) {
  const now = Date.now();
  const last = guardToastTimes.get(key) || 0;
  if (now - last < 2500) return;
  if (guardToastTimes.size > 200) guardToastTimes.clear();
  guardToastTimes.set(key, now);
  toast(msg, ms);
}

/**
 * 1.6.0 FASE 6 — diálogo do Security Gateway para URLs suspeitas.
 * A decisão é SEMPRE do usuário; "Confiar" vale só nesta sessão (RAM).
 */
async function confirmUrlGate(wc, url, gate) {
  if (SELFTEST) { try { wc.loadURL(url).catch(() => {}); } catch (_) { /* ignorado */ } return; }
  const r = await dialog.showMessageBox(win, {
    type: 'warning',
    buttons: ['Voltar', 'Navegar mesmo assim', 'Confiar neste site (sessão)'],
    defaultId: 0,
    cancelId: 0,
    noLink: true,
    title: urlgate.headline(gate.level),
    message: urlgate.headline(gate.level) + ': ' + (gate.host || hostOf(url)),
    detail: gate.reasons.slice(0, 6).join('\n') +
      '\n\nAnálise LOCAL (heurística) — pode errar. Destino completo:\n' + String(url).slice(0, 400)
  });
  if (r.response === 2 && gate.host) urlGateTrusted.add(gate.host);
  if (r.response >= 1) {
    try { wc.loadURL(url).catch(() => { /* ignora */ }); } catch (_) { /* ignorado */ }
    pushSecurityEvent({ kind: 'urlgate', host: gate.host, level: gate.level,
      detail: 'liberado pelo usuário: ' + gate.reasons.join('; ') });
  } else {
    pushSecurityEvent({ kind: 'urlgate', host: gate.host, level: gate.level,
      detail: 'navegação cancelada: ' + gate.reasons.join('; ') });
  }
}

/* ---------------------- leitor de notícias (1.4.0) ---------------------- */

function pushReaderUpdate() {
  sendToWin('reader:update', { at: Date.now() });
}

function initReader() {
  readerSvc = reader.createReaderService({
    store: readerStore,
    session: navSession,
    notify: pushReaderUpdate
  });
  // Atualização automática a cada 30 min — em memória, sem notificações
  // agressivas (o painel mostra o resultado quando aberto).
  setInterval(() => {
    if (!win || win.isDestroyed() || !readerSvc) return;
    if (!readerStore.get('items', []).length) return;
    readerSvc.refresh('all').catch(() => {});
  }, 30 * 60 * 1000);
}

function validId(v) {
  const s = String(v == null ? '' : v);
  return /^[a-zA-Z0-9_-]{1,64}$/.test(s) ? s : null;
}

/* ---------------------- janela ---------------------- */

function createWindow() {
  const workArea = screen.getPrimaryDisplay().workArea;
  const minWidth = Math.min(760, workArea.width);
  const minHeight = Math.min(500, workArea.height);
  const windowWidth = Math.max(minWidth, Math.min(1280, workArea.width));
  const windowHeight = Math.max(minHeight, Math.min(820, workArea.height));
  const opt = {
    width: windowWidth,
    height: windowHeight,
    minWidth,
    minHeight,
    frame: false,
    show: !SELFTEST,
    backgroundColor: '#0b0e13',
    icon: path.join(__dirname, '..', '..', 'assets', 'icon.png'),
    title: 'NanoDesk',
    webPreferences: {
      preload: path.join(__dirname, '..', 'preload', 'preload.js'),
      partition: MEM_PARTITION,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,              // REFORÇO 1.3.0: UI também em sandbox
      webviewTag: false,          // REFORÇO 1.3.0: tag <webview> desativada
      spellcheck: false,
      // 1.9.4 — defesa em profundidade da janela de UI (mesma justificativa
      // das abas de navegação): sem drag-drop, sem WebSQL legacy, sem
      // telemetria do Safe Browsing remoto (o NanoDesk tem seu próprio
      // pipeline de reputação via StevenBlack + Security Gateway).
      navigateOnDragDrop: false,
      enableWebSQL: false,
      safeBrowsing: false,
      enablePreferredSizeMode: false
    }
  };

  win = new BrowserWindow(opt);
  applyContentProtection();   // 1.9.1: opt-in (contentProtection)
  loadUserHashList();         // 1.9.2: hashes de malware fornecidos pelo usuário (opcional)

  // A janela de interface não deve navegar para conteúdo externo nem criar
  // janelas nativas. Links externos passam pelo fluxo explícito do app.
  win.webContents.on('will-navigate', (event, url) => {
    try {
      const destination = path.resolve(fileURLToPath(url));
      const renderer = path.resolve(path.join(__dirname, '..', 'renderer', 'index.html'));
      const same = process.platform === 'win32'
        ? destination.toLowerCase() === renderer.toLowerCase()
        : destination === renderer;
      if (!same) event.preventDefault();
    } catch (_) { event.preventDefault(); }
  });
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('did-finish-load', flushPendingToasts);

  win.setMenuBarVisibility(false);
  win.setAutoHideMenuBar(true);
  win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));

  const pushWinState = () => {
    if (win && !win.isDestroyed()) {
      sendToWin('win:state', { maximized: win.isMaximized(), fullscreen: win.isFullScreen() });
    }
  };
  ['maximize', 'unmaximize', 'enter-full-screen', 'leave-full-screen'].forEach(ev => win.on(ev, pushWinState));

  // Redimensionamento: re-aplica o último retângulo conhecido às views
  // (o ResizeObserver do renderer também envia novos limites — esta é a
  // rede de segurança para maximizar/restaurar e mudanças de escala do
  // Windows, o antigo problema de "tela cortada").
  let resizeTimer = null;
  win.on('resize', () => {
    if (resizeTimer) clearTimeout(resizeTimer);
    resizeTimer = setTimeout(reapplyBounds, 120);
  });
  win.on('closed', () => { win = null; });
}

/* ---------------------- menu / aceleradores ---------------------- */

function buildMenu() {
  const cmd = (c) => () => sendToWin('cmd', c);
  const tpl = [
    {
      label: 'NanoDesk',
      submenu: [
        { label: 'Nova aba', accelerator: 'CmdOrCtrl+T', click: cmd('new-tab') },
        { label: 'Fechar aba', accelerator: 'CmdOrCtrl+W', click: cmd('close-tab') },
        { label: 'Favoritar esta aba (só na sessão)', accelerator: 'CmdOrCtrl+D', click: cmd('favorite') },
        { type: 'separator' },
        { label: 'Sair do NanoDesk', accelerator: 'CmdOrCtrl+Q', role: 'quit' }
      ]
    },
    {
      label: 'Navegação',
      submenu: [
        { label: 'Recarregar página', accelerator: 'CmdOrCtrl+R', click: cmd('reload') },
        { label: 'Voltar', accelerator: 'Alt+Left', click: cmd('back') },
        { label: 'Avançar', accelerator: 'Alt+Right', click: cmd('forward') },
        { label: 'Página inicial', accelerator: 'Alt+Home', click: cmd('home') },
        { label: 'Barra de endereço', accelerator: 'CmdOrCtrl+L', click: cmd('focus-address') },
        { label: 'Abrir no navegador padrão', accelerator: 'CmdOrCtrl+Shift+O', click: cmd('open-external') },
        { type: 'separator' },
        { label: 'Buscar na página', accelerator: 'CmdOrCtrl+F', click: cmd('find') },
        { label: 'Próximo resultado', accelerator: 'F3', click: cmd('find-next') },
        { label: 'Resultado anterior', accelerator: 'Shift+F3', click: cmd('find-prev') },
        { type: 'separator' },
        { label: 'Aumentar zoom', accelerator: 'CmdOrCtrl+=', click: cmd('zoom-in') },
        { label: 'Diminuir zoom', accelerator: 'CmdOrCtrl+-', click: cmd('zoom-out') },
        { label: 'Zoom padrão', accelerator: 'CmdOrCtrl+0', click: cmd('zoom-reset') },
        { label: 'Tela cheia', accelerator: 'F11', role: 'togglefullscreen' },
        { type: 'separator' },
        { label: 'Próxima aba', accelerator: 'CmdOrCtrl+Tab', click: cmd('next-tab') },
        { label: 'Aba anterior', accelerator: 'CmdOrCtrl+Shift+Tab', click: cmd('prev-tab') }
      ]
    },
    {
      label: 'Ferramentas',
      submenu: [
        { label: 'Abrir arquivo (PDF/ebook)…', accelerator: 'CmdOrCtrl+O', click: cmd('open-file') },
        { type: 'separator' },
        { label: 'Proteções (pop-ups e redirecionamentos)', accelerator: 'CmdOrCtrl+Shift+P', click: cmd('protection') },
        { label: 'Conexão Tor (nativo)', accelerator: 'CmdOrCtrl+Shift+T', click: cmd('tor') },
        { label: 'Diagnóstico de compatibilidade (copiar)', click: () => { runCompatDiagnostic().catch(() => toast('Não foi possível gerar o diagnóstico.')); } },
        { label: 'Segurança (URLs, downloads e eventos)', accelerator: 'CmdOrCtrl+Shift+S', click: cmd('security') },
        { label: 'Rede (VPN, Tor, DNS e IP)', accelerator: 'CmdOrCtrl+Shift+N', click: cmd('network') },
        { label: 'Histórico da sessão', accelerator: 'CmdOrCtrl+H', click: cmd('history') },
        { type: 'separator' },
        { label: 'Traduzir página (LibreTranslate)…', click: cmd('translate-page') },
        { label: 'Traduzir área de transferência', click: cmd('translate-clipboard') },
        { label: 'Salvar página no Linkwarden', click: cmd('linkwarden-save') },
        { label: 'Cofre de senhas — preencher login deste site', accelerator: 'CmdOrCtrl+Shift+K', click: cmd('bitwarden-fill') },
        { label: 'Cofre de senhas — abrir painel…', accelerator: 'CmdOrCtrl+Shift+Y', click: cmd('vault-panel') },
        { label: 'Baixar vídeo com yt-dlp…', click: cmd('video-download') },
        { type: 'separator' },
        { label: 'Downloads', accelerator: 'CmdOrCtrl+J', click: cmd('downloads') },
        { label: 'Detectar mídia nesta página', accelerator: 'CmdOrCtrl+Shift+M', click: cmd('media') },
        { label: 'Leitor de notícias', accelerator: 'CmdOrCtrl+Shift+L', click: cmd('reader') },
        { label: 'Modo leitura (artigo limpo)', accelerator: 'F9', click: cmd('reader-mode') },
        { label: 'Arquivar página (arquivo único)…', accelerator: 'CmdOrCtrl+Alt+S', click: () => { archiveTab(activeTab(), {}); } },
        { label: 'Arquivar todas as abas…', click: () => { archiveAllTabs().catch(() => {}); } },
        { label: 'Verificar arquivo salvo…', click: () => { archiveVerifyDialog().catch(() => {}); } },
        { type: 'separator' },
        { label: 'Imprimir…', accelerator: 'CmdOrCtrl+P', click: cmd('print') },
        { label: 'DevTools da aba', accelerator: 'F12', click: cmd('devtools') },
        { label: 'Verificar atualizações…', click: cmd('updates') },
        { label: 'Atualizar listas de filtros (manual)', click: cmd('filters-refresh') },
        { label: 'Sobre o NanoDesk', click: cmd('about') }
      ]
    }
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(tpl));
}

/** 1.9.2 — lista OPCIONAL de hashes SHA-256 de malware fornecida por você (um por linha, # comentário). */
function loadUserHashList() {
  try {
    const candidates = [process.env.NANODESK_HASHLIST, path.join(app.getPath('userData'), 'hashes-malware.txt')].filter(Boolean);
    for (const f of candidates) {
      if (!fs.existsSync(f) || fs.statSync(f).size > 32 * 1024 * 1024) continue;
      nativeScanner.loadHashList(fs.readFileSync(f, 'utf8'));
    }
  } catch (_) { /* opcional: nunca bloqueia o arranque */ }
}

/* ---------------------- Área de transferência: senhas (1.9.1) ---------------------- */

let clipClearTimer = null;
let lastCopiedSecret = '';
/**
 * Copia um segredo e agenda a limpeza em 20 s — SÓ se a área de transferência ainda contiver
 * exatamente esse segredo (antes: limpava incondicionalmente, apagando o que você copiou depois,
 * e dependia da janela de UI). Também limpa ao fechar o NanoDesk.
 */
function copySecret(text) {
  const t = String(text || '').slice(0, 1024);
  if (!t) return false;
  clipboard.writeText(t);
  lastCopiedSecret = t;
  if (clipClearTimer) clearTimeout(clipClearTimer);
  clipClearTimer = setTimeout(clearCopiedSecret, 20000);
  return true;
}
function clearCopiedSecret() {
  if (clipClearTimer) { clearTimeout(clipClearTimer); clipClearTimer = null; }
  const t = lastCopiedSecret;
  lastCopiedSecret = '';
  if (!t) return;
  try { if (clipboard.readText() === t) clipboard.clear(); } catch (_) { /* ignorado */ }
}

/** Proteção de captura de tela/gravação da janela (SetWindowDisplayAffinity no Windows). */
function applyContentProtection() {
  try { if (win && !win.isDestroyed()) win.setContentProtection(!!settings.get('contentProtection', false)); } catch (_) { /* ignorado */ }
}

/* ---------------------- Arquivar página (1.9.0) ---------------------- */

const archiveBusy = new Set();

/** webFrameMain → adaptador independente de Electron (ver archive.js). */
function archiveFrameAdapter(f) {
  return {
    url: f.url,
    exec: (code) => f.executeJavaScript(code, false),
    children: (f.frames || []).map(archiveFrameAdapter)
  };
}

function archiveOptions(extra) {
  return Object.assign({
    blockNetwork: settings.get('archiveBlockNetwork', true),
    removeHidden: settings.get('archiveRemoveHidden', false),
    removeUnusedStyles: settings.get('archiveRemoveUnused', true),
    removeUnusedFonts: settings.get('archiveRemoveUnused', true),
    loadLazy: settings.get('archiveLoadLazy', true),
    skipTrackers: settings.get('archiveSkipTrackers', true),
    keepFormValues: settings.get('archiveKeepForm', true)
  }, extra || {});
}

function waitTabLoaded(wc, ms) {
  return new Promise((resolve) => {
    if (!wc.isLoading()) return resolve();
    const t = setTimeout(done, ms);
    function done() { clearTimeout(t); try { wc.removeListener('did-stop-loading', done); } catch (_) { /* ignorado */ } resolve(); }
    wc.once('did-stop-loading', done);
  });
}

/** Redução opcional de imagens grandes (só usada se archiveMaxImageEdge > 0). */
async function archiveTransformImage(buf, mime, o) {
  const img = nativeImage.createFromBuffer(buf);
  if (img.isEmpty()) return null;
  const { width, height } = img.getSize();
  const edge = Math.max(width, height);
  if (!o.maxEdge || edge <= o.maxEdge) return null;
  const k = o.maxEdge / edge;
  const small = img.resize({ width: Math.max(1, Math.round(width * k)), height: Math.max(1, Math.round(height * k)), quality: 'good' });
  if (mime === 'image/jpeg') return { buf: small.toJPEG(82), mime };
  if (mime === 'image/png') return { buf: small.toPNG(), mime };
  return null;
}

/**
 * Captura UMA aba e devolve o resultado do arquivador (sem gravar). Os recursos são buscados
 * pela SESSÃO DA ABA — cookies/contêiner/Tor/DoH da própria aba, nada sai por outro caminho.
 */
async function archiveCapture(t, extraOpts) {
  const wc = t.view.webContents;
  await waitTabLoaded(wc, 15000);
  const ses = sessionForTab(t);
  const run = archiveMod.archivePage({
    rootFrame: archiveFrameAdapter(wc.mainFrame),
    fetch: (url, referrer) => ses.fetch(url, { credentials: 'include', redirect: 'follow', referrer: referrer || t.url, bypassCustomProtocolHandlers: true }),
    shouldBlock: (u) => !!adblock.matchUrl(u, { hostSet: hostsDomainSet }),
    transformImage: archiveTransformImage
  }, archiveOptions(extraOpts));
  return Promise.race([
    run,
    new Promise((_, rej) => setTimeout(() => rej(new Error('Tempo esgotado (3 min) ao arquivar esta página.')), 180000))
  ]);
}

function archiveDefaultDir() {
  return path.join(app.getPath('downloads'), 'Páginas salvas');
}

async function archiveWriteFile(target, html) {
  const tmp = target + '.part';
  await fs.promises.writeFile(tmp, html, 'utf8');
  await fs.promises.rename(tmp, target);
}

/** Arquiva a aba (ou só a seleção) e grava um .html. */
async function archiveTab(t, opts) {
  const o = opts || {};
  if (!t || t.kind || !t.view || !isHttpUrl(t.url)) { toast('Abra uma página (http/https) para arquivar.'); return null; }
  if (archiveBusy.has(t.id)) { toast('Esta aba já está sendo arquivada.'); return null; }
  archiveBusy.add(t.id);
  try {
    // destino ANTES de capturar: se você cancelar, nada é baixado
    const guess = archiveUtil.buildFileName(null, { title: t.title, url: t.url }) + '.html';
    let target;
    if (settings.get('archiveAskWhere', true)) {
      const dir = archiveDefaultDir();
      try { fs.mkdirSync(dir, { recursive: true }); } catch (_) { /* ignorado */ }
      const r = await dialog.showSaveDialog(win, {
        title: o.selectionOnly ? 'Salvar seleção (arquivo único)' : 'Salvar página (arquivo único)',
        defaultPath: path.join(dir, guess),
        filters: [{ name: 'Página HTML', extensions: ['html'] }]
      });
      if (r.canceled || !r.filePath) return null;
      target = /\.html?$/i.test(r.filePath) ? r.filePath : r.filePath + '.html';
    }
    toast('Arquivando ' + (hostOf(t.url) || 'a página') + '…', 5000);
    const res = await archiveCapture(t, { selectionOnly: !!o.selectionOnly, fileTemplate: undefined });
    if (!target) {
      const dir = archiveDefaultDir();
      fs.mkdirSync(dir, { recursive: true });
      target = dl.uniquePath(dir, res.fileBase + '.html', fs.existsSync, reservedDownloadPaths);
    }
    await archiveWriteFile(target, res.html);
    const st = res.stats;
    const mb = (st.bytesOut / (1024 * 1024)).toFixed(st.bytesOut > 1024 * 1024 ? 1 : 2);
    toast('Página salva: ' + path.basename(target) + ' — ' + mb + ' MB · ' + st.fetched + ' recursos' +
      (st.blocked ? ' · ' + st.blocked + ' rastreador(es) ignorado(s)' : '') +
      (st.failed ? ' · ' + st.failed + ' falha(s)' : ''), 9000);
    try { shell.showItemInFolder(target); } catch (_) { /* ignorado */ }
    return { path: target, stats: st };
  } catch (e) {
    toast('Não foi possível arquivar: ' + (e && e.message ? e.message : 'erro desconhecido'), 8000);
    return null;
  } finally {
    archiveBusy.delete(t.id);
  }
}

/** Arquiva todas as abas http/https abertas numa pasta (uma por vez, para não sobrecarregar). */
async function archiveAllTabs() {
  const tabs = tabList.filter(x => x && !x.kind && x.view && isHttpUrl(x.url));
  if (!tabs.length) { toast('Nenhuma aba http/https para arquivar.'); return { saved: 0 }; }
  let dir = archiveDefaultDir();
  if (settings.get('archiveAskWhere', true)) {
    const r = await dialog.showOpenDialog(win, { title: 'Pasta para salvar ' + tabs.length + ' página(s)', defaultPath: dir, properties: ['openDirectory', 'createDirectory'] });
    if (r.canceled || !r.filePaths[0]) return { saved: 0 };
    dir = r.filePaths[0];
  }
  fs.mkdirSync(dir, { recursive: true });
  let saved = 0; let failed = 0;
  for (const t of tabs) {
    if (archiveBusy.has(t.id)) continue;
    archiveBusy.add(t.id);
    try {
      toast('Arquivando ' + (saved + failed + 1) + '/' + tabs.length + ': ' + (hostOf(t.url) || ''), 4000);
      const res = await archiveCapture(t, {});
      const target = dl.uniquePath(dir, res.fileBase + '.html', fs.existsSync, reservedDownloadPaths);
      await archiveWriteFile(target, res.html);
      saved += 1;
    } catch (_) { failed += 1; } finally { archiveBusy.delete(t.id); }
  }
  toast('Arquivamento concluído: ' + saved + ' salva(s)' + (failed ? ', ' + failed + ' falha(s)' : '') + '.', 8000);
  try { shell.openPath(dir); } catch (_) { /* ignorado */ }
  return { saved, failed };
}

/** Confere o selo SHA-256 de um arquivo salvo pelo NanoDesk. */
async function archiveVerifyDialog() {
  const r = await dialog.showOpenDialog(win, { title: 'Verificar arquivo salvo pelo NanoDesk', defaultPath: archiveDefaultDir(), properties: ['openFile'], filters: [{ name: 'Página HTML', extensions: ['html', 'htm'] }] });
  if (r.canceled || !r.filePaths[0]) return null;
  const st = await fs.promises.stat(r.filePaths[0]);
  if (st.size > 600 * 1024 * 1024) { toast('Arquivo grande demais para verificar.'); return null; }
  const html = await fs.promises.readFile(r.filePaths[0], 'utf8');
  const v = archiveUtil.verifyArchive(html);
  await dialog.showMessageBox(win, {
    type: v.ok ? 'info' : 'warning', buttons: ['OK'], noLink: true,
    title: 'Verificação do arquivo',
    message: v.ok ? 'Arquivo íntegro: o conteúdo não foi alterado desde que foi salvo.' : 'Não foi possível confirmar a integridade.',
    detail: v.ok ? 'Origem: ' + v.url + '\nSalvo em: ' + v.savedAt + '\nSHA-256: ' + v.hash
      : v.reason + '\n\nObservação: o selo prova que o arquivo não mudou depois de salvo; não prova a data nem a autenticidade do site de origem.'
  });
  return v;
}

/* ---------------------- IPC ---------------------- */

function registerIpc() {
  const invoke = (channel, fn) => ipcMain.handle(channel, (event, ...args) => {
    if (!isTrustedIpc(event)) throw new Error('Solicitação IPC de origem não confiável.');
    return fn(...args);
  });

  // Controles de janela (barra de título própria)
  invoke('win:minimize', () => win && win.minimize());
  invoke('win:maximize', () => { if (!win) return; if (win.isMaximized()) win.unmaximize(); else win.maximize(); });
  invoke('win:close', () => win && win.close());
  invoke('win:titlebar-dblclick', () => { if (!win) return; if (win.isMaximized()) win.unmaximize(); else win.maximize(); });

  // ---- Abas (WebContentsView no processo principal) ----
  invoke('tabs:list', () => tabList.map(serializeTab));
  invoke('tabs:create', (url, opts) => {
    if (url != null) {
      if (!isNavigable(url)) throw new Error('Endereço inválido ou esquema não permitido.');
    }
    const sid = (opts && typeof opts === 'object' && typeof opts.sessionId === 'string') ? opts.sessionId : undefined;
    const t = createTab(url || null, { sessionId: sid });
    return { id: t.id };
  });
  invoke('tabs:activate', (id) => activateTab(Number(id)) || true);
  invoke('tabs:close', (id) => closeTab(Number(id)) || true);
  invoke('tabs:navigate', (id, url) => {
    const t = tabList.find(x => x.id === Number(id));
    if (!t) throw new Error('Aba inexistente.');
    if (!isNavigable(url)) throw new Error('Endereço inválido (use http/https).');
    const target = navigateRecord(t, String(url));
    activateTab(target ? target.id : t.id);
    return true;
  });
  invoke('tabs:back', (id) => {
    const t = tabList.find(x => x.id === Number(id));
    if (t && t.view) { try { t.view.webContents.navigationHistory.goBack(); } catch (_) {} }
    return true;
  });
  invoke('tabs:forward', (id) => {
    const t = tabList.find(x => x.id === Number(id));
    if (t && t.view) { try { t.view.webContents.navigationHistory.goForward(); } catch (_) {} }
    return true;
  });
  invoke('tabs:reload', (id) => {
    const t = tabList.find(x => x.id === Number(id));
    if (!t) return true;
    if (t.view && t.errCode && !t.kind && isNavigable(t.url)) {
      // CORREÇÃO 1.5.2: a aba mostra a página de erro interna (data:) —
      // reload() recarregaria o próprio erro. Tenta de novo o endereço real.
      t.errCode = null;
      t.loading = true;
      try { t.view.webContents.loadURL(t.url).catch(() => { /* did-fail-load trata */ }); } catch (_) {}
      pushState();
    }
    else if (t.view) { try { t.view.webContents.reload(); } catch (_) {} }
    else if (t.kind && t.readerSrc) {
      // aba-leitor sem view: recria a página do leitor (não gera nova aba)
      t.state = 'loading';
      t.loading = true;
      if (t.active) ensureReaderView(t);
      pushState();
    }
    else if (t.url) { navigateRecord(t, t.url); activateTab(t.id); }
    return true;
  });
  invoke('tabs:stop', (id) => {
    const t = tabList.find(x => x.id === Number(id));
    if (t && t.view) { try { t.view.webContents.stop(); } catch (_) {} }
    return true;
  });
  invoke('tabs:zoom', (id, factor) => {
    const t = tabList.find(x => x.id === Number(id));
    const f = Number(factor);
    if (!t || !Number.isFinite(f)) return t ? t.zoom : 1;
    t.zoom = Math.min(2, Math.max(0.5, f));
    if (t.view) { try { t.view.webContents.setZoomFactor(t.zoom); } catch (_) {} }
    return t.zoom;
  });
  invoke('tabs:hibernate', (id) => {
    const t = tabList.find(x => x.id === Number(id));
    if (t && t.view && !t.active) hibernateTab(t);
    return true;
  });
  invoke('tabs:find', (id, text, opts) => {
    const t = tabList.find(x => x.id === Number(id));
    const txt = String(text || '');
    if (!t || !t.view || !txt) return false;
    try {
      t.view.webContents.findInPage(txt, {
        forward: !opts || opts.forward !== false,
        findNext: !!(opts && opts.findNext),
        matchCase: !!(opts && opts.matchCase)
      });
      return true;
    } catch (_) { return false; }
  });
  invoke('tabs:find-stop', (id) => {
    const t = tabList.find(x => x.id === Number(id));
    if (t && t.view) { try { t.view.webContents.stopFindInPage('clearSelection'); } catch (_) {} }
    return true;
  });
  invoke('tabs:devtools', (id) => {
    const t = tabList.find(x => x.id === Number(id));
    if (t && t.view) { try { t.view.webContents.openDevTools(); } catch (_) {} }
    return true;
  });
  invoke('tabs:print', (id) => {
    const t = tabList.find(x => x.id === Number(id));
    if (t && t.view) { try { t.view.webContents.print(); } catch (_) {} }
    return true;
  });
  invoke('tabs:bounds', (rect) => {
    if (!rect || typeof rect !== 'object') return true;
    const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
    lastBounds = {
      x: num(rect.x), y: num(rect.y),
      width: num(rect.width), height: num(rect.height)
    };
    if (boundsTimer) { clearTimeout(boundsTimer); boundsTimer = null; }
    reapplyBounds();
    return true;
  });

  // Menu de contexto das abas — NATIVO (1.4.0): menus HTML ficam escondidos
  // atrás da WebContentsView quando um site está aberto; Menu.popup nunca.
  invoke('tabs:ctxmenu', async (id) => {
    const t = tabList.find(x => x.id === Number(id));
    if (!t) return true;
    const isNtp = !t.view && t.state === 'ntp';
    const items = [
      { label: 'Recarregar', enabled: !!t.url, click: () => {
          if (t.view) { try { t.view.webContents.reload(); } catch (_) {} }
          else if (t.url) { navigateRecord(t, t.url); activateTab(t.id); }
        } },
      { label: 'Duplicar aba', enabled: !!t.url, click: () => { if (t.url) createTab(t.url, inheritOpts(t)); } },
      { label: 'Abrir no navegador padrão', enabled: !!t.url && isNavigable(t.url),
        click: () => { if (isNavigable(t.url)) shell.openExternal(t.url).catch(() => {}); } },
      { type: 'separator' },
      { label: 'Suspender aba (liberar memória)', enabled: !isNtp && !t.active,
        click: () => { if (!t.active) hibernateTab(t); } },
      { type: 'separator' },
      // 1.6.0 — sessões isoladas (contêineres)
      { label: t.tor ? 'Nova aba Tor' : 'Nova aba nesta sessão', enabled: !t.tor || !!(torMgr && torMgr.phase === 'connected'), click: () => createTab(null, inheritOpts(t)) },
      { label: 'Mover para sessão…', submenu: containers.map(c => ({
          label: c.name + (c.id === (t.sessionId || 'padrao') ? ' (atual)' : ''),
          enabled: c.id !== (t.sessionId || 'padrao') && !t.kind && !t.tor,   // 1.6.1: aba Tor não muda de sessão
          click: () => {
            try {
              t.sessionId = c.id;
              t.httpsFallback = null;
              if (t.view) {
                destroyView(t);
                t.state = 'loading';
                t.loading = true;
                if (t.active) ensureView(t);
              }
              pushState();
            } catch (_) { /* ignorado */ }
          }
        })) },
      { type: 'separator' },
      { label: 'Fechar aba', click: () => closeTab(t.id) },
      { label: 'Fechar as outras', enabled: tabList.length > 1,
        click: () => { for (const other of tabList.slice()) { if (other.id !== t.id) closeTab(other.id); } } }
    ];
    try { await Menu.buildFromTemplate(items).popup({ window: win }); }
    catch (_) { /* janela pode ter fechado */ }
    return true;
  });

  // Configurações (RAM; perfil local opcional persiste se o usuário ligar)
  invoke('settings:get', () => settings.data);
  invoke('settings:set', (key, value) => {
    if (!SETTING_KEYS.includes(key)) throw new Error('Configuracao desconhecida: ' + key);
    const safeValue = validateSetting(key, value);
    const prevPersist = settings.get('persistentData', false);
    settings.set(key, safeValue);
    if (key === 'contentProtection') applyContentProtection();
    // 1.8.11: modo efêmero do cofre — recusa a troca se já houver cofre no outro modo
    if (key === 'vaultEphemeral') {
      let r = { ok: false, reason: 'Cofre indisponível.' };
      try { r = bitwarden.setEphemeral(safeValue); } catch (_) { /* ignorado */ }
      if (!r.ok) { settings.set('vaultEphemeral', !safeValue); toast(r.reason, 8000); }
      sendToWin('vault:state', bitwarden.status());
    }
    if (key === 'adblockEnabled') { for (const e of allEngines()) e.setEnabled(safeValue); }
    if (key === 'popupBlockerEnabled' && popupGuard) popupGuard.setEnabled(safeValue);
    if (key === 'redirectGuardEnabled' && redirectGuard) redirectGuard.setEnabled(safeValue);
    // askWhereToSave é lida a cada download (applySaveChoice) — nada a propagar aqui.
    // ---- 1.6.0 ----
    if (key === 'torMode' || key === 'torPort') {
      for (const p of engines.keys()) {
        try { applyTorProxy(session.fromPartition(p)); } catch (_) { /* ignora */ }
      }
      pushNetworkState();
      if (key === 'torMode') {
        // 1.8.8: ligar torMode arranca o daemon Tor EMBUTIDO sozinho (antes
        //   só mudava o proxy — sem daemon, todas as abas caíam).
        if (safeValue) {
          toast('Tor SOCKS ativo (127.0.0.1:' + settings.get('torPort', 9050) + '). Arrancando o daemon embutido…', 6000);
          ensureEmbeddedTorForMode().then((ok) => {
            if (ok) toast('Tor conectado — use Conexão Tor (Ctrl+Shift+T) para o painel.', 7000);
            else toast('Tor: não foi possível arrancar o daemon embutido. Conecte em Conexão Tor (Ctrl+Shift+T).', 8000);
          }).catch(() => { /* já avisado */ });
        } else {
          try { if (torMgr && torMgr.phase !== 'off') torMgr.stop().catch(() => {}); } catch (_) {}
          toast('Proxy Tor desligado.', 6000);
        }
      }
    }
    if (key === 'webrtcProtect') {
      for (const tab of tabList) if (tab.view) applyWebRtcPolicy(tab.view.webContents, tab);
      pushNetworkState();
    }
    if (key === 'persistentData' && profile) {
      if (safeValue && !prevPersist) {
        profile.setEnabled(true);
        persistProfile();
        toast('Perfil local LIGADO: configurações e favoritos serão mantidos entre sessões. Histórico e cookies continuam só na RAM.', 9000);
      } else if (!safeValue && prevPersist) {
        profile.setEnabled(false);
        toast('Perfil local DESLIGADO: dados guardados foram apagados.', 6000);
      }
    }
    persistProfile();
    if (key === 'secureDns' || key === 'secureDnsCustom' || key === 'secureDnsStrict') {
      applyDohRuntime();
      toast('DNS seguro aplicado' + (settings.get('secureDns', 'cloudflare') === 'off' ? ' (desligado).' : '.'), 5000);
    }
    // 1.8.9 — cofre de senhas nativo
    if (key === 'vaultEnabled') {
      try { bitwarden.setEnabled(safeValue); } catch (_) { /* ignorado */ }
      sendToWin('vault:state', bitwarden.status());
    }
    if (key === 'vaultAutolockMinutes') {
      try { bitwarden.setAutolockMinutes(safeValue); } catch (_) { /* ignorado */ }
      sendToWin('vault:state', bitwarden.status());
    }
    return settings.data;
  });

  // Favoritos da sessão (RAM; persistem só com o perfil local ligado)
  invoke('favorites:list', () => favorites.get('items', []));
  invoke('favorites:add', (title, url) => {
    if (!isNavigable(url)) return favorites.get('items', []);
    const items = favorites.get('items', []);
    if (!items.some(i => i.url === url) && items.length < 500) {
      items.unshift({ id: nowId(), url, title: safeTitle(title, url), ts: Date.now(), folder: '', tags: [] });
      favorites.set('items', items);
      persistProfile();
    }
    return items;
  });
  invoke('favorites:remove', (url) => {
    favorites.set('items', favorites.get('items', []).filter(i => i.url !== url));
    persistProfile();
    return favorites.get('items', []);
  });
  invoke('favorites:clear', () => { favorites.set('items', []); persistProfile(); return true; });
  invoke('favorites:toggle', (title, url) => {
    let items = favorites.get('items', []);
    if (!isNavigable(url)) return { items, added: false };
    const added = !items.some(i => i.url === url);
    if (added) {
      if (items.length < 500) {
        items.unshift({ id: nowId(), url, title: safeTitle(title, url), ts: Date.now(), folder: '', tags: [] });
        favorites.set('items', items);
      }
    } else {
      items = items.filter(i => i.url !== url);
      favorites.set('items', items);
    }
    persistProfile();
    return { items, added };
  });
  // 1.6.0 — pastas/etiquetas dos favoritos + import/export (arquivo escolhido)
  invoke('favorites:set', (id, patch) => {
    const items = favorites.get('items', []);
    const it = items.find(x => x.id === id);
    if (!it) throw new Error('Favorito inexistente.');
    if (patch && typeof patch === 'object') {
      if (typeof patch.folder === 'string') it.folder = patch.folder.trim().slice(0, 60);
      if (Array.isArray(patch.tags)) {
        it.tags = patch.tags.map(t => String(t).trim().slice(0, 24)).filter(Boolean).slice(0, 8);
      }
    }
    favorites.set('items', items);
    persistProfile();
    return items;
  });
  invoke('favorites:export', async () => {
    const r = await dialog.showSaveDialog(win, {
      title: 'Exportar favoritos (JSON)',
      defaultPath: 'nanodesk-favoritos.json',
      filters: [{ name: 'JSON', extensions: ['json'] }]
    });
    if (r.canceled || !r.filePath) return { ok: false, canceled: true };
    await fs.promises.writeFile(r.filePath, JSON.stringify(favorites.get('items', []), null, 1), 'utf8');
    return { ok: true, path: r.filePath };
  });
  invoke('favorites:import', async () => {
    const r = await dialog.showOpenDialog(win, {
      title: 'Importar favoritos (JSON)',
      properties: ['openFile'],
      filters: [{ name: 'JSON', extensions: ['json'] }]
    });
    if (r.canceled || !r.filePaths || !r.filePaths[0]) return { ok: false, canceled: true };
    const stat = await fs.promises.stat(r.filePaths[0]);
    if (!stat.isFile() || stat.size > 4 * 1024 * 1024) throw new Error('Arquivo inválido ou grande demais.');
    const arr = JSON.parse(await fs.promises.readFile(r.filePaths[0], 'utf8'));
    if (!Array.isArray(arr)) throw new Error('Formato inválido (esperado: lista JSON).');
    const items = favorites.get('items', []);
    let added = 0;
    for (const it of arr.slice(0, 500)) {
      if (!it || typeof it.url !== 'string' || !isHttpUrl(it.url)) continue;
      if (items.some(x => x.url === it.url)) continue;
      items.push({
        id: nowId(), url: it.url, title: safeTitle(it.title, it.url),
        ts: Number(it.ts) || Date.now(),
        folder: typeof it.folder === 'string' ? it.folder.slice(0, 60) : '',
        tags: Array.isArray(it.tags) ? it.tags.map(t => String(t).slice(0, 24)).slice(0, 8) : []
      });
      added++;
    }
    favorites.set('items', items);
    persistProfile();
    return { ok: true, added };
  });

  // Bloqueador de anúncios (agregado: padrão + contêineres 1.6.0)
  invoke('adblock:stats', () => aggregatedAdblockStats());
  invoke('adblock:recent', () => {
    const merged = allEngines().flatMap(e => e.recent()).sort((a, b) => b.ts - a.ts);
    return merged.slice(0, 40);
  });
  invoke('adblock:setEnabled', (v) => {
    if (typeof v !== 'boolean') throw new TypeError('O bloqueador precisa receber um valor booleano.');
    for (const e of allEngines()) e.setEnabled(v);
    settings.set('adblockEnabled', v);
    persistProfile();
    return aggregatedAdblockStats();
  });
  invoke('adblock:allow', (host) => {
    for (const e of allEngines()) e.allow(host);
    const list = engine ? engine.allowlist() : [];
    allowStore.set('items', list);
    return list;
  });
  invoke('adblock:disallow', (host) => {
    for (const e of allEngines()) e.disallow(host);
    const list = engine ? engine.allowlist() : [];
    allowStore.set('items', list);
    return list;
  });
  invoke('adblock:allowlist', () => engine ? engine.allowlist() : []);
  invoke('adblock:hosts-status', () => ({
    count: hostsDomains ? hostsDomains.length : 0,
    blocked: aggregatedAdblockStats().hosts || 0,
    source: hostsEngine.STEVENBLACK_URL,
    license: hostsEngine.STEVENBLACK_LICENSE,
    status: hostsDomains ? 'ativo' : 'indisponivel'
  }));

  // Proteções (1.5.1 — Popup-Blocker-Pro + RedirectGuard)
  invoke('protection:stats', () => {
    if (!popupGuard || !redirectGuard) {
      return { popup: { enabled: false, total: 0, tab: 0 }, redirect: { enabled: false, total: 0, domain: 0, chain: 0, clickTraps: 0 } };
    }
    return protectionStatsPayload();
  });
  invoke('protection:recent', () => ({
    popup: popupGuard ? popupGuard.recent() : [],
    redirect: redirectGuard ? redirectGuard.recent() : []
  }));
  invoke('protection:popup-allowlist', () => popupGuard ? popupGuard.allowlist() : []);
  invoke('protection:redirect-allowlist', () => redirectGuard ? redirectGuard.allowlist() : []);
  invoke('protection:popup-allow', (host) => popupGuard ? popupGuard.allow(host) : []);
  invoke('protection:popup-disallow', (host) => popupGuard ? popupGuard.disallow(host) : []);
  invoke('protection:redirect-allow', (host) => redirectGuard ? redirectGuard.allow(host) : []);
  invoke('protection:redirect-disallow', (host) => redirectGuard ? redirectGuard.disallow(host) : []);
  invoke('protection:setPopupEnabled', (v) => {
    if (typeof v !== 'boolean') throw new TypeError('Valor booleano esperado.');
    popupGuard.setEnabled(v);
    settings.set('popupBlockerEnabled', v);
    return protectionStatsPayload();
  });
  invoke('protection:setRedirectEnabled', (v) => {
    if (typeof v !== 'boolean') throw new TypeError('Valor booleano esperado.');
    redirectGuard.setEnabled(v);
    settings.set('redirectGuardEnabled', v);
    return protectionStatsPayload();
  });

  // Downloads (registros apenas em memória)
  const dlFind = (id) => downloadRecords().find(i => i.id === id);
  invoke('downloads:list', () => downloadRecords());
  invoke('downloads:open', async (id) => {
    const it = dlFind(id);
    if (!it || it.state !== 'completed' || !it.path || !fs.existsSync(it.path)) return { ok: false, reason: 'missing' };
    if (dl.isRiskyFile(it.path)) { shell.showItemInFolder(it.path); return { ok: true, folder: true }; }
    const err = await shell.openPath(it.path);
    return { ok: !err, reason: err || '' };
  });
  invoke('downloads:show', (id) => {
    const it = dlFind(id);
    if (!it || !it.path || !fs.existsSync(it.path)) return false;
    shell.showItemInFolder(it.path);
    return true;
  });
  invoke('downloads:openFolder', async () => !(await shell.openPath(app.getPath('downloads'))));
  invoke('downloads:cancel', (id) => {
    const item = activeDownloadItems.get(id);
    if (item) { try { item.cancel(); } catch (_) { /* ignorado */ } return true; }
    // Download aguardando confirmação de executável (sem item ativo):
    // marcar como cancelado encerra a espera — o diálogo pendente percebe
    // (o registro não está mais em 'confirming') e não reemite a URL.
    const rec = downloadRecords().find(r => r.id === id && r.state === 'confirming');
    if (rec) { rec.state = 'cancelled'; pushDownloads(); return true; }
    return false;
  });
  invoke('downloads:remove', (id) => {
    downloadStore.set('items', downloadRecords().filter(i => i.id !== id));
    return downloadRecords();
  });
  invoke('downloads:clear', () => {
    downloadStore.set('items', downloadRecords().filter(i => i.state === 'progressing' || i.state === 'confirming'));
    return downloadRecords();
  });

  // ==================== 1.9.5 — Detecção de mídia + gerenciador central ====================
  // Validação de origem: o renderer passa tabId; o main confere se a aba existe
  // e usa tabList (fonte da verdade) — nunca confia em IDs arbitrários.
  // 1.9.6 FIX: coerção de tipo + fallback para aba ativa. Antes, um descompate
  // de tipo (string vs número) ou timing (renderer com state stale) fazia o
  // handler devolver "aba inexistente" mesmo com a aba visível na tela.
  invoke('media:detect', async (tabId) => {
    const tid = String(tabId || '');
    if (!tid || tid === 'undefined' || tid === 'null') {
      // Fallback: usa a aba ativa do main (fonte da verdade)
      const active = tabList.find(t => t.id === activeTabId);
      if (!active) return { ok: false, reason: 'Nenhuma aba ativa. Abra uma página http(s) e tente novamente.', resources: [] };
      return _detectMediaInTabSafe(active.id);
    }
    // Tenta casar por ID exato, depois por String() (coerção de tipo)
    let tab = tabList.find(t => t.id === tid) || tabList.find(t => String(t.id) === tid);
    if (!tab) {
      // Fallback: se o ID não bate, usa a aba ativa (pode ter mudado)
      tab = tabList.find(t => t.id === activeTabId);
    }
    if (!tab) return { ok: false, reason: 'aba inexistente', resources: [] };
    return _detectMediaInTabSafe(tab.id);
  });

  /** Wrapper seguro para detectMediaInTab — captura qualquer erro e devolve resultado estruturado. */
  async function _detectMediaInTabSafe(tabId) {
    try {
      const resources = await detectMediaInTab(tabId);
      return { ok: true, resources, count: resources.length };
    } catch (e) {
      return { ok: false, reason: String(e && e.message || e).slice(0, 160), resources: [] };
    }
  }

  /** 1.9.6 — Resolve um tabId (possivelmente de tipo errado ou stale) para o ID
   *  real no tabList. Tenta casamento exato, depois String(), depois ignora.
   *  Retorna o id real ou null se não encontrar. */
  function _resolveTabId(tid) {
    if (!tid || tid === 'undefined' || tid === 'null') return null;
    const tab = tabList.find(t => t.id === tid) || tabList.find(t => String(t.id) === tid);
    return tab ? tab.id : null;
  }

  invoke('media:list', (tabId) => {
    const tid = String(tabId || '');
    // 1.9.6: fallback para aba ativa se o ID não bater
    const lookupId = _resolveTabId(tid) || activeTabId;
    const entry = mediaStateByTab.get(lookupId);
    if (!entry) return [];
    return entry.state.list().map(r => {
      const { webContentsId, ...rest } = r;
      return rest;
    });
  });

  invoke('media:clear', (tabId) => {
    const tid = String(tabId || '');
    const lookupId = _resolveTabId(tid) || activeTabId;
    clearMediaState(lookupId);
    return true;
  });

  invoke('media:download', async (tabId, mediaId, opts) => {
    const tid = String(tabId || '');
    // 1.9.6: resolve o tabId real (com fallback para aba ativa)
    const realTabId = _resolveTabId(tid) || activeTabId;
    if (!realTabId) return { ok: false, reason: 'tabId ausente' };
    const entry = mediaStateByTab.get(realTabId);
    if (!entry) return { ok: false, reason: 'sem mídia detectada nesta aba — clique em "Detectar mídia" primeiro' };
    const media = entry.state.get(String(mediaId || ''));
    if (!media) return { ok: false, reason: 'recurso não encontrado' };
    if (!dlManager) return { ok: false, reason: 'gerenciador indisponível' };
    // 1.9.5: se a aba for Tor/contêiner, repassa a partition para o engine escolher Electron
    const tab = tabList.find(t => t.id === realTabId);
    const sessionPartition = tab ? partitionOf(tab) : undefined;
    // Cookies da sessão só para mídia do YouTube/Google (mesma lista do yt-dlp 1.9.4).
    // Para outros domínios, aria2/Gopeed baixam sem cookies (evita expor cookies de outros sites).
    let cookies = null;
    try {
      const host = hostOf(media.url);
      if (isYtCookieHost(host)) {
        const ses = sessionPartition ? session.fromPartition(sessionPartition) : navSession;
        if (ses) {
          const all = await ses.cookies.get({});
          cookies = all.filter(c => isYtCookieHost(c.domain));
        }
      }
    } catch (_) { cookies = null; }
    // 1.9.6: sessionPartition é calculada NO MAIN e vence o que o renderer mandar
    // (o renderer não pode escolher a sessão de rede de um download).
    return dlManager.downloadMedia(media, Object.assign({ tabId: realTabId }, opts || {}, { sessionPartition, cookies }));
  });

  invoke('media:downloadBatch', async (tabId, mediaIds, opts) => {
    const tid = String(tabId || '');
    const realTabId = _resolveTabId(tid) || activeTabId;
    if (!realTabId) return { ok: false, started: 0, errors: [{ id: '', reason: 'tabId ausente' }] };
    const entry = mediaStateByTab.get(realTabId);
    if (!entry) return { ok: false, started: 0, errors: [] };
    // CORREÇÃO 1.9.6 (ERRO 1): o fluxo em lote NÃO repassava a sessão da aba —
    // partitionOf(tab) existia no processo principal mas era ignorado aqui, e o
    // gerenciador podia escolher aria2/Gopeed para arquivos >= 5MB SEM o proxy
    // Tor da sessão de origem (conexão direta vazando o IP). Agora o lote segue
    // EXATAMENTE o mesmo caminho do download unitário:
    //   1) sessão original da aba (partitionOf); 2) aba Tor → partição Tor;
    //   3) aba com contêiner → partição isolada; 4) sessionPartition repassada
    //   ao gerenciador; 5) cookies apenas para hosts YouTube/Google.
    // Em aba Tor o gerenciador força Electron (ou aria2 só com proxy Tor
    // VALIDADO); sem proxy o download é INTERROMPIDO e o usuário avisado.
    const tab = tabList.find(t => t.id === realTabId);
    const sessionPartition = tab ? partitionOf(tab) : undefined;
    // Cookies da sessão — mesma política do media:download (só YouTube/Google).
    const batchCookies = [];
    try {
      if (sessionPartition && Array.isArray(mediaIds) && mediaIds.length) {
        const ses = session.fromPartition(sessionPartition);
        const all = await ses.cookies.get({});
        for (const mid of (Array.isArray(mediaIds) ? mediaIds : []).slice(0, 20)) {
          const media = entry.state.get(String(mid));
          if (!media) continue;
          if (isYtCookieHost(hostOf(media.url))) {
            batchCookies.push(...all.filter(c => isYtCookieHost(c.domain)));
            break;   // mesmo conjunto de cookies serve para todos os hosts YT
          }
        }
      }
    } catch (_) { /* sessão pode estar fechando — segue sem cookies */ }
    const cookies = batchCookies.length ? batchCookies : null;
    let started = 0;
    const errors = [];
    for (const mid of (Array.isArray(mediaIds) ? mediaIds : []).slice(0, 20)) {
      const media = entry.state.get(String(mid));
      if (!media) { errors.push({ id: mid, reason: 'não encontrado' }); continue; }
      // 1.9.6: sessionPartition/cookies calculados NO MAIN e vencem opts do
      // renderer — o lote nunca pode derrubar a sessão/Tor da aba de origem.
      const r = await dlManager.downloadMedia(media, Object.assign({ tabId: realTabId }, opts || {}, { sessionPartition, cookies }));
      if (r.ok) started++;
      else errors.push({ id: mid, reason: r.reason });
    }
    return { ok: true, started, errors };
  });

  invoke('media:engines', () => ({
    electron: electronAdapter ? electronAdapter.isAvailable() : true,
    aria2: aria2Adapter ? aria2Adapter.isAvailable() : false,
    gopeed: gopeedAdapter ? gopeedAdapter.isAvailable() : false
  }));

  // download:pause / resume / cancel — estendem o fluxo existente com engines externos.
  // Tentam o manager (aria2/Gopeed); se o registro for Electron, delegam ao fluxo antigo.
  invoke('downloads:pause', async (id) => {
    if (!dlManager) return false;
    const rec = downloadRecords().find(r => r.id === id);
    if (!rec) return false;
    if (rec.engine && rec.engine !== 'electron') {
      return dlManager.pause(id);
    }
    // Electron: usa activeDownloadItems (item.pause())
    const item = activeDownloadItems.get(id);
    if (item) { try { item.pause(); return true; } catch (_) { return false; } }
    return false;
  });
  invoke('downloads:resume', async (id) => {
    if (!dlManager) return false;
    const rec = downloadRecords().find(r => r.id === id);
    if (!rec) return false;
    if (rec.engine && rec.engine !== 'electron') {
      return dlManager.resume(id);
    }
    const item = activeDownloadItems.get(id);
    if (item) { try { item.resume(); return true; } catch (_) { return false; } }
    return false;
  });

  // Aplicativo
  // ---- Identidade do navegador (1.5.3) — a interface (página confiável)
  // repassa as marcas que a própria engine expõe; com elas o main monta
  // Sec-CH-UA completo (incluindo "Google Chrome") para os requests web.
  invoke('identity:report', (brands, high) => {
    // 1.9.4: addGoogleChrome=true — antes a lista só tinha o que a engine
    // reportava (apenas "Chromium"), fazendo o Sec-CH-UA divergir do UA
    // "Chrome/156.0.0.0". Um Chrome real manda "Not.A/Brand", "Chromium"
    // e "Google Chrome" — a inconsistência era um sinal claro de automação
    // que o YouTube (e o login do Google) detectavam.
    const list = identity.chromeBrandList(Array.isArray(brands) ? brands : null,
      process.versions.chrome, { addGoogleChrome: true });
    // 1.7.3: valores de alta entropia que a PRÓPRIA engine entrega ao JavaScript
    try {
      if (high && typeof high === 'object') {
        const clean = {
          fullVersionList: Array.isArray(high.fullVersionList)
            ? high.fullVersionList.slice(0, 8).filter(b => b && typeof b.brand === 'string' && typeof b.version === 'string').map(b => ({ brand: b.brand.slice(0, 64), version: b.version.slice(0, 32) }))
            : null,
          platformVersion: typeof high.platformVersion === 'string' ? high.platformVersion.slice(0, 32) : null,
          architecture: typeof high.architecture === 'string' ? high.architecture.slice(0, 16) : null,
          bitness: typeof high.bitness === 'string' ? high.bitness.slice(0, 8) : null,
          model: typeof high.model === 'string' ? high.model.slice(0, 32) : '',
          wow64: high.wow64 === true,
          uaFullVersion: typeof high.uaFullVersion === 'string' ? high.uaFullVersion.slice(0, 32) : null
        };
        if (browserIdentity) browserIdentity.high = clean;
        if (torIdentity) torIdentity.high = clean;
      }
    } catch (_) { /* ignorado */ }
    if (list && browserIdentity) {
      const serialized = identity.serializeBrandList(list);
      browserIdentity.secChUa = serialized;
      if (torIdentity) torIdentity.secChUa = serialized; // 1.6.7: Tor acompanha
    }
    return { applied: !!(browserIdentity && browserIdentity.secChUa) };
  });

  // ---- Tor nativo (1.5.3) ----
  invoke('tor:status', () => {
    if (torMgr) {
      const st = torMgr.status();
      st.supported = !!torMod.resolveTorBinary({ resourcesDir: torResourcesDir() });
      return st;
    }
    return {
      state: 'off', progress: 0, tag: '', summary: '', error: '',
      socksPort: 0, controlPort: 0,
      supported: !!torMod.resolveTorBinary({ resourcesDir: torResourcesDir() })
    };
  });
  invoke('tor:start', async () => {
    if (!torMgr) throw new Error('Gerenciador do Tor indisponível.');
    await torMgr.start();
    return torMgr.status();
  });
  invoke('tor:stop', async () => {
    if (!torMgr) return { state: 'off', supported: false };
    await torMgr.stop();
    return torMgr.status();
  });
  invoke('tor:newnym', async () => {
    if (!torMgr) throw new Error('Gerenciador do Tor indisponível.');
    // "Nova identidade" (mesmo espírito do Tor Browser): novos circuitos
    // (SIGNAL NEWNYM) + limpeza dos dados da sessão Tor (cookies/cache).
    await torMgr.newIdentity();
    if (torSession) {
      try { await torSession.clearCache(); } catch (_) { /* ignorado */ }
      try { await torSession.clearStorageData(); } catch (_) { /* ignorado */ }
    }
    return torMgr.status();
  });
  invoke('tor:openTab', () => {
    const t = createTorTab(null);
    return { id: t.id };
  });
  invoke('tor:check', async () => {
    // Verificação REAL pelo serviço oficial check.torproject.org, feita
    // pela PRÓPRIA sessão Tor (o resultado é o comportamento da rede).
    if (!torMgr || torMgr.phase !== 'connected') return { ok: false, reason: 'off' };
    const ses = getTorSession();
    const ctl = new AbortController();
    const to = setTimeout(() => ctl.abort(), 25000);
    try {
      const res = await ses.fetch('https://check.torproject.org/api/ip',
        { signal: ctl.signal, cache: 'no-store' });
      if (!res.ok) return { ok: false, reason: 'HTTP ' + res.status };
      const j = await netLimits.readJsonLimited(res, 2 * 1024 * 1024);
      return { ok: true, isTor: j.IsTor === true, ip: String(j.IP || '') };
    } catch (e) {
      return { ok: false, reason: String((e && e.message) || e).slice(0, 160) };
    } finally { clearTimeout(to); }
  });

  invoke('app:openExternal', async (url) => {
    if (!isNavigable(url)) return false;
    try { await shell.openExternal(url); return true; } catch (e) { return false; }
  });
  invoke('app:version', () => ({
    app: app.getVersion(),
    electron: process.versions.electron,
    chrome: process.versions.chrome,
    node: process.versions.node
  }));
  invoke('app:clearBrowsingData', async () => {
    await navSession.clearCache();
    await navSession.clearStorageData();
    return true;
  });

  // Atualizações (verificação manual pelo menu)
  invoke('updates:check', async () => {
    const r = await runUpdateChecks({ manual: true });
    return r;
  });

  // 1.9.6 (FASE 3): renovação das listas de filtros é SEMPRE manual (menu
  // Ferramentas > "Atualizar listas de filtros") — nenhuma consulta automática.
  // Vai pela sessão do app (herda proxy Tor/DoH) e reaproveita o cache do dia.
  invoke('filters:refresh', async () => {
    if (ghosteryRefreshBusy) return { ok: true, alreadyRunning: true, state: ghosteryState };
    toast('Atualizando listas de filtros (EasyList/EasyPrivacy/uAssets)…');
    await refreshGhosteryInBackground();
    toast('Listas de filtros atualizadas (fonte: ' + (ghosteryState.source || 'desconhecida') + ').');
    return { ok: true, state: { source: ghosteryState.source, updatedAt: ghosteryState.updatedAt, lastError: ghosteryState.lastError } };
  });

  // ---- Leitor de notícias (1.4.0 — FreshRSS/Miniflux/rssPresso) ----
  invoke('reader:list', () => readerSvc.list());
  invoke('reader:subscribe', async (url) => {
    if (!isHttpUrl(String(url || ''))) throw new Error('Informe uma URL http/https válida.');
    return readerSvc.subscribe(String(url));
  });
  invoke('reader:remove', (id) => { const v = validId(id); if (v) readerSvc.remove(v); return true; });
  invoke('reader:items', (feedId, opts) => {
    const f = feedId == null || feedId === 'all' ? 'all' : validId(feedId);
    return readerSvc.items(f, opts && typeof opts === 'object' ? {
      unreadOnly: !!opts.unreadOnly,
      withSummary: opts.withSummary !== false,
      limit: Math.min(400, Math.max(1, Number(opts.limit) || 400))
    } : {});
  });
  invoke('reader:item', (id) => {
    const v = validId(id);
    return v ? readerSvc.item(v) : null;
  });
  invoke('reader:markRead', (id, read) => {
    const v = validId(id);
    return v ? readerSvc.markRead(v, read !== false) : false;
  });
  invoke('reader:markAllRead', (feedId) => {
    const f = feedId == null || feedId === 'all' ? 'all' : validId(feedId);
    readerSvc.markAllRead(f);
    return true;
  });
  invoke('reader:refresh', async (feedId) => {
    const f = feedId == null || feedId === 'all' ? 'all' : validId(feedId);
    return readerSvc.refresh(f);
  });
  invoke('reader:opmlExport', async () => {
    const r = await dialog.showSaveDialog(win, {
      title: 'Exportar inscrições (OPML)',
      defaultPath: 'nanodesk-feeds.opml',
      filters: [{ name: 'OPML', extensions: ['opml', 'xml'] }]
    });
    if (r.canceled || !r.filePath) return { ok: false, canceled: true };
    await fs.promises.writeFile(r.filePath, readerSvc.opml(), 'utf8');
    return { ok: true, path: r.filePath };
  });
  invoke('reader:opmlImport', async () => {
    const r = await dialog.showOpenDialog(win, {
      title: 'Importar inscrições (OPML)',
      properties: ['openFile'],
      filters: [{ name: 'OPML', extensions: ['opml', 'xml'] }]
    });
    if (r.canceled || !r.filePaths || !r.filePaths[0]) return { ok: false, canceled: true };
    const file = r.filePaths[0];
    const stat = await fs.promises.stat(file);
    if (!stat.isFile() || stat.size > 4 * 1024 * 1024) throw new Error('Arquivo OPML inválido ou grande demais.');
    const xml = await fs.promises.readFile(file, 'utf8');
    const result = await readerSvc.importOpml(xml);
    return { ok: true, ...result };
  });

  // ---- Arquivar página (1.9.0) ----
  invoke('archive:save', (opts) => archiveTab(activeTab(), { selectionOnly: !!(opts && opts.selectionOnly) }).then(r => !!r));
  invoke('archive:save-all', () => archiveAllTabs());
  invoke('archive:verify', () => archiveVerifyDialog().then(v => (v ? { ok: !!v.ok } : null)));

  // ---- 1.9.1: captura de credencial vinda do preload (mundo isolado) ----
  ipcMain.on('nd:cred-capture', (event, rec) => {
    try {
      const t = tabByWebContents(event.sender);
      if (!t || t.kind || event.senderFrame !== event.sender.mainFrame) return;
      if (!settings.get('vaultEnabled', true) || !settings.get('vaultSavePrompt', true)) return;
      const url = effectiveFrameUrl(event.senderFrame);
      if (!/^https?:\/\//i.test(url)) return;
      const host = hostOf(url);
      if (!host || noInjectionHost(host)) return;
      if (!rec || typeof rec !== 'object' || typeof rec.p !== 'string' || !rec.p) return;
      let origin = '';
      try { origin = new URL(url).origin; } catch (_) { origin = ''; }
      t.pendingCred = { u: typeof rec.u === 'string' ? rec.u.slice(0, 512) : '', p: rec.p.slice(0, 512), host, origin, ts: Date.now() };
    } catch (_) { /* ignorado */ }
  });
  ipcMain.on('nd:vault-fill', (event) => {
    try {
      const t = tabByWebContents(event.sender);
      if (!t || t.kind || event.senderFrame !== event.sender.mainFrame) return;
      const offer = t.fillOffer;
      t.fillOffer = null;                                   // consumida: um clique, um preenchimento
      if (!offer || Date.now() - offer.ts > 60000) return;
      const url = effectiveFrameUrl(event.senderFrame);
      if (!/^https?:\/\//i.test(url) || hostOf(url) !== offer.host) return;
      if (t.id !== activeTabId || noInjectionHost(offer.host)) return;
      vaultFillActiveTab().catch(() => toast('Não foi possível preencher agora.'));
    } catch (_) { /* ignorado */ }
  });
  invoke('vault:copy', (id) => {
    let it = null;
    try { it = bitwarden.getOne(String(id || '')); } catch (_) { it = null; }
    return it && it.password ? copySecret(it.password) : false;
  });
  invoke('vault:copy-text', (text) => copySecret(String(text || '').slice(0, 256)));

  // ---- Modo Leitura (1.4.0) ----
  invoke('readermode:extract', async (url) => {
    if (!isHttpUrl(String(url || ''))) throw new Error('O Modo Leitura precisa de uma página http/https.');
    // 1.6.1: aba Tor extrai pela sessão Tor (o pedido não foge do circuito).
    return readerMode.extractArticle(sessionForTab(activeTab()), String(url));
  });

  // ---- Leitores internos (1.5.0) — chamados pela INTERFACE ----
  invoke('readers:open-dialog', async (kind) => {
    const which = kind === 'pdf' || kind === 'ebook' ? kind : 'any';
    const r = await dialog.showOpenDialog(win, {
      title: which === 'pdf' ? 'Abrir PDF' : which === 'ebook' ? 'Abrir livro' : 'Abrir arquivo (PDF/ebook)',
      properties: ['openFile'],
      filters: readers.DIALOG_FILTERS[which]
    });
    if (r.canceled || !r.filePaths || !r.filePaths[0]) return { ok: false, canceled: true };
    const p = r.filePaths[0];
    const target = readers.classifyReaderTarget(p);
    if (!target) throw new Error('Tipo de arquivo não suportado pelo leitor.');
    const st = await fs.promises.stat(p);
    if (!st.isFile() || st.size > readers.MAX_READER_BYTES) {
      throw new Error('Arquivo grande demais (limite de 200 MB).');
    }
    const t = createReaderTab(target);
    return { ok: true, id: t.id };
  });
  invoke('readers:open-path', async (p) => {
    const target = readers.classifyReaderTarget(String(p || ''));
    if (!target) throw new Error('Caminho ou tipo de arquivo não suportado pelo leitor.');
    const local = readers.toLocalPath(target.source);
    if (!local) throw new Error('Caminho inválido.');
    const st = await fs.promises.stat(local);
    if (!st.isFile() || st.size > readers.MAX_READER_BYTES) {
      throw new Error('Arquivo grande demais (limite de 200 MB).');
    }
    target.source = local;
    const t = createReaderTab(target);
    return { ok: true, id: t.id };
  });

  // ==================== 1.6.0 — NOVOS CANAIS ====================

  // Histórico da sessão (só RAM — some ao fechar)
  invoke('history:list', (q, opts) => {
    if (!history) return [];
    const o = (opts && typeof opts === 'object') ? { limit: Number(opts.limit) || 200 } : {};
    return history.search(String(q || ''), o);
  });
  invoke('history:clear', () => { if (history) history.clear(); return true; });

  // Sessões isoladas (contêineres)
  invoke('containers:list', () => containers);
  invoke('containers:create', (name) => {
    const nm = String(name || '').trim().slice(0, 24);
    if (!nm) throw new Error('Informe um nome para a sessão.');
    if (containers.length >= 8) throw new Error('Limite de 8 sessões isoladas.');
    const hue = (containerSeq * 47 + 205) % 360;
    const c = { id: 'c' + (++containerSeq) + Math.random().toString(36).slice(2, 5), name: nm, color: 'hsl(' + hue + ',55%,55%)' };
    containers.push(c);
    return containers;
  });
  invoke('containers:remove', (id) => {
    if (String(id) === 'padrao') throw new Error('A sessão padrão não pode ser removida.');
    const idx = containers.findIndex(c => c.id === String(id));
    if (idx < 0) return containers;
    if (tabList.some(t => t.sessionId === String(id))) {
      throw new Error('Feche as abas desta sessão antes de removê-la.');
    }
    containers.splice(idx, 1);
    return containers;
  });

  // Rede (FASE 5): estado, VPN, verificação de IP pelo caminho atual
  invoke('network:state', () => networkStatePayload());
  invoke('network:refreshVpn', () => refreshVpnState());
  invoke('network:checkIp', async () => {
    // CORREÇÃO 1.6.7 (consentimento): a consulta enviava o IP real a
    // ifconfig.co sem avisar para onde ia. Agora mostra o destino ANTES
    // (mesmo padrão da tradução).
    try {
      const r = await dialog.showMessageBox(win, {
        type: 'question',
        buttons: ['Cancelar', 'Consultar'],
        defaultId: 1, cancelId: 0, noLink: true,
        title: 'Verificar IP público',
        message: 'Consultar o IP público em ifconfig.co?',
        detail: 'O serviço ifconfig.co receberá o seu IP REAL (a consulta usa a rota atual — VPN/Tor SO quando ativos). A resposta é exibida só nesta janela.'
      });
      if (r.response !== 1) return { ok: false, reason: 'cancelado' };
      const res = await navSession.fetch('https://ifconfig.co/json', {
        signal: AbortSignal.timeout ? AbortSignal.timeout(10000) : undefined
      });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const j = await netLimits.readJsonLimited(res, 2 * 1024 * 1024);
      return {
        ok: true,
        ip: String(j.ip || '').slice(0, 64),
        country: String(j.country || '').slice(0, 60),
        city: String(j.city || '').slice(0, 60),
        viaTor: !!settings.get('torMode', false)
      };
    } catch (e) {
      return { ok: false, reason: String(e.message || e).slice(0, 120) };
    }
  });

  // Segurança (FASE 6): log, hosts confiáveis do URL Gate, scanners detectados
  invoke('security:log', () => securityLog.slice(0, 100));
  invoke('security:urlgate-list', () => [...urlGateTrusted]);
  invoke('security:urlgate-remove', (host) => {
    const h = String(host || '').toLowerCase();
    if (h) urlGateTrusted.delete(h);
    return [...urlGateTrusted];
  });
  invoke('security:scan-tools', () => scanToolPaths());

  // Quarentena (FASE 6): liberar (volta p/ Downloads) ou excluir
  invoke('downloads:release', (id) => {
    const it = dlFind(id);
    if (!it || !it.quarantine || !fs.existsSync(it.quarantine)) return { ok: false, reason: 'arquivo não encontrado' };
    try {
      const target = dl.uniquePath(app.getPath('downloads'), it.name || 'arquivo', fs.existsSync, reservedDownloadPaths);
      fs.renameSync(it.quarantine, target);
      it.path = target;
      it.quarantine = null;
      if (it.scan) { it.scan.quarantined = false; it.scan.verdict = 'liberado'; }
      pushDownloads();
      pushSecurityEvent({ kind: 'quarentena', host: it.origin, detail: 'liberado pelo usuário: ' + it.name });
      return { ok: true };
    } catch (e) { return { ok: false, reason: String(e.message || e).slice(0, 120) }; }
  });
  invoke('downloads:deleteFile', (id) => {
    const it = dlFind(id);
    const p = it && (it.quarantine || it.path);
    if (!it || !p || !fs.existsSync(p)) return { ok: false, reason: 'arquivo não encontrado' };
    try {
      fs.rmSync(p, { force: true });
      it.quarantine = null;
      it.state = 'cancelled';
      pushDownloads();
      pushSecurityEvent({ kind: 'quarentena', host: it.origin, detail: 'excluído pelo usuário: ' + it.name });
      return { ok: true };
    } catch (e) { return { ok: false, reason: String(e.message || e).slice(0, 120) }; }
  });

  // Tradução (FASE 7) — sempre com consentimento; endpoint vazio = desligado
  invoke('translate:run', async (text) => {
    const out = await translateSelection(String(text || '').slice(0, translate.MAX_TEXT));
    return out == null ? { ok: false } : { ok: true, text: out };
  });
  invoke('translate:page', () => translatePage());
  invoke('translate:clipboard', () => translateClipboard());

  // ---- 1.7.0: LibraryTranslate (biblioteca de traduções, só RAM) ----
  invoke('library:list', (q) => librarytranslate.search(library.get('items', []), String(q || '')));
  invoke('library:remove', (id) => {
    const idSafe = String(id || '');
    library.set('items', library.get('items', []).filter(r => r.id !== idSafe));
    sendToWin('library:update', { count: library.get('items', []).length });
    return library.get('items', []);
  });
  invoke('library:clear', () => {
    library.set('items', []);
    sendToWin('library:update', { count: 0 });
    return [];
  });
  invoke('library:export', () => library.get('items', []));
  invoke('linkwarden:save', (url) => saveToLinkwarden(String(url || '')));

  // ---- 1.8.9: cofre de senhas NATIVO (substitui a CLI bw externa) ----
  // Criptografia embutida: PBKDF2 (600k) + AES-256-GCM. Arquivo cifrado em
  // userData/nanodesk-vault.json; chave derivada só na RAM; autolock por
  // inatividade. Sem dependência de instalação externa — funciona nativo.

  invoke('vault:status', () => bitwarden.status());
  invoke('vault:exists', () => bitwarden.exists());
  // 1.8.10: gate em vaultEnabled nos handlers mutantes — antes, um cofre
  // "desativado" ainda aceitava unlock/add/update/remove/import via IPC.
  invoke('vault:create', (masterPw) => {
    if (!settings.get('vaultEnabled', true)) throw new Error('Cofre desativado nas configurações.');
    return new Promise((resolve, reject) => {
      bitwarden.createVault(String(masterPw || ''), (err, ok) => {
        if (err) { sendToWin('vault:state', bitwarden.status()); reject(err); }
        else { sendToWin('vault:state', bitwarden.status()); resolve(ok); }
      });
    });
  });
  invoke('vault:unlock', (masterPw) => {
    if (!settings.get('vaultEnabled', true)) throw new Error('Cofre desativado nas configurações.');
    return new Promise((resolve, reject) => {
      bitwarden.unlock(String(masterPw || ''), (err, ok) => {
        if (err) { sendToWin('vault:state', bitwarden.status()); reject(err); }
        else { sendToWin('vault:state', bitwarden.status()); resolve(ok); }
      });
    });
  });
  invoke('vault:lock', () => {
    bitwarden.lock();
    sendToWin('vault:state', bitwarden.status());
    return true;
  });
  invoke('vault:list', () => bitwarden.list());
  invoke('vault:search', (q) => bitwarden.search(q));
  invoke('vault:getByHost', (host) => bitwarden.getByHost(String(host || '')));
  invoke('vault:add', (item) => {
    if (!settings.get('vaultEnabled', true)) throw new Error('Cofre desativado nas configurações.');
    const r = bitwarden.add(item);
    sendToWin('vault:state', bitwarden.status());
    return r;
  });
  invoke('vault:update', (id, patch) => {
    if (!settings.get('vaultEnabled', true)) throw new Error('Cofre desativado nas configurações.');
    const r = bitwarden.update(id, patch);
    sendToWin('vault:state', bitwarden.status());
    return r;
  });
  invoke('vault:remove', (id) => {
    if (!settings.get('vaultEnabled', true)) throw new Error('Cofre desativado nas configurações.');
    bitwarden.remove(id);
    sendToWin('vault:state', bitwarden.status());
    return true;
  });
  invoke('vault:generate', (opts) => bitwarden.generatePassword(opts || {}));
  invoke('vault:changeMaster', (oldPw, newPw) => {
    if (!settings.get('vaultEnabled', true)) throw new Error('Cofre desativado nas configurações.');
    return new Promise((resolve, reject) => {
      bitwarden.changeMasterPassword(String(oldPw || ''), String(newPw || ''), (err, ok) => {
        if (err) reject(err); else resolve(ok);
      });
    });
  });
  invoke('vault:export', () => bitwarden.exportJson());
  invoke('vault:import', (jsonStr, mode) => {
    if (!settings.get('vaultEnabled', true)) throw new Error('Cofre desativado nas configurações.');
    return bitwarden.importJson(jsonStr, mode);
  });
  invoke('vault:destroy', () => {
    bitwarden.destroy();
    sendToWin('vault:state', bitwarden.status());
    return true;
  });
  // Comando "bitwarden-fill" (atalho/menu) — redireciona para o cofre nativo.
  invoke('bitwarden:fill', async () => {
    if (!settings.get('vaultEnabled', true)) {
      throw new Error('Cofre desativado nas configurações.');
    }
    const t = activeTab();
    if (!t || !t.view || !/^https?:\/\//i.test(String(t.url || ''))) {
      throw new Error('Abra um site (http/https) para preencher o login.');
    }
    const host = hostOf(t.url);
    if (!bitwarden.status().unlocked) {
      // Sinaliza o renderer para abrir o painel do cofre e, após desbloqueio,
      // retomar o preenchimento (pendingVaultFillHost).
      sendToWin('vault:prompt-unlock', { host, pendingFill: true });
      throw new Error('Cofre bloqueado — desbloqueie no painel do cofre para preencher.');
    }
    return await vaultFillActiveTab();
  });
  // Preenchimento direto (usado após desbloqueio, ou pelo botão flutuante).
  invoke('vault:fill-now', async () => {
    if (!bitwarden.status().unlocked) throw new Error('Cofre bloqueado.');
    return await vaultFillActiveTab();
  });

  // Vídeo (FASE 8 / 1.8.8) — apenas yt-dlp (FreeTube/Invidious/Piped REMOVIDOS)
  invoke('video:download', (url) => {
    if (!isHttpUrl(String(url || ''))) throw new Error('URL inválida.');
    startYtDlpDownload(String(url));
    return true;
  });

  // 1.8.8 — IPC do yt-dlp: status, cancelar, histórico, abrir arquivo baixado
  invoke('ytdlp:status', () => ({
    running: !!(ytdlpProc && ytdlpProc.exitCode === null),
    bin: ytdlpBinCached,
    history: ytdlpHistory.slice(0, 50)
  }));
  invoke('ytdlp:cancel', () => {
    try { if (ytdlpProc && ytdlpProc.exitCode === null) { ytdlpProc.kill(); return true; } }
    catch (_) { /* ignorado */ }
    return false;
  });
  invoke('ytdlp:history', () => ytdlpHistory.slice(0, 100));
  invoke('ytdlp:clearHistory', () => { ytdlpHistory.length = 0; return true; });
  invoke('ytdlp:openFile', (p) => {
    const fp = String(p || '');
    if (!fp) return { ok: false, reason: 'missing' };
    // 1.9.4 — defesa em profundidade: o renderer é a UI confiável, mas
    // restringimos o caminho ao diretório de Downloads do usuário para
    // evitar que um bug do renderer exponha arquivos arbitrários do disco.
    // path.relative() devolve algo começando com '..' se o caminho sai do diretório base.
    let baseDownloads;
    try { baseDownloads = app.getPath('downloads'); } catch (_) { baseDownloads = ''; }
    if (!baseDownloads) return { ok: false, reason: 'no-downloads-dir' };
    let resolved;
    try { resolved = path.resolve(fp); } catch (_) { return { ok: false, reason: 'invalid' }; }
    const rel = path.relative(baseDownloads, resolved);
    if (rel.startsWith('..') || path.isAbsolute(rel)) {
      pushSecurityEvent({ kind: 'yt-dlp', level: 'suspeito', host: 'local',
        detail: 'tentativa de abrir arquivo fora de Downloads: ' + String(fp).slice(0, 120) });
      return { ok: false, reason: 'out-of-downloads' };
    }
    if (!fs.existsSync(resolved)) return { ok: false, reason: 'missing' };
    shell.showItemInFolder(resolved);
    return { ok: true };
  });

  // 1.8.8 — status do ClamAV embutido (binário + base de assinaturas)
  invoke('security:clamavStatus', async () => clamavStatusPayload());
  // 1.9.3 — painel "Motores de varredura": o que está ATIVO, versões, idade das assinaturas e o MOTIVO se não está
  invoke('security:engines', () => scanEnginesStatus());
  invoke('security:engines-update-clamav', async () => {
    // ação EXPLÍCITA do usuário: força a atualização e reabre a decisão de baixar pelo Tor
    clamavTorConsent = null;
    if (!torInUse()) toast('Atualizando a base do ClamAV…', 4000);
    await ensureClamavDatabase(true);
    return scanEnginesStatus();
  });
}

/**
 * Canais IPC chamados pelas PRÓPRIAS páginas-leitor (ndr://readers/).
 * Validados por isTrustedReaderIpc — origem interna, dentro de uma
 * aba-leitor gerenciada pelo NanoDesk.
 */
function registerReaderIpc() {
  const invokeReader = (channel, fn) => ipcMain.handle(channel, (event, ...args) => {
    if (!isTrustedReaderIpc(event)) throw new Error('Solicitação IPC de leitor não confiável.');
    return fn(event, ...args);
  });

  invokeReader('readers:env', (event) => {
    const t = tabByWebContents(event.sender);
    if (!t || !t.kind) return { kind: null, src: null, title: null };
    return { kind: t.kind, src: t.readerSrc, title: t.readerTitle || t.title };
  });

  invokeReader('readers:get-bytes', async (event, src) => {
    const s = String(src || '');
    // HARDENING 1.5.2: a página do leitor só pode pedir a fonte da PRÓPRIA aba
    // (antes qualquer caminho local .pdf/.epub podia ser lido via IPC).
    const owner = tabByWebContents(event.sender);
    if (!owner || !owner.readerSrc || s !== owner.readerSrc) {
      throw new Error('Fonte do documento não corresponde a esta aba.');
    }
    let data = null;
    if (isHttpUrl(s)) {
      // baixa pela MESMA sessão anônima da navegação (cookies de sessão,
      // bloqueador e cabeçalhos DNT valem aqui também)
      // 1.6.1: documento de aba Tor/contêiner é buscado pela sessão DA ABA.
      const res = await sessionForTab(owner).fetch(s, { redirect: 'follow' });
      if (!res.ok) throw new Error('HTTP ' + res.status + ' ao buscar o documento.');
      // 1.9.2: lê em STREAMING e cancela ao passar do teto — antes só olhava o Content-Length (que o
      // servidor pode omitir/falsear) e depois carregava a resposta INTEIRA na memória do processo principal.
      try { data = await netLimits.readBodyLimited(res, readers.MAX_READER_BYTES); }
      catch (e) {
        if (e && e.code === 'BODY_TOO_LARGE') throw new Error('Documento grande demais (limite de 200 MB).');
        throw e;
      }
    } else {
      const local = readers.toLocalPath(s);
      if (!local || !readers.isReaderExtension(local)) {
        throw new Error('Fonte do documento inválida.');
      }
      const st = await fs.promises.stat(local);
      if (!st.isFile()) throw new Error('Arquivo não encontrado.');
      if (st.size > readers.MAX_READER_BYTES) {
        throw new Error('Documento grande demais (limite de 200 MB).');
      }
      data = await fs.promises.readFile(local);
    }
    if (data.byteLength > readers.MAX_READER_BYTES) {
      throw new Error('Documento grande demais (limite de 200 MB).');
    }
    return data;
  });

  invokeReader('readers:pick-file-bytes', async (event, kind) => {
    const which = kind === 'pdf' ? 'pdf' : kind === 'any' ? 'any' : 'ebook';
    const r = await dialog.showOpenDialog(win, {
      title: which === 'pdf' ? 'Abrir PDF' : 'Abrir livro',
      properties: ['openFile'],
      filters: readers.DIALOG_FILTERS[which]
    });
    if (r.canceled || !r.filePaths || !r.filePaths[0]) return { canceled: true };
    const p = r.filePaths[0];
    const target = readers.classifyReaderTarget(p);
    if (!target) throw new Error('Tipo de arquivo não suportado pelo leitor.');
    const st = await fs.promises.stat(p);
    if (!st.isFile() || st.size > readers.MAX_READER_BYTES) {
      throw new Error('Arquivo grande demais (limite de 200 MB).');
    }
    const bytes = await fs.promises.readFile(p);
    return { canceled: false, name: path.basename(p), bytes };
  });

  invokeReader('readers:open-in-new-tab', (event, url) => {
    if (!isHttpUrl(String(url || ''))) return false;
    sendToWin('tabs:open-in-tab', String(url));
    return true;
  });

  invokeReader('readers:toast', (event, msg) => {
    toast(String(msg || '').slice(0, 220));
    return true;
  });
}

/* ---------------- FASE 7 — Linkwarden (instância própria, opcional) -------- */

/**
 * Salva a página atual no Linkwarden do usuário via API oficial v1
 * (POST /api/v1/links). O TOKEN NUNCA é gravado pelo NanoDesk: vem da
 * variável de ambiente NANODESK_LINKWARDEN_TOKEN. Sem URL/token o menu
 * explica como configurar — sem botão fictício.
 */
async function saveToLinkwarden(url) {
  const base = String(url || '').trim();
  if (!isHttpUrl(base)) { toast('Abra um site http/https para salvar.'); return false; }
  // 1.8.10: guarda Tor — navSession.fetch não herda o proxy SOCKS5 da aba
  // Tor (só torSession herda); sem isso, salvar no Linkwarden a partir de
  // uma aba Tor vazaria o IP real do usuário para a instância configurada.
  const atvTor = activeTab();
  if (atvTor && atvTor.tor) {
    toast('Salvar no Linkwarden desativado em abas Tor: o pedido sairia do circuito Tor e revelaria seu IP real.', 8000);
    return false;
  }
  const instance = translate.normalizeEndpoint(settings.get('linkwardenUrl', ''));
  const token = process.env.NANODESK_LINKWARDEN_TOKEN || '';
  if (!instance || !token) {
    toast('Linkwarden: configure a instância em Configurações e o token em NANODESK_LINKWARDEN_TOKEN (nunca é gravado).', 9000);
    return false;
  }
  try {
    const res = await navSession.fetch(instance + '/api/v1/links', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify({ url: base, collection: { name: 'NanoDesk' } }),
      signal: AbortSignal.timeout ? AbortSignal.timeout(20000) : undefined
    });
    if (res.status === 401) { toast('Linkwarden: token inválido (NANODESK_LINKWARDEN_TOKEN).'); return false; }
    if (!res.ok) throw new Error('HTTP ' + res.status);
    toast('Página salva no Linkwarden.');
    return true;
  } catch (e) {
    toast('Falha ao salvar no Linkwarden: ' + String(e.message || e).slice(0, 120));
    return false;
  }
}

/* ---------------- FASE 7 — tradução privada (LibreTranslate) ---------------- */

const translateConsent = new Map(); // endpoint|idioma -> ts (dedupe 2 min, só RAM)

/**
 * Envia texto ao LibreTranslate configurado — SEMPRE com consentimento
 * prévio mostrando o destino (regra da especificação). Endpoint vazio
 * = recurso desligado (nada é enviado a serviço algum).
 * @returns {string|null} texto traduzido (null = cancelado/desligado)
 */
async function translateRequest(text, kind) {
  // 1.6.1: em aba Tor o texto iria para o servidor de tradução FORA do circuito Tor.
  const atv = activeTab();
  if (atv && atv.tor) {
    toast('Tradução desativada em abas Tor: o texto sairia do circuito Tor para o servidor de tradução.', 7000);
    return null;
  }
  const endpoint = translate.normalizeEndpoint(settings.get('translateUrl', ''));
  if (!endpoint) {
    // 1.7.1: sem LibreTranslate configurado NÃO é mais "tradução desligada".
    // Tradução de página inteira continua exigindo LibreTranslate (o MyMemory
    // aceita só 500 caracteres); texto curto cai para o MyMemory, sempre com
    // o diálogo de consentimento.
    if (kind === 'página inteira') {
      toast('Tradução de página inteira precisa de um servidor LibreTranslate (Configurações). O MyMemory público aceita apenas ' + librarytranslate.MAX_TEXT + ' caracteres.', 7000);
      return null;
    }
    return mymemoryTranslate(text, kind);
  }
  const target = settings.get('translateTarget', 'pt');
  const key = endpoint + '|' + target;
  const now = Date.now();
  if (!translateConsent.get(key) || now - translateConsent.get(key) > 120000) {
    const local = translate.isLocalhost(endpoint);
    const r = await dialog.showMessageBox(win, {
      type: 'question',
      buttons: ['Cancelar', 'Traduzir'],
      defaultId: 1, cancelId: 0, noLink: true,
      title: 'Tradução privada',
      message: local ? 'Traduzir localmente (servidor no seu computador)?' : 'Enviar texto a serviço externo?',
      detail: translate.consentMessage(endpoint, Math.min(text.length, translate.MAX_TEXT), kind || 'texto')
    });
    if (r.response !== 1) return null;
    translateConsent.set(key, now);
    if (translateConsent.size > 20) translateConsent.clear();
  }
  const payload = translate.translatePayload(text, target, 'auto');
  const apiKey = process.env.NANODESK_LT_KEY || '';
  if (apiKey) payload.api_key = apiKey;
  const res = await navSession.fetch(endpoint + '/translate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout ? AbortSignal.timeout(30000) : undefined
  });
  if (!res.ok) throw new Error('LibreTranslate respondeu HTTP ' + res.status);
  return translate.parseResponse(await netLimits.readJsonLimited(res, 2 * 1024 * 1024));
}

/* ---------------- 1.7.1 — MyMemory para o "Traduzir" comum ----------------
 * O LibreTranslate público está praticamente morto (libretranslate.com
 * exige chave; espelhos caídos — testado no build com curl). O MyMemory
 * segue funcionando SEM chave. Uso: substituto quando não há LibreTranslate
 * configurado e RECURSO quando o LibreTranslate configurado falha (o
 * relatório do usuário citou LibreTranslate fora do ar). Sempre com o
 * diálogo de consentimento; o texto vai RECORTADO a 500 caracteres. */
const mmConsent = new Map();
async function mymemoryTranslate(text, kind) {
  const atv = activeTab();
  if (atv && atv.tor) {
    toast('Tradução desativada em abas Tor: o texto sairia do circuito Tor.', 7000);
    return null;
  }
  const slice = String(text || '').trim().slice(0, librarytranslate.MAX_TEXT);
  if (!slice) {
    toast('MyMemory aceita no máximo ' + librarytranslate.MAX_TEXT + ' caracteres por consulta.');
    return null;
  }
  const target = settings.get('translateTarget', 'pt');
  const now = Date.now();
  const key = 'mm|' + target;
  if (!mmConsent.get(key) || now - mmConsent.get(key) > 120000) {
    const r = await dialog.showMessageBox(win, {
      type: 'question',
      buttons: ['Cancelar', 'Traduzir'],
      defaultId: 1, cancelId: 0, noLink: true,
      title: 'Tradução privada (MyMemory)',
      message: 'Enviar texto ao MyMemory (serviço público, sem chave)?',
      detail: 'LibreTranslate não está configurado (ou não respondeu agora), então a tradução usa o MyMemory público (api.mymemory.translated.net). O texto vai RECORTADO a ' + librarytranslate.MAX_TEXT + ' caracteres. Nada é gravado. Continuar?'
    });
    if (r.response !== 1) return null;
    mmConsent.set(key, now);
    if (mmConsent.size > 20) mmConsent.clear();
  }
  // Origem: LanguageTool detecta (se ativo); sem ele, 'en' — o MyMemory
  // NÃO aceita 'auto' (correção 1.7.1 também no langpair da biblioteca).
  let src = 'en';
  if (settings.get('languagetoolEnabled', true)) {
    try {
      const api = languagetool.normalizeApi(settings.get('languagetoolApi', ''));
      const out = await ltCheckResilient(slice.slice(0, 4000), 'auto', api);
      const d = String(out.detected || '').split('-')[0];
      if (d && d !== 'auto') src = d;
    } catch (_) { /* segue 'en' */ }
  }
  const url = librarytranslate.mymemoryUrl(slice, src, target);
  if (!url) return null;
  const res = await navSession.fetch(url, {
    signal: AbortSignal.timeout ? AbortSignal.timeout(20000) : undefined
  });
  if (!res.ok) throw new Error('MyMemory respondeu HTTP ' + res.status);
  const out = librarytranslate.parseMymemory(await netLimits.readJsonLimited(res, 2 * 1024 * 1024));
  if (!out) throw new Error('MyMemory não devolveu tradução.');
  return out;
}

async function translateSelection(text) {
  const clean = String(text || '').trim().slice(0, translate.MAX_TEXT);
  if (!clean) return null;
  try {
    const out = await translateRequest(clean, 'texto selecionado');
    if (out == null) return null;
    sendToWin('translate:result', { title: 'Texto traduzido', html: '<p>' + escHtml(out).slice(0, 8000) + '</p>' });
    toast('Tradução pronta (painel Leitor).');
    return out;
  } catch (e) {
    // 1.7.1: LibreTranslate configurado falhou (instância pública fora do
    // ar é o cenário reportado). Tenta o MyMemory com consentimento próprio
    // antes de desistir.
    try {
      const out = await mymemoryTranslate(clean, 'texto selecionado (reserva do MyMemory)');
      if (out != null) {
        sendToWin('translate:result', { title: 'Texto traduzido (MyMemory)', html: '<p>' + escHtml(out).slice(0, 8000) + '</p>' });
        toast('Tradução pronta via MyMemory (o LibreTranslate configurado não respondeu).', 5000);
        return out;
      }
    } catch (_) { /* segue com o erro original */ }
    toast('Falha na tradução: ' + String(e.message || e).slice(0, 140));
    return null;
  }
}

/* =====================================================================
 * 1.7.0 — LANGUAGETOOL (verificação gramatical on-demand)
 * =====================================================================
 * A consulta HTTP é feita AQUI (processo principal — não depende do CSP
 * da página) e o painel só renderiza. Consentimento igual ao da
 * tradução: o destino é mostrado ANTES do primeiro envio.
 */
const ltConsent = new Map();   // api -> timestamp da última autorização (2 min)

/* ---------------- 1.7.1 — resiliência do LanguageTool ----------------
 * Relatório do usuário: LanguageTool "às vezes funciona, às vezes não" —
 * a API pública limita ~20 consultas/min (HTTP 429) e oscila. Agora:
 * fila com espaçamento mínimo de 3 s entre consultas públicas, reenvio
 * com espera em 429/5xx, ESPELHO oficial (api.languagetoolplus.com,
 * testado no build) e cache de resultados por texto+idioma (RAM, 10 min).
 * O espelho só entra para API pública (nunca para servidor local/próprio)
 * e o diálogo de consentimento cita os dois destinos. */
const LT_PUBLIC_MIRROR = 'https://api.languagetoolplus.com';
const ltThrottle = { last: 0, chain: Promise.resolve() };
const ltCache = new Map();   // chave (idioma|texto) -> { ts, api, detected, matches }

function ltTextKey(text, lang) {
  const s = String(lang || 'auto') + '|' + String(text || '');
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h * 33) ^ s.charCodeAt(i)) >>> 0;
  return 'h' + h;
}
const ltSleep = (ms) => new Promise(r => setTimeout(r, ms));

/** Consulta /v2/check com resiliência. Devolve { api, detected, matches } ou lança. */
async function ltCheckResilient(text, lang, api) {
  // 1.8.11 (P-08): fail-closed próprio — não depende mais de quem chama ter guardado o Tor.
  { const atvTor = activeTab(); if (atvTor && atvTor.tor) throw new Error('Desativado em abas Tor (o texto sairia do circuito).'); }
  const local = translate.isLocalhost(api);
  const key = ltTextKey(text, lang);
  const cached = ltCache.get(key);
  if (cached && Date.now() - cached.ts < 600000) {
    return { api: cached.api, detected: cached.detected, matches: cached.matches };
  }
  const endpoints = local ? [api] : [api, ...(api === LT_PUBLIC_MIRROR ? [] : [LT_PUBLIC_MIRROR])];
  let lastErr = null;
  const run = ltThrottle.chain.then(async () => {
    for (const ep of endpoints) {
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          if (!translate.isLocalhost(ep)) {          // API pública: espaçamento mínimo
            const gap = Date.now() - ltThrottle.last;
            if (gap < 3000) await ltSleep(3000 - gap);
            ltThrottle.last = Date.now();
          }
          const res = await navSession.fetch(ep + '/v2/check', {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: languagetool.checkBody(text, lang),
            signal: AbortSignal.timeout ? AbortSignal.timeout(20000) : undefined
          });
          if (res.status === 429 || res.status >= 500) {
            lastErr = new Error('LanguageTool (' + ep + ') respondeu HTTP ' + res.status +
              (res.status === 429 ? ' — limite de uso, repetindo' : ''));
            await ltSleep(1600 + attempt * 1600);
            continue;
          }
          if (!res.ok) throw new Error('LanguageTool (' + ep + ') respondeu HTTP ' + res.status);
          const j = await netLimits.readJsonLimited(res, 2 * 1024 * 1024);
          const out = {
            api: ep,
            detected: languagetool.detectedLanguage(j),
            matches: languagetool.parseMatches(j)
          };
          if (ltCache.size > 40) ltCache.clear();
          ltCache.set(key, { ts: Date.now(), ...out });
          return out;
        } catch (e) {
          lastErr = e;
          if (attempt === 0) await ltSleep(1400);
        }
      }
    }
    throw lastErr || new Error('LanguageTool indisponível.');
  });
  ltThrottle.chain = run.catch(() => {});
  return run;
}

async function runGrammarCheck(wc, selText, fromField) {
  if (!settings || !settings.get('languagetoolEnabled', true)) {
    toast('LanguageTool está desligado em Configurações.');
    return;
  }
  const atv = activeTab();
  if (atv && atv.tor) {
    toast('Verificação desativada em abas Tor: o texto sairia do circuito Tor.', 7000);
    return;
  }
  const api = languagetool.normalizeApi(settings.get('languagetoolApi', ''));
  let text = String(selText || '').slice(0, languagetool.MAX_TEXT);
  if (!text.trim()) {
    // sem seleção: usa o campo em foco (quando veio do menu em campo editável)
    try {
      const grab = '(function(){var el=document.activeElement;' +
        'if(el&&(el.tagName==="TEXTAREA"||(el.tagName==="INPUT"&&/^(text|search|url|email)$/i.test(el.type||"text"))))' +
        'return String(el.value||"").slice(0,' + languagetool.MAX_TEXT + ');' +
        'var s=window.getSelection();return s&&!s.isCollapsed?String(s.toString()).slice(0,' + languagetool.MAX_TEXT + '):"";})()';
      text = String(await wc.executeJavaScript(grab, true).catch(() => '') || '');
    } catch (_) { text = ''; }
  }
  if (!text.trim()) {
    toast('Selecione um texto (ou clique dentro de um campo) para verificar.');
    return;
  }
  const now = Date.now();
  const key = 'lt|' + api;
  if (!ltConsent.get(key) || now - ltConsent.get(key) > 120000) {
    const local = translate.isLocalhost(api);
    const r = await dialog.showMessageBox(win, {
      type: 'question',
      buttons: ['Cancelar', 'Verificar'],
      defaultId: 1, cancelId: 0, noLink: true,
      title: 'LanguageTool',
      message: local ? 'Verificar LOCALMENTE (servidor no seu computador)?' : 'Enviar texto a serviço externo?',
      detail: (local ? 'Processamento local via ' : 'O texto será ENVIADO a ') + api +
        (!local && api !== LT_PUBLIC_MIRROR ? ' (e, se indisponível, ao espelho oficial ' + LT_PUBLIC_MIRROR + ')' : '') +
        ' (' + Math.min(text.length, languagetool.MAX_TEXT) + ' caracteres). Continuar?'
    });
    if (r.response !== 1) return;
    ltConsent.set(key, now);
    if (ltConsent.size > 20) ltConsent.clear();
  }
  try {
    const out = await ltCheckResilient(text, settings.get('languagetoolLang', 'auto'), api);
    await wc.executeJavaScript(languagetool.buildPanelScript({
      api: out.api,
      detected: out.detected,
      matches: out.matches,
      error: ''
    }), false);
  } catch (e) {
    try {
      await wc.executeJavaScript(languagetool.buildPanelScript({
        api, detected: '', matches: [],
        error: 'Falha ao verificar: ' + String(e.message || e).slice(0, 120)
      }), false);
    } catch (_) { toast('Falha na verificação: ' + String(e.message || e).slice(0, 140)); }
  }
}

/* =====================================================================
 * 1.7.0 — LIBRARYTRANSLATE (traduz e salva na Biblioteca)
 * =====================================================================
 * Motor: LibreTranslate configurado (se houver) → MyMemory público
 * (sem chave, funciona de imediato), SEMPRE com o diálogo de
 * consentimento. Registro guardado SÓ NA RAM (some ao fechar).
 */
const libConsent = new Map();
async function libraryTranslateSelection(rawText) {
  const text = String(rawText || '').trim().slice(0, translate.MAX_TEXT);
  if (!text) { toast('Selecione um texto para traduzir.'); return null; }
  const atv = activeTab();
  if (atv && atv.tor) {
    toast('Tradução desativada em abas Tor: o texto sairia do circuito Tor.', 7000);
    return null;
  }
  const target = settings.get('translateTarget', 'pt');
  const ltEndpoint = translate.normalizeEndpoint(settings.get('translateUrl', ''));
  const endpoint = ltEndpoint || 'https://api.mymemory.translated.net';
  const local = translate.isLocalhost(endpoint);
  const now = Date.now();
  const key = endpoint + '|lib|' + target;
  if (!libConsent.get(key) || now - libConsent.get(key) > 120000) {
    const r = await dialog.showMessageBox(win, {
      type: 'question',
      buttons: ['Cancelar', 'Traduzir e salvar'],
      defaultId: 1, cancelId: 0, noLink: true,
      title: 'LibraryTranslate',
      message: local ? 'Traduzir LOCALMENTE e salvar na Biblioteca?' : 'Enviar texto a serviço externo e salvar na Biblioteca?',
      detail: (local ? 'Processamento local via ' : 'O texto será ENVIADO a ') + endpoint +
        '. A tradução fica guardada SÓ NA MEMÓRIA do NanoDesk (some ao fechar). Continuar?'
    });
    if (r.response !== 1) return null;
    libConsent.set(key, now);
    if (libConsent.size > 20) libConsent.clear();
  }
  let translation = '';
  let src = 'auto';
  try {
    if (ltEndpoint) {
      const payload = librarytranslate.libretranslatePayload(text, target, 'auto');
      const apiKey = process.env.NANODESK_LT_KEY || '';
      if (apiKey) payload.api_key = apiKey;
      const res = await navSession.fetch(ltEndpoint + '/translate', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout ? AbortSignal.timeout(30000) : undefined
      });
      if (!res.ok) throw new Error('LibreTranslate respondeu HTTP ' + res.status);
      translation = librarytranslate.parseLibretranslate(await netLimits.readJsonLimited(res, 2 * 1024 * 1024));
    }
    if (!translation) {
      // idioma de origem pelo LanguageTool (melhora o par do MyMemory)
      if (settings.get('languagetoolEnabled', true)) {
        try {
          const api = languagetool.normalizeApi(settings.get('languagetoolApi', ''));
          const out = await ltCheckResilient(text.slice(0, 4000), 'auto', api);   // 1.7.1: espelho + reenvio
          src = (String(out.detected || '').split('-')[0] || 'auto');
        } catch (_) { /* segue com 'auto' — o langpair agora cai para 'en' */ }
      }
      const mmUrl = librarytranslate.mymemoryUrl(text, src, target);
      if (mmUrl) {
        const res2 = await navSession.fetch(mmUrl, {
          signal: AbortSignal.timeout ? AbortSignal.timeout(20000) : undefined
        });
        if (res2.ok) translation = librarytranslate.parseMymemory(await netLimits.readJsonLimited(res2, 2 * 1024 * 1024));
      }
    }
  } catch (e) {
    toast('Falha na tradução: ' + String(e.message || e).slice(0, 120));
    return null;
  }
  if (!translation) {
    toast('Não foi possível traduzir agora (serviço indisponível).');
    return null;
  }
  const at = activeTab();
  const rec = librarytranslate.makeRecord({
    text, translation, src, target,
    url: at ? String(at.url || '') : '',
    title: at ? String(at.title || '') : ''
  });
  library.set('items', librarytranslate.addItem(library.get('items', []), rec));
  sendToWin('library:update', { count: library.get('items', []).length });
  sendToWin('translate:result', {
    title: 'LibraryTranslate — salvo na Biblioteca',
    html: '<p><b>' + escHtml(rec.text.slice(0, 300)) + '</b></p><p>' + escHtml(rec.translation).slice(0, 5000) + '</p>'
  });
  toast('✔ Tradução salva na Biblioteca (painel Biblioteca).', 3200);
  return rec;
}

function escHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
}

/** Traduz o conteúdo da área de transferência (ação explícita no menu). */
async function translateClipboard() {
  let text = '';
  try { text = clipboard.readText() || ''; } catch (_) { text = ''; }
  const clean = text.trim().slice(0, translate.MAX_TEXT);
  if (!clean) { toast('A área de transferência está vazia ou sem texto.'); return null; }
  // 1.8.11 (P-06): confirmação com PRÉVIA do conteúdo em TODA chamada — o consentimento
  // genérico é lembrado por 2 min e um atalho acionado por engano enviaria o que estivesse
  // copiado (senha, token, dado pessoal) sem diálogo algum.
  const preview = clean.replace(/\s+/g, ' ').slice(0, 80) + (clean.length > 80 ? '…' : '');
  const ask = await dialog.showMessageBox(win, {
    type: 'warning',
    buttons: ['Cancelar', 'Traduzir'],
    defaultId: 0, cancelId: 0, noLink: true,
    title: 'Traduzir área de transferência',
    message: 'Enviar o texto copiado para tradução?',
    detail: 'Prévia: “' + preview + '”\n\nSe isto for uma senha, token ou dado pessoal, cancele.'
  });
  if (ask.response !== 1) return null;
  return translateSelection(clean);
}

/** Traduz a página atual reutilizando o pipeline do Modo Leitura. */
async function translatePage() {
  const t = activeTab();
  if (!t || !/^https?:\/\//i.test(String(t.url || ''))) {
    toast('Abra um site (http/https) para traduzir.');
    return false;
  }
  try {
    const art = await readerMode.extractArticle(sessionForTab(t), t.url);
    const out = await translateRequest((art.title ? '<h2>' + escHtml(art.title) + '</h2>' : '') +
      (art.contentHtml || ''), 'página inteira');
    if (out == null) return false;
    // 1.8.11: o HTML volta de um servidor LibreTranslate configurável (não confiável) e vai
    // para innerHTML da UI privilegiada — passa pelo MESMO sanitizador do modo leitura.
    const safeHtml = htmlutil.sanitizeHtml(String(out), { baseUrl: t.url, allowDataImages: false });
    sendToWin('translate:result', { title: art.title || hostOf(t.url), html: safeHtml });
    toast('Página traduzida (painel Leitor).');
    return true;
  } catch (e) {
    toast('Falha na tradução: ' + String(e.message || e).slice(0, 140));
    return false;
  }
}

/* ---------------- FASE 8 / 1.8.8 — vídeo: apenas yt-dlp ---------------- */
/* 1.8.8: FreeTube/Invidious/Piped REMOVIDOS. Apenas yt-dlp baixa vídeos
 *   do YouTube sob demanda do usuário (menu Ferramentas / context-menu).
 *   SponsorBlock + ytguard + bloqueador continuam protegendo o YouTube
 *   comum dentro do NanoDesk. */

let ytdlpProc = null;
let ytdlpBinCached = '';            // 1.8.8: último binário usado (status IPC)
const ytdlpHistory = [];            // 1.8.8: histórico de downloads só RAM
/** Pasta de binários embutidos (resources/bin) — yt-dlp, ffmpeg opcional etc.
 *  1.8.10: usa process.resourcesPath (idiomático Electron) como PRIMEIRA
 *  opção no modo packaged — antes usava app.getAppPath()/.. que só funciona
 *  se o build pipeline colocar bin/ como irmão de app.asar, o que não
 *  acontece com electron-packager sem --extra-resource. */
function binResourcesDir() {
  if (app.isPackaged) {
    // Primeira tentativa: resources/bin (extra-resource pattern)
    try {
      const p = path.join(process.resourcesPath, 'bin');
      if (require('fs').existsSync(p)) return p;
    } catch (_) { /* sem resourcesPath? cai abaixo */ }
    // Segunda tentativa: app.asar/.. /bin (legacy)
    return path.join(app.getAppPath(), '..', 'bin');
  }
  return path.join(app.getAppPath(), 'resources', 'bin');
}

/* ---------------- 1.6.7 — ATUALIZAÇÃO DO YT-DLP ----------------
 * O YouTube muda a cada semana e quebra versões antigas do yt-dlp
 * ("Sign in to confirm you're not a bot", extração falha). A 1.6.x não
 * tinha NENHUM mecanismo de atualização — o download de vídeos degrada
 * com o tempo. Agora: ao iniciar um download, compara a versão local com
 * a latest release oficial (GitHub API, cache de 24 h); se houver novidade,
 * o binário novo é baixado PARA A PASTA TEMPORÁRIA DA SESSÃO (nada fica
 * gravado — coerente com o projeto) e usado no lugar do embutido.
 * Sem internet/atualização: segue o binário local + fallback sem flags
 * novas (yt-dlp antigo rejeitava a linha inteira por causa de --js-runtimes).
 */
const YTDLP_RELEASE_API = 'https://api.github.com/repos/yt-dlp/yt-dlp/releases/latest';
let ytdlpVersionCache = { at: 0, local: '', latest: '', url: '', checked: false };

/* ---------------- 1.9.4 — spawnCapture protegido ----------------
 * Achado da 4ª auditoria: a função spawnCapture() acumulava stdout e stderr
 * em strings SEM LIMITE de bytes. Era usada para consultar `yt-dlp --version`
 * (resposta de 1 linha, inofensiva em si), mas o padrão é perigoso: um
 * subprocesso que produzisse MBs/kBs de saída (binário corrompido, loop,
 * erro verboso) faria o Node alocar strings sem parar. Aplicamos a mesma
 * proteção dos scanners externos (1.9.3 / B4 do RELATORIO-DE-CORRECOES):
 * teto duro de bytes, abate do processo ao exceder e corte multibyte seguro.
 */
const SPAWN_CAPTURE_MAX_BYTES = 64 * 1024;   // 64 KB — bem além de qualquer --version
const SPAWN_CAPTURE_DEFAULT_TIMEOUT = 8000;  // ms

/**
 * Captura stdout+stderr de um subprocesso com TETO de bytes, TIMEOUT real
 * e encerramento em caso de excesso. Nunca lança — devolve { ok, output,
 * truncated } para o caller tratar. O `timeout` do Node apenas manda
 * SIGTERM; aqui garantimos o kill do filho e liberamos os listeners.
 * @param {string} cmd  executável
 * @param {string[]} args  argumentos
 * @param {number} [timeoutMs]  timeout (ms); default 8000
 * @returns {Promise<{ok:boolean, output:string, truncated:boolean}>}
 */
function spawnCapture(cmd, args, timeoutMs) {
  return new Promise((resolve) => {
    const timeout = Number(timeoutMs) > 0 ? Number(timeoutMs) : SPAWN_CAPTURE_DEFAULT_TIMEOUT;
    const chunks = { out: [], err: [] };  // acumula Buffers para corte multibyte seguro
    let totalBytes = 0;
    let truncated = false;
    let settled = false;
    let child;
    let killTimer = null;

    const finish = (ok) => {
      if (settled) return;
      settled = true;
      if (killTimer) { clearTimeout(killTimer); killTimer = null; }
      // Garante que o filho morra mesmo se o evento 'close' demorar (processo-zumbi
      // pendurado em stdout). Tenta SIGTERM; ignora erros (já pode ter saído).
      try { if (child && typeof child.kill === 'function') child.kill('SIGTERM'); } catch (_) { /* ignorado */ }
      // Corte multibyte seguro: concatena Buffers, trunca no teto e decodifica uma única vez.
      const merged = Buffer.concat([...chunks.out, ...chunks.err]);
      const slice = merged.length > SPAWN_CAPTURE_MAX_BYTES
        ? merged.slice(0, SPAWN_CAPTURE_MAX_BYTES)
        : merged;
      resolve({
        ok: !!ok,
        output: slice.toString('utf8').trim(),
        truncated: truncated || merged.length > SPAWN_CAPTURE_MAX_BYTES
      });
    };

    try {
      child = spawn(cmd, args, { windowsHide: true });
    } catch (e) {
      resolve({ ok: false, output: String(e && e.message || e), truncated: false });
      return;
    }

    // 1) Limite de bytes: ao cruzar o teto, paramos de acumular e matamos o filho.
    const onData = (chunk, key) => {
      if (truncated) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8');
      if (totalBytes + buf.length > SPAWN_CAPTURE_MAX_BYTES) {
        const remaining = SPAWN_CAPTURE_MAX_BYTES - totalBytes;
        if (remaining > 0) chunks[key].push(buf.slice(0, remaining));
        totalBytes = SPAWN_CAPTURE_MAX_BYTES;
        truncated = true;
        try { if (typeof child.kill === 'function') child.kill('SIGTERM'); } catch (_) { /* ignorado */ }
        return;
      }
      chunks[key].push(buf);
      totalBytes += buf.length;
    };

    if (child.stdout) child.stdout.on('data', (d) => onData(d, 'out'));
    if (child.stderr) child.stderr.on('data', (d) => onData(d, 'err'));

    child.on('error', (e) => {
      if (settled) return;
      if (killTimer) { clearTimeout(killTimer); killTimer = null; }
      resolve({ ok: false, output: String(e && e.message || e), truncated });
    });
    child.on('close', (code) => finish(code === 0));

    // 2) Timeout efetivo: o `timeout` do child_process só manda SIGTERM uma vez e
    //    não garante o 'close' se o filho tiver handlers de SIGTERM. Aqui matamos
    //    explicitamente e finalizamos a Promise.
    killTimer = setTimeout(() => {
      try { if (child && typeof child.kill === 'function') child.kill('SIGKILL'); } catch (_) { /* ignorado */ }
      // Pequena tolerância para o 'close' chegar; se não vier, finaliza agora.
      setTimeout(() => finish(false), 250);
    }, timeout);
  });
}

async function ytdlpLocalVersion(bin) {
  if (ytdlpVersionCache.local && Date.now() - ytdlpVersionCache.at < 5 * 60 * 1000) {
    return ytdlpVersionCache.local;
  }
  const r = await spawnCapture(bin, ['--version'], 8000);
  // 1.9.4: se o --version devolveu MBs (binário corrompido, loop), o spawnCapture
  // cortou em 64 KB — não confie na "versão" extraída de uma saída truncada.
  if (r.truncated) {
    ytdlpVersionCache.at = Date.now();
    return '';   // tratado como "versão desconhecida" → segue o binário local
  }
  const v = r.ok ? r.output.split(/\r?\n/)[0].trim().slice(0, 24) : '';
  if (v) ytdlpVersionCache.local = v;
  return v;
}

/** Última versão oficial (cache 24 h; falha de rede = segue o binário local). */
let ytdlpProxy = '';   // 1.8.11: socks5h://127.0.0.1:<porta> quando o download deve sair pelo Tor
async function ytdlpLatestRelease(fetchFn) {
  if (ytdlpVersionCache.checked && Date.now() - ytdlpVersionCache.at < 24 * 60 * 60 * 1000) {
    return { latest: ytdlpVersionCache.latest, url: ytdlpVersionCache.url };
  }
  try {
    const res = await (fetchFn || sessionFetch())(YTDLP_RELEASE_API, {
      headers: { 'user-agent': 'nanodesk', 'accept': 'application/vnd.github+json' },
      signal: AbortSignal.timeout ? AbortSignal.timeout(10000) : undefined
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const j = await netLimits.readJsonLimited(res, 2 * 1024 * 1024);
    ytdlpVersionCache.at = Date.now();
    ytdlpVersionCache.checked = true;
    ytdlpVersionCache.latest = String(j.tag_name || '').replace(/^[^\d]*/, '');
    ytdlpVersionCache.url = String(j.html_url || '');
    return { latest: ytdlpVersionCache.latest, url: ytdlpVersionCache.url };
  } catch (_) {
    // 1.8.10: marcar 'checked' mesmo em falha para HONRAR o backoff de 24h
    // (antes: 'checked' ficava false, e a próxima chamada re-martelava a API).
    ytdlpVersionCache.at = Date.now();
    ytdlpVersionCache.checked = true; // mantém latest='' e url='' → UI mostra "indisponível"
    return { latest: '', url: '' };
  }
}

/**
 * Baixa o yt-dlp.exe da última release para a pasta TEMPORÁRIA da sessão.
 * Fonte oficial (github.com/yt-dlp/yt-dlp/releases); o binário NUNCA é
 * gravado fora de SESSION_TMP (morre quando o NanoDesk fecha).
 * @returns {Promise<string>} caminho do binário novo, ou '' em caso de falha
 */
async function ytdlpDownloadUpdate(latestTag, fetchFn) {
  try {
    const doFetch = fetchFn || sessionFetch();
    const base = 'https://github.com/yt-dlp/yt-dlp/releases/download/' + encodeURIComponent(latestTag) + '/';
    const url = base + 'yt-dlp.exe';
    const res = await doFetch(url, {
      signal: AbortSignal.timeout ? AbortSignal.timeout(120000) : undefined
    });
    if (!res.ok) return '';
    // 1.9.2: teto de 64 MB aplicado em STREAMING (antes: só via Content-Length, que pode faltar)
    let buf;
    try { buf = await netLimits.readBodyLimited(res, 64 * 1024 * 1024); } catch (_) { return ''; }
    if (buf.length < 5 * 1024 * 1024) return '';             // resposta truncada/HTML de erro
    // PE real (MZ + e_lfanew + "PE\0\0") — nunca executar algo que não é PE
    if (!securityGateway.isPeBinary(buf.slice(0, 4096))) return '';
    // 1.8.11 (M-01): confere o SHA-256 contra o SHA2-256SUMS publicado NA MESMA release.
    // Fail-closed: sem lista, sem linha do yt-dlp.exe ou hash diferente = NÃO executa.
    const sumsRes = await doFetch(base + 'SHA2-256SUMS', {
      signal: AbortSignal.timeout ? AbortSignal.timeout(20000) : undefined
    });
    if (!sumsRes.ok) return '';
    const sumLine = String(await netLimits.readTextLimited(sumsRes, 256 * 1024)).split(/\r?\n/).map(l => l.trim())
      .find(l => /^[a-fA-F0-9]{64}\s+\*?yt-dlp\.exe$/.test(l));
    const wantHash = sumLine ? sumLine.split(/\s+/)[0].toLowerCase() : '';
    if (!wantHash || crypto.createHash('sha256').update(buf).digest('hex') !== wantHash) return '';
    const dir = path.join(SESSION_TMP, 'ytdlp-update');
    fs.mkdirSync(dir, { recursive: true });
    const target = path.join(dir, 'yt-dlp.exe');
    await fs.promises.writeFile(target, buf);
    return target;
  } catch (_) { return ''; }
}

/**
 * Garante o MELHOR binário de yt-dlp disponível: atualiza se necessário.
 * @returns {Promise<{bin:string, updated:boolean}>}
 */
async function ensureYtDlp(bin, fetchFn) {
  try {
    const [local, rel] = await Promise.all([ytdlpLocalVersion(bin), ytdlpLatestRelease(fetchFn)]);
    if (local && rel.latest && updates.compareVersions(local, rel.latest) < 0) {
      const newBin = await ytdlpDownloadUpdate(rel.latest, fetchFn);
      if (newBin) {
        toast('yt-dlp atualizado (' + local + ' → ' + rel.latest + ') para downloads do YouTube.', 7000);
        return { bin: newBin, updated: true };
      }
      toast('Há uma versão mais nova do yt-dlp (' + rel.latest + ', local: ' + local + ') — não foi possível atualizar agora. Se os downloads falharem, atualize manualmente.', 9000);
    }
  } catch (_) { /* segue com o binário local */ }
  return { bin, updated: false };
}

function startYtDlpDownload(url, retryOpts = null) {
  if (!video.isYoutubeUrl(url)) { toast('Baixe direto do YouTube com yt-dlp (links /watch, /shorts, /embed, youtu.be).'); return; }
  const dirs = [binResourcesDir()];
  const foundBin = video.findYtDlp(undefined, undefined, dirs);
  if (!foundBin) {
    toast('yt-dlp não encontrado em resources\\bin nem no PATH. Reinstale o NanoDesk completo ou instale o yt-dlp (github.com/yt-dlp/yt-dlp). Baixe apenas conteúdos autorizados.', 9000);
    return;
  }
  if (ytdlpProc && ytdlpProc.exitCode === null) { toast('Já existe um download de vídeo em andamento.'); return; }
  // 1.8.11 (achado próprio): o yt-dlp.exe é subprocesso e NÃO herda o proxy do Tor. Em aba Tor
  // ou modo Tor, baixava pela rede direta (IP real exposto ao YouTube/Google) e a checagem de
  // atualização também saía direta. Agora: exige o daemon conectado, passa --proxy socks5h://
  // (DNS remoto) e faz a atualização pela sessão Tor. Sem daemon: bloqueia (fail-closed).
  let ytFetch;
  ytdlpProxy = '';
  if (torRequiredNow()) {
    const port = torMgr && torMgr.phase === 'connected' && torMgr.socksPort ? Number(torMgr.socksPort) : 0;
    if (!port) {
      toast('Download de vídeo bloqueado: o Tor está em uso, mas o daemon não está conectado — o yt-dlp sairia pela rede direta e exporia seu IP. Conecte o Tor (Ctrl+Shift+T) e tente de novo.', 10000);
      return;
    }
    ytdlpProxy = 'socks5h://127.0.0.1:' + port;
    try { const ts = getTorSession(); ytFetch = ts.fetch.bind(ts); } catch (_) { ytFetch = undefined; }
    if (!ytFetch) { ytdlpProxy = ''; toast('Sessão Tor indisponível — download cancelado.', 7000); return; }
  }
  ytdlpBinCached = foundBin;
  // 1.9.4: exporta cookies da sessão ANTES de chamar ensureYtDlp/startYtDlpProcess
  // (exportYtCookiesForYtDlp é async; o ensureYtDlp também — encadeamos).
  Promise.resolve()
    .then(() => exportYtCookiesForYtDlp(url))
    .then((cookiesFile) => ensureYtDlp(foundBin, ytFetch)
      .then(({ bin }) => {
        ytdlpBinCached = bin;
        startYtDlpProcess(bin, url, retryOpts, cookiesFile);
      })
      .catch(() => startYtDlpProcess(foundBin, url, retryOpts, cookiesFile))
    )
    .catch(() => startYtDlpProcess(foundBin, url, retryOpts, ''));
}

/* ---------------- 1.9.4 — exportação de cookies da sessão para o yt-dlp ----------------
 * O YouTube vem apertando a detecção de bot: mesmo com UA coerente e Sec-CH-UA
 * correto, downloads sem cookies de sessão autenticada caem no desafio "Sign in
 * to confirm you're not a bot". Exportamos os cookies da SESSÃO DE NAVEGAÇÃO
 * (a que o usuário já está usando para ver o YouTube) para um arquivo no formato
 * Netscape cookies.txt, dentro de SESSION_TMP (apagado ao fechar o NanoDesk).
 * O yt-dlp recebe --cookies <arquivo> e segue com a mesma sessão do usuário.
 *
 * Formato Netscape: tab-separated, uma linha por cookie (após o cabeçalho).
 * Seguro: o domínio é filtrado para hosts do YouTube/Google (não vaza cookies
 * de outros sites) e o arquivo fica em SESSION_TMP com permissões restritas.
 */
const YT_COOKIE_HOSTS = new Set([
  'youtube.com', '.youtube.com', 'www.youtube.com', 'm.youtube.com', 'music.youtube.com',
  'youtu.be', '.youtu.be',
  'google.com', '.google.com', 'accounts.google.com',
  'youtube-nocookie.com', '.youtube-nocookie.com'
]);

function isYtCookieHost(host) {
  const h = String(host || '').toLowerCase().replace(/^\.+/, '');
  if (!h) return false;
  for (const allowed of YT_COOKIE_HOSTS) {
    const a = String(allowed).replace(/^\.+/, '');
    if (h === a || h.endsWith('.' + a)) return true;
  }
  return false;
}

/**
 * Serializa um cookie Electron no formato Netscape cookies.txt.
 * Documentação: curl.dev/docs/http-cookies — 7 campos tab-separated.
 * @returns {string|null} linha pronta para o arquivo, ou null se o cookie for inválido.
 */
function cookieToNetscapeLine(c) {
  try {
    const domain = String(c.domain || '');
    if (!domain) return null;
    const includeSubdomains = domain.startsWith('.') ? 'TRUE' : 'FALSE';
    const path = String(c.path || '/');
    const secure = c.secure ? 'TRUE' : 'FALSE';
    const expires = String(c.expirationDate || 0);
    const name = String(c.name || '');
    const value = String(c.value || '');
    // Format: domain  includeSubdomains  path  secure  expiration  name  value
    return [
      domain, includeSubdomains, path, secure, expires, name, value
    ].join('\t');
  } catch (_) { return null; }
}

/**
 * Exporta os cookies do YouTube/Google da sessão de navegação para um
 * arquivo cookies.txt em SESSION_TMP. Devolve o caminho do arquivo ou ''
 * em caso de falha. É assíncrono (cookies API do Electron é async).
 * @param {string} urlOrHost  URL ou host da aba atual (define a sessão)
 * @returns {Promise<string>}
 */
async function exportYtCookiesForYtDlp(urlOrHost) {
  try {
    const ses = navSession;
    if (!ses) return '';
    // Pega TODOS os cookies da sessão e filtra só hosts do YouTube/Google.
    // electron session.cookies.get({}) aceita filtro vazio = todos.
    let cookies = [];
    try { cookies = await ses.cookies.get({}); }
    catch (_) { cookies = []; }
    if (!Array.isArray(cookies) || !cookies.length) return '';
    const lines = ['# Netscape HTTP Cookie File', '# Generated by NanoDesk (1.9.4) — apagado ao fechar o app.'];
    let count = 0;
    for (const c of cookies) {
      if (!isYtCookieHost(c.domain)) continue;
      const line = cookieToNetscapeLine(c);
      if (line) { lines.push(line); count++; }
    }
    if (!count) return '';  // sem cookies de YT/Google nesta sessão
    const dir = path.join(SESSION_TMP, 'ytdlp-cookies');
    try { fs.mkdirSync(dir, { recursive: true }); } catch (_) { /* ignorado */ }
    const target = path.join(dir, 'cookies.txt');
    // Tenta restringir permissões no POSIX; no Windows o mkdir acima já é privado do usuário.
    try { fs.writeFileSync(target, lines.join('\n') + '\n', { mode: 0o600 }); }
    catch (_) { fs.writeFileSync(target, lines.join('\n') + '\n'); }
    return target;
  } catch (_) { return ''; }
}

/** Remove o arquivo de cookies temporário do yt-dlp (chamado no close). */
function cleanupYtCookiesFile(file) {
  if (!file) return;
  try { fs.unlinkSync(file); } catch (_) { /* já removido ou não criado */ }
}

function startYtDlpProcess(bin, url, retryOpts, cookiesFile) {
  const dirs = [binResourcesDir()];
  const ffmpegPath = video.findFfmpeg(undefined, undefined, dirs);
  const hasFfmpeg = !!ffmpegPath;
  // O YouTube exige um runtime JS para os desafios de assinatura. Se houver Deno
  // (embutido ou no PATH) o yt-dlp o usa sozinho; senão usamos o próprio Electron
  // como Node (ELECTRON_RUN_AS_NODE) — só no ambiente do yt-dlp, nunca no do app.
  const denoFound = video.findTool('deno', undefined, undefined, dirs);
  const env = Object.assign({}, process.env);
  let jsRuntime = '';
  if (!denoFound) { jsRuntime = process.execPath; env.ELECTRON_RUN_AS_NODE = '1'; }
  const outPattern = path.join(app.getPath('downloads'), '%(title).80s.%(ext)s');
  let tail = '';
  let lastFile = '';
  const keep = (d) => {
    const t = String(d);
    for (const line of t.split(/\r?\n/)) {
      const l = line.trim();
      if (l && !l.startsWith('[') && !/^(WARNING|ERROR|Deleting|Merging|Extracting|Downloading)/i.test(l)) lastFile = l;
      // 1.8.8: progresso percentual/speed -> renderer (onYtdlpProgress)
      const prog = video.parseProgressLine(l);
      if (prog) sendToWin('ytdlp:progress', { percent: prog.percent, speed: prog.speed, done: false });
    }
    tail = (tail + t).slice(-4000);
  };
  try {
    ytdlpProc = spawn(bin, video.ytdlpArgs(url, Object.assign({
      outPath: outPattern,
      quality: settings.get('videoQuality', 'best'),
      hasFfmpeg,
      ffmpegPath: ffmpegPath || '',
      jsRuntime,
      subtitles: settings.get('ytdlpSubtitles', false),
      thumbnail: settings.get('ytdlpThumbnail', false),
      proxy: ytdlpProxy,
      // 1.9.4: cookies da sessão atual + ritmo humano — evita o desafio
      // "Sign in to confirm you're not a bot" que o YouTube aplica a
      // requests sem cookies autenticados.
      cookiesFile: cookiesFile || '',
      sleepRequests: 1
    }, retryOpts || {})), { windowsHide: true, env });
    if (!retryOpts) {
      toast('Baixando vídeo com yt-dlp (pasta Downloads)…' + (hasFfmpeg ? '' : ' (sem ffmpeg: formato único, até ~720p)'), 6000);
      pushSecurityEvent({ kind: 'yt-dlp', host: hostOf(url), detail: 'download iniciado (responsabilidade do usuário)' });
    }
    ytdlpProc.stdout.on('data', keep);
    ytdlpProc.stderr.on('data', keep);
    ytdlpProc.on('close', (code) => {
      ytdlpProc = null;
      // 1.9.4: limpa o cookies.txt temporário em qualquer saída (sucesso ou falha).
      cleanupYtCookiesFile(cookiesFile);
      if (code === 0) {
        toast('Vídeo baixado' + (lastFile ? ': ' + path.basename(lastFile) : '') + '.', 7000);
        // 1.8.8: histórico só RAM (limite 100)
        ytdlpHistory.unshift({ url: String(url || '').slice(0, 500), file: lastFile, ts: Date.now() });
        if (ytdlpHistory.length > 100) ytdlpHistory.length = 100;
        sendToWin('ytdlp:progress', { done: true, file: lastFile });
        return;
      }
      // CORREÇÃO 1.6.7: yt-dlp ANTIGO não conhece --js-runtimes e rejeita a
      // linha de comando inteira — repete UMA vez sem a flag antes de falhar.
      if (retryOpts === null && video.ytdlpUnknownOption(tail)) {
        toast('yt-dlp antigo detectado (sem suporte a runtime JS) — repetindo em modo compatível…', 6000);
        startYtDlpProcess(bin, url, { skipJsRuntime: true }, cookiesFile);
        return;
      }
      const hint = /sign in to confirm|not a bot/i.test(tail)
        ? ' — o YouTube pediu verificação: faça login no YouTube numa aba antes de baixar, ou atualize o yt-dlp'
        : '';
      toast('yt-dlp falhou (código ' + code + '): ' + (video.ytdlpErrorLine(tail) || 'sem detalhes') + hint + ' — baixe apenas conteúdos autorizados.', 10000);
    });
    ytdlpProc.on('error', (e) => {
      ytdlpProc = null;
      cleanupYtCookiesFile(cookiesFile);
      toast('Falha ao iniciar yt-dlp: ' + e.message, 8000);
    });
  } catch (e) {
    cleanupYtCookiesFile(cookiesFile);
    toast('Falha ao iniciar yt-dlp: ' + e.message, 8000);
  }
}

/* ---------------- FASE 5 — estado de rede (VPN/Tor/DoH) ---------------- */

function networkStatePayload() {
  const torActive = settings ? settings.get('torMode', false) : false;
  const warnings = netmgr.leakWarnings({
    tor: { active: torActive, isolated: true },
    webrtcProtected: settings ? settings.get('webrtcProtect', true) : true
  });
  return {
    vpn: netState.vpn,
    tor: { active: torActive, port: settings ? settings.get('torPort', 9050) : 9050, isolated: true },
    webrtcProtected: settings ? settings.get('webrtcProtect', true) : true,
    doh: { provider: settings ? settings.get('secureDns', 'cloudflare') : 'cloudflare', strict: settings ? settings.get('secureDnsStrict', false) : false },
    warnings
  };
}

function pushNetworkState() {
  if (win && !win.isDestroyed()) sendToWin('network:state', networkStatePayload());
}

function refreshVpnState() {
  netState.vpn = netmgr.detectVpnTunnel();
  pushNetworkState();
  return netState.vpn;
}

// Detecção de VPN leve: a cada 12 s apenas com janela aberta.
setInterval(() => {
  if (win && !win.isDestroyed() && settings) refreshVpnState();
}, 12000);

/* ---------------- FASE 4 — StevenBlack hosts (camada de bloqueio) ---------------- */

async function loadStevenBlack() {
  try {
    // 1.6.7: fetch pela SESSÃO (herda Tor SOCKS/DoH) — era o fetch global
    const r = await hostsEngine.fetchStevenBlack(sessionFetch(), 15000);
    hostsDomains = r.domains;
    // 1.8.8: hostsDomainSet = Set(hostsDomains) para .has() O(1) no malwareSiteBlock.
    //   O hostsDomains é um ARRAY (do hosts-engine) — chamar .has() nele crasha.
    try { hostsDomainSet = (hostsDomains && hostsDomains.length) ? new Set(hostsDomains) : new Set(); }
    catch (_) { hostsDomainSet = new Set(); }
    for (const e of allEngines()) e.setHosts(r.domains);
    pushStatsThrottled();
  } catch (_) {
    hostsDomains = null;
    hostsDomainSet = new Set();
    for (const e of allEngines()) e.setHosts(null);
    // silencioso: o painel de listas mostra o status honesto
  }
}

/* ---------------- 1.8.8 — Tor: probe SOCKS + auto-start do daemon embutido ---------------- */

/** Proba rápida se uma porta SOCKS5 está aceitando conexões. (puro) */
function probeSocksPort(port) {
  return new Promise((resolve) => {
    const p = Number(port);
    if (!Number.isFinite(p) || p < 1 || p > 65535) return resolve(false);
    const net = require('net');
    const sock = net.createConnection({ port: p, host: '127.0.0.1' }, () => {
      // SOCKS5 handshake: 0x05 0x00 (no-auth)
      try { sock.write(Buffer.from([0x05, 0x00])); } catch (_) { /* segue */ }
    });
    const t = setTimeout(() => { try { sock.destroy(); } catch (_) {} resolve(false); }, 1200);
    sock.on('error', () => { clearTimeout(t); resolve(false); });
    sock.on('data', (buf) => {
      clearTimeout(t);
      try {
        // 0x05 0x00 = SOCKS5 + no-auth aceito
        resolve(Buffer.isBuffer(buf) && buf.length >= 2 && buf[0] === 0x05);
      } catch (_) { resolve(false); }
      try { sock.destroy(); } catch (_) { /* ignorado */ }
    });
  });
}

/**
 * 1.8.8 — quando o usuário liga torMode, garante que o daemon Tor embutido
 * esteja rodando. Antes, ligar "Tor SOCKS" só mudava o proxy da sessão: se
 * o usuário não conectasse o daemon em Conexão Tor (Ctrl+Shift+T), TODAS as
 * abas caíam (proxy morto). Agora torMode=true arranca o daemon embutido.
 * @returns {Promise<boolean>} true se Tor está conectado (ou já estava).
 */
async function ensureEmbeddedTorForMode() {
  try {
    if (!torMgr) {
      const torDataDir = path.join(SESSION_TMP, 'tor-runtime');
      try { fs.mkdirSync(torDataDir, { recursive: true }); } catch (_) { /* ignorado */ }
      torMgr = torMod.createTorManager({
        resourcesDir: torResourcesDir(),
        dataDir: torDataDir,
        onEvent: onTorEvent
      });
    }
    // já conectado?
    if (torMgr && torMgr.phase === 'connected' && torMgr.socksPort) {
      const ok = await probeSocksPort(torMgr.socksPort);
      if (ok) return true;
    }
    if (torMgr && torMgr.phase !== 'connecting' && torMgr.phase !== 'connected') {
      await torMgr.start();
    }
    return torMgr && torMgr.phase === 'connected';
  } catch (_) { return false; }
}

/* ---------------- 1.8.8 — ClamAV embutido (status payload) ---------------- */

/** Devolve o estado do ClamAV (binário + base de assinaturas). */
async function clamavStatusPayload() {
  const tools = scanToolPaths();
  const out = {
    binary: tools.clamav || null,
    bundled: bundledClamAvPath(),
    databaseDir: clamavDatabaseDir(),
    databaseReady: false,
    version: ''
  };
  try {
    if (out.databaseDir && fs.existsSync(out.databaseDir)) {
      const files = fs.readdirSync(out.databaseDir).filter(f => /^(main|daily|bytecode)\./i.test(f));
      out.databaseReady = files.length >= 2;  // main.cvd + daily.cvd
    }
  } catch (_) { /* sem pasta ainda */ }
  return out;
}

/** 1.9.3 — monta o estado dos motores (ClamAV/YARA/nativo) para o painel de Segurança. */
async function scanEnginesStatus() {
  const tools = scanToolPaths();
  const dir = clamavDatabaseDir();
  let versionText = '';
  if (tools.clamav) {
    try { const r = await securityGateway.runExternal({ cmd: tools.clamav, args: ['--version'], timeoutMs: 8000, maxOutputBytes: 64 * 1024 }); versionText = r.output || ''; } catch (_) { /* sem versão */ }
  }
  return enginesStatus.buildEnginesStatus({
    clamBinary: tools.clamav, clamBundled: tools.clamavBundled, clamVersionText: versionText,
    dbDir: dir, dbPersist: !!settings.get('clamavPersistDb', false),
    dbStatus: clamavDb.dbStatus(dir), dbFiles: enginesStatus.readDbFiles(dir, clamavDb.parseCvdHeader),
    skipReasonText: clamavDbSkipReason ? clamavSkipMessage(clamavDbSkipReason) : '',
    torInUse: torInUse(), yaraBinary: tools.yara, yaraRules: !!process.env.NANODESK_YARA_RULES,
    nativeHashCount: nativeScanner.MALWARE_HASHES.size, appVersion: app.getVersion(), staleDays: CLAMAV_STALE_DAYS
  });
}

/** Pasta da base de assinaturas do ClamAV (SESSION_TMP/clamav-db/). */
function clamavDatabaseDir() {
  // 1.9.2: com clamavPersistDb a base sobrevive entre sessões (userData); senão fica na pasta temporária da sessão
  if (settings && settings.get('clamavPersistDb', false)) return path.join(app.getPath('userData'), 'clamav-db');
  return path.join(SESSION_TMP, 'clamav-db');
}

/** Caminho do binário clamscan.exe EMBUTIDO em resources/clamav/. */
function bundledClamAvPath() {
  try {
    const appPath = app.getAppPath();
    // 1.8.10: process.resourcesPath PRIMEIRO (idiomático Electron em modo packaged).
    // desenvolvimento: appPath/.../resources/clamav/clamscan.exe
    // empacotado: process.resourcesPath/clamav/clamscan.exe
    const cands = process.platform === 'win32' ? [
      (typeof process.resourcesPath === 'string' ? path.join(process.resourcesPath, 'clamav', 'clamscan.exe') : ''),
      path.join(appPath, 'resources', 'clamav', 'clamscan.exe'),
      path.join(appPath, '..', 'clamav', 'clamscan.exe')
    ] : [
      path.join(appPath, 'resources', 'clamav', 'clamscan'),
      path.join(appPath, '..', 'clamav', 'clamscan')
    ].filter(Boolean);
    for (const c of cands) { try { if (c && fs.existsSync(c)) return c; } catch (_) { /* segue */ } }
  } catch (_) { /* sem app pronto ainda */ }
  return null;
}

/** Caminho do binário freshclam.exe EMBUTIDO em resources/clamav/. */
function bundledFreshclamPath() {
  try {
    const appPath = app.getAppPath();
    // 1.8.10: process.resourcesPath PRIMEIRO (mesma lógica do bundledClamAvPath).
    const cands = process.platform === 'win32' ? [
      (typeof process.resourcesPath === 'string' ? path.join(process.resourcesPath, 'clamav', 'freshclam.exe') : ''),
      path.join(appPath, 'resources', 'clamav', 'freshclam.exe'),
      path.join(appPath, '..', 'clamav', 'freshclam.exe')
    ] : [
      path.join(appPath, 'resources', 'clamav', 'freshclam'),
      path.join(appPath, '..', 'clamav', 'freshclam')
    ].filter(Boolean);
    for (const c of cands) { try { if (c && fs.existsSync(c)) return c; } catch (_) { /* segue */ } }
  } catch (_) { /* sem app pronto ainda */ }
  return null;
}

/**
 * 1.8.8 — baixa a base de assinaturas do ClamAV (freshclam.exe embutido) para
 * a pasta temporária da sessão (SESSION_TMP/clamav-db/). Roda UMA vez por
 * sessão; a base morre junto com o app (nada fica gravado — coerente com
 * "100% em memória"). Falha de rede = silenciosa (ClamAV fica sem base,
 * mas o scanner NATIVO continua funcionando).
 * @returns {Promise<boolean>} true se a base está pronta
 */
let clamavDbSkipReason = '';
let clamavDbInflight = null;
let clamavTorConsent = null;      // null | 'yes' | 'no' — decisão de baixar a base PELO TOR (uma vez por sessão)
const CLAMAV_STALE_DAYS = 14;

/** Texto exato (e honesto) de POR QUE o ClamAV não rodou — aparece no veredito do download. */
function clamavSkipMessage(reason) {
  switch (reason) {
    case 'tor': return 'O Tor está em uso e o freshclam sairia pela rede direta (exporia seu IP real).';
    case 'tor-recusado': return 'O Tor está em uso e você recusou baixar a base do ClamAV pelo Tor.';
    case 'tor-desconectado': return 'O Tor está em uso, mas o daemon não está conectado para baixar a base por ele.';
    case 'tor-falhou': return 'O download da base do ClamAV pelo Tor falhou.';
    default: return 'base de assinaturas indisponível (sem rede?)';
  }
}

/** 1.9.2 — baixa a base do ClamAV PELA SESSÃO TOR (o freshclam não herda o proxy). Pede consentimento 1x/sessão. */
async function updateClamavViaTor(dir, haveOld) {
  if (!torMgr || torMgr.phase !== 'connected' || !torMgr.socksPort) { clamavDbSkipReason = 'tor-desconectado'; return false; }
  if (clamavTorConsent === 'no') { clamavDbSkipReason = 'tor-recusado'; return false; }
  if (clamavTorConsent === null) {
    const r = await dialog.showMessageBox(win, {
      type: 'question', buttons: ['Baixar pelo Tor', 'Agora não'], defaultId: 1, cancelId: 1, noLink: true,
      title: 'Base do antivírus (ClamAV)',
      message: haveOld ? 'A base de assinaturas do ClamAV está desatualizada.' : 'O ClamAV precisa baixar a base de assinaturas (~250–350 MB).',
      detail: 'O Tor está em uso, então o download seria feito PELO TOR (lento) para não expor o seu IP.\n' +
        'Sem a base, os arquivos baixados ficam SEM varredura antivírus.' +
        (settings.get('clamavPersistDb', false) ? '' : '\n\nA base só dura esta sessão. Ative "Guardar a base do antivírus" em Configurações para não baixar de novo.')
    });
    clamavTorConsent = r.response === 0 ? 'yes' : 'no';
    if (clamavTorConsent === 'no') { clamavDbSkipReason = 'tor-recusado'; return false; }
  }
  toast('Baixando a base do ClamAV pelo Tor… (pode demorar vários minutos)', 9000);
  let lastToast = 0;
  const ts = getTorSession();
  const r = await clamavDb.updateViaFetch(dir, (u, init) => ts.fetch(u, Object.assign({ redirect: 'follow', credentials: 'omit' }, init || {})), {
    onProgress: (p) => { const n = Date.now(); if (n - lastToast > 15000) { lastToast = n; toast('ClamAV (Tor): ' + p.file + ' ' + (p.bytes / 1048576).toFixed(0) + ' MB' + (p.total ? ' / ' + (p.total / 1048576).toFixed(0) + ' MB' : ''), 4000); } }
  });
  if (!r.ok) { toast('Não foi possível baixar a base do ClamAV pelo Tor: ' + r.reason, 9000); clamavDbSkipReason = 'tor-falhou'; return false; }
  toast('Base do ClamAV atualizada pelo Tor.', 5000);
  return true;
}

/** Garante uma base utilizável. Serializada: vários downloads terminando juntos não repetem diálogo/baixa. */
function ensureClamavDatabase(force) {
  if (!clamavDbInflight) clamavDbInflight = ensureClamavDatabaseInner(!!force).finally(() => { clamavDbInflight = null; });
  return clamavDbInflight;
}

async function ensureClamavDatabaseInner(force) {
  clamavDbSkipReason = '';
  const dir = clamavDatabaseDir();
  try { fs.mkdirSync(dir, { recursive: true }); } catch (_) { /* já existe */ }
  const st = clamavDb.dbStatus(dir);
  if (!force && st.complete && st.ageDays <= CLAMAV_STALE_DAYS) return true;
  const usable = st.complete;                       // base antiga ainda é MELHOR que nenhuma (varredura local, sem rede)
  if (torInUse()) {
    // 1.9.2: freshclam não usa o proxy do Tor; a base vai pela sessão Tor (com consentimento) ou fica a antiga
    const ok = await updateClamavViaTor(dir, usable);
    return ok || usable;
  }
  const freshclam = bundledFreshclamPath();
  if (!freshclam) return usable;
  try {
    const r = await securityGateway.runExternal({ cmd: freshclam, args: ['--datadir=' + dir, '--no-dns'], timeoutMs: 180000 });
    if (r.ran && clamavDb.dbStatus(dir).complete) return true;
  } catch (_) { /* melhor esforço */ }
  return usable;
}

/* ---------------------- atualizações ---------------------- */

async function runUpdateChecks(opts = {}) {
  const results = { electron: null, app: null, checkedAt: Date.now() };
  try { results.electron = await updates.checkElectronUpdate(); }
  catch (e) { results.electron = { checked: false, reason: e.message }; }
  try { results.app = await updates.checkAppUpdate(app.getVersion()); }
  catch (e) { results.app = { checked: false, reason: e.message }; }

  if (results.electron && results.electron.updateAvailable) {
    toast('Atualização do Electron disponível: ' + results.electron.latest +
      ' (NanoDesk usa ' + results.electron.current + '). Segurança recomenda atualizar o aplicativo.');
  }
  if (results.app && results.app.updateAvailable) {
    toast('Nova versão do NanoDesk disponível: ' + results.app.latest +
      (results.app.url ? '' : ''));
  }
  if (opts.manual && results.electron && !results.electron.updateAvailable &&
      !(results.app && results.app.updateAvailable)) {
    // CORREÇÃO 1.5.2: sem internet a checagem falha (checked:false) — antes
    // o aviso dizia "Electron  está em dia" mesmo sem ter verificado nada.
    if (results.electron.checked) {
      toast('Nenhuma atualização disponível. Electron ' + (results.electron.current || '') + ' está em dia.');
    } else {
      toast('Não foi possível verificar atualizações agora' +
        (results.electron.reason ? ' (' + String(results.electron.reason).slice(0, 80) + ')' : '') + '.');
    }
  }
  return results;
}

/**
 * CORREÇÃO 1.6.7: pastas nanodesk-session-* ÓRFÃS no %TEMP% (crash, energia,
 * kill do processo) ficavam para sempre — cada partida criava uma pasta nova
 * e a antiga (com cache, dumps e runtime do Tor) só era apagada no fechamento
 * LIMPO. Agora resíduos com mais de 1 hora são removidos na partida.
 */
function wipeOrphanSessionDirs() {
  try {
    const tmp = os.tmpdir();
    const now = Date.now();
    for (const name of fs.readdirSync(tmp)) {
      if (!/^nanodesk-session-/.test(name)) continue;
      const dir = path.join(tmp, name);
      try {
        const st = fs.statSync(dir);
        // 1.8.11 (P-07): há trava de instância única, então qualquer outra pasta
        // nanodesk-session-* é resíduo de crash. Antes esperava 1 h; agora apaga já
        // (exceto a sessão atual). Margem de 30 s só por segurança.
        if (path.resolve(dir) === path.resolve(SESSION_TMP)) continue;
        if (st.isDirectory() && now - st.mtimeMs > 30 * 1000) {
          fs.rmSync(dir, { recursive: true, force: true });
        }
      } catch (_) { /* ocupada por outra instância: segue */ }
    }
  } catch (_) { /* melhor esforço */ }
}

/* ---------------------- partida ---------------------- */

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (win) { if (win.isMinimized()) win.restore(); win.focus(); }
  });

  app.whenReady().then(async () => {
    app.setAppUserModelId('br.edu.nanodesk');

    // Despejos de memória: pasta criada ANTES de apontar o caminho
    // (app.setPath lança erro quando o diretório não existe).
    const crashDir = path.join(SESSION_TMP, 'crashdumps');
    try {
      fs.mkdirSync(crashDir, { recursive: true });
      app.setPath('crashDumps', crashDir);
    } catch (_) { /* opcional */ }

    // CrashReporter local: dumps ficam só na pasta temporária; NADA é
    // enviado para servidor algum (uploadToServer: false).
    try {
      crashReporter.start({ submitURL: '', uploadToServer: false });
    } catch (_) { /* opcional */ }

    wipeLegacyData();
    initStores();
    wipeOrphanSessionDirs();   // 1.6.7: resíduos de crashes anteriores

    // 1.9.6 (ciclo de dados): a sessão DEFAULT (usada por serviços internos do
    // Chromium) tem spellcheck ATIVO por padrão no Electron — é ela que baixa
    // o en-US.bdic do CDN mesmo com spellcheck:false nas janelas. Desliga aqui
    // e aponta o download de dicionários para um endpoint MORTO em loopback
    // (porta 1): a busca falha instantaneamente, SEM consulta externa e sem
    // arquivo de dicionário no disco. (Electron issue #22995: o download pode
    // ocorrer antes deste código rodar — se o arquivo ainda assim aparecer, é
    // esqueleto estático do Chromium, sem dado de usuário, dentro de SESSION_TMP.)
    try { session.defaultSession.spellCheckerEnabled = false; } catch (_) { /* segue */ }
    try { session.defaultSession.setSpellCheckerDictionaryDownloadURL('http://127.0.0.1:1/'); } catch (_) { /* segue */ }

    // Downloads via electron-dl. CORREÇÃO 1.5.2: o electron-dl só se registra
    // em sessões criadas DEPOIS da chamada (evento 'session-created'). Antes,
    // a sessão anônima era criada primeiro — o electron-dl nunca a enxergava e
    // aviso de executável, limites, lista de downloads e SHA-256 não rodavam.
    try { await initDownloads(); }
    catch (e) { console.warn('[nanodesk:downloads] electron-dl indisponível:', e.message); }

    // 1.9.5 — Gerenciador central de downloads + adaptadores.
    // O electronAdapter wraps o electron-dl existente; aria2Adapter só sobe se o
    // binário aria2c estiver embutido em resources/aria2/ ou no PATH; gopeedAdapter
    // é OPCIONAL (requer NANODESK_GOPEED_URL/TOKEN no env — decisão técnica
    // documentada em gopeed-adapter.js). O manager escolhe engine por tarefa.
    try {
      electronAdapter = createElectronAdapter({
        activeDownloadItems,
        downloads: dl, downloadStore,
        handleNewDownload, pushDownloads, nowId,
        sessionFor: (task) => {
          // Resolve a Session a partir da partition informada (igual applyTorProxy).
          if (!task || !task.sessionPartition) return navSession;
          if (task.sessionPartition === TOR_PARTITION && torSession) return torSession;
          try { return session.fromPartition(task.sessionPartition); } catch (_) { return navSession; }
        }
      });
      aria2Adapter = createAria2Adapter({
        app, isPeBinary: (head) => securityGateway.isPeBinary(head),
        findTool: (name) => video.findTool(name, undefined, undefined, [binResourcesDir && binResourcesDir()]),
        log: (lvl, msg) => { if (lvl === 'error' || lvl === 'warn') console.warn(msg); }
      });
      gopeedAdapter = createGopeedAdapter({
        log: (lvl, msg) => { if (lvl === 'error' || lvl === 'warn') console.warn(msg); }
      });
      dlManager = createDownloadManager({
        electronAdapter, aria2Adapter, gopeedAdapter,
        downloads: dl, downloadStore,
        pushDownloads: () => pushDownloads(),
        toast, pushSecurityEvent,
        app, hostOf,
        // CORREÇÃO 1.9.6 (ERRO 1): partição da sessão Tor + proxy VALIDADO.
        // O manager só aceita motor externo em aba Tor quando o daemon Tor
        // embutido está de fato CONECTADO e tem porta SOCKS real; sem isso,
        // o download é interrompido (nunca conexão direta).
        torPartition: TOR_PARTITION,
        torProxy: () => (torMgr && torMgr.phase === 'connected' && Number(torMgr.socksPort) > 0)
          ? 'socks5://127.0.0.1:' + Number(torMgr.socksPort)
          : null,
        // CORREÇÃO 1.9.6 (ERRO 2): camada CENTRAL de segurança — TODO engine
        // (aria2/Gopeed incluídos) passa pelo mesmo gate do fluxo Electron
        // (limites, destino, Security Gateway, quarentena).
        security: { limits: dl.LIMITS, onComplete: managerDownloadGate, quarantineMove: moveToQuarantine },
        log: (lvl, msg) => { if (lvl === 'error' || lvl === 'warn') console.warn(msg); }
      });
      // recover no boot: se aria2 estiver disponível, sobe o processo e recupera
      // tarefas da sessão anterior (continue=true no boot do aria2).
      dlManager.recover().catch(() => { /* aria2 indisponível: ok */ });
      console.log('[nanodesk:media] detector + gerenciador de downloads prontos (aria2=' +
        (aria2Adapter.isAvailable() ? 'sim' : 'não') + ', gopeed=' +
        (gopeedAdapter.isAvailable() ? 'sim' : 'não') + ')');
    } catch (e) { console.warn('[nanodesk:media] gerenciador central indisponível:', e.message); }

    // Sessão de navegação EM MEMÓRIA: cookies, cache, localStorage,
    // IndexedDB e service workers nunca tocam o disco.
    // Identidade do navegador (1.5.3): UA do Chrome da própria engine,
    // Accept-Language do sistema e client hints coerentes (montados com as
    // marcas que a engine reporta — a interface repassa via 'identity:report').
    // Definida ANTES da primeira sessão para valer em todas (applySessionSettings).
    // 1.9.4: secChUa NÃO inicia mais null — antes a primeira requisição a
    // qualquer site (incluindo YouTube) saía SEM Sec-CH-UA e o YouTube
    // respondia com JSON em vez de HTML ("Só a janela de UI aparece em /json").
    // Agora montamos um fallback síncrono coerente com o UA (Google Chrome
    // + Chromium + grease); quando o renderer reporta as marcas reais da
    // engine via identity:report, o fallback é trocado pela lista "viva".
    const fallbackList = identity.fallbackBrandList(process.versions.chrome);
    const fallbackSecChUa = identity.serializeBrandList(fallbackList);
    const baseIdentity = {
      userAgent: identity.chromeUserAgent(process.versions.chrome, process.platform),
      acceptLanguage: identity.acceptLanguages(app.getLocale()),
      secChUa: fallbackSecChUa || null,
      secChUaMobile: '?0',
      chPlatform: identity.CH_PLATFORM[process.platform] || '"Windows"'
    };
    browserIdentity = baseIdentity;
    // CORREÇÃO 1.6.7: abas Tor usam identidade NORMALIZADA (en-US) —
    // o idioma do sistema (ex.: pt-BR) reduzia o conjunto de anonimato
    // e ligava a sessão Tor à normal quando o mesmo site via as duas.
    torIdentity = Object.assign({}, baseIdentity, { acceptLanguage: 'en-US,en' });

    navSession = session.fromPartition(MEM_PARTITION);
    try { navSession.clearCache(); } catch (_) { /* ignorado */ }
    try { navSession.clearStorageData(); } catch (_) { /* ignorado */ }

    // Páginas dos leitores internos (PDF/ebook) — o esquema ndr:// precisa
    // estar registrado na sessão padrão (interface) E na de navegação
    // (as abas-leitor usam a mesma partição anônima).
    try {
      protocol.handle('ndr', serveReaders);
      navSession.protocol.handle('ndr', serveReaders);
    } catch (e) {
      console.warn('[nanodesk:readers] protocolo ndr:// indisponível:', e.message);
    }

    // UA padrão de navegador (melhor compatibilidade e compatível com o
    // login do Google; remove a marca Electron).
    try { app.userAgentFallback = browserIdentity.userAgent; } catch (_) { /* opcional */ }

    // Bloqueador de anúncios: UM motor por sessão (padrão agora;
    // contêineres criam os seus sob demanda via engineFor).
    // applySessionSettings já aplica UA/DNT/cookies-3p/Tor/permissões/
    // preload de fingerprinting nesta sessão.
    engine = engineFor(MEM_PARTITION);
    loadGhosteryEngine();
    loadStevenBlack();
    refreshVpnState();
    // 1.8.8: startVideoHealthLoop REMOVIDO (Piped/Invidious/FreeTube fora).
    // 1.8.10: Tor auto-start MOVIDO para depois de torMgr = createTorManager
    // (estava ANTES — race condition: ensureEmbeddedTorForMode criava uma
    // instância #1 e startava o daemon; depois a linha mais abaixo criava
    // uma instância #2 SEM start, sobrescrevendo torMgr. O daemon ficava
    // vivo na porta 9050 mas torMgr.phase === 'off' para todo o resto).

    // Proteções ativas (1.5.1 — Popup-Blocker-Pro + RedirectGuard):
    // núcleos em RAM, ligados pelas configurações da sessão.
    popupGuard = popupBlocker.createPopupBlocker();
    redirectGuard = redirectGuardMod.createRedirectGuard();
    popupGuard.setEnabled(settings.get('popupBlockerEnabled', true));
    redirectGuard.setEnabled(settings.get('redirectGuardEnabled', true));

    // Leitor de notícias (1.4.0): inscrições e estado "lido" só na memória;
    // feeds buscados pela mesma sessão anônima da navegação.
    initReader();

    // Privacidade: cabeçalhos DNT + GPC + cookies de terceiros — AGORA em
    // applySessionSettings (uma vez por sessão, com contêineres inclusos).

    // Leitores 1.5.0: a detecção de PDF/ebook pelo Content-Type é instalada por
    // sessão em applySessionSettings (padrão, contêineres e Tor — 1.6.1).

    // Tor NATIVO (1.5.3): gerenciador do daemon embutido. A sessão das abas Tor
    // só é criada quando o usuário conecta (getTorSession) — nunca existe uma
    // sessão de Tor sem o proxy definido. Dados do daemon: pasta TEMPORÁRIA da
    // sessão (apagada ao fechar o NanoDesk).
    const torDataDir = path.join(SESSION_TMP, 'tor-runtime');
    try { fs.mkdirSync(torDataDir, { recursive: true }); } catch (_) { /* ignorado */ }
    applyDohRuntime();   // 1.6.2
    torMgr = torMod.createTorManager({
      resourcesDir: torResourcesDir(),
      dataDir: torDataDir,
      onEvent: onTorEvent
    });

    // 1.8.10: Tor auto-start APÓS torMgr canônico (evita a race condition
    // documentada acima). Se o usuário ligou torMode numa sessão anterior
    // (perfil local) e o daemon embutido está disponível, sobe sozinho.
    if (settings && settings.get('torMode', false) === true) {
      ensureEmbeddedTorForMode().catch(() => { /* sem daemon ou rede — segue */ });
    }

    // Canais IPC das páginas-leitor (validados por origem ndr://readers/)
    registerFrameInitIpc();   // 1.6.3
    registerReaderIpc();

    // Flag sincrona lida pelo preload de anti-fingerprinting (1.6.0):
    // devolve SOMENTE um booleano (nada sensível).
    ipcMain.on('nanodesk:fp-enabled', (event) => {
      try { event.returnValue = settings ? settings.get('fingerprintProtect', true) : true; }
      catch (_) { event.returnValue = true; }
    });

    // Certificados (FASE 3): SEMPRE negados (o padrão do Electron já nega;
    // aqui o evento fica registrado no painel de segurança).
    app.on('certificate-error', (event, wc, url, error, certificate, callback) => {
      pushSecurityEvent({
        kind: 'certificado',
        host: hostOf(url),
        level: 'suspeito',
        detail: 'Certificado rejeitado: ' + String(error || '').slice(0, 140)
      });
      toast('Certificado inválido em ' + (hostOf(url) || 'site') + ' — conexão bloqueada.', 6000);
      callback(false);
    });

    registerIpc();
    buildMenu();
    createWindow();

    // Verificação de atualizações NO ARRANQUE — CORREÇÃO 1.6.7: virou
    // OPT-IN (Configurações > "Verificar atualizações automaticamente").
    // Um navegador de privacidade não devia contatar endoflife.date por
    // conta própria a cada partida; o menu "Verificar atualizações…"
    // continua funcionando sempre (ação explícita do usuário).
    if (!SELFTEST && settings && settings.get('updateCheck', false) === true) {
      runUpdateChecks().catch(() => { /* rede pode estar fora */ });
    }

    // Primeira aba: Nova Aba limpa (sessão anônima sempre começa vazia).
    createTab(null);

    // Auto-teste de inicialização (usado na validação do build)
    if (SELFTEST) {
      setTimeout(() => {
        const t = createTab('data:text/html,<title>selftest</title><h1>ok</h1>');
        if (t && t.view) { /* did-finish-load imprime SELFTEST-WEBVIEW-OK */ }
      }, 800);
      setTimeout(() => { console.log('SELFTEST-FAIL-TIMEOUT'); app.exit(1); }, 20000);
    }
  });

  app.on('window-all-closed', () => app.quit());

  // Encerramento: nada a gravar. Toda a sessão (abas, cookies, cache,
  // favoritos, histórico, configurações, lista de downloads) morre junto
  // com o processo; a pasta temporária exclusiva é apagada.
  app.on('before-quit', () => {
    clearCopiedSecret();   // 1.9.1: não deixa senha copiada na área de transferência
    if (boundsTimer) { clearTimeout(boundsTimer); boundsTimer = null; }
    if (statsTimer) { clearTimeout(statsTimer); statsTimer = null; }
    if (protTimer) { clearTimeout(protTimer); protTimer = null; }
    if (mediaPollTimer) { clearInterval(mediaPollTimer); mediaPollTimer = null; }   // 1.9.5
    // 1.6.0: subprocesso de vídeo não deve sobreviver ao app
    try { if (ytdlpProc && ytdlpProc.exitCode === null) ytdlpProc.kill(); } catch (_) { /* ignorado */ }
    translateConsent.clear();
    try { if (torMgr) torMgr.killNow(); } catch (_) { /* ignorado */ } // 1.6.1: encerra o daemon Tor embutido
    // 1.9.5: encerra aria2c/Gopeed gracefully (shutdown do manager)
    if (dlManager) { try { dlManager.shutdown().catch(() => {}); } catch (_) { /* ignorado */ } }
    for (const t of tabList) destroyView(t);
    try { fs.rmSync(SESSION_TMP, { recursive: true, force: true }); }
    catch (_) { /* Windows pode segurar arquivos por alguns ms */ }
    // 1.9.6 (ciclo de dados): o shutdown do Chromium pode RE-CRIAR um esqueleto
    // (Session Storage/Cache vazios, Local State, Preferences) DEPOIS deste
    // handler — o flush final acontece entre o before-quit e a morte real do
    // processo. O apagamento decisivo roda no ÚLTIMO gancho síncrono que
    // existe ('exit' do processo), quando todo o teardown do Chromium já
    // terminou. Idempotente: se before-quit já apagou tudo, não faz nada.
    process.once('exit', () => {
      try { fs.rmSync(SESSION_TMP, { recursive: true, force: true }); } catch (_) { /* melhor esforço */ }
    });
    // Cinto e suspensório: o flush do Chromium pode acontecer DEPOIS até do
    // gancho 'exit' do Node (teardown nativo pós-Node). Filho DESTACADO dorme
    // 2 s, espera o app morrer e apaga a pasta inteira — apaga inclusive o que
    // o shutdown escrever no fim. Se falhar, o órfão é apagado no próximo boot
    // (wipeOrphanSessionDirs; a pasta já terá > 30 s de idade).
    try {
      if (process.platform === 'win32') {
        spawn('cmd.exe', ['/c', 'timeout /t 2 /nobreak >nul & rmdir /s /q "' + SESSION_TMP + '"'],
          { detached: true, stdio: 'ignore', windowsHide: true }).unref();
      } else {
        spawn('/bin/sh', ['-c', 'sleep 2; rm -rf "$1"', '--', SESSION_TMP],
          { detached: true, stdio: 'ignore' }).unref();
      }
    } catch (_) { /* melhor esforço */ }
  });
}

/* ---------------------- motor Ghostery (EasyList + EasyPrivacy + uBlock) ----------------------
 *
 * CORREÇÃO 1.6.7 — a 1.6.x re-baixava TODAS as listas e re-parseava ~130 mil
 * filtros A CADA PARTIDA (o cache do motor ficava na pasta temporária, apagada
 * no fechamento), com 3 tentativas por URL × 14 URLs no GitHub. Sintomas:
 * startup de até ~45 s, telas brancas e "anúncios passando" quando o download
 * falhava em silêncio (o motor ficava morto para sempre — só console.warn).
 *
 * CORREÇÃO 1.6.8 — o nome do arquivo de cache ganhou VERSÃO
 * (filters-engine-<SCHEMA>.bin): motor serializado das 1.6.x antigas podia
 * ter sido construído SEM quick-fixes/unbreak (sem os scriptlets anti-adblock
 * do YouTube) e seria reutilizado para sempre. Cache antigo é apagado e o
 * motor é reconstruído do pacote embutido novo na primeira partida.
 *
 * Novo fluxo:
 *  1. CACHE PERSISTENTE (userData/cache-filtros/filters-engine-<SCHEMA>.bin):
 *     start seguinte carrega do disco (sem rede, sem parse de texto);
 *  2. SEM cache: parse do snapshot EMBUTIDO (offline, imediato) — o app
 *     abre protegido MESMO sem internet;
 *  3. EM SEGUNDO PLANO: se a fonte veio do embutido ou o cache está velho
 *     (>24 h), baixa as listas do dia e troca o motor ativo (e grava o
 *     novo cache para o próximo start);
 *  4. FALHA TOTAL: nova tentativa automática em 60 s (até 5) + aviso na UI.
 */
const GHOSTERY_REFRESH_MS = 24 * 60 * 60 * 1000;   // listas novas: no máx. 1×/dia
const GHOSTERY_RETRY_MS = 60 * 1000;
let ghosteryRetriesLeft = 5;
let ghosteryRefreshBusy = false;

function applyGhostery(blocker, source) {
  ghosteryBlocker = blocker;
  ghosteryState.ready = true;
  ghosteryState.source = source;
  ghosteryState.lastError = '';
  cosmeticsGen++;               // 1.6.7: invalida o cache de scriptlets/CSS
  cosmeticsCache.clear();
  for (const e of allEngines()) e.setGhostery(blocker);
  pushStatsThrottled();
}

function scheduleGhosteryRetry(reason) {
  ghosteryState.ready = false;
  ghosteryState.lastError = String(reason || 'desconhecida').slice(0, 160);
  if (ghosteryRetryTimer || SELFTEST) return;
  if (ghosteryRetriesLeft <= 0) {
    toast('Bloqueador: não foi possível carregar o motor de filtros (' + ghosteryState.lastError + '). Reinicie o NanoDesk para tentar de novo.', 10000);
    return;
  }
  ghosteryRetriesLeft--;
  ghosteryRetryTimer = setTimeout(() => {
    ghosteryRetryTimer = null;
    loadGhosteryEngine().catch(() => {});
  }, GHOSTERY_RETRY_MS);
}

/** Parse do pacote EMBUTIDO (verificado por SHA-256) — offline, sem rede.
 *  CORREÇÃO 1.6.8: o pacote passou a acompanhar o MESMO conjunto do modo
 *  online (uAssets filters por ano + quick-fixes — scriptlets anti-adblock
 *  do YouTube — + unbreak + badware + privacy + resource-abuse). */
const EMBEDDED_LIST_URLS = [
  'bundled://easylist.txt', 'bundled://easyprivacy.txt', 'bundled://ublock.txt',
  'bundled://ublock-2020.txt', 'bundled://ublock-2021.txt', 'bundled://ublock-2022.txt',
  'bundled://ublock-2023.txt', 'bundled://ublock-2024.txt', 'bundled://ublock-2025.txt',
  'bundled://badware.txt', 'bundled://privacy.txt', 'bundled://resource-abuse.txt',
  'bundled://quick-fixes.txt', 'bundled://unbreak.txt'
];

async function parseEmbeddedGhostery(extraText) {
  const { ElectronBlocker } = require('@ghostery/adblocker-electron');
  const bundle = filtersBundle.loadBundle(path.join(__dirname, '..', '..', 'resources', 'filters'));
  const bundleFor = (url) => (String(url).includes('extra-filters') ? (extraText || '') : bundle.for(url));
  const shimFetch = (url) => Promise.resolve({
    ok: true,
    status: 200,
    text: async () => bundleFor(url),
    json: async () => JSON.parse(bundleFor(url))
  });
  return ElectronBlocker.fromLists(
    shimFetch,
    EMBEDDED_LIST_URLS.concat(extraText ? ['bundled://extra-filters.txt'] : []),
    {},
    undefined
  );
}

/**
 * CORREÇÃO 1.6.7 (privacidade): as listas eram baixadas com o fetch GLOBAL —
 * fora do proxy/DoH do app: em modo Tor, o download das listas saía pela
 * rota DIRETA do SO (o IP real era revelado ao CDN das listas). Agora as
 * descargas usam a sessão de navegação (herda proxy Tor SOCKS/DoH).
 */
function sessionFetch() {
  try { return navSession ? navSession.fetch.bind(navSession) : fetch; }
  catch (_) { return fetch; }
}

/** Renova as listas do dia em segundo plano (só quando faz sentido). */
async function refreshGhosteryInBackground() {
  if (ghosteryRefreshBusy || process.env.NANODESK_EXTRA_FILTERS) return;
  ghosteryRefreshBusy = true;
  try {
    const { ElectronBlocker } = require('@ghostery/adblocker-electron');
    // fromLists SEM caching = sempre busca as listas do dia (ignora o cache)
    const blocker = await ElectronBlocker.fromLists(sessionFetch(),
      ['https://easylist.to/easylist/easylist.txt',
       'https://easylist.to/easylist/easyprivacy.txt',
       'https://raw.githubusercontent.com/uBlockOrigin/uAssetsCDN/main/filters/filters.txt',
       'https://raw.githubusercontent.com/uBlockOrigin/uAssetsCDN/main/filters/filters-2020.txt',
       'https://raw.githubusercontent.com/uBlockOrigin/uAssetsCDN/main/filters/filters-2021.txt',
       'https://raw.githubusercontent.com/uBlockOrigin/uAssetsCDN/main/filters/filters-2022.txt',
       'https://raw.githubusercontent.com/uBlockOrigin/uAssetsCDN/main/filters/filters-2023.txt',
       'https://raw.githubusercontent.com/uBlockOrigin/uAssetsCDN/main/filters/filters-2024.txt',
       'https://raw.githubusercontent.com/uBlockOrigin/uAssetsCDN/main/filters/filters-2025.txt',
       'https://raw.githubusercontent.com/uBlockOrigin/uAssetsCDN/main/filters/badware.txt',
       'https://raw.githubusercontent.com/uBlockOrigin/uAssetsCDN/main/filters/quick-fixes.txt',
       'https://raw.githubusercontent.com/uBlockOrigin/uAssetsCDN/main/filters/privacy.txt',
       'https://raw.githubusercontent.com/uBlockOrigin/uAssetsCDN/main/filters/resource-abuse.txt',
       'https://raw.githubusercontent.com/uBlockOrigin/uAssetsCDN/main/filters/unbreak.txt']);
    applyGhostery(blocker, 'online');
    // grava o cache para o PRÓXIMO start (escrita atômica tmp → rename)
    try {
      const cacheFile = engineCacheFile();
      const tmp = cacheFile + '.tmp';
      await fs.promises.writeFile(tmp, await blocker.serialize());
      await fs.promises.rename(tmp, cacheFile);
    } catch (_) { /* disco cheio/readonly: cache continua o antigo */ }
  } catch (_) {
    // silencioso: o motor atual (cache/embutido) continua protegendo
  } finally {
    ghosteryRefreshBusy = false;
  }
}

async function loadGhosteryEngine() {
  // Modo de desenvolvimento/testes: força o pacote embutido (+ extras).
  if (process.env.NANODESK_EXTRA_FILTERS) {
    try {
      let extraText = '';
      try { extraText = fs.readFileSync(process.env.NANODESK_EXTRA_FILTERS, 'utf8'); } catch (_) { /* ignora */ }
      const blocker = await parseEmbeddedGhostery(extraText);
      applyGhostery(blocker, 'embutido');
      return;
    } catch (e) {
      console.warn('[nanodesk:adblock] Embutido indisponível:', e.message);
      scheduleGhosteryRetry(e.message);
      return;
    }
  }

  const { ElectronBlocker } = require('@ghostery/adblocker-electron');
  const cacheFile = engineCacheFile();

  // CORREÇÃO 1.6.8: caches de schema antigo (motor SEM quick-fixes = YouTube
  // em loop) são removidos uma única vez por partida.
  cleanupLegacyEngineCaches();

  // 1) CACHE do motor (binário já parseado): sem rede e com deserialize
  //    bem mais rápido que o parse de texto (~10× menos trabalho no main).
  try {
    const st = await fs.promises.stat(cacheFile);
    const buffer = await fs.promises.readFile(cacheFile);
    const blocker = await ElectronBlocker.deserialize(buffer);
    applyGhostery(blocker, 'cache');
    ghosteryState.updatedAt = st.mtimeMs;
    // listas do dia: renova em segundo plano SOMENTE se o usuário ligou
    // (FASE 3/1.9.6: filterAutoRefresh, opt-in — sem consulta automática).
    if (Date.now() - st.mtimeMs > GHOSTERY_REFRESH_MS &&
        settings && settings.get('filterAutoRefresh', false) === true) {
      setTimeout(() => { refreshGhosteryInBackground().catch(() => {}); }, 30000).unref?.();
    }
    return;
  } catch (_) { /* sem cache ou corrompido: segue para o embutido */ }

  // 2) EMBUTIDO (offline-first): o app abre protegido sem esperar rede.
  try {
    const blocker = await parseEmbeddedGhostery('');
    applyGhostery(blocker, 'embutido');
    // grava o cache e, em segundo plano, tenta as listas do dia
    try {
      const tmp = cacheFile + '.tmp';
      await fs.promises.writeFile(tmp, await blocker.serialize());
      await fs.promises.rename(tmp, cacheFile);
    } catch (_) { /* melhor esforço */ }
    // 1.9.6 (FASE 3): renovação automática removida — só ação manual do
    // usuário (menu Ferramentas > "Atualizar listas de filtros") ou opt-in
    // explícito em Configurações (filterAutoRefresh).
    if (settings && settings.get('filterAutoRefresh', false) === true) {
      setTimeout(() => { refreshGhosteryInBackground().catch(() => {}); }, 30000).unref?.();
    }
    return;
  } catch (e) {
    console.warn('[nanodesk:adblock] Embutido indisponível:', e.message);
  }

  // 3) ONLINE direto (último recurso: embutido falhou — pacote adulterado?)
  try {
    const blocker = await ElectronBlocker.fromPrebuiltAdsAndTracking(sessionFetch(), {}); // sem cache: não suja disco com falha parcial
    applyGhostery(blocker, 'online');
    try {
      const tmp = cacheFile + '.tmp';
      await fs.promises.writeFile(tmp, await blocker.serialize());
      await fs.promises.rename(tmp, cacheFile);
    } catch (_) { /* melhor esforço */ }
  } catch (e) {
    console.warn('[nanodesk:adblock] Motor Ghostery indisponível nesta sessão:', e.message);
    scheduleGhosteryRetry(e.message);
  }
}

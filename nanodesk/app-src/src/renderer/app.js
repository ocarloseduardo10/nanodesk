/**
 * NanoDesk — Interface (renderer) 1.3.0
 * ==================================================================
 * Vanilla JS, sem frameworks. O renderer é um CLIENTE FINO:
 *  - as abas são WebContentsView no processo principal; aqui existem
 *    apenas os registros espelhados (título, URL, favicon, áudio…);
 *  - toda ação vira um comando api.tabs.*; o main responde com o
 *    estado consolidado (api.tabs.onState);
 *  - o retângulo de #view-area é reportado ao main (tabs:bounds) para
 *    posicionar as views nativas — na troca de tamanho, maximizar,
 *    painel aberto e mudança de escala do Windows;
 *  - favoritos (só memória), downloads (electron-dl), bloqueador
 *    nativo + Ghostery, configurações e Nova Aba limpa.
 */
'use strict';

const api = window.nanodesk;
const validation = window.NanoDeskValidation;
const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));

/* ---------------- ícones (SVG inline, sem dependências) ---------------- */

const ICONS = {
  back: '<path d="M19 12H5M12 19l-7-7 7-7"/>',
  fwd: '<path d="M5 12h14M12 5l7 7-7 7"/>',
  reload: '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
  home: '<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>',
  star: '<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>',
  up: '<polyline points="18 15 12 9 6 15"/>',
  down: '<polyline points="6 9 12 15 18 9"/>',
  ext: '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
  folder: '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  menu: '<line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/>',
  x: '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
  min: '<line x1="5" y1="12" x2="19" y2="12"/>',
  max: '<rect x="5" y="5" width="14" height="14" rx="2"/>',
  restore: '<rect x="4" y="8" width="12" height="12" rx="2"/><path d="M8 4h12v12"/>',
  plus: '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
  search: '<circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.5" y2="16.5"/>',
  lock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  warn: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
  // 1.6.1 — cebola (Tor nativo)
  onion: '<path d="M4.5 12.5a7.5 7.5 0 1 0 15 0c0-4.6-3.4-8.4-7.5-9.5-4.1 1.1-7.5 4.9-7.5 9.5z"/><path d="M7.5 12.5a4.5 4.5 0 0 0 9 0c0-2.8-2-5.1-4.5-5.8-2.5.7-4.5 3-4.5 5.8z"/><circle cx="12" cy="12.5" r="1.4"/>',
  net: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 4 5.6 4 9s-1.5 6.4-4 9c-2.5-2.6-4-5.6-4-9s1.5-6.4 4-9z"/>',
  trash: '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>',
  clock: '<circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15.5 14"/>',
  moon: '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
  refresh: '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
  rss: '<path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/>',
  pdf: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="16" y2="17"/>',
  epub: '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>',
  archive: '<rect x="3" y="3" width="18" height="5" rx="1"/><path d="M5 8v11a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8"/><path d="M12 11v6"/><path d="m9 14 3 3 3-3"/>',
  book: '<path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/>',
  popup: '<rect x="3" y="8" width="12" height="10" rx="2"/><path d="M8 8V6a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-2"/><line x1="6" y1="11" x2="12" y2="17"/><line x1="12" y1="11" x2="6" y2="17"/>',
  route: '<polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/>',
  gear: '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>',
  check: '<polyline points="20 6 9 17 4 12"/>',
  // 1.7.0 — copiar (biblioteca de traduções)
  copy: '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  // 1.9.5 — mídia: player de vídeo (retângulo com triângulo play), distinto de download/rss/book
  media: '<rect x="3" y="6" width="18" height="12" rx="2"/><polygon points="11 9 11 15 15 12"/>'
};

function svg(name, size) {
  return '<svg width="' + (size || 16) + '" height="' + (size || 16) + '" viewBox="0 0 24 24" fill="none" ' +
    'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    (ICONS[name] || '') + '</svg>';
}

$$('[data-icon]').forEach(el => { el.insertAdjacentHTML('afterbegin', svg(el.dataset.icon)); });

/* A CSP (style-src 'self') bloqueia atributos style="" inline; por isso as
   cores por site vão em data-hue e são aplicadas via CSSOM, que é permitido. */
function paintHues(node) {
  if (node.dataset && node.dataset.hue) node.style.background = 'hsl(' + node.dataset.hue + ',30%,40%)';
  if (node.querySelectorAll) node.querySelectorAll('[data-hue]').forEach(el => {
    el.style.background = 'hsl(' + el.dataset.hue + ',30%,40%)';
  });
}
new MutationObserver((muts) => {
  for (const m of muts) m.addedNodes.forEach(n => { if (n.nodeType === 1) paintHues(n); });
}).observe(document.body, { childList: true, subtree: true });

/* ---------------- constantes ---------------- */

const ENGINES = {
  duckduckgo: (q) => 'https://duckduckgo.com/?q=' + encodeURIComponent(q),
  bing: (q) => 'https://www.bing.com/search?q=' + encodeURIComponent(q),
  google: (q) => 'https://www.google.com/search?q=' + encodeURIComponent(q),
  startpage: (q) => 'https://www.startpage.com/sp/search?query=' + encodeURIComponent(q),
  // 1.6.0 FASE 7: Brave Search e SearXNG (instância própria configurável)
  brave: (q) => 'https://search.brave.com/search?q=' + encodeURIComponent(q),
  searxng: (q) => {
    const base = String(settings.searxngUrl || '').trim().replace(/\/+$/, '');
    if (!/^https?:\/\//i.test(base)) return ENGINES.duckduckgo(q);
    return base + '/search?q=' + encodeURIComponent(q);
  }
};

/* ---------------- estado global ---------------- */

let settings = null;
let versions = { app: '1.7.3', electron: '-', chrome: '-' };
let tabs = [];            // registros espelhados do main (fonte: tabs:state)
let activeId = null;
let currentPanel = null;
let favoritesCache = [];
let blockStats = { enabled: true, session: 0, total: 0, native: 0, ghostery: 0, lists: 'nativas' };
/* 1.5.1 — Proteções (Popup-Blocker-Pro + RedirectGuard): estatísticas em RAM */
let protectionStats = {
  popup: { enabled: true, total: 0, tab: 0 },
  redirect: { enabled: true, total: 0, domain: 0, chain: 0, clickTraps: 0, maxHops: 7, windowMs: 15000 }
};

/* estado do Leitor de notícias / Modo Leitura (1.4.0) — tudo em RAM */
let readerState = {
  view: 'list',        // list | article | page | trans
  feedId: 'all',
  feeds: [],
  items: [],
  article: null,
  page: null,
  loadingPage: false,
  adding: false,
  refreshing: false
};

/* 1.5.3 — estado da conexão Tor (espelhado do main) */
let torState = {
  state: 'off',        // off | starting | bootstrapping | connected | stopping | error
  progress: 0,
  tag: '',
  summary: '',
  error: '',
  supported: true,
  check: null          // resultado da última verificação (check.torproject.org)
};

/* 1.6.0 — rede (FASE 5), segurança (FASE 6) e contêineres (FASE 2) */
let netState = {
  vpn: { connected: false, kind: '', interfaces: [] },
  tor: { active: false, port: 9050, isolated: true },
  webrtcProtected: true,
  doh: { provider: 'cloudflare', strict: false },
  warnings: []
};
let securityLogCache = [];
let containersList = [{ id: 'padrao', name: 'Padrão', color: '#4f8cff' }];
let historyQuery = '';
// 1.8.9 — cofre de senhas nativo
let vaultState = { enabled: true, initialized: false, unlocked: false, itemCount: 0, autolockMinutes: 15 };
let vaultPendingFill = false;   // após desbloqueio, retoma o preenchimento
let vaultQuery = '';            // busca atual no painel
let vaultEditId = null;         // id em edição (null = novo)
let vaultReveal = {};           // ids com senha revelada

/* ---------------- utilitários ---------------- */

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function hue(str) {
  let h = 0;
  for (const ch of String(str)) h = (h * 31 + ch.charCodeAt(0)) % 360;
  return h;
}

function hostOf(u) {
  try { return new URL(u).hostname.replace(/^www\./, ''); } catch (e) { return ''; }
}

function fmtTime(ts) {
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function fmtDate(ts) {
  const d = new Date(ts);
  return d.toLocaleDateString([], { day: '2-digit', month: 'short' }) + ' ' + fmtTime(ts);
}

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n >= 100 ? 0 : 1).replace('.', ',') + ' ' + u[i];
}

function toast(msg, ms) {
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), ms || 4200);
}

/* ---------------- abrir no navegador padrão ---------------- */

const GOOGLE_LOGIN_HOST = 'accounts.google.com';

function externalTargetFor(t) {
  if (!t || !t.url || !/^https?:\/\//i.test(t.url)) return null;
  // na tela de login do Google, abre o site de onde o usuário veio
  if (hostOf(t.url) === GOOGLE_LOGIN_HOST && t.lastSiteUrl) return t.lastSiteUrl;
  return t.url;
}

/* ---------------- barra de endereço e navegação ---------------- */

function normalizeInput(input) {
  const s = String(input || '').trim();
  if (!s) return null;
  if (/^https?:\/\//i.test(s)) return validation.isHttpUrl(s) ? s : null;
  if (/^nanodesk:/i.test(s)) return null;
  if (/^localhost(:\d+)?([\/?#].*)?$/i.test(s)) {
    const localUrl = 'http://' + s;
    return validation.isHttpUrl(localUrl) ? localUrl : null;
  }
  if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?([\/?#].*)?$/.test(s)) {
    const ipUrl = 'http://' + s;
    return validation.isHttpUrl(ipUrl) ? ipUrl : null;
  }
  if (/\s/.test(s) || !s.includes('.')) return searchUrl(s);
  // 1.6.1: endereço .onion sem esquema vira http:// (serviços onion costumam não ter HTTPS;
  // o Tor já criptografa o trajeto). Com esquema explícito, respeita o que foi digitado.
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)*\.onion(:\d{1,5})?([\/?#].*)?$/i.test(s)) {
    const onionUrl = 'http://' + s;
    return validation.isHttpUrl(onionUrl) ? onionUrl : null;
  }
  // CORREÇÃO 1.5.2: "site.com:8080/caminho" era tratado como esquema "site.com:"
  // e rejeitado. host.dominio:porta agora vira https://host.dominio:porta
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+:\d{1,5}([\/?#].*)?$/i.test(s)) {
    const portUrl = 'https://' + s;
    return validation.isHttpUrl(portUrl) ? portUrl : null;
  }
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(s)) return null; // outros esquemas: bloqueados
  return 'https://' + s;
}

function searchUrl(q) {
  const eng = ENGINES[settings.searchEngine] || ENGINES.duckduckgo;
  return eng(q);
}

function activeTab() {
  return tabs.find(t => t.id === activeId) || null;
}

/** 1.5.0: caminho local de PDF/ebook digitável na barra (C:\…, /home/…, file:///…). */
function looksLikeLocalReaderPath(input) {
  const s = String(input || '').trim();
  if (!s || s.length > 1000) return false;
  if (!/^(file:\/\/\/|[a-zA-Z]:[\\/]|\\\\|\/)/.test(s)) return false;
  return /\.(pdf|epub|mobi|azw3?|fb2|cbz)($)/i.test(s.split(/[?#]/)[0]);
}

async function navigateActive(input) {
  const t = activeTab();
  const url = normalizeInput(input);
  if (!t || !url) {
    // 1.5.0: aceita caminhos locais de PDF/ebook na barra de endereço
    if (t && looksLikeLocalReaderPath(input)) {
      try { await api.readers.openPath(String(input).trim()); return; }
      catch (e) { toast(String((e && e.message) || 'Não foi possível abrir o arquivo.')); return; }
    }
    toast('Endereço inválido ou esquema não permitido (use http/https).');
    return;
  }
  try { await api.tabs.navigate(t.id, url); } catch (_) { toast('Não foi possível navegar.'); }
}

async function createTab(url) {
  try {
    const r = await api.tabs.create(url || null);
    await api.tabs.activate(r.id);
  } catch (_) { toast('Não foi possível abrir a aba.'); }
}

/* ---------------- progresso de carregamento ---------------- */

let progTimer = null;
function setProgress(p) {
  const bar = $('#progress-bar');
  if (p >= 100) {
    bar.style.width = '100%';
    if (progTimer) clearTimeout(progTimer);
    progTimer = setTimeout(() => { bar.style.width = '0'; }, 250);
  } else {
    bar.style.width = p + '%';
  }
}

/* ---------------- buscar na página (Ctrl+F) ---------------- */

function updateFindCount(r) {
  const c = $('#find-count');
  if (!r) { c.textContent = ''; c.classList.remove('none'); return; }
  const none = !r.matches;
  c.classList.toggle('none', none && !!$('#find-input').value);
  c.textContent = none ? ($('#find-input').value ? 'Sem resultados' : '') : r.activeMatchOrdinal + ' de ' + r.matches;
}

function openFind() {
  const t = activeTab();
  if (!t || t.state === 'ntp') { toast('Nada para buscar nesta aba.'); return; }
  $('#findbar').classList.add('open');
  // CORREÇÃO 1.4.0: reserva a faixa da findbar encolhendo a view nativa
  // (senão a WebContentsView cobre a barra — mesmo bug do painel de menu)
  $('#views').classList.add('find-open');
  scheduleBounds();
  const inp = $('#find-input');
  inp.focus();
  inp.select();
  if (inp.value) runFind(true, false);
}

function closeFind() {
  const bar = $('#findbar');
  if (!bar.classList.contains('open')) return;
  bar.classList.remove('open');
  $('#views').classList.remove('find-open');
  scheduleBounds();
  updateFindCount(null);
  const t = activeTab();
  if (t) api.tabs.findStop(t.id);
}

/** forward: sentido; next: true continua a busca atual, false inicia uma nova. */
function runFind(forward, next) {
  const t = activeTab();
  const text = $('#find-input').value;
  if (!t || !text) {
    if (t) api.tabs.findStop(t.id);
    updateFindCount(null);
    return;
  }
  api.tabs.find(t.id, text, { forward: forward !== false, findNext: !!next, matchCase: false });
}

function findStep(forward) {
  if (!$('#findbar').classList.contains('open')) { openFind(); return; }
  runFind(forward, true);
}

/* ---------------- dimensões da área de conteúdo ----------------
   As abas são WebContentsView NATIVAS: o main posiciona cada view
   exatamente sobre #view-area. O retângulo é reportado sempre que a
   área muda (janela, maximizar, painel, escala do Windows). */

let boundsFrame = 0;
function reportBounds() {
  const area = document.getElementById('view-area');
  if (!area) return;
  const rect = area.getBoundingClientRect();
  if (rect.width < 2 || rect.height < 2) return;
  api.tabs.bounds({
    x: rect.x, y: rect.y,
    width: rect.width, height: rect.height
  });
}
function scheduleBounds() {
  if (boundsFrame) return;
  boundsFrame = requestAnimationFrame(() => {
    boundsFrame = 0;
    reportBounds();
  });
}

/* ---------------- renderização: abas ----------------
 * CORREÇÃO 1.6.7 (velocidade): renderTabs reconstruía o innerHTML de TODAS
 * as abas a cada estado (120 ms durante carregamentos) e re-anexava os
 * listeners de <img>. Agora reconcilia por aba: cada <div class=tab> tem
 * uma assinatura; só a aba que MUDOU é recriada. */
const tabDom = new Map();   // id -> { el, sig }
function tabSignature(t) {
  return [t.id, t.url, t.title, t.favicon || '', t.audio ? 1 : 0, t.sleeping ? 1 : 0,
    t.id === activeId ? 1 : 0, t.sessionId || 'padrao', t.tor ? 1 : 0].join('|');
}
function buildTabEl(t) {
  const h = hostOf(t.url) || t.title || 'N';
  const fav = t.favicon
    ? '<img class="t-fav" src="' + esc(t.favicon) + '">'
    : '<span class="t-fav t-letter" data-hue="' + hue(h) + '">' +
      esc(String(h)[0].toUpperCase()) + '</span>';
  const audio = t.audio ? '<span class="t-audio" title="Reproduzindo áudio"></span>' : '';
  // 1.6.0: marcador da sessão isolada (contêiner)
  const cont = containersList.find(x => x.id === (t.sessionId || 'padrao'));
  const badge = (cont && cont.id !== 'padrao')
    ? '<span class="t-cont" title="Sessão isolada: ' + esc(cont.name) + '" data-hue="' + hue(cont.name) + '"></span>'
    : '';
  const torIc = t.tor ? '<span class="t-tor" title="Aba Tor — tráfego pela rede Tor">' + svg('onion', 12) + '</span>' : '';
  const shown = t.sleeping ? '[suspensa] ' + t.title : t.title;
  const el = document.createElement('div');
  el.className = 'tab' + (t.id === activeId ? ' active' : '') + (t.sleeping ? ' sleeping' : '');
  el.dataset.id = String(t.id);
  el.title = shown;
  el.innerHTML = badge + torIc + fav + audio +
    '<span class="t-title">' + esc(shown) + '</span>' +
    '<button class="t-close" title="Fechar aba">' + svg('x', 12) + '</button>';
  // favicons que falharem são removidos silenciosamente (anexado UMA vez por elemento)
  const img = el.querySelector('img.t-fav');
  if (img) img.addEventListener('error', () => img.remove());
  return el;
}
function renderTabs() {
  const c = $('#tabs');
  const seen = new Set();
  let before = c.firstChild;
  for (const t of tabs) {
    seen.add(t.id);
    const sig = tabSignature(t);
    const cached = tabDom.get(t.id);
    if (cached && cached.sig === sig && cached.el.isConnected) continue;
    const el = buildTabEl(t);
    if (cached && cached.el.isConnected) {
      c.replaceChild(el, cached.el);
    } else {
      // inserir na posição correta (a lista de abas é a fonte da verdade)
      const ref = before ? before.nextSibling : c.firstChild;
      c.insertBefore(el, ref);
    }
    tabDom.set(t.id, { el, sig });
    before = el;
  }
  for (const [id, cached] of [...tabDom]) {
    if (!seen.has(id)) {
      if (cached.el.isConnected) cached.el.remove();
      tabDom.delete(id);
    }
  }
}

/* ---------------- renderização: barra de ferramentas ---------------- */

function renderToolbar() {
  const t = activeTab();
  $('#btn-back').disabled = !!(t && !t.canBack);
  $('#btn-fwd').disabled = !!(t && !t.canFwd);
  $('#btn-reload').innerHTML = svg(t && t.loading ? 'x' : 'reload');
  $('#btn-reload').title = t && t.loading ? 'Parar carregamento (Esc)' : 'Recarregar (Ctrl+R)';
  const starred = !!(t && t.url && favoritesCache.some(f => f.url === t.url));
  $('#btn-star').classList.toggle('starred', starred);
  $('#btn-shield').classList.toggle('off', !(settings && settings.adblockEnabled));
  $('#btn-protection').classList.toggle('off', !!(settings &&
    !settings.popupBlockerEnabled && !settings.redirectGuardEnabled));
  // 1.5.3: indicador do Tor na barra (cor/estado)
  const torBtn = $('#btn-tor');
  if (torBtn) {
    torBtn.classList.toggle('tor-on', torState.state === 'connected');
    torBtn.classList.toggle('tor-busy',
      torState.state === 'starting' || torState.state === 'bootstrapping');
    torBtn.classList.toggle('tor-err', torState.state === 'error');
    torBtn.title = torState.state === 'connected'
      ? 'Tor conectado — painel da conexão (Ctrl+Shift+T)'
      : torState.state === 'bootstrapping' || torState.state === 'starting'
        ? 'Tor conectando (' + (torState.progress || 0) + '%)…'
        : torState.state === 'error'
          ? 'Tor: ' + (torState.error || 'falha') + ' — painel da conexão'
          : 'Conexão Tor (nativo) — Ctrl+Shift+T';
  }
  const badge = $('#tor-badge');
  if (badge) {
    const show = torState.state === 'bootstrapping' || torState.state === 'starting';
    badge.hidden = !show;
    if (show) badge.textContent = String(torState.progress || 0);
  }
  updateShieldBadge();
  updateProtectionBadge();
}

function updateShieldBadge() {
  const b = $('#shield-badge');
  if (b) b.textContent = String(blockStats.session || 0);
}

/* 1.5.1: badge = pop-ups + redirecionamentos bloqueados na sessão
 * 1.7.0: inclui os contadores nativos (SponsorBlock + Consent-O-Matic) */
function updateProtectionBadge() {
  const b = $('#protection-badge');
  if (!b) return;
  const nat = protectionStats.native || { sbSkips: 0, cmDenies: 0 };
  const n = (protectionStats.popup ? protectionStats.popup.total : 0) +
            (protectionStats.redirect ? protectionStats.redirect.total : 0) +
            (nat.sbSkips || 0) + (nat.cmDenies || 0);
  b.textContent = String(n);
  b.hidden = n === 0;
}

function renderAddress() {
  const t = activeTab();
  if (!t) return;
  const el = $('#address');
  const chip = $('#sec-chip');
  if (document.activeElement === el) return; // não sobrescrever enquanto o usuário digita
  if (t.state === 'ntp' || !t.url) {
    el.value = '';
    chip.className = 'sec-chip';
    chip.innerHTML = svg('search', 14);
    chip.title = '';
  } else {
    el.value = t.url;
    const https = /^https:/i.test(t.url);
    if (t.tor) {
      chip.className = 'sec-chip tor';
      chip.innerHTML = svg('onion', 14);
      chip.title = 'Tráfego desta aba passa pela rede Tor (sessão isolada, WebRTC restrito)';
    } else if (/^http:\/\/[^/?#]*\.onion(?::\d+)?(?:[/?#]|$)/i.test(t.url)) {
      // 1.6.1: .onion em HTTP é criptografado de ponta a ponta pela própria rede Tor
      chip.className = 'sec-chip https';
      chip.innerHTML = svg('onion', 14);
      chip.title = 'Serviço .onion: criptografia de ponta a ponta do próprio Tor';
    } else {
      chip.className = 'sec-chip ' + (https ? 'https' : 'http');
      chip.innerHTML = svg(https ? 'lock' : 'warn', 14);
      chip.title = https ? 'Conexão segura (HTTPS)' : 'Conexão não criptografada (HTTP)';
    }
  }
}

/* ---------------- renderização: Nova Aba ---------------- */

function renderNtp() {
  // Nova Aba enxuta: nada de atalhos ou sugestões — apenas busca e estatística
  // de bloqueios da sessão. Nenhum estado é gravado nem exibido nesta página.
  const parts = [];
  if (blockStats.native) parts.push(blockStats.native + ' nativas');
  if (blockStats.ghostery) parts.push(blockStats.ghostery + ' EasyList/EasyPrivacy');
  const detail = parts.length ? ' (' + parts.join(' + ') + ')' : '';
  $('#ntp-stats').innerHTML =
    svg('shield', 14) + ' Anúncios e rastreadores bloqueados nesta sessão: <b>' +
    (blockStats.session || 0) + '</b>' + esc(detail);
}

/* relógio da Nova Aba — atualiza apenas quando ela está visível */
function tickNtpClock() {
  if (!$('#ntp').classList.contains('show')) return;
  const now = new Date();
  const clock = $('#ntp-clock');
  const date = $('#ntp-date');
  if (clock) clock.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  if (date) date.textContent = now.toLocaleDateString([], { weekday: 'long', day: '2-digit', month: 'long' });
}
setInterval(tickNtpClock, 1000);

/* ---------------- renderização geral ---------------- */

function renderAll() {
  renderTabs();
  renderToolbar();
  renderAddress();
  const t = activeTab();
  $('#ntp').classList.toggle('show', !!(t && t.state === 'ntp'));
  $('#views').classList.toggle('has-view', !!(t && t.state !== 'ntp'));
  scheduleBounds(); // aba/Nova Aba trocaram: reconfirma o retângulo das views
  if (t && t.loading) setProgress(55);
  else setProgress(100);
  if (t && t.state === 'ntp') { renderNtp(); tickNtpClock(); document.title = 'Nova aba — NanoDesk'; }
  else if (t) document.title = (t.title || 'NanoDesk') + ' — NanoDesk';
}

function syncFromMain(list) {
  tabs = list || [];
  // A fonte da verdade do "active" é o processo principal.
  const act = tabs.find(x => x.active);
  activeId = act ? act.id : (tabs.length ? tabs[tabs.length - 1].id : null);
  for (const x of tabs) x.active = x.id === activeId;
  renderAll();
}

/* ---------------- painéis laterais ---------------- */

function closePanels() {
  currentPanel = null;
  $$('.panel').forEach(p => p.classList.remove('open'));
  $('#views').classList.remove('panel-open');
  scheduleBounds();
}

function togglePanel(name) {
  if (currentPanel === name) { closePanels(); return; }
  closePanels();
  currentPanel = name;
  $('#panel-' + name).classList.add('open');
  $('#views').classList.add('panel-open');
  scheduleBounds();
  if (name === 'favorites') renderFavoritesPanel();
  if (name === 'adblock') renderAdblockPanel();
  if (name === 'protection') renderProtectionPanel();
  if (name === 'downloads') renderDownloadsPanel();
  if (name === 'settings') renderSettingsPanel();
  if (name === 'menu') renderMenuPanel();
  if (name === 'reader') refreshReader();
  // 1.6.0
  if (name === 'network') renderNetworkPanel();
  if (name === 'security') renderSecurityPanel();
  if (name === 'history') renderHistoryPanel();
  if (name === 'tor') renderTorPanel();
  // 1.7.0
  if (name === 'biblioteca') renderBibliotecaPanel();
  // 1.8.9
  if (name === 'vault') renderVaultPanel();
  // 1.9.5
  if (name === 'media') renderMediaPanel();
}

/* ---------------- leitor de notícias (1.4.0) ---------------- */

function feedTitle(id) {
  const f = readerState.feeds.find(x => x.id === id);
  return f ? f.title : '';
}

function totalUnread() {
  return readerState.feeds.reduce((n, f) => n + (f.unread || 0), 0);
}

function updateReaderBadge() {
  const b = $('#reader-badge');
  const n = totalUnread();
  if (b) { b.textContent = String(n); b.hidden = n === 0; }
  $('#btn-reader').classList.toggle('unread', n > 0);
}

async function refreshReader() {
  try {
    readerState.feeds = await api.reader.list();
    if (readerState.feedId !== 'all' && !readerState.feeds.some(f => f.id === readerState.feedId)) {
      readerState.feedId = 'all';
    }
    readerState.items = await api.reader.items(readerState.feedId, { limit: 300 });
  } catch (_) { /* main pode ter recarregado */ }
  updateReaderBadge();
  if (currentPanel === 'reader' && readerState.view !== 'page' && readerState.view !== 'article') {
    renderReaderPanel();
  }
}

async function renderReaderPanel() {
  const body = $('#reader-body');
  const head = $('#reader-head');
  if (readerState.view === 'article') return renderReaderArticle(body, head);
  if (readerState.view === 'page') return renderReadingPage(body, head);
  if (readerState.view === 'trans') return renderTranslation(body, head);
  return renderReaderList(body, head);
}

/* 1.6.0 FASE 7 — resultado da tradução (texto ou página) */
function renderTranslation(body, head) {
  head.textContent = 'Tradução';
  const tr = readerState.trans;
  if (!tr) {
    body.innerHTML = '<div class="empty">Nenhuma tradução ainda.<br>Selecione texto em uma página e use “Traduzir seleção”, ou o menu Ferramentas > Traduzir página (requer servidor LibreTranslate configurado).</div>' +
      '<div class="btn-row"><button class="btn" id="tr-back">← Artigos</button></div>';
    $('#tr-back').addEventListener('click', () => { readerState.view = 'list'; renderReaderPanel(); });
    return;
  }
  body.innerHTML =
    '<div class="btn-row"><button class="btn" id="tr-back">← Artigos</button>' +
      '<button class="btn" id="tr-again">Traduzir página atual</button></div>' +
    '<div class="art-head"><h2>' + esc(tr.title || 'Tradução') + '</h2>' +
      '<div class="art-meta">via LibreTranslate configurado — o texto foi enviado só depois do seu consentimento</div></div>' +
    '<div class="art-body">' + tr.html + '</div>';
  $('#tr-back').addEventListener('click', () => { readerState.view = 'list'; renderReaderPanel(); });
  $('#tr-again').addEventListener('click', async () => {
    try { await api.translate.page(); } catch (e) { toast(e && e.message ? e.message : 'Falha na tradução.'); }
  });
  body.querySelectorAll('.art-body a[href]').forEach(a => {
    a.addEventListener('click', (e) => { e.preventDefault(); if (a.href) createTab(a.href); });
  });
}

function renderReaderList(body, head) {
  head.textContent = 'Leitor de notícias';
  const unreadAll = totalUnread();
  const tools = '<div class="panel-tools">' +
    '<button class="btn" id="rd-refresh">' + svg('refresh', 14) + ' Atualizar</button>' +
    '<button class="btn" id="rd-add">' + svg('plus', 14) + ' Feed</button>' +
    '<button class="btn" id="rd-import">Importar OPML</button>' +
    '<button class="btn" id="rd-export">Exportar</button>' +
    '</div>';
  const addForm = readerState.adding
    ? '<div class="add-form"><input id="rd-url" type="text" placeholder="URL do site ou do feed (http/https)" spellcheck="false" autocomplete="off">' +
      '<button class="btn" id="rd-add-go">Acompanhar</button>' +
      '<button class="icon-btn small" id="rd-add-cancel" title="Cancelar">' + svg('x', 14) + '</button></div>'
    : '';
  const chips = '<div class="feed-chips">' +
    '<span class="chip fchip' + (readerState.feedId === 'all' ? ' active' : '') + '" data-feed="all">Todos' +
      (unreadAll ? ' <b>' + unreadAll + '</b>' : '') + '</span>' +
    readerState.feeds.map(f =>
      '<span class="chip fchip' + (f.id === readerState.feedId ? ' active' : '') + '" data-feed="' + esc(f.id) + '" title="' + esc(f.url) + '">' +
      esc(f.title) + (f.unread ? ' <b>' + f.unread + '</b>' : '') +
      '<button data-unfeed="' + esc(f.id) + '" title="Remover inscrição">' + svg('x', 11) + '</button></span>'
    ).join('') + '</div>';
  const note = '<p class="dl-note">Inscrições e estado "lido" existem só nesta sessão — nada é gravado no PC. ' +
    'Use <b>Exportar</b> para salvar sua lista em OPML (arquivo que você escolhe). ' +
    'Links de artigos têm parâmetros de rastreamento (utm_*, fbclid…) removidos.</p>';
  const list = readerState.items.length
    ? readerState.items.map(it =>
        '<div class="row ritem' + (it.read ? '' : ' unread') + '" data-item="' + esc(it.id) + '">' +
          '<div class="row-main"><div class="row-title">' + esc(it.title) + '</div>' +
          '<div class="row-url">' + esc(feedTitle(it.feedId) || 'feed') + ' · ' + fmtDate(it.ts) + '</div></div>' +
        '</div>').join('')
    : '<div class="empty">Nenhum artigo' + (readerState.feedId !== 'all' ? ' neste feed' : ' ainda') + '.<br>' +
      'Adicione um feed com <b>+ Feed</b> (cole a URL de um site ou de um feed) ou importe um OPML.</div>';
  body.innerHTML = tools + addForm + chips + note + list;

  $('#rd-refresh').addEventListener('click', async () => {
    if (readerState.refreshing) return;
    readerState.refreshing = true;
    toast('Atualizando feeds…');
    try { await api.reader.refresh('all'); } finally { readerState.refreshing = false; }
    await refreshReader();
  });
  $('#rd-add').addEventListener('click', () => {
    readerState.adding = !readerState.adding;
    renderReaderPanel();
    if (readerState.adding) { const el = $('#rd-url'); if (el) el.focus(); }
  });
  $('#rd-import').addEventListener('click', async () => {
    try {
      const r = await api.reader.opmlImport();
      if (r && r.canceled) return;
      toast('OPML importado: ' + r.added + ' novo(s), ' + r.failed + ' falha(s)' +
        (r.skipped ? ', ' + r.skipped + ' já existente(s)' : '') + '.', 6000);
      await refreshReader();
    } catch (e) { toast(e && e.message ? e.message : 'Falha ao importar OPML.'); }
  });
  $('#rd-export').addEventListener('click', async () => {
    try {
      const r = await api.reader.opmlExport();
      if (r && r.canceled) return;
      toast(r && r.ok ? 'Lista salva em: ' + r.path : 'Não foi possível salvar.', 6000);
    } catch (e) { toast(e && e.message ? e.message : 'Falha ao exportar OPML.'); }
  });
  if (readerState.adding) {
    const go = async () => {
      const url = $('#rd-url').value.trim();
      if (!url) return;
      try {
        await api.reader.subscribe(url);
        toast('Feed adicionado.');
        readerState.adding = false;
        await refreshReader();
      } catch (e) { toast(e && e.message ? e.message : 'Não foi possível adicionar o feed.'); }
    };
    $('#rd-add-go').addEventListener('click', go);
    $('#rd-url').addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
    $('#rd-add-cancel').addEventListener('click', () => { readerState.adding = false; renderReaderPanel(); });
  }
  body.querySelectorAll('.fchip').forEach(ch => ch.addEventListener('click', async (e) => {
    if (e.target.closest('[data-unfeed]')) return;
    readerState.feedId = ch.dataset.feed;
    readerState.view = 'list';
    await refreshReader();
  }));
  body.querySelectorAll('[data-unfeed]').forEach(b => b.addEventListener('click', async (e) => {
    e.stopPropagation();
    await api.reader.remove(b.dataset.unfeed);
    if (readerState.feedId === b.dataset.unfeed) readerState.feedId = 'all';
    await refreshReader();
  }));
  body.querySelectorAll('.ritem').forEach(r => r.addEventListener('click', () => openReaderItem(r.dataset.item)));
}

async function openReaderItem(id) {
  const art = await api.reader.item(id);
  if (!art) { toast('Artigo não encontrado (o feed foi atualizado?).'); return; }
  // CORREÇÃO 1.5.2: o selo usava a lista de feeds antiga (contagem não caía)
  api.reader.markRead(id, true).then(() => refreshReader()).catch(() => {});
  readerState.view = 'article';
  readerState.article = art;
  renderReaderPanel();
}

function renderReaderArticle(body, head) {
  head.textContent = 'Leitor';
  const art = readerState.article;
  body.innerHTML =
    '<button class="btn" id="rd-back">← Artigos</button>' +
    '<div class="art-head"><h2>' + esc(art.title) + '</h2>' +
      '<div class="art-meta">' + esc(art.feedTitle || 'feed') +
        (art.author ? ' · ' + esc(art.author) : '') + ' · ' + fmtDate(art.ts) + '</div></div>' +
    '<div class="art-body">' +
      (art.contentHtml || art.summaryHtml || '<p class="empty">Este item não tem conteúdo — abra o original.</p>') +
    '</div>' +
    '<div class="btn-row art-actions">' +
      (art.url ? '<button class="btn" id="rd-open">Abrir original</button>' : '') +
      '<button class="btn" id="rd-unread">Marcar não lido</button>' +
    '</div>';
  $('#rd-back').addEventListener('click', () => { readerState.view = 'list'; readerState.article = null; renderReaderPanel(); });
  const unread = $('#rd-unread');
  if (unread) unread.addEventListener('click', async () => {
    await api.reader.markRead(art.id, false);
    await refreshReader();
    readerState.view = 'list';
    renderReaderPanel();
  });
  const open = $('#rd-open');
  if (open) open.addEventListener('click', () => {
    const t = activeTab();
    closePanels();
    if (t) navigateActive(art.url); else createTab(art.url);
  });
  // links do artigo abrem em abas (a janela da UI não navega)
  body.querySelectorAll('.art-body a[href]').forEach(a => {
    a.addEventListener('click', (e) => { e.preventDefault(); if (a.href) createTab(a.href); });
  });
}

/* Modo Leitura: texto público da página atual, limpo e sem anúncios.
   Não revela conteúdo atrás de login/assinatura (não é bypass de paywall). */
async function runReaderMode() {
  const t = activeTab();
  if (!t || !validation.isHttpUrl(t.url)) {
    toast('Abra um site (http/https) para usar o Modo Leitura.');
    return;
  }
  readerState = { ...readerState, view: 'page', page: null, loadingPage: true, article: null };
  if (currentPanel !== 'reader') togglePanel('reader');
  else renderReaderPanel();
  try {
    readerState.page = await api.readerMode.extract(t.url);
  } catch (e) {
    toast(e && e.message ? e.message : 'Não foi possível extrair o artigo desta página.');
    readerState.view = 'list';
  }
  readerState.loadingPage = false;
  if (currentPanel === 'reader') renderReaderPanel();
}

function renderReadingPage(body, head) {
  head.textContent = 'Modo leitura';
  if (readerState.loadingPage || !readerState.page) {
    body.innerHTML = '<div class="empty">Extraindo o artigo…</div>';
    return;
  }
  const art = readerState.page;
  body.innerHTML =
    '<div class="btn-row"><button class="btn" id="rd-close-page">Voltar</button>' +
      '<button class="btn" id="rd-open-page">Abrir página</button></div>' +
    '<div class="art-head"><h2>' + esc(art.title) + '</h2>' +
      '<div class="art-meta">' + esc(art.siteName || hostOf(art.url)) +
        (art.byline ? ' · ' + esc(art.byline) : '') + ' · ' +
        (art.wordCount ? art.wordCount + ' palavras' : '') + '</div></div>' +
    '<div class="art-body">' + art.contentHtml + '</div>' +
    '<p class="dl-note">O Modo Leitura mostra o texto público da página, sem anúncios; ' +
      'não revela conteúdo atrás de login ou assinatura.</p>';
  $('#rd-close-page').addEventListener('click', () => { readerState.view = 'list'; readerState.page = null; renderReaderPanel(); });
  $('#rd-open-page').addEventListener('click', () => {
    const t = activeTab();
    closePanels();
    if (t) navigateActive(art.url); else createTab(art.url);
  });
  body.querySelectorAll('.art-body a[href]').forEach(a => {
    a.addEventListener('click', (e) => { e.preventDefault(); if (a.href) createTab(a.href); });
  });
}

async function refreshFavorites() {
  favoritesCache = await api.favorites.list();
  renderToolbar();
  if (currentPanel === 'favorites') renderFavoritesPanel();
}

function rowIcon(url, title) {
  const h = hostOf(url);
  return '<span class="row-ic" data-hue="' + hue(h) + '">' +
    esc(String(h || title || 'N')[0].toUpperCase()) + '</span>';
}

function renderFavoritesPanel() {
  const body = $('#favorites-body');
  // 1.6.0: busca + pastas/etiquetas (tudo em RAM)
  const toolbar = '<div class="panel-tools">' +
    '<input id="fav-search" type="text" placeholder="Buscar favorito (título, URL, etiqueta)" spellcheck="false" autocomplete="off" value="' + esc(favQuery) + '">' +
    '<button class="btn" data-fav="export">Exportar</button>' +
    '<button class="btn" data-fav="import">Importar</button>' +
    '</div>';
  if (!favoritesCache.length) {
    body.innerHTML = toolbar + '<div class="empty">Nenhum favorito nesta sessão.<br>Abra um site e pressione a estrela na barra de endereço (Ctrl+D).<br><br>Favoritos existem só na memória e somem ao fechar o NanoDesk — a não ser que você ative o perfil local em Configurações.</div>';
    bindFavoritesToolbar(body);
    return;
  }
  const q = favQuery.trim().toLowerCase();
  const norm = (s) => String(s || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  const list = q
    ? favoritesCache.filter(f => norm(f.url + ' ' + (f.title || '') + ' ' + (f.folder || '') + ' ' + (f.tags || []).join(' ')).includes(norm(q)))
    : favoritesCache;
  // agrupa por pasta (sem pasta = "Geral")
  const groups = {};
  for (const f of list) {
    const g = (f.folder || '').trim() || 'Geral';
    (groups[g] = groups[g] || []).push(f);
  }
  const groupHtml = Object.keys(groups).sort().map(g =>
    '<h5 class="fav-folder">' + svg('folder', 13) + ' ' + esc(g) + '</h5>' +
    groups[g].map(f =>
      '<div class="row" data-id="' + esc(f.id) + '" data-url="' + esc(f.url) + '">' +
        rowIcon(f.url, f.title) +
        '<div class="row-main"><div class="row-title">' + esc(f.title || f.url) + '</div>' +
          '<div class="row-url">' + esc(f.url) + '</div>' +
          ((f.tags && f.tags.length) ? '<div class="fav-tags">' + f.tags.map(t => '<span class="chip">' + esc(t) + '</span>').join('') + '</div>' : '') +
        '</div>' +
        '<button class="icon-btn row-edit" title="Pasta e etiquetas">' + svg('gear', 14) + '</button>' +
        '<button class="icon-btn row-del" title="Remover favorito">' + svg('trash', 14) + '</button>' +
      '</div>'
    ).join('')
  ).join('');
  body.innerHTML = toolbar +
    (list.length ? groupHtml : '<div class="empty">Nada encontrado para “' + esc(favQuery) + '”.</div>');
  bindFavoritesToolbar(body);
  body.querySelectorAll('.row').forEach(r => {
    r.addEventListener('click', (e) => {
      const t = activeTab();
      if (e.target.closest('.row-del')) {
        api.favorites.remove(r.dataset.url).then(() => refreshFavorites());
        return;
      }
      if (e.target.closest('.row-edit')) {
        openFavoriteEditor(r.dataset.id);
        return;
      }
      closePanels();
      if (t) navigateActive(r.dataset.url);
      else createTab(r.dataset.url);
    });
  });
}

let favQuery = '';

function bindFavoritesToolbar(body) {
  const input = body.querySelector('#fav-search');
  if (input) {
    input.addEventListener('input', () => { favQuery = input.value; renderFavoritesPanel(); const el = body.querySelector('#fav-search'); if (el) { el.focus(); el.setSelectionRange(el.value.length, el.value.length); } });
  }
  body.querySelectorAll('[data-fav]').forEach(b => b.addEventListener('click', async () => {
    try {
      if (b.dataset.fav === 'export') {
        const r = await api.favorites.export();
        if (r && r.ok) toast('Favoritos exportados para ' + r.path);
      } else {
        const r = await api.favorites.import();
        if (r && r.canceled) return;
        toast('Importados: ' + r.added + ' novo(s).');
        await refreshFavorites();
      }
    } catch (e) { toast(e && e.message ? e.message : 'Falha na operação.'); }
  }));
}

/** Editor de pasta/etiquetas via prompts nativos (sem estados persistentes). */
function openFavoriteEditor(id) {
  const f = favoritesCache.find(x => x.id === id);
  if (!f) return;
  const folder = prompt('Pasta do favorito (vazio = Geral):', f.folder || '');
  if (folder === null) return;
  const tags = prompt('Etiquetas separadas por vírgula:', (f.tags || []).join(', '));
  if (tags === null) return;
  api.favorites.set(id, { folder, tags: tags.split(',').map(t => t.trim()).filter(Boolean) })
    .then(() => refreshFavorites())
    .catch((e) => toast(e && e.message ? e.message : 'Não foi possível salvar.'));
}

let downloadsCache = [];

function dlStatus(d) {
  if (d.state === 'confirming') return 'Aguardando confirmação (arquivo executável)';
  if (d.state === 'progressing') {
    return d.total > 0
      ? 'Baixando ' + Math.min(100, Math.round(d.received / d.total * 100)) + '% · ' + fmtBytes(d.received) + ' de ' + fmtBytes(d.total)
      : 'Baixando · ' + fmtBytes(d.received);
  }
  if (d.state === 'completed') return 'Concluído · ' + fmtBytes(d.total || d.received) + ' · ' + fmtDate(d.ts);
  if (d.state === 'security_error') return 'ANÁLISE DE SEGURANÇA FALHOU — arquivo NÃO liberado para abertura';
  if (d.state === 'cancelled') return 'Cancelado';
  return 'Interrompido';
}

function setDownloads(items) {
  downloadsCache = items || [];
  $('#btn-downloads').classList.toggle('busy', downloadsCache.some(d => d.state === 'progressing'));
  if (currentPanel === 'downloads') renderDownloadsPanel();
}

function renderDownloadsPanel() {
  const body = $('#downloads-body');
  const head = '<div class="panel-tools">' +
    '<button class="btn" data-dl="folder">Abrir pasta Downloads</button>' +
    '<button class="btn danger" data-dl="clear">Limpar lista</button></div>' +
    '<p class="dl-note">Os arquivos são salvos na pasta Downloads do Windows (ou onde você escolher, se "perguntar onde salvar" estiver ativo) e continuam no computador após fechar o NanoDesk. A LISTA de downloads existe só nesta sessão — nada é registrado no navegador.</p>';
  if (!downloadsCache.length) {
    body.innerHTML = head + '<div class="empty">Nenhum download nesta sessão.</div>';
  } else {
    body.innerHTML = head + downloadsCache.map(d => {
      const active = d.state === 'progressing' || d.state === 'confirming';
      const done = d.state === 'completed';
      const ext = d.name.includes('.') ? d.name.split('.').pop().slice(0, 4).toUpperCase() : 'ARQ';
      const bar = d.state === 'progressing'
        ? (d.total > 0 ? '<progress max="100" value="' + Math.round(d.received / d.total * 100) + '"></progress>' : '<progress></progress>')
        : '';
      const metaCls = d.state === 'interrupted' ? ' bad' : (done && d.risky ? ' warn' : '');
      const hash = done && d.sha256
        ? '<div class="dl-hash" title="SHA-256 para conferência de integridade">SHA-256: ' + esc(String(d.sha256).slice(0, 16)) + '…</div>'
        : '';
      // 1.6.0 — Security Gateway: veredito da varredura
      let scanHtml = '';
      if (d.scan) {
        const s = d.scan;
        if (s.status === 'analisando') {
          scanHtml = '<div class="dl-scan scan-wait">Verificando (Security Gateway)…</div>';
        } else if (s.verdict) {
          const cls = s.verdict === 'infectado' ? 'scan-bad' : (s.verdict === 'suspeito' ? 'scan-warn' : 'scan-ok');
          const det = (s.findings && s.findings.length)
            ? '<div class="dl-scan-det">' + s.findings.slice(0, 3).map(f => esc(f)).join('<br>') + '</div>' : '';
          const engs = [];
          if (s.clamav && s.clamav.ran) engs.push('ClamAV');
          if (s.yara && s.yara.ran) engs.push('YARA');
          if (s.magic && s.magic.label) engs.push('tipo real: ' + s.magic.label);
          scanHtml = '<div class="dl-scan ' + cls + '">' + esc(s.verdictLabel || s.verdict) +
            (engs.length ? ' <span class="dl-scan-eng">(' + esc(engs.join(' · ')) + ')</span>' : '') + '</div>' + det;
        }
      }
      const quar = d.quarantine
        ? '<div class="dl-scan scan-warn">EM QUARENTENA — pasta NanoDesk-Quarantine em Downloads</div>' : '';
      return '<div class="row" data-id="' + esc(d.id) + '">' +
        '<span class="row-ic dl-ic">' + esc(ext) + '</span>' +
        '<div class="row-main"><div class="row-title" title="' + esc(d.name) + '">' + esc(d.name) + '</div>' + bar +
        '<div class="dl-meta' + metaCls + '">' + esc(dlStatus(d)) + ' · origem: ' + esc(d.origin || '—') +
        (done && d.risky ? ' · executável: abra com cuidado' : '') + '</div>' + hash + scanHtml + quar + '</div>' +
        '<div class="dl-actions">' +
          (active ? '<button class="icon-btn" data-act="cancel" title="Cancelar">' + svg('x', 14) + '</button>' : '') +
          (done && !d.risky && !d.quarantine ? '<button class="icon-btn" data-act="open" title="Abrir">' + svg('ext', 14) + '</button>' : '') +
          (done && !d.quarantine ? '<button class="icon-btn" data-act="show" title="Mostrar na pasta">' + svg('folder', 14) + '</button>' : '') +
          (d.quarantine ? '<button class="icon-btn" data-act="release" title="Liberar (voltar p/ Downloads)">' + svg('check', 14) + '</button>' : '') +
          (d.quarantine ? '<button class="icon-btn del" data-act="delete" title="Excluir arquivo">' + svg('trash', 14) + '</button>' : '') +
          (!active ? '<button class="icon-btn del" data-act="remove" title="Remover da lista">' + svg('trash', 14) + '</button>' : '') +
        '</div></div>';
    }).join('');
  }
  body.onclick = (e) => {
    const tool = e.target.closest('[data-dl]');
    if (tool) {
      if (tool.dataset.dl === 'folder') api.downloads.openFolder();
      else api.downloads.clear().then(setDownloads);
      return;
    }
    const btn = e.target.closest('[data-act]');
    const row = e.target.closest('.row');
    if (!btn || !row) return;
    const id = row.dataset.id;
    switch (btn.dataset.act) {
      case 'cancel': api.downloads.cancel(id); break;
      case 'show': api.downloads.show(id); break;
      case 'remove': api.downloads.remove(id).then(setDownloads); break;
      case 'release':
        api.downloads.release(id).then(r => {
          if (r && r.ok) toast('Arquivo liberado para a pasta Downloads.');
          else toast('Não foi possível liberar: ' + ((r && r.reason) || '?'));
        });
        break;
      case 'delete':
        api.downloads.deleteFile(id).then(r => {
          if (r && r.ok) toast('Arquivo excluído.');
          else toast('Não foi possível excluir: ' + ((r && r.reason) || '?'));
        });
        break;
      case 'open':
        api.downloads.open(id).then(r => {
          if (!r.ok) toast('Não foi possível abrir o arquivo' + (r.reason === 'missing' ? ' (não encontrado — foi movido ou apagado?).' : '.'));
          else if (r.folder) toast('Arquivo executável: mostrado na pasta em vez de aberto.');
        });
        break;
    }
  };
}

/* ---------------- 1.9.5 — painel de mídia detectada ---------------- */

let mediaCache = [];          // recursos da aba ativa
let mediaFilter = 'all';      // 'all' | 'audio' | 'video' | 'stream'
let mediaSelected = new Set();
let mediaDetecting = false;

function fmtDuration(sec) {
  if (!sec || !Number.isFinite(Number(sec))) return '';
  const s = Math.round(Number(sec));
  const m = Math.floor(s / 60), r = s % 60;
  return m + ':' + String(r).padStart(2, '0');
}

function fmtBytes(n) {
  n = Number(n);
  if (!Number.isFinite(n) || n <= 0) return '';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
  return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}

function mediaTypeLabel(t) {
  if (t === 'audio') return 'Áudio';
  if (t === 'video') return 'Vídeo';
  if (t === 'stream') return 'Stream';
  return 'Arquivo';
}

function mediaTypeIcon(t) {
  if (t === 'audio') return svg('note', 14);
  if (t === 'video') return svg('play', 14);
  if (t === 'stream') return svg('rss', 14);
  return svg('download', 14);
}

async function detectMedia() {
  const t = activeTab();
  if (!t || !t.url || !/^https?:/i.test(t.url)) {
    toast('Abra uma página http(s) para detectar mídia.');
    return;
  }
  mediaDetecting = true;
  renderMediaPanel();
  try {
    const r = await api.media.detect(t.id);
    mediaDetecting = false;
    if (!r || !r.ok) {
      toast('Detecção falhou: ' + (r && r.reason || 'erro desconhecido'));
      mediaCache = [];
    } else {
      mediaCache = r.resources || [];
      mediaSelected.clear();
      // Atualiza badge do botão
      const badge = $('#media-badge');
      if (mediaCache.length) { badge.textContent = String(mediaCache.length); badge.hidden = false; }
      else { badge.hidden = true; }
      if (mediaCache.length === 0) {
        toast('Nenhuma mídia detectada nesta aba.');
      }
    }
    renderMediaPanel();
  } catch (e) {
    mediaDetecting = false;
    toast('Detecção falhou: ' + String(e && e.message || e).slice(0, 120));
    renderMediaPanel();
  }
}

function renderMediaPanel() {
  const body = $('#media-body');
  if (!body) return;
  const filtered = mediaCache.filter(r => mediaFilter === 'all' || r.mediaType === mediaFilter);
  const head = '<div class="panel-tools">' +
    '<button class="btn" id="media-detect"' + (mediaDetecting ? ' disabled' : '') + '>' +
      (mediaDetecting ? 'Detectando…' : 'Detectar mídia') + '</button>' +
    '<select id="media-filter" class="sel">' +
      '<option value="all"' + (mediaFilter === 'all' ? ' selected' : '') + '>Todos (' + mediaCache.length + ')</option>' +
      '<option value="audio"' + (mediaFilter === 'audio' ? ' selected' : '') + '>Áudio (' + mediaCache.filter(r => r.mediaType === 'audio').length + ')</option>' +
      '<option value="video"' + (mediaFilter === 'video' ? ' selected' : '') + '>Vídeo (' + mediaCache.filter(r => r.mediaType === 'video').length + ')</option>' +
      '<option value="stream"' + (mediaFilter === 'stream' ? ' selected' : '') + '>Streams (' + mediaCache.filter(r => r.mediaType === 'stream').length + ')</option>' +
    '</select>' +
    (mediaSelected.size > 0
      ? '<button class="btn primary" id="media-dl-batch">Baixar ' + mediaSelected.size + '</button>'
      : '') +
    '</div>' +
    '<p class="dl-note">Recursos de áudio, vídeo e streaming (HLS/DASH) detectados nesta aba. Para streaming protegido por DRM, o download não é possível.</p>';

  if (!filtered.length) {
    body.innerHTML = head + '<div class="empty">' +
      (mediaDetecting ? 'Procurando recursos de mídia…' :
        (mediaCache.length === 0 ? 'Clique em "Detectar mídia" para identificar áudio, vídeo e streams nesta aba.' : 'Nenhum recurso deste filtro.')) +
      '</div>';
  } else {
    body.innerHTML = head + filtered.map(r => {
      const sel = mediaSelected.has(r.id);
      const meta = [
        mediaTypeLabel(r.mediaType),
        r.extension ? r.extension.toUpperCase() : '',
        fmtBytes(r.fileSize),
        r.duration ? fmtDuration(r.duration) : '',
        r.width && r.height ? r.width + '×' + r.height : '',
        r.source === 'manifest' ? 'manifesto' : (r.source === 'dom' ? 'DOM' : (r.source === 'network' ? 'rede' : r.source || ''))
      ].filter(Boolean).join(' · ');
      const dlHint = r.mediaType === 'stream' ? 'Stream — use yt-dlp/FFmpeg' : 'Baixar';
      return '<div class="row' + (sel ? ' selected' : '') + '" data-id="' + esc(r.id) + '">' +
        '<input type="checkbox" class="media-sel"' + (sel ? ' checked' : '') + '>' +
        '<span class="row-ic">' + mediaTypeIcon(r.mediaType) + '</span>' +
        '<div class="row-main">' +
          '<div class="row-title" title="' + esc(r.url) + '">' + esc(r.title || r.url) + '</div>' +
          '<div class="dl-meta">' + esc(meta) + '</div>' +
        '</div>' +
        '<div class="dl-actions">' +
          (r.mediaType === 'stream'
            ? '<button class="icon-btn" data-act="info" title="' + esc(dlHint) + '">' + svg('info', 14) + '</button>'
            : '<button class="icon-btn" data-act="download" title="Baixar">' + svg('download', 14) + '</button>') +
          '<button class="icon-btn" data-act="copy" title="Copiar endereço">' + svg('copy', 14) + '</button>' +
        '</div></div>';
    }).join('');
  }
  body.onclick = (e) => {
    const detectBtn = e.target.closest('#media-detect');
    if (detectBtn) { detectMedia(); return; }
    const filterSel = e.target.closest('#media-filter');
    if (filterSel) return;   // change handler abaixo
    const batchBtn = e.target.closest('#media-dl-batch');
    if (batchBtn) {
      const ids = [...mediaSelected];
      const t = activeTab();
      if (!t) return;
      api.media.downloadBatch(t.id, ids).then(r => {
        toast(r.started + ' download(s) iniciado(s)' + (r.errors.length ? ' · ' + r.errors.length + ' falha(s)' : ''));
        if (r.started > 0) togglePanel('downloads');
      });
      return;
    }
    const row = e.target.closest('.row');
    if (!row) return;
    const id = row.dataset.id;
    const cb = e.target.closest('.media-sel');
    if (cb) {
      if (cb.checked) mediaSelected.add(id); else mediaSelected.delete(id);
      renderMediaPanel();
      return;
    }
    const btn = e.target.closest('[data-act]');
    if (!btn) return;
    const act = btn.dataset.act;
    const t = activeTab();
    if (!t) return;
    if (act === 'download') {
      api.media.download(t.id, id).then(r => {
        if (r.ok) { toast('Download iniciado via ' + (r.engine || 'motor') + '.'); togglePanel('downloads'); }
        else toast('Não foi possível baixar: ' + (r.reason || 'erro'));
      });
    } else if (act === 'copy') {
      const r = mediaCache.find(m => m.id === id);
      if (r) navigator.clipboard.writeText(r.url).then(() => toast('Endereço copiado.'));
    } else if (act === 'info') {
      toast('Streaming detectado — baixe com yt-dlp (menu de contexto) ou FFmpeg externo.');
    }
  };
  const filterEl = body.querySelector('#media-filter');
  if (filterEl) {
    filterEl.onchange = (e) => {
      mediaFilter = e.target.value;
      renderMediaPanel();
    };
  }
}

async function renderAdblockPanel() {
  blockStats = await api.adblock.stats();
  const allow = await api.adblock.allowlist();
  const recent = await api.adblock.recent();
  const t = activeTab();
  const host = t && t.url && /^https?:/i.test(t.url) ? hostOf(t.url) : '';

  const body = $('#adblock-body');
  body.innerHTML =
    '<div class="stat-line">' +
      '<div class="stat-box"><b>' + (blockStats.session || 0) + '</b><span>bloqueios nesta sessão</span></div>' +
      '<div class="stat-sub">motor nativo: ' + (blockStats.native || 0) + ' · EasyList/EasyPrivacy (Ghostery): ' + (blockStats.ghostery || 0) + '</div>' +
    '</div>' +
    '<label class="check"><input type="checkbox" id="ab-toggle" ' + (blockStats.enabled ? 'checked' : '') + '>' +
      '<span>Bloqueador ativo (requisições + filtros cosméticos)</span></label>' +
    '<h4>Permitir sites (allowlist)</h4>' +
    '<p class="dl-note">A allowlist libera apenas os recursos do PRÓPRIO site autorizado. Rastreadores de terceiros continuam bloqueados mesmo em sites permitidos. A lista vive só na memória.</p>' +
    '<div>' + (allow.length
      ? allow.map(d =>
          '<span class="chip">' + esc(d) + '<button data-host="' + esc(d) + '" title="Remover">' + svg('x', 11) + '</button></span>'
        ).join('')
      : '<span class="empty tight">Nenhum site na allowlist.</span>') + '</div>' +
    (host
      ? '<button class="btn" id="ab-allow-current">Permitir recursos de ' + esc(host) + '</button>'
      : '') +
    '<h4>Últimos bloqueios</h4>' +
    (recent.length
      ? recent.slice(0, 20).map(r =>
          '<div class="row tight">' +
            '<div class="row-main"><div class="row-title">' + esc(r.host) + '</div>' +
            '<div class="row-url">' + esc(r.rule) + ' (' + esc(r.type) + ')</div></div>' +
            '<span class="row-time">' + fmtTime(r.ts) + '</span>' +
          '</div>'
        ).join('')
      : '<div class="empty">Nenhum bloqueio ainda nesta sessão.</div>');

  $('#ab-toggle').addEventListener('change', async (e) => {
    blockStats = await api.adblock.setEnabled(e.target.checked);
    settings.adblockEnabled = e.target.checked;
    renderToolbar();
    renderAdblockPanel();
  });

  body.querySelectorAll('.chip button').forEach(b => {
    b.addEventListener('click', async () => {
      await api.adblock.disallow(b.dataset.host);
      renderAdblockPanel();
    });
  });

  const allowCur = body.querySelector('#ab-allow-current');
  if (allowCur) {
    allowCur.addEventListener('click', async () => {
      await api.adblock.allow(host);
      toast('Recursos de ' + host + ' liberados (rastreadores de terceiros continuam bloqueados).');
      renderAdblockPanel();
    });
  }
}

/* ---------------- painel Proteções (1.5.1) ---------------- */

async function renderProtectionPanel() {
  const body = $('#protection-body');
  try {
    protectionStats = await api.protection.stats();
    const recent = await api.protection.recent();
    renderProtectionBody(body, recent);
  } catch (_) {
    body.innerHTML = '<div class="empty">Não foi possível carregar as proteções.</div>';
  }
}

function renderProtectionBody(body, recent) {
  const ps = protectionStats.popup || { enabled: false, total: 0, tab: 0 };
  const rd = protectionStats.redirect || { enabled: false, total: 0, domain: 0, chain: 0, clickTraps: 0 };
  const nt = protectionStats.native || { sbSkips: 0, sbSecs: 0, cmDenies: 0 };
  const popRecent = (recent && recent.popup) || [];
  const rdRecent = (recent && recent.redirect) || [];
  const t = activeTab();
  const host = t && t.url && /^https?:/i.test(t.url) ? hostOf(t.url) : '';

  body.innerHTML =
    '<h4 class="pt-title">' + svg('popup', 15) + ' Bloqueador de pop-ups</h4>' +
    '<div class="stat-line">' +
      '<div class="stat-box"><b>' + (ps.total || 0) + '</b><span>pop-ups bloqueados nesta sessão</span></div>' +
      '<div class="stat-sub">critério do Popup-Blocker-Pro: sem interação do usuário = bloqueado</div>' +
    '</div>' +
    '<label class="check"><input type="checkbox" id="pt-popup-toggle" ' + (ps.enabled ? 'checked' : '') + '>' +
      '<span>Bloquear pop-ups abertos sem clique/tecla (pop-under e tab-under inclusos)</span></label>' +
    '<h5>Pop-ups sempre permitidos (allowlist)</h5>' +
    '<p class="dl-note">Sites autorizados podem abrir pop-ups mesmo sem interação. A lista vive só na memória.</p>' +
    '<div id="pt-popup-allow"></div>' +
    (host ? '<button class="btn" id="pt-popup-allow-cur">Permitir pop-ups de ' + esc(host) + '</button>' : '') +
    '<h5>Últimos pop-ups bloqueados</h5>' +
    (popRecent.length
      ? popRecent.slice(0, 12).map(r =>
          '<div class="row tight"><div class="row-main"><div class="row-title">' + esc(r.host) + '</div>' +
          '<div class="row-url">' + esc(r.url || '') + '</div></div>' +
          '<span class="row-time">' + fmtTime(r.ts) + '</span>' +
          '<button class="icon-btn" data-pt-allow="popup" data-host="' + esc(r.host) + '" title="Permitir pop-ups deste site">' + svg('star', 13) + '</button></div>'
        ).join('')
      : '<div class="empty tight">Nenhum pop-up bloqueado ainda nesta sessão.</div>') +

    '<h4 class="pt-title">' + svg('route', 15) + ' Guardião de redirecionamentos</h4>' +
    '<div class="stat-line">' +
      '<div class="stat-box"><b>' + (rd.total || 0) + '</b><span>redirecionamentos bloqueados</span></div>' +
      '<div class="stat-sub">redes: ' + (rd.domain || 0) + ' · cadeias: ' + (rd.chain || 0) + ' · armadilhas de clique: ' + (rd.clickTraps || 0) + '</div>' +
    '</div>' +
    '<label class="check"><input type="checkbox" id="pt-redirect-toggle" ' + (rd.enabled ? 'checked' : '') + '>' +
      '<span>Cortar redes de redirecionamento e cadeias suspeitas (RedirectGuard)</span></label>' +
    '<p class="dl-note">Bloqueia alvos de navegação para redes conhecidas (DoubleClick, ExoClick, PropellerAds, PopCash, Go2Speed…) e cadeias com mais de ' +
      esc(String(rd.maxHops || 7)) + ' origens em poucos segundos. Overlays invisíveis usados como armadilha de clique perdem o clique (pointer-events: none).</p>' +
    '<h5>Redirecionamentos sempre permitidos (allowlist)</h5>' +
    '<div id="pt-redirect-allow"></div>' +
    '<h5>Últimos redirecionamentos bloqueados</h5>' +
    (rdRecent.length
      ? rdRecent.slice(0, 12).map(r =>
          '<div class="row tight"><div class="row-main"><div class="row-title">' + esc(r.host) + '</div>' +
          '<div class="row-url">' + (r.kind === 'cadeia' ? 'cadeia (' + esc(r.rule || '') + ')' : 'rede (' + esc(r.rule || '') + ')') + ' · ' + esc(r.url || '') + '</div></div>' +
          '<span class="row-time">' + fmtTime(r.ts) + '</span>' +
          '<button class="icon-btn" data-pt-allow="redirect" data-host="' + esc(r.host) + '" title="Permitir redirecionamentos para este domínio">' + svg('star', 13) + '</button></div>'
        ).join('')
      : '<div class="empty tight">Nenhum redirecionamento bloqueado ainda nesta sessão.</div>') +

    '<h4 class="pt-title">' + svg('shield', 15) + ' Módulos nativos (1.7.0)</h4>' +
    '<div class="stat-line">' +
      '<div class="stat-box"><b>' + (nt.sbSkips || 0) + '</b><span>segmentos pulados (SponsorBlock)</span></div>' +
      '<div class="stat-box"><b>' + Math.round((nt.sbSecs || 0) / 60) + '</b><span>minutos poupados</span></div>' +
      '<div class="stat-box"><b>' + (nt.cmDenies || 0) + '</b><span>consentimentos negados (Consent-O-Matic)</span></div>' +
    '</div>' +
    '<p class="dl-note">SponsorBlock pula patrocínios automaticamente (API pública, envia apenas o ID do vídeo). ' +
      'Consent-O-Matic responde os popups de cookies SEMPRE NEGANDO rastreadores, no nível máximo. ' +
      'Alternar/desligar: Configurações.</p>';

  // allowlists em chips
  api.protection.popupAllowlist().then(list => {
    const el = $('#pt-popup-allow');
    if (el) el.innerHTML = list.length
      ? list.map(d => '<span class="chip">' + esc(d) + '<button data-pt-disallow="popup" data-host="' + esc(d) + '" title="Remover">' + svg('x', 11) + '</button></span>').join('')
      : '<span class="empty tight">Nenhum site na allowlist.</span>';
  }).catch(() => {});
  api.protection.redirectAllowlist().then(list => {
    const el = $('#pt-redirect-allow');
    if (el) el.innerHTML = list.length
      ? list.map(d => '<span class="chip">' + esc(d) + '<button data-pt-disallow="redirect" data-host="' + esc(d) + '" title="Remover">' + svg('x', 11) + '</button></span>').join('')
      : '<span class="empty tight">Nenhum domínio na allowlist.</span>';
  }).catch(() => {});

  $('#pt-popup-toggle').addEventListener('change', async (e) => {
    try {
      protectionStats = await api.protection.setPopupEnabled(e.target.checked);
      settings.popupBlockerEnabled = e.target.checked;
      renderToolbar();
    } catch (_) { e.target.checked = !e.target.checked; }
  });
  $('#pt-redirect-toggle').addEventListener('change', async (e) => {
    try {
      protectionStats = await api.protection.setRedirectEnabled(e.target.checked);
      settings.redirectGuardEnabled = e.target.checked;
      renderToolbar();
    } catch (_) { e.target.checked = !e.target.checked; }
  });

  const allowCur = $('#pt-popup-allow-cur');
  if (allowCur) {
    allowCur.addEventListener('click', async () => {
      await api.protection.popupAllow(host);
      toast('Pop-ups de ' + host + ' permitidos nesta sessão.');
      renderProtectionPanel();
    });
  }

  body.onclick = async (e) => {
    const btn = e.target.closest('[data-pt-allow]');
    if (btn) {
      if (btn.dataset.ptAllow === 'popup') await api.protection.popupAllow(btn.dataset.host);
      else await api.protection.redirectAllow(btn.dataset.host);
      toast(btn.dataset.host + ' adicionado à allowlist.');
      renderProtectionPanel();
      return;
    }
    const rm = e.target.closest('[data-pt-disallow]');
    if (rm) {
      if (rm.dataset.ptDisallow === 'popup') await api.protection.popupDisallow(rm.dataset.host);
      else await api.protection.redirectDisallow(rm.dataset.host);
      renderProtectionPanel();
    }
  };
}

/* ---------------- painéis 1.6.0: Rede / Segurança / Histórico ---------------- */

function updateNetDot() {
  const dot = $('#net-dot');
  const btn = $('#btn-net');
  if (!dot || !btn) return;
  let cls = 'net-dot';
  let title = 'Rede — VPN, Tor e DNS';
  if (netState.tor.active) { cls += ' tor'; title += ' · Tor externo (SOCKS) ativo'; }
  else if (netState.vpn.connected) { cls += ' vpn'; title += ' · ' + (netState.vpn.kind || 'VPN detectada'); }
  else cls += ' plain';
  if (!netState.webrtcProtected) { cls += ' warn'; title += ' · WebRTC sem proteção'; }
  dot.className = cls;
  btn.title = title;
}

function renderNetworkPanel() {
  const body = $('#network-body');
  const s = netState;
  const vpnStatus = s.vpn.connected
    ? '<div class="stat-line"><div class="stat-box ok"><b>VPN ativa</b><span>' + esc(s.vpn.kind || 'túnel detectado') + '</span></div>' +
      '<div class="stat-sub">interface(s): ' + esc((s.vpn.interfaces || []).join(', ') || '—') + '</div></div>'
    : '<div class="stat-line"><div class="stat-box"><b>Sem VPN detectada</b><span>o tráfego sai pelo seu provedor</span></div></div>';
  const torStatus = s.tor.active
    ? '<div class="stat-line"><div class="stat-box ok"><b>Tor externo (SOCKS)</b><span>127.0.0.1:' + esc(String(s.tor.port)) + ' · sessão isolada</span></div>' +
      '<div class="stat-sub">o cliente Tor desktop precisa estar rodando; sem ele as páginas não abrem</div></div>'
    : '<div class="stat-line"><div class="stat-box"><b>Tor externo desligado</b><span>Tor embutido: painel Conexão Tor (Ctrl+Shift+T). Tor externo (seu cliente): ative em Configurações</span></div></div>';
  body.innerHTML =
    '<h4 class="pt-title">' + svg('net', 15) + ' Estado da conexão</h4>' +
    vpnStatus + torStatus +
    '<div class="btn-row"><button class="btn" id="net-refresh">Atualizar detecção</button>' +
      '<button class="btn" id="net-checkip">Verificar meu IP</button></div>' +
    '<div id="net-ipresult"></div>' +
    '<h4>Proteções ativas</h4>' +
    '<div class="row tight"><div class="row-main"><div class="row-title">WebRTC</div><div class="row-url">' +
      (s.webrtcProtected ? 'UDP fora do proxy bloqueado (sem vazamento de IP)' : 'SEM proteção — risco de vazamento de IP') + '</div></div></div>' +
    '<div class="row tight"><div class="row-main"><div class="row-title">DNS seguro (DoH)</div>' +
      '<div class="row-url">' + esc(String(s.doh.provider || 'off')) + (s.doh.strict ? ' (modo restrito)' : ' (modo automático)') + ' — aplicado na hora</div></div></div>' +
    ((s.warnings && s.warnings.length)
      ? s.warnings.map(w => '<div class="dl-scan scan-warn">' + esc(w) + '</div>').join('') : '') +
    '<p class="dl-note">A detecção de VPN usa apenas as interfaces de rede do seu computador — nada é consultado. “Verificar meu IP” usa ifconfig.co pela MESMA sessão do navegador (mostra o efeito real do VPN/Tor) e só roda quando você clica.</p>' +
    '<h4>Sessões isoladas (contêineres)</h4>' +
    '<div id="net-containers"></div>' +
    '<div class="add-form"><input id="cont-name" type="text" placeholder="Nome da nova sessão (ex.: Trabalho)" spellcheck="false" autocomplete="off">' +
      '<button class="btn" id="cont-create">Criar</button></div>' +
    '<p class="dl-note">Cada sessão tem cookies/armazenamento próprios, TODOS em RAM. Clique direito na aba para mover entre sessões.</p>';

  const renderContainers = () => {
    api.containers.list().then(list => {
      containersList = list;
      const el = $('#net-containers');
      if (!el) return;
      el.innerHTML = list.map(c =>
        '<div class="row tight"><span class="row-ic" data-hue="' + hue(c.name) + '">' + esc(c.name[0].toUpperCase()) + '</span>' +
        '<div class="row-main"><div class="row-title">' + esc(c.name) + (c.id === 'padrao' ? ' (padrão)' : '') + '</div></div>' +
        (c.id !== 'padrao' ? '<button class="icon-btn del" data-cont="' + esc(c.id) + '" title="Remover sessão">' + svg('trash', 14) + '</button>' : '') +
        '</div>').join('');
      el.querySelectorAll('[data-cont]').forEach(b => b.addEventListener('click', async () => {
        try { await api.containers.remove(b.dataset.cont); renderContainers(); }
        catch (e) { toast(e && e.message ? e.message : 'Não foi possível remover.'); }
      }));
      renderTabs();
    }).catch(() => {});
  };
  renderContainers();
  const createBtn = $('#cont-create');
  if (createBtn) createBtn.addEventListener('click', async () => {
    const name = $('#cont-name').value.trim();
    if (!name) return;
    try { await api.containers.create(name); $('#cont-name').value = ''; renderContainers(); toast('Sessão isolada criada.'); }
    catch (e) { toast(e && e.message ? e.message : 'Não foi possível criar.'); }
  });
  $('#net-refresh').addEventListener('click', async () => {
    await api.network.refreshVpn();
    renderNetworkPanel();
  });
  $('#net-checkip').addEventListener('click', async () => {
    const el = $('#net-ipresult');
    el.innerHTML = '<div class="empty tight">Consultando…</div>';
    const r = await api.network.checkIp();
    el.innerHTML = r.ok
      ? '<div class="dl-scan scan-ok">IP público visto pelos sites: <b>' + esc(r.ip) + '</b>' +
        (r.country ? ' — ' + esc(r.country) : '') + (r.viaTor ? ' (via Tor)' : '') + '</div>'
      : '<div class="dl-scan scan-warn">Não foi possível verificar: ' + esc(r.reason || '?') + '</div>';
  });
}

function renderSecurityPanel() {
  const body = $('#security-body');
  api.security.scanTools().then(tools => {
    api.security.urlgateList().then(trusted => {
      const scans = downloadsCache.filter(d => d.scan || d.quarantine);
      body.innerHTML =
        '<h4 class="pt-title">' + svg('shield', 15) + ' Security Gateway</h4>' +
        '<div class="stat-line"><div class="stat-box"><b>' + scans.length + '</b><span>downloads verificados nesta sessão</span></div></div>' +
        '<h5>Motores de varredura</h5>' +
        '<div id="engines-box"><div class="empty tight">Consultando os motores…</div></div>' +
        '<div class="btn-row"><button class="btn" id="engines-refresh">Atualizar estado</button> <button class="btn" id="engines-update">Atualizar base do ClamAV agora</button></div>' +
        '<p class="dl-note">Nenhum resultado é garantia de que o arquivo é seguro. “Nenhuma ameaça detectada” só significa que os motores ativos não encontraram nada; sem antivírus ativo o download aparece como “SEM varredura antivírus”. Confira sempre a origem.</p>' +
        '<h5>Hosts confiáveis do alerta de URLs (nesta sessão)</h5>' +
        '<div>' + (trusted.length
          ? trusted.map(h => '<span class="chip">' + esc(h) + '<button data-trust="' + esc(h) + '" title="Remover">' + svg('x', 11) + '</button></span>').join('')
          : '<span class="empty tight">Nenhum — todos os sites suspeitos continuarão gerando alerta.</span>') + '</div>' +
        '<h5>Eventos de segurança</h5>' +
        (securityLogCache.length
          ? securityLogCache.slice(0, 30).map(ev =>
            '<div class="row tight"><div class="row-main"><div class="row-title">' +
              '<span class="ev-kind ' + (ev.level !== 'info' ? 'ev-warn' : '') + '">' + esc(ev.kind) + '</span> ' + esc(ev.host || '') + '</div>' +
              '<div class="row-url">' + esc(ev.detail || '') + '</div></div>' +
              '<span class="row-time">' + fmtTime(ev.ts) + '</span></div>').join('')
          : '<div class="empty tight">Nenhum evento ainda nesta sessão.</div>');
      body.querySelectorAll('[data-trust]').forEach(b => b.addEventListener('click', async () => {
        await api.security.urlgateRemove(b.dataset.trust);
        renderSecurityPanel();
      }));
      const paintEngines = (st) => {
        const box = $('#engines-box');
        if (!box) return;
        const label = { ativo: 'ATIVO', 'sem-base': 'SEM BASE', 'base-antiga': 'BASE ANTIGA', ausente: 'AUSENTE', indisponivel: 'INDISPONÍVEL' };
        box.innerHTML =
          '<div class="dl-scan ' + (st.antivirusAtivo ? 'scan-ok' : 'scan-warn') + '">' + esc(st.resumo) + '</div>' +
          st.engines.map(e => {
            const b = e.base;
            const det = [];
            if (e.versao) det.push('versão ' + esc(e.versao));
            if (e.embutido) det.push('embutido no pacote');
            if (e.id === 'clamav' && b) det.push(b.assinaturas.toLocaleString('pt-BR') + ' assinaturas · daily ' + b.daily + ' · main ' + b.main + ' · base com ' + b.idadeDias + ' dia(s)' + (b.persistente ? ' · guardada em disco' : ' · só nesta sessão'));
            if (e.id === 'nativo' && b) det.push(b.hashesDoUsuario + ' hash(es) da sua lista');
            return '<div class="row tight"><div class="row-main"><div class="row-title">' + esc(e.nome) + ' — <b>' + (label[e.estado] || esc(e.estado)) + '</b></div>' +
              '<div class="row-url">' + det.join(' · ') + (e.motivo ? (det.length ? '<br>' : '') + esc(e.motivo) : '') + '</div></div></div>';
          }).join('');
      };
      api.security.engines().then(paintEngines).catch(() => { const bx = $('#engines-box'); if (bx) bx.innerHTML = '<div class="empty tight">Não foi possível consultar os motores.</div>'; });
      $('#engines-refresh').addEventListener('click', () => api.security.engines().then(paintEngines).catch(() => {}));
      $('#engines-update').addEventListener('click', async (ev) => {
        ev.target.disabled = true;
        try { paintEngines(await api.security.enginesUpdateClamav()); } catch (_) { toast('Não foi possível atualizar agora.'); }
        ev.target.disabled = false;
      });
    }).catch(() => {});
  }).catch(() => {});
}

function renderHistoryPanel() {
  const body = $('#history-body');
  body.innerHTML =
    '<div class="panel-tools">' +
      '<input id="hist-search" type="text" placeholder="Buscar no histórico da sessão" spellcheck="false" autocomplete="off" value="' + esc(historyQuery) + '">' +
      '<button class="btn danger" id="hist-clear">Limpar</button></div>' +
    '<p class="dl-note">O histórico existe SÓ na memória — ao fechar o NanoDesk ele desaparece por completo e nunca é gravado no disco.</p>' +
    '<div id="hist-list"><div class="empty">Carregando…</div></div>';
  const loadList = async () => {
    const items = await api.history.list(historyQuery, { limit: 200 });
    const el = $('#hist-list');
    if (!el) return;
    el.innerHTML = items.length
      ? items.map(h =>
        '<div class="row" data-url="' + esc(h.url) + '">' +
          rowIcon(h.url, h.title) +
          '<div class="row-main"><div class="row-title">' + esc(h.title || h.url) + '</div>' +
          '<div class="row-url">' + esc(h.url) + '</div></div>' +
          '<span class="row-time">' + fmtTime(h.ts) + '</span></div>').join('')
      : '<div class="empty">' + (historyQuery ? 'Nada encontrado.' : 'Nenhuma navegação ainda nesta sessão.') + '</div>';
    el.querySelectorAll('.row').forEach(r => r.addEventListener('click', () => {
      const t = activeTab();
      closePanels();
      if (t) navigateActive(r.dataset.url);
      else createTab(r.dataset.url);
    }));
  };
  const inp = $('#hist-search');
  inp.addEventListener('input', () => { historyQuery = inp.value; loadList(); });
  $('#hist-clear').addEventListener('click', async () => {
    await api.history.clear();
    historyQuery = '';
    inp.value = '';
    loadList();
    toast('Histórico da sessão apagado.');
  });
  loadList();
}

/* ---------------- painel Cofre de senhas NATIVO (1.8.9) ----------------
 * Cofre embutido: AES-256-GCM + PBKDF2 (600k). A senha-mestra nunca
 * sai do processo principal — o renderer só recebe itens decifrados
 * via IPC confiável. Estados: desativado / não-criado / bloqueado /
 * desbloqueado (lista + editor).
 */

function renderVaultPanel() {
  const body = $('#vault-body');
  if (!body) return;
  if (!vaultState.enabled) {
    body.innerHTML =
      '<h4 class="pt-title">' + svg('lock', 15) + ' Cofre de senhas</h4>' +
      '<p class="dl-note">O cofre está desativado nas configurações. Ative “Cofre de senhas nativo” para usar o preenchimento automático de logins.</p>';
    return;
  }
  if (!vaultState.initialized) return renderVaultCreate(body);
  if (!vaultState.unlocked) return renderVaultUnlock(body);
  renderVaultList(body);
}

function renderVaultCreate(body) {
  body.innerHTML =
    '<h4 class="pt-title">' + svg('lock', 15) + ' Criar cofre de senhas</h4>' +
    '<p class="dl-note">O cofre é cifrado com AES-256-GCM e a senha-mestra é derivada com PBKDF2 (600 000 iterações). ' +
      'A chave fica só na RAM; o arquivo em disco é ilegível sem a senha. <b>Não há como recuperar a senha-mestra — se a esquecer, o cofre é perdido.</b></p>' +
    '<div class="vault-form">' +
      '<label>Senha-mestra' +
        '<input id="vault-new-pw" type="password" placeholder="mínimo 14 caracteres (frase-senha)" autocomplete="new-password"></label>' +
      '<label>Confirmar senha' +
        '<input id="vault-new-pw2" type="password" placeholder="repita a senha-mestra" autocomplete="new-password"></label>' +
      '<div class="btn-row"><button type="button" class="btn" id="vault-vk-toggle" title="Digite com o mouse: protege contra keyloggers que só gravam teclas">⌨ Teclado virtual</button></div>' +
      '<div id="vault-vk-host"></div>' +
      '<div class="btn-row">' +
        '<button class="btn primary" id="vault-create-btn">Criar cofre</button>' +
      '</div>' +
    '</div>';
  const pw = $('#vault-new-pw');
  const pw2 = $('#vault-new-pw2');
  const submit = async () => {
    const a = pw.value || '';
    const b = pw2.value || '';
    if (Array.from(a).length < 14) { toast('A senha-mestra precisa ter ao menos 14 caracteres (use uma frase-senha: 4 palavras ao acaso já bastam).'); return; }
    if (a !== b) { toast('As senhas não coincidem.'); return; }
    try {
      await api.vault.create(a);
      toast('Cofre criado. Desbloqueie com a senha-mestra para começar.');
      try { vaultState = Object.assign({}, vaultState, await api.vault.status()); } catch (_) {}
      renderVaultPanel();
    } catch (e) { toast(e && e.message ? e.message : 'Não foi possível criar o cofre.'); }
  };
  $('#vault-create-btn').addEventListener('click', submit);
  pw.addEventListener('keydown', e => { if (e.key === 'Enter') pw2.focus(); });
  pw2.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
  try { NDVKeyboard.attach({ inputs: [pw, pw2], host: $('#vault-vk-host'), toggle: $('#vault-vk-toggle') }); } catch (_) { /* sem teclado virtual */ }
  setTimeout(() => pw.focus(), 50);
}

function renderVaultUnlock(body) {
  body.innerHTML =
    '<h4 class="pt-title">' + svg('lock', 15) + ' Desbloquear cofre</h4>' +
    '<div class="stat-line"><div class="stat-box"><b>' + vaultState.itemCount + '</b><span>itens no cofre (bloqueado)</span></div></div>' +
    '<p class="dl-note">A senha-mestra destrava a chave de cifragem na RAM. Após ' + vaultState.autolockMinutes + ' min de inatividade, o cofre se bloqueia sozinho.</p>' +
    '<div class="vault-form">' +
      '<label>Senha-mestra' +
        '<input id="vault-unlock-pw" type="password" placeholder="senha-mestra" autocomplete="current-password"></label>' +
      '<div class="btn-row"><button type="button" class="btn" id="vault-vk-toggle" title="Digite com o mouse: protege contra keyloggers que só gravam teclas">⌨ Teclado virtual</button></div>' +
      '<div id="vault-vk-host"></div>' +
      '<div class="btn-row">' +
        '<button class="btn primary" id="vault-unlock-btn">Desbloquear</button>' +
        '<button class="btn danger" id="vault-destroy-btn" title="Apaga o cofre e todos os itens — irreversível">Redefinir cofre</button>' +
      '</div>' +
    '</div>';
  const pw = $('#vault-unlock-pw');
  const submit = async () => {
    try {
      await api.vault.unlock(pw.value || '');
      pw.value = '';
      toast('Cofre desbloqueado.');
      try { vaultState = Object.assign({}, vaultState, await api.vault.status()); } catch (_) {}
      renderVaultPanel();
    } catch (e) { toast(e && e.message ? e.message : 'Não foi possível desbloquear.'); }
  };
  $('#vault-unlock-btn').addEventListener('click', submit);
  pw.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
  try { NDVKeyboard.attach({ inputs: [pw], host: $('#vault-vk-host'), toggle: $('#vault-vk-toggle') }); } catch (_) { /* sem teclado virtual */ }
  $('#vault-destroy-btn').addEventListener('click', async () => {
    if (!confirm('Apagar o cofre inteiro? Todos os itens cifrados serão perdidos. Esta ação é irreversível.')) return;
    try {
      await api.vault.destroy();
      toast('Cofre apagado. Crie um novo para usar o preenchimento de login.');
      try { vaultState = Object.assign({}, vaultState, await api.vault.status()); } catch (_) {}
      renderVaultPanel();
    } catch (e) { toast(e && e.message ? e.message : 'Falha ao apagar.'); }
  });
  setTimeout(() => pw.focus(), 50);
}

function renderVaultList(body) {
  // modo edição/novo?
  if (vaultEditId !== null) {
    return renderVaultEditor(body);
  }
  body.innerHTML =
    '<div class="panel-tools">' +
      '<input id="vault-search" type="text" placeholder="Buscar por nome, usuário ou site" spellcheck="false" autocomplete="off" value="' + esc(vaultQuery) + '">' +
      '<button class="btn primary" id="vault-add-btn">' + svg('plus', 14) + ' Novo</button>' +
      '<button class="btn" id="vault-lock-btn" title="Bloquear agora">' + svg('lock', 14) + ' Bloquear</button>' +
    '</div>' +
    '<div class="stat-line"><div class="stat-box"><b>' + vaultState.itemCount + '</b><span>itens no cofre · autolock em ' + vaultState.autolockMinutes + ' min</span></div></div>' +
    '<div id="vault-list"><div class="empty">Carregando…</div></div>' +
    '<div class="btn-row" style="margin-top:14px">' +
      '<button class="btn" id="vault-gen-btn">' + svg('refresh', 13) + ' Gerar senha</button>' +
      '<button class="btn" id="vault-export-btn">Exportar</button>' +
      '<button class="btn" id="vault-import-btn">Importar</button>' +
      '<button class="btn" id="vault-changemaster-btn">Trocar senha-mestra</button>' +
    '</div>';
  const inp = $('#vault-search');
  inp.addEventListener('input', () => { vaultQuery = inp.value; loadVaultList(); });
  $('#vault-add-btn').addEventListener('click', () => { vaultEditId = 'new'; renderVaultPanel(); });
  $('#vault-lock-btn').addEventListener('click', async () => {
    try { await api.vault.lock(); toast('Cofre bloqueado.'); } catch (e) { toast(e && e.message || 'Falha.'); }
  });
  $('#vault-gen-btn').addEventListener('click', () => vaultGenerateDialog());
  $('#vault-export-btn').addEventListener('click', () => vaultExport());
  $('#vault-import-btn').addEventListener('click', () => vaultImport());
  $('#vault-changemaster-btn').addEventListener('click', () => vaultChangeMasterDialog());
  loadVaultList();
}

async function loadVaultList() {
  const el = $('#vault-list');
  if (!el) return;
  let items = [];
  try {
    items = vaultQuery
      ? await api.vault.search(vaultQuery)
      : await api.vault.list();
  } catch (e) {
    el.innerHTML = '<div class="empty">' + esc((e && e.message) || 'Cofre bloqueado.') + '</div>';
    return;
  }
  if (!items.length) {
    el.innerHTML = '<div class="empty">' + (vaultQuery ? 'Nada encontrado.' : 'Cofre vazio. Clique em “Novo” para adicionar um login.') + '</div>';
    return;
  }
  el.innerHTML = items.map(it => {
    const reveal = !!vaultReveal[it.id];
    const host = (it.uris && it.uris[0]) ? hostOf(it.uris[0]) : '';
    return '<div class="row" data-id="' + esc(it.id) + '">' +
      '<div class="row-main">' +
        '<div class="row-title">' + esc(it.name || '(sem nome)') + '</div>' +
        '<div class="row-url">' + esc(it.username || '(sem usuário)') + (host ? ' · ' + esc(host) : '') + '</div>' +
      '</div>' +
      '<div class="row-actions">' +
        (reveal
          ? '<code class="vault-pw">' + esc(it.password || '') + '</code>'
          : '<span class="vault-pw-mask">●●●●●●●●</span>') +
        '<button class="icon-btn" data-reveal="' + esc(it.id) + '" title="' + (reveal ? 'Ocultar' : 'Mostrar') + ' senha">' + svg(reveal ? 'lock' : 'check', 13) + '</button>' +
        '<button class="icon-btn" data-copy="' + esc(it.id) + '" title="Copiar senha">' + svg('download', 13) + '</button>' +
        '<button class="icon-btn" data-edit="' + esc(it.id) + '" title="Editar">' + svg('gear', 13) + '</button>' +
        '<button class="icon-btn" data-del="' + esc(it.id) + '" title="Excluir">' + svg('trash', 13) + '</button>' +
      '</div>' +
    '</div>';
  }).join('');
  el.querySelectorAll('[data-reveal]').forEach(b => b.addEventListener('click', () => {
    const id = b.dataset.reveal;
    vaultReveal[id] = !vaultReveal[id];
    loadVaultList();
  }));
  el.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', async () => {
    try {
      // 1.9.1: a cópia é feita no processo principal (limpa em 20 s só se ainda for a senha)
      const ok = await api.vault.copy(b.dataset.copy);
      toast(ok ? 'Senha copiada (limpa em 20 s ou ao fechar).' : 'Não foi possível copiar.');
    } catch (e) { toast('Não foi possível copiar.'); }
  }));
  el.querySelectorAll('[data-edit]').forEach(b => b.addEventListener('click', () => {
    vaultEditId = b.dataset.edit;
    renderVaultPanel();
  }));
  el.querySelectorAll('[data-del]').forEach(b => b.addEventListener('click', async () => {
    if (!confirm('Excluir este item do cofre?')) return;
    try {
      await api.vault.remove(b.dataset.del);
      toast('Item excluído do cofre.');
    } catch (e) { toast(e && e.message || 'Falha.'); }
  }));
}

function renderVaultEditor(body) {
  const isNew = vaultEditId === 'new';
  let item = { name: '', username: '', password: '', uris: [''], notes: '' };
  // pré-preenche com o host da aba ativa quando for novo
  if (isNew) {
    const t = activeTab();
    if (t && /^https?:\/\//i.test(String(t.url || ''))) {
      item.uris = [t.url];
      item.name = hostOf(t.url) || '';
    }
  }
  body.innerHTML =
    '<h4 class="pt-title">' + svg('lock', 15) + ' ' + (isNew ? 'Novo item' : 'Editar item') + '</h4>' +
    '<div class="vault-form">' +
      '<label>Nome' +
        '<input id="vault-ed-name" type="text" placeholder="ex.: Email principal" value="' + esc(item.name) + '"></label>' +
      '<label>Usuário / e-mail' +
        '<input id="vault-ed-user" type="text" autocomplete="off" value="' + esc(item.username) + '"></label>' +
      '<label>Senha' +
        '<div class="vault-pw-row">' +
          '<input id="vault-ed-pass" type="text" autocomplete="off" value="' + esc(item.password) + '">' +
          '<button class="btn" id="vault-ed-gen" title="Gerar senha forte">' + svg('refresh', 13) + '</button>' +
        '</div></label>' +
      '<label>URL(s) do site (uma por linha)' +
        '<textarea id="vault-ed-uris" rows="2" autocomplete="off">' + esc(item.uris.join('\n')) + '</textarea></label>' +
      '<label>Notas (opcional)' +
        '<textarea id="vault-ed-notes" rows="3" autocomplete="off">' + esc(item.notes) + '</textarea></label>' +
      '<div class="btn-row">' +
        '<button class="btn primary" id="vault-ed-save">Salvar</button>' +
        '<button class="btn" id="vault-ed-cancel">Cancelar</button>' +
      '</div>' +
    '</div>';
  $('#vault-ed-gen').addEventListener('click', async () => {
    try {
      const pw = await api.vault.generate({ length: 24, uppercase: true, lowercase: true, digits: true, symbols: true });
      $('#vault-ed-pass').value = pw;
    } catch (_) { toast('Não foi possível gerar.'); }
  });
  $('#vault-ed-cancel').addEventListener('click', () => { vaultEditId = null; renderVaultPanel(); });
  $('#vault-ed-save').addEventListener('click', async () => {
    const name = $('#vault-ed-name').value.trim();
    const username = $('#vault-ed-user').value;
    const password = $('#vault-ed-pass').value;
    const uris = $('#vault-ed-uris').value.split('\n').map(s => s.trim()).filter(Boolean);
    const notes = $('#vault-ed-notes').value;
    if (!name && !username && !password) { toast('Preencha ao menos um campo.'); return; }
    try {
      if (isNew) {
        await api.vault.add({ name, username, password, uris, notes });
        toast('Item adicionado ao cofre.');
      } else {
        await api.vault.update(vaultEditId, { name, username, password, uris, notes });
        toast('Item atualizado.');
      }
      vaultEditId = null;
      try { vaultState = Object.assign({}, vaultState, await api.vault.status()); } catch (_) {}
      renderVaultPanel();
    } catch (e) { toast(e && e.message || 'Falha ao salvar.'); }
  });
  setTimeout(() => $('#vault-ed-name').focus(), 50);
}

async function vaultGenerateDialog() {
  // diálogo simples: prompt nativo não existe; usamos um mini-form inline.
  const body = $('#vault-body');
  body.innerHTML =
    '<h4 class="pt-title">' + svg('refresh', 15) + ' Gerar senha forte</h4>' +
    '<div class="vault-form">' +
      '<label>Tamanho' +
        '<input id="vault-gen-len" type="number" min="6" max="128" value="24"></label>' +
      '<div class="vault-chk">' +
        '<label><input type="checkbox" id="vault-gen-up" checked> Maiúsculas</label>' +
        '<label><input type="checkbox" id="vault-gen-lo" checked> Minúsculas</label>' +
        '<label><input type="checkbox" id="vault-gen-di" checked> Dígitos</label>' +
        '<label><input type="checkbox" id="vault-gen-sy" checked> Símbolos</label>' +
      '</div>' +
      '<div class="btn-row">' +
        '<button class="btn primary" id="vault-gen-go">Gerar</button>' +
        '<button class="btn" id="vault-gen-copy">Copiar</button>' +
        '<button class="btn" id="vault-gen-back">Voltar</button>' +
      '</div>' +
      '<code id="vault-gen-out" class="vault-gen-out">(gera aqui)</code>' +
    '</div>';
  const gen = async () => {
    const len = Number($('#vault-gen-len').value) || 24;
    const pw = await api.vault.generate({
      length: len,
      uppercase: $('#vault-gen-up').checked,
      lowercase: $('#vault-gen-lo').checked,
      digits: $('#vault-gen-di').checked,
      symbols: $('#vault-gen-sy').checked
    });
    $('#vault-gen-out').textContent = pw;
  };
  $('#vault-gen-go').addEventListener('click', gen);
  $('#vault-gen-copy').addEventListener('click', () => {
    const t = $('#vault-gen-out').textContent;
    if (t && t !== '(gera aqui)') {
      api.vault.copyText(t).then((ok) => toast(ok ? 'Senha copiada (limpa em 20 s ou ao fechar).' : 'Não foi possível copiar.')).catch(() => toast('Não foi possível copiar.'));
    }
  });
  $('#vault-gen-back').addEventListener('click', () => { vaultEditId = null; renderVaultPanel(); });
  gen();
}

async function vaultExport() {
  try {
    const json = await api.vault.exportJson();
    const blob = new Blob([json], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'nanodesk-vault-' + new Date().toISOString().slice(0, 10) + '.json';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    toast('Cofre exportado (texto plano — guarde com cuidado!).');
  } catch (e) { toast(e && e.message || 'Falha ao exportar.'); }
}

function vaultImport() {
  const inp = document.createElement('input');
  inp.type = 'file';
  inp.accept = '.json,application/json';
  inp.addEventListener('change', async () => {
    const f = inp.files && inp.files[0];
    if (!f) return;
    const txt = await f.text();
    const mode = confirm('Substituir todos os itens existentes? (OK = substituir, Cancelar = adicionar aos existentes)') ? 'replace' : 'merge';
    try {
      const r = await api.vault.importJson(txt, mode);
      toast('Importação concluída: ' + r.added + ' itens adicionados (' + r.total + ' no total).');
      try { vaultState = Object.assign({}, vaultState, await api.vault.status()); } catch (_) {}
      renderVaultPanel();
    } catch (e) { toast(e && e.message || 'Falha ao importar.'); }
  });
  inp.click();
}

function vaultChangeMasterDialog() {
  const body = $('#vault-body');
  body.innerHTML =
    '<h4 class="pt-title">' + svg('lock', 15) + ' Trocar senha-mestra</h4>' +
    '<p class="dl-note">A nova senha reencripta TODOS os itens do cofre com um novo salt. Não há como recuperá-la se esquecer.</p>' +
    '<div class="vault-form">' +
      '<label>Senha-mestra atual' +
        '<input id="vault-cm-old" type="password" autocomplete="current-password"></label>' +
      '<label>Nova senha-mestra' +
        '<input id="vault-cm-new" type="password" autocomplete="new-password" placeholder="mínimo 14 caracteres (frase-senha)"></label>' +
      '<label>Confirmar nova senha' +
        '<input id="vault-cm-new2" type="password" autocomplete="new-password"></label>' +
      '<div class="btn-row">' +
        '<button class="btn primary" id="vault-cm-go">Trocar senha</button>' +
        '<button class="btn" id="vault-cm-back">Voltar</button>' +
      '</div>' +
    '</div>';
  $('#vault-cm-back').addEventListener('click', () => { vaultEditId = null; renderVaultPanel(); });
  $('#vault-cm-go').addEventListener('click', async () => {
    const oldPw = $('#vault-cm-old').value;
    const newPw = $('#vault-cm-new').value;
    const newPw2 = $('#vault-cm-new2').value;
    if (Array.from(newPw).length < 14) { toast('A nova senha precisa ter ao menos 14 caracteres (use uma frase-senha).'); return; }
    if (newPw !== newPw2) { toast('As senhas novas não coincidem.'); return; }
    try {
      await api.vault.changeMaster(oldPw, newPw);
      toast('Senha-mestra trocada com sucesso.');
      vaultEditId = null;
      renderVaultPanel();
    } catch (e) { toast(e && e.message || 'Falha ao trocar a senha.'); }
  });
  setTimeout(() => $('#vault-cm-old').focus(), 50);
}

/* ---------------- painel Conexão Tor (1.5.3) ---------------- */

function torStatusText() {
  switch (torState.state) {
    case 'connected': return 'Conectado à rede Tor';
    case 'starting': return 'Iniciando o daemon Tor…';
    case 'bootstrapping': return 'Conectando à rede Tor — ' + (torState.progress || 0) + '%';
    case 'stopping': return 'Desconectando…';
    case 'error': return 'Falhou: ' + (torState.error || 'erro desconhecido');
    default: return torState.supported === false
      ? 'Indisponível: o pacote do Tor não foi encontrado nesta instalação.'
      : 'Desconectado';
  }
}

async function renderTorPanel() {
  const body = $('#tor-body');
  try { torState = Object.assign({}, torState, await api.tor.status()); } catch (_) { /* ignora */ }
  const connected = torState.state === 'connected';
  const busy = torState.state === 'starting' || torState.state === 'bootstrapping';

  const checkHtml = torState.check
    ? (torState.check.ok
      ? (torState.check.isTor
        ? '<div class="tor-check ok">✓ Confirmado pelo check.torproject.org: o tráfego SAIU pela rede Tor' +
          (torState.check.ip ? ' (IP de saída: ' + esc(torState.check.ip) + ')' : '') + '.</div>'
        : '<div class="tor-check bad">Atenção: o check.torproject.org reportou saída FORA da rede Tor.</div>')
      : '<div class="tor-check bad">Não foi possível verificar agora: ' + esc(torState.check.reason || '') + '</div>')
    : '';

  body.innerHTML =
    '<div class="stat-line">' +
      '<div class="stat-box tor-box"><b>' + (connected ? 'ON' : busy ? (torState.progress || 0) + '%' : 'OFF') + '</b>' +
      '<span>' + esc(torStatusText()) + '</span></div>' +
    '</div>' +
    (busy || connected ? '<progress max="100" value="' + (connected ? 100 : (torState.progress || 0)) + '"></progress>' : '') +
    (busy && torState.summary ? '<p class="dl-note">' + esc(torState.summary) + '</p>' : '') +
    '<div class="btn-row">' +
      (connected || busy
        ? '<button class="btn danger" id="tor-stop">Desconectar</button>'
        : '<button class="btn" id="tor-start">' + svg('onion', 14) + ' Conectar ao Tor</button>') +
      (connected
        ? '<button class="btn" id="tor-newnym">Nova identidade</button>' +
          '<button class="btn" id="tor-opentab">Abrir aba Tor</button>'
        : '') +
    '</div>' +
    (connected ? '<button class="btn" id="tor-verify">Verificar conexão (check.torproject.org)</button>' + checkHtml : '') +
    '<h4>Como funciona</h4>' +
    '<p class="dl-note">O NanoDesk inicia o <b>daemon Tor oficial</b> (Tor Expert Bundle, embarcado no aplicativo) — nenhum cliente externo é necessário. ' +
    'Ao conectar, novas <b>abas Tor</b> são criadas com uma sessão SEPARADA da navegação normal (cookies próprios, só em memória) e o tráfego ' +
    'delas sai EXCLUSIVAMENTE pela rede Tor via SOCKS5: sem rota alternativa, WebRTC restrito e permissões sempre negadas. Se o Tor cair, ' +
    'as abas Tor ficam SEM internet em vez de vazar tráfego direto.</p>' +
    '<p class="dl-note">Seus hábitos continuam sendo sua responsabilidade: evite entrar em contas reais em abas Tor (o Google, por exemplo, ' +
    'costuma bloquear logins vindos de saídas do Tor — isso é decisão do próprio site).</p>' +
    (torState.socksPort && connected ? '<p class="dl-note tight">Daemon local: SOCKS5 127.0.0.1:' + esc(String(torState.socksPort)) + ' · nada é gravado em disco além do consenso público (apagado ao fechar).</p>' : '');

  const start = $('#tor-start');
  if (start) start.addEventListener('click', async () => {
    start.disabled = true;
    try { await api.tor.start(); } catch (e) { toast(String((e && e.message) || 'Não foi possível iniciar o Tor.')); }
    renderTorPanel();
  });
  const stop = $('#tor-stop');
  if (stop) stop.addEventListener('click', async () => {
    try { await api.tor.stop(); toast('Tor desconectado. Abas Tor ficam sem internet (sem vazamento).'); }
    catch (e) { toast(String((e && e.message) || 'Falha ao desconectar.')); }
    renderTorPanel();
  });
  const nym = $('#tor-newnym');
  if (nym) nym.addEventListener('click', async () => {
    try {
      await api.tor.newIdentity();
      toast('Nova identidade: circuitos novos e cookies da sessão Tor apagados.');
    } catch (e) { toast(String((e && e.message) || 'Falha ao trocar a identidade.')); }
  });
  const openTab = $('#tor-opentab');
  if (openTab) openTab.addEventListener('click', async () => {
    try { closePanels(); await api.tor.openTab(); }
    catch (e) { toast(String((e && e.message) || 'Não foi possível abrir a aba Tor.')); }
  });
  const verify = $('#tor-verify');
  if (verify) verify.addEventListener('click', async () => {
    verify.disabled = true;
    verify.textContent = 'Verificando…';
    try {
      const r = await api.tor.check();
      torState.check = r;
    } catch (e) {
      torState.check = { ok: false, reason: String((e && e.message) || e) };
    }
    renderTorPanel();
  });
}

/* ---------------- 1.7.0: Biblioteca de traduções (LibraryTranslate) ---------------- */

let libCache = [];

async function renderBibliotecaPanel() {
  const body = $('#biblioteca-body');
  try { libCache = await api.library.list(''); } catch (_) { libCache = []; }
  drawBiblioteca(body, '');
}

function drawBiblioteca(body, q) {
  const needle = String(q || '').toLowerCase();
  const items = libCache.filter(r =>
    !needle ||
    (r.text || '').toLowerCase().includes(needle) ||
    (r.translation || '').toLowerCase().includes(needle) ||
    (r.title || '').toLowerCase().includes(needle));
  body.innerHTML =
    '<div class="btn-row"><input id="lib-q" type="text" placeholder="Buscar texto ou tradução…" value="' + esc(q || '') + '"></div>' +
    '<p class="dl-note">Seleciona um texto em qualquer site → clique direito → “Traduzir e salvar na Biblioteca”. Tudo vive só na memória do NanoDesk: fecha o app, some tudo.</p>' +
    (items.length
      ? items.map(r =>
          '<div class="row tight"><div class="row-main">' +
            '<div class="row-title">' + esc((r.text || '').slice(0, 160)) + '</div>' +
            '<div class="row-url" data-lib-tr>' + esc((r.translation || '').slice(0, 300)) + '</div>' +
            '<div class="row-url">' + esc((r.src || '?') + ' → ' + (r.target || '?') + (r.title ? ' · ' + String(r.title).slice(0, 60) : '')) + '</div>' +
          '</div>' +
          '<span class="row-time">' + fmtTime(r.date) + '</span>' +
          '<button class="icon-btn" data-lib-copy="' + esc(r.id) + '" title="Copiar tradução">' + svg('copy', 13) + '</button>' +
          '<button class="icon-btn" data-lib-del="' + esc(r.id) + '" title="Excluir">' + svg('x', 13) + '</button></div>'
        ).join('')
      : '<div class="empty">Nenhuma tradução ainda.<br>Selecione um texto em uma página e use “Traduzir e salvar na Biblioteca (LibraryTranslate)”.</div>') +
    (libCache.length
      ? '<div class="btn-row" style="margin-top:10px">' +
        '<button class="btn" id="lib-export">Exportar JSON</button>' +
        '<button class="btn danger" id="lib-clear">Limpar tudo</button></div>'
      : '');

  const qi = $('#lib-q');
  if (qi) {
    let tm = null;
    qi.addEventListener('input', () => {
      clearTimeout(tm);
      tm = setTimeout(() => drawBiblioteca(body, qi.value), 250);
    });
  }
  body.onclick = async (e) => {
    const cp = e.target.closest('[data-lib-copy]');
    if (cp) {
      const rec = libCache.find(r => r.id === cp.dataset.libCopy);
      if (rec) {
        try { await navigator.clipboard.writeText(rec.translation || ''); toast('Tradução copiada.'); } catch (_) {}
      }
      return;
    }
    const del = e.target.closest('[data-lib-del]');
    if (del) {
      try { libCache = await api.library.remove(del.dataset.libDel); drawBiblioteca(body, $('#lib-q') ? $('#lib-q').value : ''); } catch (_) {}
      return;
    }
    if (e.target.closest('#lib-clear')) {
      if (confirm('Apagar TODAS as traduções salvas nesta sessão?')) {
        try { libCache = await api.library.clear(); renderBibliotecaPanel(); } catch (_) {}
      }
      return;
    }
    if (e.target.closest('#lib-export')) {
      try {
        const all = await api.library.export();
        const blob = new Blob([JSON.stringify(all, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'nanodesk-biblioteca-traducoes.json';
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 4000);
      } catch (_) { toast('Não foi possível exportar.'); }
    }
  };
}

function renderSettingsPanel() {
  const body = $('#settings-body');
  body.innerHTML =
    '<h4>Geral</h4>' +
    '<label class="field"><span>Página inicial (botão "casa")</span>' +
      '<input id="set-homepage" type="text" placeholder="Deixe vazio para a Nova Aba interna" value="' + esc(settings.homepage || '') + '"></label>' +
    '<label class="field"><span>Buscador padrão</span>' +
      '<select id="set-engine">' +
        '<option value="duckduckgo">DuckDuckGo</option>' +
        '<option value="startpage">Startpage</option>' +
        '<option value="brave">Brave Search</option>' +
        '<option value="searxng">SearXNG (instância própria)</option>' +
        '<option value="bing">Bing</option>' +
        '<option value="google">Google</option>' +
      '</select></label>' +
    '<h4>Bloqueador de anúncios</h4>' +
    '<label class="check"><input type="checkbox" id="set-adblock" ' + (settings.adblockEnabled ? 'checked' : '') + '>' +
      '<span>Ativo (motor nativo + EasyList/EasyPrivacy via Ghostery)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-adscriptlets" ' + (settings.adblockScriptlets !== false ? 'checked' : '') + '>' +
      '<span>Neutralizar anúncios do YouTube e similares (scriptlets uBlock Origin) — desligue se um site não abrir; vale em novas páginas</span></label>' +
    '<h4>Proteções</h4>' +
    '<label class="check"><input type="checkbox" id="set-popupblock" ' + (settings.popupBlockerEnabled !== false ? 'checked' : '') + '>' +
      '<span>Bloquear pop-ups sem interação (conceitos Popup-Blocker-Pro)</span></label>' +
    '<label class="sel"><span>Modais e overlays de página (PopUpOFF nativo)</span>' +
      '<select id="set-overlayblock">' +
        '<option value="off">Desligado</option>' +
        '<option value="delicate">Delicado — converte fixos em estáticos (não esconde nada)</option>' +
        '<option value="easy">Moderado — overlays grandes e avisos de cookie/bloqueador</option>' +
        '<option value="hard">Agressivo (recomendado) — remove TODO fixo/sticky: mata modais anti-bloqueador como o do globo</option>' +
      '</select></label>' +
    '<label class="check"><input type="checkbox" id="set-redirectguard" ' + (settings.redirectGuardEnabled !== false ? 'checked' : '') + '>' +
      '<span>Cortar redirecionamentos de redes de anúncios e cadeias suspeitas (conceitos RedirectGuard)</span></label>' +
    '<h4>Downloads</h4>' +
    '<label class="check"><input type="checkbox" id="set-asksave" ' + (settings.askWhereToSave ? 'checked' : '') + '>' +
      '<span>Perguntar onde salvar cada arquivo</span></label>' +
    '<h4>Desempenho</h4>' +
    '<label class="check"><input type="checkbox" id="set-hibernate" ' + (settings.hibernateTabs ? 'checked' : '') + '>' +
      '<span>Suspender abas inativas automaticamente (economia de RAM)</span></label>' +
    '<label class="field"><span>Suspender após (minutos, 3–180)</span>' +
      '<input id="set-hibmin" type="number" min="3" max="180" value="' + esc(settings.hibernateMinutes || 15) + '"></label>' +
    '<h4>Privacidade</h4>' +
    '<label class="check"><input type="checkbox" id="set-dnt" ' + (settings.doNotTrack ? 'checked' : '') + '>' +
      '<span>Enviar cabeçalhos Do Not Track (DNT) e Global Privacy Control</span></label>' +
    '<label class="check"><input type="checkbox" id="set-fp" ' + (settings.fingerprintProtect !== false ? 'checked' : '') + '>' +
      '<span>Proteção contra fingerprinting (canvas com ruído, GPU genérica, áudio com ruído inaudível)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-clearurls" ' + (settings.clearUrls !== false ? 'checked' : '') + '>' +
      '<span>Limpar parâmetros de rastreamento dos endereços (utm_*, fbclid, gclid…)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-3pstrict" ' + (settings.thirdPartyCookiesStrict === true ? 'checked' : '') + '>' +
      '<span>Cookies de terceiros — modo estrito: também bloqueia quando o site de origem é DESCONHECIDO (service workers, requisições sem aba). Pode quebrar PWAs/logins.</span></label>' +
    '<label class="check"><input type="checkbox" id="set-3pcookies" ' + (settings.blockThirdPartyCookies !== false ? 'checked' : '') + '>' +
      '<span>Bloquear cookies de terceiros</span></label>' +
    '<h4>Rede (VPN / Tor / DNS)</h4>' +
    '<label class="check"><input type="checkbox" id="set-webrtc" ' + (settings.webrtcProtect !== false ? 'checked' : '') + '>' +
      '<span>Proteção WebRTC (bloqueia UDP fora do proxy — evita vazamento de IP)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-httpsfirst" ' + (settings.httpsFirst !== false ? 'checked' : '') + '>' +
      '<span>HTTPS preferencial (tenta https:// primeiro; cai para http só em erro)</span></label>' +
    '<label class="field"><span>DNS seguro (DoH — aplicado na hora)</span>' +
      '<select id="set-doh">' +
        '<option value="off">Desligado (DNS do sistema)</option>' +
        '<option value="cloudflare">Cloudflare</option>' +
        '<option value="cloudflare_family">Cloudflare Family (malware+adulto)</option>' +
        '<option value="quad9">Quad9</option>' +
        '<option value="google">Google</option>' +
        '<option value="custom">Personalizado…</option>' +
      '</select></label>' +
    '<label class="field"><span>Template DoH personalizado (se "Personalizado")</span>' +
      '<input id="set-dohcustom" type="text" placeholder="https://dns.meudominio/dns-query" value="' + esc(settings.secureDnsCustom || '') + '"></label>' +
    '<label class="check"><input type="checkbox" id="set-dohstrict" ' + (settings.secureDnsStrict ? 'checked' : '') + '>' +
      '<span>Modo restrito (nunca usa DNS comum — pode quebrar redes corporativas)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-tor" ' + (settings.torMode ? 'checked' : '') + '>' +
      '<span>Tor externo (SOCKS 127.0.0.1:9050 — usa um cliente Tor que VOCÊ roda; vale para todas as abas. Para o Tor embutido, use o painel Conexão Tor)</span></label>' +
    '<label class="field"><span>Porta do Tor</span><input id="set-torport" type="number" min="1024" max="65535" value="' + esc(settings.torPort || 9050) + '"></label>' +
    '<h4>Segurança</h4>' +
    '<label class="check"><input type="checkbox" id="set-urlgate" ' + (settings.urlGateEnabled !== false ? 'checked' : '') + '>' +
      '<span>Alertar antes de navegar para sites suspeitos (análise local)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-dlscan" ' + (settings.downloadScan !== false ? 'checked' : '') + '>' +
      '<span>Verificar downloads (tipo real, pacotes compactados, ClamAV/YARA se instalados)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-quarantine" ' + (settings.quarantineDownloads !== false ? 'checked' : '') + '>' +
      '<span>Quarentena quando o ANTIVÍRUS (ClamAV) detectar ameaça — arquivos apenas "suspeitos" ficam no lugar, com aviso</span></label>' +
    '<h4>Aplicativo</h4>' +
    '<label class="check"><input type="checkbox" id="set-updcheck" ' + (settings.updateCheck ? 'checked' : '') + '>' +
      '<span>Verificar atualizações automaticamente ao abrir (contata endoflife.date; o yt-dlp dos downloads de vídeo tem atualização própria e independente)</span></label>' +
    '<h4>Vídeo (YouTube) — 1.8.8</h4>' +
    '<p class="dl-note">1.8.8: o sistema Piped/Invidious/FreeTube foi REMOVIDO. O YouTube abre comum, protegido pelo bloqueador + SponsorBlock + anti-adblock. Apenas o yt-dlp baixa vídeos sob demanda (menu Ferramentas / botão direito).</p>' +
    '<label class="field"><span>Qualidade padrão do yt-dlp</span>' +
      '<select id="set-videoq">' +
        '<option value="best">Melhor disponível</option>' +
        '<option value="1080">1080p</option>' +
        '<option value="720">720p</option>' +
        '<option value="audio">Somente áudio (mp3)</option>' +
      '</select></label>' +
    '<label class="check"><input type="checkbox" id="set-ytdsubs" ' + (settings.ytdlpSubtitles ? 'checked' : '') + '>' +
      '<span>Embutir legendas (auto + manual) no .mp4 baixado</span></label>' +
    '<label class="check"><input type="checkbox" id="set-ytdthumb" ' + (settings.ytdlpThumbnail ? 'checked' : '') + '>' +
      '<span>Embutir capa (.jpg) no .mp4 baixado</span></label>' +
    '<h4>Proteções ativas (1.8.8)</h4>' +
    '<label class="check"><input type="checkbox" id="set-noredir" ' + (settings.noredirectEnabled !== false ? 'checked' : '') + '>' +
      '<span>Resolver redirecionamentos de trackers (Google url?q=, Bing base64, DuckDuckGo uddg, Reddit r., Steam, Facebook l.php, YouTube /redirect)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-adclean" ' + (settings.adCleanupEnabled !== false ? 'checked' : '') + '>' +
      '<span>Remover barras cinzentas de anúncio (containers vazios: .bstn-ad, gib-ad, .bastian-feed-item[data-type*=ad]…)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-pagesec" ' + (settings.pageSecurityScan !== false ? 'checked' : '') + '>' +
      '<span>Segurança da página: detectar miners de criptomoeda, iframes ocultos (phishing), senha em HTTP, auto-download de .exe</span></label>' +
    '<label class="check"><input type="checkbox" id="set-malblock" ' + (settings.malwareSiteBlock !== false ? 'checked' : '') + '>' +
      '<span>Bloquear sites de malware (StevenBlack hosts) ANTES de navegar</span></label>' +
    '<label class="check"><input type="checkbox" id="set-ppstrict" ' + (settings.popupBlockerStrict ? 'checked' : '') + '>' +
      '<span>Bloquear TODOS os pop-ups (modo estrito, schomery-style) — exceto same-origin e about:blank</span></label>' +
    '<label class="check"><input type="checkbox" id="set-ppaggr" ' + (settings.popupBlockerAggressive ? 'checked' : '') + '>' +
      '<span>Modo agressivo (bloqueia também some-origin em alguns casos)</span></label>' +
    '<h4>Antivírus dos downloads (ClamAV)</h4>' +
    '<p class="dl-note">O ClamAV só varre se tiver a base de assinaturas (~300 MB). Com o Tor em uso ela é baixada PELO TOR, com a sua permissão. Sem ela, o download aparece como <b>"SEM varredura antivírus"</b> — a análise local é só heurística e não é garantia.</p>' +
    '<label class="check"><input type="checkbox" id="set-avpersist" ' + (settings.clamavPersistDb === true ? 'checked' : '') + '>' +
      '<span>Guardar a base do antivírus em disco (~300 MB) para não baixar a cada sessão (grava em disco: exceção à regra "nada no disco")</span></label>' +
    '<h4>Proteção de teclado e de captura (1.9.1)</h4>' +
    '<p class="dl-note">Defesas locais contra keyloggers <b>de página</b>. Não substituem antivírus: um malware no sistema operacional grava o teclado fora do navegador (use o teclado virtual do cofre para a senha-mestra).</p>' +
    '<label class="check"><input type="checkbox" id="set-kguard" ' + (settings.keyboardGuard !== false ? 'checked' : '') + '>' +
      '<span>Esconder as teclas digitadas em campos de senha dos scripts do site (barra keyloggers por evento de tecla; não impede quem lê o valor do campo)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-kguardauth" ' + (settings.keyboardGuardAuthSites === true ? 'checked' : '') + '>' +
      '<span>Aplicar também em páginas de login e bancos (pode atrapalhar antifraude que mede o ritmo de digitação)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-cprot" ' + (settings.contentProtection === true ? 'checked' : '') + '>' +
      '<span>Impedir captura de tela e gravação da janela do NanoDesk (também some em compartilhamento de tela)</span></label>' +
    '<h4>Arquivar página (1.9.0)</h4>' +
    '<p class="dl-note">Salva a página inteira num único .html, 100% local: os recursos são buscados pela sessão da própria aba (inclusive Tor), rastreadores são ignorados e nada vai a serviço de terceiros. Atalho: Ctrl+Alt+S. O arquivo leva um selo SHA-256 verificável (menu Ferramentas → Verificar arquivo salvo).</p>' +
    '<label class="check"><input type="checkbox" id="set-arcnet" ' + (settings.archiveBlockNetwork !== false ? 'checked' : '') + '>' +
      '<span>Blindar o arquivo salvo: bloqueia rede e scripts ao abri-lo (não "liga para casa" nem rastreia)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-arcunused" ' + (settings.archiveRemoveUnused !== false ? 'checked' : '') + '>' +
      '<span>Remover CSS e fontes que a página não usa (arquivo menor)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-arclazy" ' + (settings.archiveLoadLazy !== false ? 'checked' : '') + '>' +
      '<span>Rolar a página antes de salvar para carregar imagens "lazy"</span></label>' +
    '<label class="check"><input type="checkbox" id="set-arctrk" ' + (settings.archiveSkipTrackers !== false ? 'checked' : '') + '>' +
      '<span>Ignorar recursos de rastreadores (lista do bloqueador)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-arcform" ' + (settings.archiveKeepForm !== false ? 'checked' : '') + '>' +
      '<span>Manter o que foi digitado em campos visíveis (senhas e campos ocultos NUNCA são salvos)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-archidden" ' + (settings.archiveRemoveHidden === true ? 'checked' : '') + '>' +
      '<span>Remover elementos ocultos (display:none)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-arcask" ' + (settings.archiveAskWhere !== false ? 'checked' : '') + '>' +
      '<span>Perguntar onde salvar (desligado: Downloads\\Páginas salvas)</span></label>' +
    '<h4>Cofre de senhas nativo (1.8.9)</h4>' +
    '<p class="dl-note">O cofre embutido substitui a antiga ponte pela CLI do Bitwarden. Criptografia AES-256-GCM + PBKDF2 (600 000 iterações); a senha-mestra nunca sai do processo principal e a chave derivada fica só na RAM. O arquivo cifrado fica em userData/nanodesk-vault.json.</p>' +
    '<label class="check"><input type="checkbox" id="set-vault" ' + (settings.vaultEnabled !== false ? 'checked' : '') + '>' +
      '<span>Cofre de senhas ativo (preenchimento de login + botão flutuante nas páginas)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-vaultsave" ' + (settings.vaultSavePrompt !== false ? 'checked' : '') + '>' +
      '<span>Oferecer salvar credenciais após enviar um formulário de login</span></label>' +
    '<label class="field"><span>Bloqueio automático após (minutos, 1–720)</span>' +
      '<input id="set-vaultlock" type="number" min="1" max="720" value="' + esc(settings.vaultAutolockMinutes || 15) + '"></label>' +
    '<label class="check"><input type="checkbox" id="set-vaultephemeral" ' + (settings.vaultEphemeral === true ? 'checked' : '') + '>' +
      '<span>Cofre temporário: só na memória, nada é gravado em disco e os itens somem ao fechar (só pode ser ligado se não existir cofre em disco; sem isto, o cofre é gravado cifrado em nanodesk-vault.json mesmo com o perfil local desligado)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-filtercache" ' + (settings.filtersCacheOnDisk !== false ? 'checked' : '') + '>' +
      '<span>Guardar o cache do bloqueador em disco para abrir mais rápido (desligue para não deixar nada em disco)</span></label>' +
    '<div class="btn-row"><button class="btn" id="btn-vault-open">Abrir painel do cofre</button></div>' +
    '<h4>SponsorBlock nativo (1.7.0)</h4>' +
    '<label class="check"><input type="checkbox" id="set-sb" ' + (settings.sponsorBlockEnabled === true ? 'checked' : '') + '>' +
      '<span>Pular patrocínios automaticamente (DESLIGADO por padrão: consulta sponsor.ajay.app a cada vídeo do YouTube; envia só um prefixo do hash do ID e seu IP — não funciona em abas Tor)</span></label>' +
    '<label class="check"><input type="checkbox" id="set-sbtoast" ' + (settings.sponsorBlockToast !== false ? 'checked' : '') + '>' +
      '<span>Mostrar aviso ao pular segmento</span></label>' +
    '<label class="field"><span>Categorias para pular</span><span id="set-sbcats">' +
      [['sponsor','Patrocínio'],['selfpromo','Autopromoção'],['interaction','Interação (curtir/inscrever)'],['intro','Introdução'],['outro','Encerramento'],['preview','Prévia/Recapitulação'],['filler','Enrolação'],['music_offtopic','Música não relacionada']].map(c =>
        '<label class="check"><input type="checkbox" class="sbcat" value="' + c[0] + '" ' +
        ((settings.sbCategories || []).includes(c[0]) ? 'checked' : '') + '> <span>' + esc(c[1]) + '</span></label>').join('') +
      '</span></label>' +
    '<h4>Consent-O-Matic nativo (1.7.0)</h4>' +
    '<label class="check"><input type="checkbox" id="set-cm" ' + (settings.consentomaticEnabled !== false ? 'checked' : '') + '>' +
      '<span>SEMPRE negar rastreadores nos popups de cookies (baseado na ideia do Consent-O-Matic)</span></label>' +
    '<label class="field"><span>Nível</span>' +
      '<select id="set-cmlevel">' +
        '<option value="max">Máximo (padrão): recusa tudo; se só houver “Gerenciar”, abre, desmarca tudo e salva</option>' +
        '<option value="smart">Moderado: apenas botões diretos de recusa</option>' +
      '</select></label>' +
    '<label class="field"><span>Reprocessar o mesmo site após (horas)</span>' +
      '<input id="set-cmcool" type="number" min="1" max="720" value="' + esc(settings.cmCooldownHours || 24) + '"></label>' +
    '<label class="field"><span>Sites onde NÃO interferir (um domínio por linha)</span>' +
      '<textarea id="set-cmwl" rows="2" spellcheck="false">' + esc((settings.cmWhitelist || []).join('\n')) + '</textarea></label>' +
    '<label class="field"><span>Sites de login/banco onde NADA é injetado (anti-fingerprint, bloqueio de página) — um domínio por linha. Google, Microsoft, Apple, gov.br e bancos já vêm incluídos.</span>' +
      '<textarea id="set-fpex" rows="2" spellcheck="false">' + esc((settings.fpExempt || []).join('\n')) + '</textarea></label>' +
    '<h4>LanguageTool + LibraryTranslate (1.7.0)</h4>' +
    '<label class="check"><input type="checkbox" id="set-lt" ' + (settings.languagetoolEnabled !== false ? 'checked' : '') + '>' +
      '<span>LanguageTool ativo (clique direito → “Verificar gramática”; consulta só quando VOCÊ pede)</span></label>' +
    '<label class="field"><span>Servidor LanguageTool (se a API pública limitar/oscilar, o NanoDesk reenvia, usa o espelho oficial api.languagetoolplus.com e cacheia resultados)</span>' +
      '<input id="set-ltapi" type="text" placeholder="https://api.languagetool.org ou http://127.0.0.1:8081 (local)" value="' + esc(settings.languagetoolApi || '') + '"></label>' +
    '<label class="field"><span>Idioma da verificação</span>' +
      '<select id="set-ltlang">' +
        [['auto','Detectar automaticamente'],['pt-BR','Português (Brasil)'],['pt-PT','Português (Portugal)'],['en-US','Inglês (EUA)'],['en-GB','Inglês (Reino Unido)'],['es','Espanhol'],['fr','Francês'],['de','Alemão'],['it','Italiano']].map(l => '<option value="' + l[0] + '">' + esc(l[1]) + '</option>').join('') +
      '</select></label>' +
    '<p class="dl-note">LibraryTranslate: seleção → clique direito → “Traduzir e salvar na Biblioteca”. Usa o LibreTranslate configurado abaixo; sem ele, MyMemory (público, sem chave) — sempre com o diálogo de consentimento. A biblioteca fica só na RAM (painel Menu → Biblioteca).</p>' +
    '<h4>Busca e tradução</h4>' +
    '<label class="field"><span>Instância SearXNG (para o buscador "SearXNG")</span>' +
      '<input id="set-searxng" type="text" placeholder="https://searx.minha-instancia" value="' + esc(settings.searxngUrl || '') + '"></label>' +
    '<label class="field"><span>Servidor LibreTranslate (vazio = tradução desligada)</span>' +
      '<input id="set-translate" type="text" placeholder="http://127.0.0.1:5000 (local) ou https://…" value="' + esc(settings.translateUrl || '') + '"></label>' +
    '<label class="field"><span>Linkwarden (instância própria; token em NANODESK_LINKWARDEN_TOKEN)</span>' +
      '<input id="set-linkwarden" type="text" placeholder="https://links.minha-instancia" value="' + esc(settings.linkwardenUrl || '') + '"></label>' +
    '<label class="field"><span>Traduzir para</span>' +
      '<select id="set-trtarget">' +
        '<option value="pt">Português</option><option value="en">Inglês</option>' +
        '<option value="es">Espanhol</option><option value="fr">Francês</option>' +
        '<option value="de">Alemão</option><option value="it">Italiano</option>' +
        '<option value="ja">Japonês</option>' +
      '</select></label>' +
    '<p class="dl-note">Nenhum texto é enviado a serviço externo sem o seu consentimento em cada ação. Servidores locais (127.0.0.1) são identificados como processamento local.</p>' +
    '<h4>Perfil local (opcional)</h4>' +
    '<label class="check"><input type="checkbox" id="set-persist" ' + (settings.persistentData ? 'checked' : '') + '>' +
      '<span>Manter configurações e favoritos entre sessões (histórico/cookies NUNCA são gravados)</span></label>' +
    '<div class="anon-note">Sua sessão de navegação não mantém cookies, histórico e dados de sites após o encerramento do NanoDesk. ' +
      'Os downloads são salvos normalmente na pasta Downloads e continuam no computador. ' +
      'A navegação privada não garante anonimato perante sites ou provedores de Internet.</div>' +
    '<h4>Dados</h4>' +
    '<div class="btn-row">' +
      '<button class="btn danger" id="btn-clear-favs">Favoritos da sessão</button>' +
      '<button class="btn danger" id="btn-clear-data">Cookies e cache da sessão</button>' +
    '</div>' +
    '<h4>Sobre</h4>' +
    '<p class="about">NanoDesk v' + esc(versions.app) + ' · Electron ' + esc(versions.electron) +
      ' · Chromium ' + esc(versions.chrome) + '<br>' +
      'Navegação anônima ultraleve — projeto acadêmico.<br>' +
      'Sem histórico, cookies ou cache persistidos. Sem telemetria. Abas em WebContentsView com sandbox.</p>';

  $('#set-engine').value = settings.searchEngine || 'duckduckgo';
  $('#set-doh').value = settings.secureDns || 'off';
  $('#set-videoq').value = settings.videoQuality || 'best';
  $('#set-trtarget').value = settings.translateTarget || 'pt';
  $('#set-cmlevel').value = settings.consentomaticLevel || 'max';
  $('#set-ltlang').value = settings.languagetoolLang || 'auto';
  $('#set-overlayblock').value = settings.overlayBlockerMode || 'hard';   // 1.9.6-e

  const save = async (key, value) => {
    try {
      settings = await api.settings.set(key, value);
      toast('Configuração salva.');
    } catch (error) {
      toast(error && error.message ? error.message : 'Configuração inválida.');
    }
  };

  $('#set-homepage').addEventListener('change', e => save('homepage', e.target.value.trim()));
  $('#set-engine').addEventListener('change', e => save('searchEngine', e.target.value));
  $('#set-adblock').addEventListener('change', async (e) => {
    try {
      blockStats = await api.adblock.setEnabled(e.target.checked);
      settings.adblockEnabled = e.target.checked;
      renderToolbar();
    } catch (_) {
      e.target.checked = !!settings.adblockEnabled;
      toast('Não foi possível alterar o bloqueador.');
    }
  });
  $('#set-adscriptlets').addEventListener('change', e => save('adblockScriptlets', e.target.checked));
  $('#set-popupblock').addEventListener('change', async (e) => {
    try {
      protectionStats = await api.protection.setPopupEnabled(e.target.checked);
      settings.popupBlockerEnabled = e.target.checked;
      renderToolbar();
    } catch (_) {
      e.target.checked = settings.popupBlockerEnabled !== false;
      toast('Não foi possível alterar o bloqueador de pop-ups.');
    }
  });
  $('#set-redirectguard').addEventListener('change', async (e) => {
    try {
      protectionStats = await api.protection.setRedirectEnabled(e.target.checked);
      settings.redirectGuardEnabled = e.target.checked;
      renderToolbar();
    } catch (_) {
      e.target.checked = settings.redirectGuardEnabled !== false;
      toast('Não foi possível alterar o guardião de redirecionamentos.');
    }
  });
  $('#set-asksave').addEventListener('change', e => save('askWhereToSave', e.target.checked));
  $('#set-hibernate').addEventListener('change', e => save('hibernateTabs', e.target.checked));
  $('#set-hibmin').addEventListener('change', e => save('hibernateMinutes', e.target.value));
  $('#set-dnt').addEventListener('change', e => save('doNotTrack', e.target.checked));
  // ---- 1.6.0 ----
  $('#set-fp').addEventListener('change', e => save('fingerprintProtect', e.target.checked));
  $('#set-clearurls').addEventListener('change', e => save('clearUrls', e.target.checked));
  $('#set-3pcookies').addEventListener('change', e => save('blockThirdPartyCookies', e.target.checked));
  $('#set-3pstrict').addEventListener('change', e => save('thirdPartyCookiesStrict', e.target.checked));
  $('#set-webrtc').addEventListener('change', e => save('webrtcProtect', e.target.checked));
  $('#set-httpsfirst').addEventListener('change', e => save('httpsFirst', e.target.checked));
  $('#set-doh').addEventListener('change', e => save('secureDns', e.target.value));
  $('#set-dohcustom').addEventListener('change', e => save('secureDnsCustom', e.target.value.trim()));
  $('#set-dohstrict').addEventListener('change', e => save('secureDnsStrict', e.target.checked));
  $('#set-tor').addEventListener('change', e => save('torMode', e.target.checked));
  $('#set-torport').addEventListener('change', e => save('torPort', e.target.value));
  $('#set-urlgate').addEventListener('change', e => save('urlGateEnabled', e.target.checked));
  $('#set-dlscan').addEventListener('change', e => save('downloadScan', e.target.checked));
  $('#set-quarantine').addEventListener('change', e => save('quarantineDownloads', e.target.checked));
  $('#set-updcheck').addEventListener('change', e => save('updateCheck', e.target.checked));
  // ---- 1.8.8 — vídeo (yt-dlp apenas) + proteções ativas novas ----
  $('#set-videoq').addEventListener('change', e => save('videoQuality', e.target.value));
  $('#set-ytdsubs').addEventListener('change', e => save('ytdlpSubtitles', e.target.checked));
  $('#set-ytdthumb').addEventListener('change', e => save('ytdlpThumbnail', e.target.checked));
  $('#set-noredir').addEventListener('change', e => save('noredirectEnabled', e.target.checked));
  $('#set-adclean').addEventListener('change', e => save('adCleanupEnabled', e.target.checked));
  $('#set-pagesec').addEventListener('change', e => save('pageSecurityScan', e.target.checked));
  $('#set-overlayblock').addEventListener('change', e => save('overlayBlockerMode', e.target.value));   // 1.9.6-e
  $('#set-malblock').addEventListener('change', e => save('malwareSiteBlock', e.target.checked));
  $('#set-ppstrict').addEventListener('change', e => save('popupBlockerStrict', e.target.checked));
  $('#set-ppaggr').addEventListener('change', e => save('popupBlockerAggressive', e.target.checked));
  // 1.8.9 — cofre nativo
  $('#set-vault').addEventListener('change', e => save('vaultEnabled', e.target.checked));
  $('#set-vaultsave').addEventListener('change', e => save('vaultSavePrompt', e.target.checked));
  $('#set-vaultlock').addEventListener('change', e => save('vaultAutolockMinutes', e.target.value));
  $('#set-vaultephemeral').addEventListener('change', e => save('vaultEphemeral', e.target.checked));
  $('#set-avpersist').addEventListener('change', e => save('clamavPersistDb', e.target.checked));
  $('#set-kguard').addEventListener('change', e => save('keyboardGuard', e.target.checked));
  $('#set-kguardauth').addEventListener('change', e => save('keyboardGuardAuthSites', e.target.checked));
  $('#set-cprot').addEventListener('change', e => save('contentProtection', e.target.checked));
  $('#set-arcnet').addEventListener('change', e => save('archiveBlockNetwork', e.target.checked));
  $('#set-arcunused').addEventListener('change', e => save('archiveRemoveUnused', e.target.checked));
  $('#set-arclazy').addEventListener('change', e => save('archiveLoadLazy', e.target.checked));
  $('#set-arctrk').addEventListener('change', e => save('archiveSkipTrackers', e.target.checked));
  $('#set-arcform').addEventListener('change', e => save('archiveKeepForm', e.target.checked));
  $('#set-archidden').addEventListener('change', e => save('archiveRemoveHidden', e.target.checked));
  $('#set-arcask').addEventListener('change', e => save('archiveAskWhere', e.target.checked));
  $('#set-filtercache').addEventListener('change', e => save('filtersCacheOnDisk', e.target.checked));
  $('#btn-vault-open').addEventListener('click', () => togglePanel('vault'));
  // ---- 1.7.0 (nativo) ----
  $('#set-sb').addEventListener('change', e => save('sponsorBlockEnabled', e.target.checked));
  $('#set-sbtoast').addEventListener('change', e => save('sponsorBlockToast', e.target.checked));
  $$('.sbcat').forEach(cb => cb.addEventListener('change', () => {
    const cats = $$('.sbcat').filter(x => x.checked).map(x => x.value);
    save('sbCategories', cats);
  }));
  $('#set-cm').addEventListener('change', e => save('consentomaticEnabled', e.target.checked));
  $('#set-cmlevel').addEventListener('change', e => save('consentomaticLevel', e.target.value));
  $('#set-cmcool').addEventListener('change', e => save('cmCooldownHours', Number(e.target.value)));
  $('#set-cmwl').addEventListener('change', e => save('cmWhitelist', e.target.value.split(/\r?\n/).map(x => x.trim()).filter(Boolean)));
  $('#set-fpex').addEventListener('change', e => save('fpExempt', e.target.value.split(/\r?\n/).map(x => x.trim()).filter(Boolean)));
  $('#set-lt').addEventListener('change', e => save('languagetoolEnabled', e.target.checked));
  $('#set-ltapi').addEventListener('change', e => save('languagetoolApi', e.target.value.trim()));
  $('#set-ltlang').addEventListener('change', e => save('languagetoolLang', e.target.value));
  $('#set-linkwarden').addEventListener('change', e => save('linkwardenUrl', e.target.value.trim()));
  $('#set-searxng').addEventListener('change', e => save('searxngUrl', e.target.value.trim()));
  $('#set-translate').addEventListener('change', e => save('translateUrl', e.target.value.trim()));
  $('#set-trtarget').addEventListener('change', e => save('translateTarget', e.target.value));
  $('#set-persist').addEventListener('change', e => save('persistentData', e.target.checked));

  $('#btn-clear-favs').addEventListener('click', async () => {
    if (confirm('Remover todos os favoritos desta sessão?')) {
      await api.favorites.clear();
      await refreshFavorites();
      toast('Favoritos removidos.');
    }
  });
  $('#btn-clear-data').addEventListener('click', async () => {
    if (confirm('Apagar cookies, caches e dados de sites?\nVocê será desconectado dos sites.')) {
      await api.app.clearBrowsingData();
      toast('Dados de navegação apagados.');
    }
  });
}

/* ---------------- painel "menu" (antes menu flutuante) ---------------- */

function renderMenuPanel() {
  const el = $('#menu-body');
  const items = [
    { label: 'Nova aba', icon: 'plus', act: () => { createTab(null); focusAddress(); } },
    { label: 'Abrir PDF…', icon: 'pdf', act: () => api.readers.openDialog('pdf').catch(() => {}) },
    { label: 'Abrir ebook (EPUB/MOBI)…', icon: 'epub', act: () => api.readers.openDialog('ebook').catch(() => {}) },
    { sep: true },
    { label: 'Leitor de notícias', icon: 'rss', act: () => togglePanel('reader') },
    { label: 'Modo leitura (F9)', icon: 'book', act: () => runReaderMode() },
    { label: 'Abrir no navegador padrão', icon: 'ext', act: () => openExternal() },
    { sep: true },
    { label: 'Rede (VPN, Tor, DNS)', icon: 'net', act: () => togglePanel('network') },
    { label: 'Conexão Tor (nativo)', icon: 'onion', act: () => togglePanel('tor') },
    { label: 'Segurança (URLs e downloads)', icon: 'shield', act: () => togglePanel('security') },
    { label: 'Histórico da sessão', icon: 'clock', act: () => togglePanel('history') },
    { label: 'Traduzir página (LibreTranslate)…', icon: 'book', act: () => { api.translate.page().catch(() => {}); } },
    { label: 'Biblioteca de traduções (LibraryTranslate)', icon: 'book', act: () => togglePanel('biblioteca') },
    { label: 'Cofre de senhas (nativo)', icon: 'lock', act: () => togglePanel('vault') },
    { label: 'Cofre: preencher login deste site (Ctrl+Shift+K)', icon: 'lock', act: () => {
      api.bitwarden.fill().catch(e => toast(e && e.message ? e.message : 'Cofre indisponível.'));
    } },
    { label: 'Baixar vídeo com yt-dlp…', icon: 'download', act: () => {
      const t = activeTab();
      if (t && t.url) api.video.download(t.url).catch(e => toast(e && e.message ? e.message : 'Falha no yt-dlp.'));
    } },
    { sep: true },
    { label: 'Downloads', icon: 'download', act: () => togglePanel('downloads') },
    { label: 'Favoritos (só nesta sessão)', icon: 'star', act: () => togglePanel('favorites') },
    { label: 'Bloqueador de anúncios', icon: 'shield', act: () => togglePanel('adblock') },
    { label: 'Proteções (pop-ups e redirecionamentos)', icon: 'popup', act: () => togglePanel('protection') },
    { label: 'Configurações', icon: 'gear', act: () => togglePanel('settings') },
    { label: 'Verificar atualizações…', icon: 'refresh', act: () => checkUpdates() },
    { sep: true },
    { label: 'Sobre o NanoDesk', act: () =>
      toast('NanoDesk v' + versions.app + ' · Electron ' + versions.electron + ' · Chromium ' + versions.chrome) },
    { label: 'Sair', act: () => api.win.close() }
  ];
  el.innerHTML = items.map((it, i) => it.sep
    ? '<div class="ctx-sep"></div>'
    : '<div class="ctx-item" data-i="' + i + '">' + (it.icon ? svg(it.icon, 14) : '') + esc(it.label) + '</div>'
  ).join('');
  el.querySelectorAll('.ctx-item').forEach(item => {
    item.addEventListener('click', () => { items[Number(item.dataset.i)].act(); });
  });
}

// 1.9.6 (FASE 3): renovação manual das listas de filtros — nunca automática.
function refreshFilters() {
  toast('Atualizando listas de filtros…');
  api.filters.refresh()
    .then(() => {})
    .catch(() => toast('Não foi possível atualizar as listas agora (rede fora?).', 8000));
}

async function checkUpdates() {
  toast('Verificando atualizações…');
  try {
    const r = await api.updates.check();
    const el = r && r.electron;
    if (el && el.updateAvailable) {
      toast('Atualização do Electron disponível: ' + el.latest + ' (atual: ' + el.current + '). Atualize o NanoDesk para aplicar o patch de segurança.', 9000);
    } else if (el && el.checked) {
      toast('Electron ' + el.current + ' — em dia com a linha ' + String(el.current).split('.')[0] + '.');
    } else {
      toast('Não foi possível verificar agora (sem acesso ao serviço de versões).');
    }
  } catch (_) {
    toast('Não foi possível verificar atualizações agora.');
  }
}

/* ---------------- menu de contexto das abas (NATIVO) ----------------
 * CORREÇÃO 1.4.0: o menu antigo era HTML (#ctx-menu) — ficava escondido
 * ATRÁS da WebContentsView sempre que um site estava aberto. Menus
 * nativos (Menu.popup no main) aparecem sempre acima de views nativas. */

function openTabMenu(tab) {
  api.tabs.ctxmenu(tab.id).catch(() => {});
}

/* ---------------- comandos do menu nativo ---------------- */

async function toggleFavorite() {
  const t = activeTab();
  if (!t || !validation.isHttpUrl(t.url)) {
    toast('Abra um site (http/https) para favoritar.');
    return;
  }
  try {
    const res = await api.favorites.toggle(t.title || hostOf(t.url), t.url);
    await refreshFavorites();
    toast(res.added ? 'Adicionado aos favoritos.' : 'Removido dos favoritos.');
  } catch (_) {
    toast('Não foi possível atualizar os favoritos.');
  }
}

function openExternal(t) {
  const url = externalTargetFor(t || activeTab());
  if (!url) { toast('Não há uma página http/https para abrir no navegador padrão.'); return; }
  api.app.openExternal(url).then(ok =>
    toast(ok ? 'Aberto no navegador padrão.' : 'Não foi possível abrir no navegador padrão.'));
}

function handleCmd(cmd) {
  const t = activeTab();
  switch (cmd) {
    case 'new-tab': createTab(null); focusAddress(); break;
    case 'close-tab': if (t) api.tabs.close(t.id); break;
    case 'favorite': toggleFavorite(); break;
    case 'reload': if (t) api.tabs.reload(t.id); break;
    case 'back': if (t) api.tabs.back(t.id); break;
    case 'forward': if (t) api.tabs.forward(t.id); break;
    case 'home': goHome(); break;
    case 'focus-address': focusAddress(); break;
    case 'zoom-in': if (t) api.tabs.zoom(t.id, (t.zoom || 1) * 1.1).then(z => toast('Zoom: ' + Math.round(z * 100) + '%')); break;
    case 'zoom-out': if (t) api.tabs.zoom(t.id, (t.zoom || 1) / 1.1).then(z => toast('Zoom: ' + Math.round(z * 100) + '%')); break;
    case 'zoom-reset': if (t) api.tabs.zoom(t.id, 1).then(() => toast('Zoom: 100%')); break;
    case 'next-tab': cycleTab(1); break;
    case 'prev-tab': cycleTab(-1); break;
    case 'devtools': if (t) api.tabs.devtools(t.id); break;
    case 'open-external': openExternal(t); break;
    case 'find': openFind(); break;
    case 'find-next': findStep(true); break;
    case 'find-prev': findStep(false); break;
    case 'print': if (t) api.tabs.print(t.id); break;
    case 'downloads': togglePanel('downloads'); break;
    case 'media': {
      // 1.9.5: Ctrl+Shift+M — detecta mídia e abre o painel
      if (currentPanel === 'media') closePanels();
      else { togglePanel('media'); detectMedia(); }
      break;
    }
    case 'reader': togglePanel('reader'); break;
    case 'protection': togglePanel('protection'); break;
    // ---- 1.6.0 ----
    case 'network': togglePanel('network'); break;
    case 'tor': togglePanel('tor'); break;
    case 'security': togglePanel('security'); break;
    case 'history': togglePanel('history'); break;
    case 'translate-page': api.translate.page().catch(e => toast(e && e.message ? e.message : 'Falha na tradução.')); break;
    case 'translate-clipboard': api.translate.clipboard().catch(e => toast(e && e.message ? e.message : 'Falha na tradução.')); break;
    case 'linkwarden-save':
      if (t && t.url) api.linkwarden.save(t.url).catch(e => toast(e && e.message ? e.message : 'Falha no Linkwarden.'));
      else toast('Abra uma página para salvar.');
      break;
    case 'bitwarden-fill':
      api.bitwarden.fill().catch(e => toast(e && e.message ? e.message : 'Cofre indisponível.'));
      break;
    case 'vault-panel':
      // 1.9.6-b (P1): cofre DESLIGADO por padrão (privacidade rigorosa).
      // O painel só abre se o usuário ligar o cofre nas Configurações.
      if (!settings || !settings.vaultEnabled) {
        toast('Cofre de senhas está DESLIGADO (padrão de privacidade). Ligue em Configurações — e ele funciona no modo só-RAM (nada em disco).', 9000);
        break;
      }
      togglePanel('vault');
      break;
    case 'video-download':
      if (t && t.url) api.video.download(t.url).catch(e => toast(e && e.message ? e.message : 'Falha no yt-dlp.'));
      else toast('Abra um vídeo para baixar.');
      break;
    case 'reader-mode': runReaderMode(); break;
    case 'open-file': api.readers.openDialog('any').catch(() => {}); break;
    case 'updates': checkUpdates(); break;
    case 'filters-refresh': refreshFilters(); break;
    case 'about': toast('NanoDesk v' + versions.app + ' · Electron ' + versions.electron + ' · Chromium ' + versions.chrome); break;
  }
}

function cycleTab(dir) {
  if (tabs.length < 2) return;
  const idx = Math.max(0, tabs.findIndex(t => t.id === activeId));
  const next = tabs[(idx + dir + tabs.length) % tabs.length];
  api.tabs.activate(next.id);
}

function goHome() {
  const t = activeTab();
  const hp = (settings.homepage || '').trim();
  if (!hp || hp === 'about:ntp' || hp === 'nanodesk://nova-aba') {
    // home = Nova Aba: abre uma aba limpa
    createTab(null);
  } else if (t) {
    navigateActive(hp);
  } else {
    createTab(hp);
  }
}

function focusAddress() {
  const el = $('#address');
  el.focus();
  el.select();
}

/* ---------------- ligação da interface estática ---------------- */

function bindStaticUI() {
  // controles de janela
  $('#btn-min').addEventListener('click', () => api.win.minimize());
  $('#btn-max').addEventListener('click', () => api.win.maximize());
  $('#btn-close').addEventListener('click', () => api.win.close());
  $('#titlebar').addEventListener('dblclick', (e) => {
    if (!e.target.closest('.win-btn') && !e.target.closest('.brand')) api.win.titlebarDblclick();
  });

  // abas (delegação)
  $('#tabs').addEventListener('click', (e) => {
    const tabEl = e.target.closest('.tab');
    if (!tabEl) return;
    const id = Number(tabEl.dataset.id);
    if (e.target.closest('.t-close')) { api.tabs.close(id); return; }
    api.tabs.activate(id);
  });
  $('#tabs').addEventListener('auxclick', (e) => {
    if (e.button !== 1) return;
    const tabEl = e.target.closest('.tab');
    if (!tabEl) return;
    api.tabs.close(Number(tabEl.dataset.id));
  });
  $('#tabs').addEventListener('contextmenu', (e) => {
    const tabEl = e.target.closest('.tab');
    if (!tabEl) return;
    e.preventDefault();
    const t = tabs.find(x => x.id === Number(tabEl.dataset.id));
    if (t) openTabMenu(t);
  });
  $('#btn-newtab').addEventListener('click', () => { createTab(null); focusAddress(); });

  // navegação
  $('#btn-back').addEventListener('click', () => { const t = activeTab(); if (t) api.tabs.back(t.id); });
  $('#btn-fwd').addEventListener('click', () => { const t = activeTab(); if (t) api.tabs.forward(t.id); });
  $('#btn-reload').addEventListener('click', () => {
    const t = activeTab();
    if (!t) return;
    if (t.loading) api.tabs.stop(t.id); else api.tabs.reload(t.id);
  });
  $('#btn-home').addEventListener('click', goHome);

  // barra de endereço
  $('#address').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      if (e.target.value.trim()) { navigateActive(e.target.value); e.target.blur(); }
    } else if (e.key === 'Escape') {
      e.target.blur();
      renderAddress();
    }
  });

  // favoritos / escudo / proteções / menu
  $('#btn-star').addEventListener('click', toggleFavorite);
  $('#btn-shield').addEventListener('click', () => togglePanel('adblock'));
  $('#btn-ext').addEventListener('click', () => openExternal());
  $('#btn-net').addEventListener('click', () => togglePanel('network'));
  $('#btn-tor').addEventListener('click', () => togglePanel('tor'));
  $('#btn-reader').addEventListener('click', () => togglePanel('reader'));
  $('#btn-readmode').addEventListener('click', runReaderMode);
  $('#btn-archive').addEventListener('click', () => { api.archive.save({}).catch(() => {}); });
  $('#btn-protection').addEventListener('click', () => togglePanel('protection'));
  $('#btn-menu').addEventListener('click', () => togglePanel('menu'));

  // busca na página
  const fi = $('#find-input');
  fi.addEventListener('input', () => runFind(true, false));
  fi.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); runFind(!e.shiftKey, true); }
    else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closeFind(); }
  });
  $('#find-prev').addEventListener('click', () => runFind(false, true));
  $('#find-next').addEventListener('click', () => runFind(true, true));
  $('#find-close').addEventListener('click', closeFind);
  $('#btn-downloads').addEventListener('click', () => togglePanel('downloads'));
  // 1.9.5 — botão de mídia: detecta e abre o painel
  const btnMedia = $('#btn-media');
  if (btnMedia) btnMedia.addEventListener('click', () => {
    if (currentPanel === 'media') { closePanels(); return; }
    togglePanel('media');
    detectMedia();
  });

  // Nova Aba interna
  $('#ntp-search').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      if (e.target.value.trim()) { navigateActive(e.target.value); e.target.blur(); }
    }
  });

  // painéis
  $$('.panel-close').forEach(b => b.addEventListener('click', closePanels));

  // O retângulo de #view-area é reportado ao main em qualquer mudança de
  // tamanho (janela, maximizar/restaurar, painel, escala do Windows).
  if (typeof ResizeObserver === 'function') {
    const viewportObserver = new ResizeObserver(scheduleBounds);
    viewportObserver.observe($('#view-area'));
  } else {
    let rszTimer = null;
    window.addEventListener('resize', () => {
      if (rszTimer) clearTimeout(rszTimer);
      rszTimer = setTimeout(scheduleBounds, 80);
    });
  }
  window.addEventListener('resize', scheduleBounds);

  // Esc: fecha painel ou para o carregamento (o menu de contexto de abas
  // é nativo e fecha sozinho)
  window.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if ($('#findbar').classList.contains('open')) { closeFind(); return; }
    if (currentPanel) { closePanels(); return; }
    const t = activeTab();
    if (t && t.loading) api.tabs.stop(t.id);
  });
}

/* ---------------- partida ---------------- */

async function boot() {
  settings = await api.settings.get();
  versions = await api.app.version();
  await refreshFavorites();
  blockStats = await api.adblock.stats();

  // 1.5.3: as marcas da engine (reportadas pela página confiável da UI)
  // permitem montar client hints coerentes com um Chrome real.
  try {
    const uad = navigator.userAgentData;
    let high = null;
    try {
      // 1.7.3: valores de alta entropia (Accept-CH) = os mesmos que a engine entrega às páginas
      high = uad ? await uad.getHighEntropyValues(['fullVersionList', 'platformVersion', 'architecture', 'bitness', 'model', 'wow64', 'uaFullVersion']) : null;
    } catch (_) { high = null; }
    await api.app.reportIdentity(uad ? uad.brands : null, high);
  } catch (_) { /* sem CH: mantém o comportamento atual */ }

  api.tor.onState((ev) => {
    torState = Object.assign({}, torState, ev);
    if (ev.state === 'connected') torState.check = null;
    renderToolbar();
    if (currentPanel === 'tor') renderTorPanel();
  });
  api.tor.status().then(st => { torState = Object.assign({}, torState, st); renderToolbar(); }).catch(() => {});

  api.tabs.onState(syncFromMain);
  api.tabs.onFound((e) => { if (e.id === activeId) updateFindCount(e.result); });
  api.adblock.onStats(s => {
    blockStats = s;
    updateShieldBadge();
    if (currentPanel === 'adblock') renderAdblockPanel();
  });
  protectionStats = await api.protection.stats();
  api.protection.onStats(s => {
    protectionStats = s;
    updateProtectionBadge();
    if (currentPanel === 'protection') renderProtectionPanel();
  });
  setDownloads(await api.downloads.list());
  api.downloads.onUpdate(setDownloads);
  api.reader.onUpdate(() => refreshReader());
  // ---- 1.6.0 ----
  api.translate.onResult((tr) => {
    readerState.view = 'trans';
    readerState.trans = { title: tr && tr.title, html: tr && tr.html };
    if (currentPanel !== 'reader') togglePanel('reader');
    else renderReaderPanel();
  });
  api.security.onUpdate((log) => {
    securityLogCache = log || [];
    if (currentPanel === 'security') renderSecurityPanel();
  });
  // 1.8.9 — cofre de senhas nativo
  api.vault.onState((st) => {
    const wasUnlocked = vaultState.unlocked;
    vaultState = Object.assign({}, vaultState, st || {});
    if (currentPanel === 'vault') renderVaultPanel();
    // se acabou de desbloquear e há preenchimento pendente, dispara agora
    if (!wasUnlocked && vaultState.unlocked && vaultPendingFill) {
      vaultPendingFill = false;
      api.vault.fillNow().catch(e => toast(e && e.message ? e.message : 'Não foi possível preencher.'));
    }
  });
  api.vault.onPromptUnlock((p) => {
    vaultPendingFill = !!(p && p.pendingFill);
    togglePanel('vault');
    toast('Desbloqueie o cofre para preencher o login de ' + (p && p.host ? p.host : 'deste site') + '.', 8000);
  });
  try { vaultState = Object.assign({}, vaultState, await api.vault.status()); } catch (_) { /* ignora */ }
  api.network.onState((st) => {
    if (st) netState = st;
    updateNetDot();
    if (currentPanel === 'network') renderNetworkPanel();
  });
  try { netState = await api.network.state() || netState; } catch (_) { /* ignora */ }
  try { containersList = await api.containers.list(); } catch (_) { /* ignora */ }
  try { securityLogCache = await api.security.log(); } catch (_) { /* ignora */ }
  updateNetDot();
  api.onOpenTab(url => createTab(url));
  api.onSearchTab(text => createTab(searchUrl(text)));
  api.onToast((p) => toast(p && p.msg ? p.msg : String(p), p && p.ms));
  api.onCmd(handleCmd);
  api.win.onState(st => { $('#btn-max').innerHTML = svg(st.maximized ? 'restore' : 'max'); });

  bindStaticUI();

  // Estado inicial das abas + retângulo de conteúdo.
  syncFromMain(await api.tabs.list());
  reportBounds();
  renderAll();
}

boot();

/**
 * NanoDesk — Preload de frame (1.6.3): anti-fingerprinting + bloqueio cosmético/scriptlets
 * ==================================================================
 * Registrado na SESSÃO (registerPreloadScript tipo 'frame'): roda em TODAS as frames de
 * TODAS as abas ANTES dos scripts da página. Em preload SANDBOX não existe require()
 * relativo — por isso (CORREÇÃO 1.6.3) o conteúdo vem do processo principal por
 * ipcRenderer.sendSync('nd:frame-init'):
 *   - fp:      script de hooks do fingerprint (canvas/áudio/WebGL). Antes o require
 *              relativo falhava e só o hook mínimo de WebGL era instalado;
 *   - scripts: SCRIPTLETS do uBlock Origin (json-prune, set-constant…) para esta frame;
 *   - styles:  CSS cosmético do host.
 * Tudo roda no MUNDO PRINCIPAL via webFrame.executeJavaScript (única forma de afetar a
 * página com contextIsolation). Depois do DOMContentLoaded, classes/ids/links viram regras
 * genéricas (nd:cosmetic-dom), com MutationObserver em lote.
 * Idempotente (guarda __nanodeskFp no window do mundo principal).
 */
'use strict';

const { webFrame, ipcRenderer } = require('electron');

const HOOK_SCRIPT = null; // compatibilidade: o script real é entregue pelo processo principal

let installed = false;

function run(code) {
  try { webFrame.executeJavaScript(String(code), false).catch(() => { /* best-effort */ }); }
  catch (_) { /* webFrame pode estar em transição */ }
}

/** Instala os hooks de fingerprint na frame atual (uma vez). */
function install(script) {
  if (installed || typeof script !== 'string' || !script) return;
  installed = true;
  run(script); // idempotente via window.__nanodeskFp
}
/**
 * 1.6.6: cada scriptlet roda ISOLADO (IIFE + try/catch). Eles chegam como código de nível
 * global que declara funções auxiliares com o MESMO nome (proxyApplyFn, safeSelf…). Executados
 * todos no escopo global da página, o último sobrescrevia o anterior SEM os membros estáticos
 * (proxyApplyFn.CallContext…) e o JSON.parse hookado passava a lançar
 * "Cannot read properties of undefined (reading 'factory')" — o YouTube não abria.
 */
function isolate(code) {
  return '(function(){try{' + String(code) + '\n}catch(_){}})();';
}

// CORREÇÃO 1.6.7 (velocidade): insertCSS ACUMULA stylesheets — o frame-init
// injetava o CSS base, o dom-ready reinjetava o MESMO CSS e cada flush do
// MutationObserver somava mais uma folha. Em sessão longa no YouTube isso
// degradava a resolução de estilo de forma progressiva. Agora só injeta CSS
// cujo hash ainda não foi visto nesta frame.
const cssSeen = new Set();
function cssHash(s) {
  const str = String(s || '');
  let h = 5381;
  for (let i = 0; i < str.length; i += 97) { h = ((h << 5) + h + str.charCodeAt(i)) | 0; }
  return str.length + ':' + h;
}
function css(styles) {
  if (!styles) return;
  const key = cssHash(styles);
  if (cssSeen.has(key)) return;
  if (cssSeen.size > 400) cssSeen.clear(); // guarda-chuva p/ páginas infinitas
  cssSeen.add(key);
  try { webFrame.insertCSS(String(styles)); } catch (_) { /* best-effort */ }
}

let init = null;
try { init = ipcRenderer.sendSync('nd:frame-init'); } catch (_) { init = null; }

if (init && typeof init === 'object') {
  if (init.fp) install(init.fp);
  if (Array.isArray(init.scripts)) for (const sc of init.scripts) run(isolate(sc));
  css(init.styles);
} else {
  // sem resposta do processo principal: hook mínimo de WebGL (melhor esforço)
  // CORREÇÃO 1.6.7: máscara coerente com o UA Windows (antes "Intel Iris
  // OpenGL Engine", string que só existe no macOS — contradição detectável).
  install(
    '(function(){if(window.__nanodeskFp)return window.__nanodeskFp;' +
    'try{var v=37445,r=37446,G="Google Inc. (Intel)",R="ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00003E9B) Direct3D11 vs_5_0 ps_5_0, D3D11";' +
    'function m(p){if(!p||!p.getParameter)return;var g=p.getParameter;' +
    'p.getParameter=function(x){if(x===v)return G;if(x===r)return R;return g.apply(this,arguments);};}' +
    'if(typeof WebGLRenderingContext!=="undefined")m(WebGLRenderingContext.prototype);' +
    'if(typeof WebGL2RenderingContext!=="undefined")m(WebGL2RenderingContext.prototype);' +
    'window.__nanodeskFp={webgl:1};}catch(_){}})();'
  );
}

/* ---- regras genéricas baseadas no DOM (classes/ids/links) — só quando há bloqueador ---- */
if (init && (init.dom === true) && /^https?:$/.test(location.protocol)) {
  const seenC = new Set(), seenI = new Set(), seenH = new Set();
  let pendC = [], pendI = [], pendH = [], timer = null;
  // CORREÇÃO 1.6.7 (velocidade): o observer varria o DOM PARA SEMPRE — no
  // YouTube (chat ao vivo, listas virtualizadas) isso rodava o vídeo inteiro.
  // CORREÇÃO 1.6.8 (blocos cinza): a 1.6.7 desligava o observer PARA SEMPRE
  // depois de 30 varridas sem novidade (~13,5 s). Em SPAs (novas "páginas" no
  // MESMO documento) e em sites com anúncio preguiçoso (lazy), os contêineres
  // que apareciam DEPOIS nunca recebiam a regra de ocultação — ficavam como
  // BLOCOS CINZA na página. Agora o observer PAUSA quando o site fica estável
  // e VOLTA sozinho: navegação SPA (pushState/replaceState/popstate), aba que
  // volta a ficar visível e uma reavaliação leve a cada 5 min com a aba aberta.
  const EMPTY_STOP = 30;
  let emptyFlushes = 0;
  let observer = null;
  let rearmTimer = null;

  const scan = (root) => {
    try {
      const els = root.nodeType === 1 ? [root, ...root.querySelectorAll('[class],[id],a[href]')] : [];
      for (const el of els) {
        const id = el.id; if (id && !seenI.has(id)) { seenI.add(id); pendI.push(id); }
        const cl = el.classList; if (cl) for (const c of cl) { if (!seenC.has(c)) { seenC.add(c); pendC.push(c); } }
        if (el.tagName === 'A') { const h = el.getAttribute('href'); if (h && !seenH.has(h) && h.length < 300) { seenH.add(h); pendH.push(h); } }
        if (seenC.size > 6000 || seenI.size > 3000) return;
      }
    } catch (_) { /* ignora */ }
  };
  const flush = () => {
    timer = null;
    if (!pendC.length && !pendI.length && !pendH.length) {
      // Site estável: pausa a observação (o MutationObserver para de receber
      // eventos = zero custo). O rearme é quem traz o observer de volta.
      if (++emptyFlushes >= EMPTY_STOP && observer) { try { observer.disconnect(); } catch (_) {} observer = null; armRearm(); }
      return;
    }
    emptyFlushes = 0;
    const msg = { classes: pendC.slice(0, 1500), ids: pendI.slice(0, 800), hrefs: pendH.slice(0, 800) };
    pendC = []; pendI = []; pendH = [];
    ipcRenderer.invoke('nd:cosmetic-dom', msg).then(css).catch(() => { /* best-effort */ });
  };
  const schedule = () => {
    if (timer) return;
    try { if (document.hidden) return; } catch (_) { /* segue */ }
    timer = setTimeout(flush, 450);
  };

  /** Liga o observer (idempotente). 1.6.8: observa TAMBÉM mudanças de
   *  atributo class/id/href — contêineres de anúncio que aparecem por
   *  mutação de classe em elementos existentes eram perdidos. */
  const ensureObserver = () => {
    if (observer) return;
    try {
      observer = new MutationObserver((muts) => {
        try { if (document.hidden) return; } catch (_) { /* segue */ }
        for (const m of muts) {
          if (m.type === 'attributes') scan(m.target);
          else for (const n of m.addedNodes) if (n.nodeType === 1) scan(n);
        }
        schedule();
      });
      observer.observe(document.documentElement, {
        childList: true, subtree: true,
        attributes: true, attributeFilter: ['class', 'id', 'href']
      });
      emptyFlushes = 0;
    } catch (_) { observer = null; }
  };

  /** Rearme pós-pausa: varre de novo e religa a observação. */
  const rearm = () => {
    try { if (document.hidden) { armRearm(); return; } } catch (_) { /* segue */ }
    ensureObserver();
    scan(document.documentElement);
    schedule();
  };
  /** Agenda a reavaliação leve periódica (5 min) — cobre anúncio preguiçoso
   *  em páginas que o usuário deixa abertas sem navegar. */
  function armRearm() {
    if (rearmTimer) return;
    rearmTimer = setTimeout(() => { rearmTimer = null; rearm(); }, 5 * 60 * 1000);
  }

  document.addEventListener('DOMContentLoaded', () => {
    try {
      scan(document.documentElement); schedule();
      ensureObserver();
      // voltar a avaliar quando a aba voltar a ficar visível
      document.addEventListener('visibilitychange', () => {
        try { if (!document.hidden) rearm(); } catch (_) { /* ignora */ }
      });
      // CORREÇÃO 1.6.8: navegação SPA (YouTube, portais de notícia) troca a
      // "página" SEM trocar o documento — o observer pausado precisa voltar.
      let lastUrl = String(location.href || '');
      const onSpaNav = () => {
        try {
          const u = String(location.href || '');
          if (u === lastUrl) return;
          lastUrl = u;
          seenC.clear(); seenI.clear(); seenH.clear(); // DOM novo: regras antigas podem não cobrir
          rearm();
        } catch (_) { /* ignora */ }
      };
      try {
        const _ps = history.pushState, _rs = history.replaceState;
        history.pushState = function () { const r = _ps.apply(this, arguments); setTimeout(onSpaNav, 120); return r; };
        history.replaceState = function () { const r = _rs.apply(this, arguments); setTimeout(onSpaNav, 120); return r; };
        window.addEventListener('popstate', () => setTimeout(onSpaNav, 120), { passive: true });
        window.addEventListener('hashchange', () => setTimeout(onSpaNav, 120), { passive: true });
      } catch (_) { /* ignora */ }
    } catch (_) { /* ignora */ }
  }, { once: true });
}

/* ---- 1.7.0 — encaminha eventos dos módulos nativos (SponsorBlock /
 * Consent-O-Matic / popup-blocker-strict / page-security) que rodam no
 * MUNDO PRINCIPAL para o processo principal (contadores de proteção,
 * toasts e painel Segurança). Eventos de DOM atravessam os mundos; IPC
 * não — por isso a ponte é aqui.
 * 1.8.10: adicionada a ponte para popup-strict e page-sec (sem isso,
 * toasts como "Miner de criptomoeda bloqueado…" e "Pop-up bloqueado…"
 * nunca disparavam — o main ouvia msg.type mas o preload não repassava). */
try {
  if (typeof document !== 'undefined') {
    document.addEventListener('nd-sb-skip', function (ev) {
      try { ipcRenderer.invoke('nd:native-event', { type: 'sb', secs: Number(ev && ev.detail && ev.detail.secs) || 0 }); } catch (_) {}
    });
    document.addEventListener('nd-cm-deny', function () {
      try { ipcRenderer.invoke('nd:native-event', { type: 'cm' }); } catch (_) {}
    });
    document.addEventListener('nd-popup-blocked', function (ev) {
      try {
        var d = (ev && ev.detail) || {};
        ipcRenderer.invoke('nd:native-event', { type: 'popup-strict', url: String(d.url || '').slice(0, 240), reason: String(d.reason || '').slice(0, 80) });
      } catch (_) {}
    });
    document.addEventListener('nd-page-security', function (ev) {
      try {
        var d = (ev && ev.detail) || {};
        ipcRenderer.invoke('nd:native-event', { type: 'page-sec', kind: String(d.kind || ''), detail: String(d.detail || ''), url: String(d.url || '') });
      } catch (_) {}
    });
  }
} catch (_) { /* best-effort */ }

/* =====================================================================================
 * 1.9.1 — PROTEÇÃO DE TECLADO / SENHAS (roda no mundo ISOLADO, antes de qualquer script do site)
 * =====================================================================================
 * Listeners de captura registrados AQUI são os primeiros da cadeia de eventos — e o mundo
 * isolado é invisível para o site (nenhum marcador em window/sessionStorage).
 *
 * (1) installKeyGuard — keyloggers de página registram document/window.addEventListener('keydown'
 *     |'keypress'|'keyup') e leem event.key. Em campos <input type=password> os eventos de tecla
 *     que carregam um CARACTERE são cortados (stopImmediatePropagation) ANTES de chegarem a
 *     qualquer script do site. A digitação em si não é afetada (a ação padrão do navegador
 *     continua); Enter/Tab/Backspace/setas/modificadores passam, para o site funcionar.
 *     LIMITE HONESTO: não impede quem lê o VALOR do campo (eventos input/change/submit) —
 *     só o keylogger "clássico" por evento de tecla. Não protege contra malware do sistema.
 *
 * (2) installCredCapture — captura do login para o cofre. ANTES: um script no mundo principal
 *     gravava a senha em texto puro no sessionStorage da página (legível por qualquer script
 *     da origem, e por tempo indeterminado). AGORA: capturada aqui, enviada por IPC só ao
 *     processo principal (memória, expira em 2 min) e nunca tocada pelo site.
 */

/* KEYGUARD-BEGIN */
function installKeyGuard(win, opts) {
  if (!win || !win.addEventListener) return false;
  const trusted = (opts && typeof opts.trusted === 'function') ? opts.trusted : (e) => e.isTrusted;   // opts só nos testes
  const isPwd = (n) => {
    try { return !!n && n.nodeType === 1 && n.localName === 'input' && String(n.type).toLowerCase() === 'password'; }
    catch (_) { return false; }
  };
  const origin = (e) => {
    try { const p = e.composedPath && e.composedPath(); return (p && p.length) ? p[0] : e.target; }
    catch (_) { return e.target; }
  };
  const carriesChar = (e) => {
    if (e.type === 'keypress') return true;               // keypress só existe para caracteres
    const k = e.key;
    if (typeof k !== 'string') return false;
    if (e.metaKey) return false;                          // atalhos do sistema
    if (e.ctrlKey && !e.altKey) return false;            // Ctrl+C/V/A...; AltGr (Ctrl+Alt) é caractere
    if (k === 'Dead' || k === 'Unidentified' || k === 'Process') return true;   // acentos/IME
    if (k.length === 1) return true;
    return k.length === 2 && k.charCodeAt(0) >= 0xd800 && k.charCodeAt(0) <= 0xdbff;   // par substituto
  };
  const handler = (e) => {
    try { if (trusted(e) && isPwd(origin(e)) && carriesChar(e)) e.stopImmediatePropagation(); }
    catch (_) { /* nunca quebra a página */ }
  };
  ['keydown', 'keypress', 'keyup'].forEach((t) => win.addEventListener(t, handler, true));
  return true;
}
/* KEYGUARD-END */

/* CREDCAPTURE-BEGIN */
function installCredCapture(win, send, opts) {
  if (!win || !win.document || typeof send !== 'function') return false;
  try { if (win.top !== win) return false; } catch (_) { return false; }   // só o frame principal
  const doc = win.document;
  const vis = (opts && typeof opts.isVisible === 'function') ? opts.isVisible : (el) => { try { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0; } catch (_) { return false; } };
  const SELS = ['input[type=email]', 'input[type=text]', 'input:not([type])', 'input[type=tel]'];
  const candidates = (root) => {
    const out = [];
    for (const sel of SELS) for (const el of root.querySelectorAll(sel)) if (vis(el) && el.value) out.push(el);
    return out;
  };
  // usuário = campo de texto preenchido que PRECEDE a senha (o mais próximo), dentro do formulário
  // ou, se não há <form>, de um contêiner próximo (até 3 níveis; nunca varre o documento inteiro)
  const pickUser = (pw) => {
    let list = [];
    if (pw.form) list = candidates(pw.form);
    else {
      let c = pw.parentElement;
      for (let i = 0; i < 3 && c && c !== doc.body && c !== doc.documentElement; i++, c = c.parentElement) {
        list = candidates(c);
        if (list.length) break;
      }
    }
    const before = list.filter((el) => { try { return !!(pw.compareDocumentPosition(el) & 2); } catch (_) { return true; } });   // 2 = PRECEDING
    return (before.length ? before[before.length - 1] : list[0]) || null;
  };
  const grab = (scope, only) => {
    const pws = only ? [only] : scope.querySelectorAll('input[type=password]');
    for (const p of pws) {
      if (!vis(p) || !p.value) continue;
      const u = pickUser(p);
      return { u: u ? String(u.value) : '', p: String(p.value) };
    }
    return null;
  };
  const emit = (scope, only) => {
    try {
      const rec = grab(scope, only);
      if (rec && rec.p.length <= 512 && rec.u.length <= 512) send(rec);
    } catch (_) { /* ignorado */ }
  };
  doc.addEventListener('submit', (e) => { const f = e.target; if (f && f.querySelectorAll) emit(f); }, true);
  doc.addEventListener('click', (e) => {
    const t = e.target;
    if (!t || !t.closest) return;
    const b = t.closest('button, input[type=submit], input[type=button], input[type=image]');
    if (b && b.form) emit(b.form);
  }, true);
  doc.addEventListener('keydown', (e) => {
    const t = e.target;
    if (e.key === 'Enter' && t && t.localName === 'input' && String(t.type).toLowerCase() === 'password' && !t.form) emit(doc, t);   // exatamente o campo onde o Enter foi pressionado
  }, true);
  return true;
}
/* CREDCAPTURE-END */

/* VAULTBUTTON-BEGIN */
/**
 * 1.9.2 — botão "Cofre: preencher". ANTES: um <div> injetado no mundo principal que avisava o processo
 * principal com console.log('__nanodesk_fill_request__') — qualquer script da página podia emitir a mesma
 * mensagem e fazer o cofre PREENCHER as credenciais sem clique algum (e o texto emitido pelo botão nem era
 * o mesmo que o main.js procurava, então o botão nem funcionava). AGORA: o botão vive no mundo isolado,
 * dentro de um shadow root FECHADO; só um clique REAL (isTrusted) com o botão visível e no topo envia o
 * IPC 'nd:vault-fill', que o processo principal ainda valida (oferta recente, mesmo host, frame principal).
 */
function installVaultButton(win, ipc, opts) {
  if (!win || !win.document || !ipc || typeof ipc.on !== 'function' || typeof ipc.send !== 'function') return false;
  try { if (win.top !== win) return false; } catch (_) { return false; }
  const doc = win.document;
  const trusted = (opts && typeof opts.trusted === 'function') ? opts.trusted : (e) => e.isTrusted;
  let host = null; let timer = null;
  const remove = () => {
    if (timer) { win.clearTimeout(timer); timer = null; }
    try { if (host && host.parentNode) host.parentNode.removeChild(host); } catch (_) { /* ignorado */ }
    host = null;
  };
  const intact = (e) => {
    try {
      if (!host || !host.isConnected) return false;
      const cs = win.getComputedStyle(host);
      if (cs.display === 'none' || cs.visibility !== 'visible' || cs.pointerEvents === 'none' || parseFloat(cs.opacity) < 0.99) return false;
      const root = win.getComputedStyle(doc.documentElement);
      if (parseFloat(root.opacity) < 0.99 || root.visibility !== 'visible') return false;
      if (typeof doc.elementFromPoint === 'function') {
        const top = doc.elementFromPoint(e.clientX, e.clientY);
        if (top !== host) return false;                      // coberto por outro elemento (clickjacking)
      }
      return true;
    } catch (_) { return false; }
  };
  const show = (label) => {
    if (host) return;
    host = doc.createElement('div');
    host.style.cssText = 'all:initial;position:fixed;z-index:2147483647;right:18px;bottom:18px;opacity:1;visibility:visible;';
    const root = host.attachShadow({ mode: 'closed' });
    const b = doc.createElement('button');
    b.type = 'button';
    b.textContent = '\uD83D\uDD11 Cofre: preencher' + (label ? ' (' + String(label).slice(0, 60) + ')' : '');   // texto puro, nunca HTML
    b.style.cssText = 'all:initial;display:block;background:#175ddc;color:#fff;border-radius:24px;padding:10px 14px;' +
      'font:600 13px/1 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;box-shadow:0 4px 14px rgba(0,0,0,.35);cursor:pointer;border:2px solid #fff;';
    b.addEventListener('click', (e) => {
      if (!trusted(e) || !intact(e)) return;                 // clique sintético/forjado ou botão adulterado: ignora
      try { ipc.send('nd:vault-fill'); } catch (_) { /* ignorado */ }
      remove();
    }, true);
    root.appendChild(b);
    doc.documentElement.appendChild(host);
    timer = win.setTimeout(remove, 45000);
  };
  ipc.on('nd:vault-button', (_e, msg) => { try { show(msg && typeof msg.label === 'string' ? msg.label : ''); } catch (_) { /* ignorado */ } });
  return true;
}
/* VAULTBUTTON-END */

try { installVaultButton(window, ipcRenderer); } catch (_) { /* best-effort */ }

try {
  if (init && typeof init === 'object') {
    if (init.kg === true) installKeyGuard(window);
    if (init.cc === true) installCredCapture(window, (rec) => { try { ipcRenderer.send('nd:cred-capture', rec); } catch (_) { /* ignorado */ } });
  }
} catch (_) { /* best-effort */ }

module.exports = { install, HOOK_SCRIPT, isolate, installKeyGuard, installCredCapture, installVaultButton };

/**
 * NanoDesk — Preload (ponte segura renderer <-> principal)
 * ------------------------------------------------------------------
 * Expõe SOMENTE as APIs listadas abaixo via contextBridge.
 * contextIsolation + sandbox ativos; nenhum acesso a Node nas páginas.
 * Não existem APIs de histórico ou de restauração de sessão:
 * o NanoDesk não guarda nada no PC.
 *
 * 1.3.0: as abas agora são WebContentsView gerenciadas pelo processo
 * principal — o renderer envia comandos (api.tabs.*) e recebe o
 * estado (api.tabs.onState); não há mais tag <webview>.
 */
'use strict';

const { contextBridge, ipcRenderer } = require('electron');

function subscribe(channel, cb) {
  const handler = (e, payload) => cb(payload);
  ipcRenderer.on(channel, handler);
  return () => ipcRenderer.removeListener(channel, handler);
}

contextBridge.exposeInMainWorld('nanodesk', {
  win: {
    minimize: () => ipcRenderer.invoke('win:minimize'),
    maximize: () => ipcRenderer.invoke('win:maximize'),
    close: () => ipcRenderer.invoke('win:close'),
    titlebarDblclick: () => ipcRenderer.invoke('win:titlebar-dblclick'),
    onState: (cb) => subscribe('win:state', cb)
  },
  tabs: {
    list: () => ipcRenderer.invoke('tabs:list'),
    create: (url, opts) => ipcRenderer.invoke('tabs:create', url, opts),
    activate: (id) => ipcRenderer.invoke('tabs:activate', id),
    close: (id) => ipcRenderer.invoke('tabs:close', id),
    navigate: (id, url) => ipcRenderer.invoke('tabs:navigate', id, url),
    back: (id) => ipcRenderer.invoke('tabs:back', id),
    forward: (id) => ipcRenderer.invoke('tabs:forward', id),
    reload: (id) => ipcRenderer.invoke('tabs:reload', id),
    stop: (id) => ipcRenderer.invoke('tabs:stop', id),
    zoom: (id, factor) => ipcRenderer.invoke('tabs:zoom', id, factor),
    hibernate: (id) => ipcRenderer.invoke('tabs:hibernate', id),
    find: (id, text, opts) => ipcRenderer.invoke('tabs:find', id, text, opts),
    findStop: (id) => ipcRenderer.invoke('tabs:find-stop', id),
    devtools: (id) => ipcRenderer.invoke('tabs:devtools', id),
    print: (id) => ipcRenderer.invoke('tabs:print', id),
    bounds: (rect) => ipcRenderer.invoke('tabs:bounds', rect),
    ctxmenu: (id) => ipcRenderer.invoke('tabs:ctxmenu', id),
    onState: (cb) => subscribe('tabs:state', cb),
    onError: (cb) => subscribe('tabs:error', cb),
    onFound: (cb) => subscribe('tabs:found', cb)
  },
  settings: {
    get: () => ipcRenderer.invoke('settings:get'),
    set: (k, v) => ipcRenderer.invoke('settings:set', k, v)
  },
  tor: {
    // 1.5.3 — Tor nativo (daemon embutido; sem cliente externo)
    status: () => ipcRenderer.invoke('tor:status'),
    start: () => ipcRenderer.invoke('tor:start'),
    stop: () => ipcRenderer.invoke('tor:stop'),
    newIdentity: () => ipcRenderer.invoke('tor:newnym'),
    openTab: () => ipcRenderer.invoke('tor:openTab'),
    check: () => ipcRenderer.invoke('tor:check'),
    onState: (cb) => subscribe('tor:state', cb)
  },
  history: { // 1.6.0 — histórico da sessão (só RAM)
    list: (q, opts) => ipcRenderer.invoke('history:list', q, opts),
    clear: () => ipcRenderer.invoke('history:clear')
  },
  containers: { // 1.6.0 — sessões isoladas
    list: () => ipcRenderer.invoke('containers:list'),
    create: (name) => ipcRenderer.invoke('containers:create', name),
    remove: (id) => ipcRenderer.invoke('containers:remove', id)
  },
  network: { // 1.6.0 — FASE 5
    state: () => ipcRenderer.invoke('network:state'),
    refreshVpn: () => ipcRenderer.invoke('network:refreshVpn'),
    checkIp: () => ipcRenderer.invoke('network:checkIp'),
    onState: (cb) => subscribe('network:state', cb)
  },
  security: { // 1.6.0 — FASE 6 (1.8.8: + status ClamAV embutido)
    log: () => ipcRenderer.invoke('security:log'),
    urlgateList: () => ipcRenderer.invoke('security:urlgate-list'),
    urlgateRemove: (h) => ipcRenderer.invoke('security:urlgate-remove', h),
    scanTools: () => ipcRenderer.invoke('security:scan-tools'),
    clamavStatus: () => ipcRenderer.invoke('security:clamavStatus'),
    engines: () => ipcRenderer.invoke('security:engines'),
    enginesUpdateClamav: () => ipcRenderer.invoke('security:engines-update-clamav'),
    onUpdate: (cb) => subscribe('security:update', cb)
  },
  translate: { // 1.6.0 — FASE 7
    run: (text) => ipcRenderer.invoke('translate:run', text),
    page: () => ipcRenderer.invoke('translate:page'),
    clipboard: () => ipcRenderer.invoke('translate:clipboard'),
    onResult: (cb) => subscribe('translate:result', cb)
  },
  library: { // 1.7.0 — LibraryTranslate (biblioteca de traduções, só RAM)
    list: (q) => ipcRenderer.invoke('library:list', q),
    remove: (id) => ipcRenderer.invoke('library:remove', id),
    clear: () => ipcRenderer.invoke('library:clear'),
    export: () => ipcRenderer.invoke('library:export'),
    onUpdate: (cb) => subscribe('library:update', cb)
  },
  linkwarden: { // 1.6.0 — FASE 7 (instância própria; token via env)
    save: (url) => ipcRenderer.invoke('linkwarden:save', url)
  },
  bitwarden: { // 1.6.0 — FASE 7 (mantido por compat: delega ao cofre nativo 1.8.9)
    fill: () => ipcRenderer.invoke('bitwarden:fill')
  },
  vault: { // 1.8.9 — cofre de senhas NATIVO (AES-256-GCM + PBKDF2)
    // 1.9.1: cópia pelo processo principal (limpeza condicional em 20 s / ao fechar)
    copy: (id) => ipcRenderer.invoke('vault:copy', id),
    copyText: (t) => ipcRenderer.invoke('vault:copy-text', t),
    status: () => ipcRenderer.invoke('vault:status'),
    exists: () => ipcRenderer.invoke('vault:exists'),
    create: (masterPw) => ipcRenderer.invoke('vault:create', masterPw),
    unlock: (masterPw) => ipcRenderer.invoke('vault:unlock', masterPw),
    lock: () => ipcRenderer.invoke('vault:lock'),
    list: () => ipcRenderer.invoke('vault:list'),
    search: (q) => ipcRenderer.invoke('vault:search', q),
    getByHost: (host) => ipcRenderer.invoke('vault:getByHost', host),
    add: (item) => ipcRenderer.invoke('vault:add', item),
    update: (id, patch) => ipcRenderer.invoke('vault:update', id, patch),
    remove: (id) => ipcRenderer.invoke('vault:remove', id),
    generate: (opts) => ipcRenderer.invoke('vault:generate', opts),
    changeMaster: (oldPw, newPw) => ipcRenderer.invoke('vault:changeMaster', oldPw, newPw),
    exportJson: () => ipcRenderer.invoke('vault:export'),
    importJson: (jsonStr, mode) => ipcRenderer.invoke('vault:import', jsonStr, mode),
    destroy: () => ipcRenderer.invoke('vault:destroy'),
    fillNow: () => ipcRenderer.invoke('vault:fill-now'),
    onState: (cb) => subscribe('vault:state', cb),
    onPromptUnlock: (cb) => subscribe('vault:prompt-unlock', cb)
  },
  video: { // 1.6.0 — FASE 8 (1.8.8: apenas yt-dlp; FreeTube/Invidious/Piped removidos)
    download: (url) => ipcRenderer.invoke('video:download', url),
    status: () => ipcRenderer.invoke('ytdlp:status'),
    cancel: () => ipcRenderer.invoke('ytdlp:cancel'),
    history: () => ipcRenderer.invoke('ytdlp:history'),
    clearHistory: () => ipcRenderer.invoke('ytdlp:clearHistory'),
    openFile: (p) => ipcRenderer.invoke('ytdlp:openFile', p),
    onProgress: (cb) => subscribe('ytdlp:progress', cb)
  },
  favorites: {
    list: () => ipcRenderer.invoke('favorites:list'),
    add: (t, u) => ipcRenderer.invoke('favorites:add', t, u),
    remove: (u) => ipcRenderer.invoke('favorites:remove', u),
    clear: () => ipcRenderer.invoke('favorites:clear'),
    toggle: (t, u) => ipcRenderer.invoke('favorites:toggle', t, u),
    set: (id, patch) => ipcRenderer.invoke('favorites:set', id, patch), // 1.6.0
    export: () => ipcRenderer.invoke('favorites:export'),
    import: () => ipcRenderer.invoke('favorites:import')
  },
  adblock: {
    stats: () => ipcRenderer.invoke('adblock:stats'),
    recent: () => ipcRenderer.invoke('adblock:recent'),
    setEnabled: (v) => ipcRenderer.invoke('adblock:setEnabled', v),
    allow: (h) => ipcRenderer.invoke('adblock:allow', h),
    disallow: (h) => ipcRenderer.invoke('adblock:disallow', h),
    allowlist: () => ipcRenderer.invoke('adblock:allowlist'),
    hostsStatus: () => ipcRenderer.invoke('adblock:hosts-status'), // 1.6.0
    onStats: (cb) => subscribe('adblock:stats', cb)
  },
  protection: {
    // 1.5.1 — pop-ups (Popup-Blocker-Pro) + redirecionamentos (RedirectGuard)
    stats: () => ipcRenderer.invoke('protection:stats'),
    recent: () => ipcRenderer.invoke('protection:recent'),
    popupAllowlist: () => ipcRenderer.invoke('protection:popup-allowlist'),
    redirectAllowlist: () => ipcRenderer.invoke('protection:redirect-allowlist'),
    popupAllow: (h) => ipcRenderer.invoke('protection:popup-allow', h),
    popupDisallow: (h) => ipcRenderer.invoke('protection:popup-disallow', h),
    redirectAllow: (h) => ipcRenderer.invoke('protection:redirect-allow', h),
    redirectDisallow: (h) => ipcRenderer.invoke('protection:redirect-disallow', h),
    setPopupEnabled: (v) => ipcRenderer.invoke('protection:setPopupEnabled', v),
    setRedirectEnabled: (v) => ipcRenderer.invoke('protection:setRedirectEnabled', v),
    onStats: (cb) => subscribe('protection:stats', cb)
  },
  downloads: {
    list: () => ipcRenderer.invoke('downloads:list'),
    open: (id) => ipcRenderer.invoke('downloads:open', id),
    show: (id) => ipcRenderer.invoke('downloads:show', id),
    openFolder: () => ipcRenderer.invoke('downloads:openFolder'),
    cancel: (id) => ipcRenderer.invoke('downloads:cancel', id),
    remove: (id) => ipcRenderer.invoke('downloads:remove', id),
    clear: () => ipcRenderer.invoke('downloads:clear'),
    release: (id) => ipcRenderer.invoke('downloads:release', id),     // 1.6.0
    deleteFile: (id) => ipcRenderer.invoke('downloads:deleteFile', id), // 1.6.0
    pause: (id) => ipcRenderer.invoke('downloads:pause', id),          // 1.9.5: pause via manager
    resume: (id) => ipcRenderer.invoke('downloads:resume', id),        // 1.9.5: resume via manager
    onUpdate: (cb) => subscribe('downloads:update', cb)
  },
  // 1.9.5 — detector de mídia + gerenciador central de downloads (Electron/aria2/Gopeed).
  // API tipada e mínima: o renderer NÃO conhece o token do aria2 nem a URL do Gopeed.
  // Tudo passa pelo main que valida tabId + mediaId + origem antes de agir.
  media: {
    detect: (tabId) => ipcRenderer.invoke('media:detect', tabId),
    list: (tabId) => ipcRenderer.invoke('media:list', tabId),
    clear: (tabId) => ipcRenderer.invoke('media:clear', tabId),
    download: (tabId, mediaId, opts) => ipcRenderer.invoke('media:download', tabId, mediaId, opts),
    downloadBatch: (tabId, mediaIds, opts) => ipcRenderer.invoke('media:downloadBatch', tabId, mediaIds, opts),
    engines: () => ipcRenderer.invoke('media:engines')
  },
  updates: {
    check: () => ipcRenderer.invoke('updates:check')
  },
  filters: {
    refresh: () => ipcRenderer.invoke('filters:refresh')
  },
  reader: {
    list: () => ipcRenderer.invoke('reader:list'),
    subscribe: (url) => ipcRenderer.invoke('reader:subscribe', url),
    remove: (id) => ipcRenderer.invoke('reader:remove', id),
    items: (feedId, opts) => ipcRenderer.invoke('reader:items', feedId, opts),
    item: (id) => ipcRenderer.invoke('reader:item', id),
    markRead: (id, read) => ipcRenderer.invoke('reader:markRead', id, read),
    markAllRead: (feedId) => ipcRenderer.invoke('reader:markAllRead', feedId),
    refresh: (feedId) => ipcRenderer.invoke('reader:refresh', feedId),
    opmlExport: () => ipcRenderer.invoke('reader:opmlExport'),
    opmlImport: () => ipcRenderer.invoke('reader:opmlImport'),
    onUpdate: (cb) => subscribe('reader:update', cb)
  },
  readerMode: {
    extract: (url) => ipcRenderer.invoke('readermode:extract', url)
  },
  // 1.9.0 — arquivar página (arquivo único local)
  archive: {
    save: (opts) => ipcRenderer.invoke('archive:save', opts || {}),
    saveAll: () => ipcRenderer.invoke('archive:save-all'),
    verify: () => ipcRenderer.invoke('archive:verify')
  },
  readers: {
    // diálogos "abrir arquivo" (PDF/ebook) — 1.5.0
    openDialog: (kind) => ipcRenderer.invoke('readers:open-dialog', kind),
    openPath: (p) => ipcRenderer.invoke('readers:open-path', p)
  },
  app: {
    openExternal: (url) => ipcRenderer.invoke('app:openExternal', url),
    version: () => ipcRenderer.invoke('app:version'),
    clearBrowsingData: () => ipcRenderer.invoke('app:clearBrowsingData'),
    // 1.5.3: repassa as marcas da engine (navigator.userAgentData) para o
    // main montar Sec-CH-UA coerente com um Chrome real.
    reportIdentity: (brands, high) => ipcRenderer.invoke('identity:report', brands, high)
  },
  onOpenTab: (cb) => subscribe('tabs:open-in-tab', cb),
  onSearchTab: (cb) => subscribe('tabs:search', cb),
  onToast: (cb) => subscribe('status:toast', (p) => cb(typeof p === 'string' ? { msg: p } : p)),
  onCmd: (cb) => subscribe('cmd', cb)
});

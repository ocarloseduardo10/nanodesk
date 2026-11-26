/**
 * NanoDesk — Resolvedor de redirecionamentos (1.8.8)
 * ==================================================================
 * Inspiração: LibRedirect + RedirectGuard. Resolve URL de redirect
 * trackers (Google url?q=, DuckDuckGo uddg, Bing base64, Reddit,
 * Steam, Facebook l.php, YouTube redirect, etc.) SEM chamar nenhuma
 * API externa — 100% local, parsing de querystring/base64.
 *
 * `resolveRedirect(url)` devolve a URL destino real (string) ou null
 * quando a URL não é um redirect conhecido.
 *
 * Núcleo puro: testável sem rede/Electron.
 */
'use strict';

/** Decodifica base64 com padding flexível (padrão URL-safe incluído). */
function decodeBase64Flex(s) {
  let v = String(s || '').replace(/[-_]/g, m => m === '-' ? '+' : '/');
  while (v.length % 4) v += '=';
  try {
    const buf = Buffer.from(v, 'base64');
    const txt = buf.toString('utf8');
    // só vale se o resultado parece uma URL http(s)
    if (/^https?:\/\//i.test(txt) && !/[\x00-\x1f]/.test(txt)) return txt;
    return null;
  } catch (_) { return null; }
}

/** Procura o primeiro valor de querystring que seja http(s) (puro). */
function firstHttpParam(u, names) {
  for (const n of names) {
    const v = u.searchParams.get(n);
    if (v && /^https?:\/\//i.test(v)) return v;
  }
  return null;
}

/**
 * Resolve uma URL de redirect.
 * @param {string} urlStr URL suspeita de redirect
 * @returns {string|null} destino real ou null (não é redirect conhecido)
 */
function resolveRedirect(urlStr) {
  let u;
  try { u = new URL(String(urlStr || '')); }
  catch (_) { return null; }
  const host = u.hostname.toLowerCase();
  const path = u.pathname || '/';

  // Google (web, images, news, shopping, maps): url= ou url?q= ou imgurl=
  if (host === 'www.google.com' || host === 'google.com' ||
      host.endsWith('.google.com') || host === 'www.googleadservices.com') {
    if (path === '/url' || path === '/searchurl/ii' || path === '/imgres' ||
        path === '/aclk' || path === '/uds/d' || path === '/local_url') {
      return firstHttpParam(u, ['url', 'q', 'imgurl', 'adurl', 'dest_url', 'sa', 'imgrefurl']) || null;
    }
  }
  // DuckDuckGo: uddg= ou u= (também o redirecionador r.ddg.co)
  if (host === 'duckduckgo.com' || host.endsWith('.duckduckgo.com') ||
      host === 'r.ddg.co' || host === 'duck.com' || host === 'www.duck.com') {
    const v = firstHttpParam(u, ['uddg', 'u', 'url', 'redirect']);
    if (v) return v;
    // r.ddg.co/URL -> URL em base64-URL-safe ou direto
    if ((host === 'r.ddg.co') && path.length > 1) {
      const b = decodeBase64Flex(path.slice(1));
      if (b) return b;
    }
  }
  // Bing: b64url base64-URL-safe  (alternativa: u=)
  if (host === 'www.bing.com' || host === 'bing.com' || host.endsWith('.bing.com')) {
    const v = firstHttpParam(u, ['u', 'url']);
    if (v) return v;
    if (path === '/ck/a' || path === '/L') {
      const b64 = u.searchParams.get('u') || u.searchParams.get('a');
      if (b64) {
        const dec = decodeBase64Flex(b64);
        if (dec) return dec;
      }
    }
  }
  // Brave search
  if (host === 'search.brave.com' || host.endsWith('.search.brave.com')) {
    return firstHttpParam(u, ['url']) || null;
  }
  // Startpage
  if (host === 'www.startpage.com' || host === 'startpage.com') {
    return firstHttpParam(u, ['url', 'q']) || null;
  }
  // YouTube redirect: /redirect?q=  (ANTES do genérico /redirect)
  // 1.8.10: aceita também o host nu `youtube.com` (endsWith('.youtube.com')
  // não bate para `youtube.com` — string mais curta que o sufixo).
  if ((host === 'youtube.com' || host.endsWith('.youtube.com')) && path === '/redirect') {
    return firstHttpParam(u, ['q', 'url']) || null;
  }
  // SearXNG / genérico: /redirect?url= ou /url?url=
  // 1.8.10: aceita host nu `searxng`/`searx.be` (mesmo motivo do YouTube).
  if (host === 'searxng' || host.endsWith('.searxng') || host === 'searx.be' || host.endsWith('.searx.be') || path === '/redirect' || path === '/url') {
    const r = firstHttpParam(u, ['url', 'to', 'goto']);
    if (r) return r;
  }
  // Reddit: out.reddit.com?...&url=  /  r.reddit.com/URL_BASE64
  if (host === 'out.reddit.com' || host === 'www.reddit.com' && path === '/click') {
    return firstHttpParam(u, ['url']) || null;
  }
  if (host === 'r.reddit.com' && path.length > 1) {
    const dec = decodeBase64Flex(path.slice(1));
    if (dec) return dec;
  }
  // Steam: steam://openurl/URL ou /url/URL
  if (host === 'steamcommunity.com' && path.startsWith('/linkfilter/')) {
    const v = u.searchParams.get('u');
    if (v && /^https?:\/\//i.test(v)) return v;
  }
  if (host === 'store.steampowered.com' && path.startsWith('/url/')) {
    const rest = path.slice('/url/'.length);
    if (/^https?:\/\//i.test(rest)) return rest;
  }
  // Facebook l.php?u=
  if (host === 'www.facebook.com' || host === 'facebook.com' || host === 'm.facebook.com') {
    if (path === '/l.php' || path === '/login.php') {
      return firstHttpParam(u, ['u', 'url']) || null;
    }
  }
  // YouTube redirect já tratado acima (antes do genérico).
  // Twitter/X: t.co/ABC -> resolve só pelo caminho (não dá para resolver
  // offline); mas o filtro de "redirect tracking" pode considerar isto.
  // Pinterest: pin.it/ABC → igual (redirecionador curto do Pinterest).
  // Git.io / buff.ly / bit.ly: shorteners genéricos — deixamos passar (não
  // dá para resolver 100% local sem rede).
  // Genérico: ?url=, ?to=, ?target=, ?dest=, ?redirect=, ?redir=, ?goto=
  if (path === '/redirect' || path === '/go' || path === '/redir' || path === '/jump') {
    return firstHttpParam(u, ['url', 'to', 'target', 'dest', 'redirect', 'redir', 'goto']) || null;
  }
  return null;
}

/** Lista de hosts que são redirecionadores conhecidos (para match rápido). */
const REDIRECT_HOSTS = new Set([
  'www.google.com', 'google.com', 'www.googleadservices.com',
  'duckduckgo.com', 'r.ddg.co', 'duck.com', 'www.duck.com',
  'www.bing.com', 'bing.com',
  'search.brave.com', 'www.startpage.com', 'startpage.com',
  'out.reddit.com', 'r.reddit.com',
  'steamcommunity.com', 'store.steampowered.com',
  'www.facebook.com', 'facebook.com', 'm.facebook.com'
]);

/** É um host que merece checagem de redirect? (puro) */
function isRedirectHost(urlStr) {
  try {
    const u = new URL(String(urlStr || ''));
    const h = u.hostname.toLowerCase();
    if (REDIRECT_HOSTS.has(h)) return true;
    if (h.endsWith('.google.com') || h.endsWith('.bing.com') ||
        h.endsWith('.duckduckgo.com') || h.endsWith('.youtube.com')) return true;
    // 1.8.10: hosts nus que falham o endsWith('.X') acima
    if (h === 'youtube.com') return true;
    return false;
  } catch (_) { return false; }
}

module.exports = { resolveRedirect, isRedirectHost, REDIRECT_HOSTS, decodeBase64Flex };

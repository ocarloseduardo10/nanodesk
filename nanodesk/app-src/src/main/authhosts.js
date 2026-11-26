/**
 * NanoDesk — Domínios de LOGIN/identidade (1.7.2)
 * ==================================================================
 * Por quê: serviços de login (Google, Microsoft, Apple, gov.br, bancos) executam
 * verificações de integridade do navegador (BotGuard e similares): "esta função nativa
 * ainda é nativa?", consistência de canvas/WebGL/áudio, scripts estranhos na página.
 * Os hooks de anti-fingerprinting (canvas/áudio/WebGL) e os módulos que mexem na página
 * (Consent-O-Matic, neutralizador de overlay, scriptlets) são DETECTÁVEIS por elas, e o
 * resultado é "Este navegador ou app talvez não seja seguro" / login recusado.
 *
 * Solução (como Firefox/Brave fazem com exceções): nessas páginas o NanoDesk NÃO injeta
 * nada no mundo principal. O resto da proteção continua (DNT/GPC, bloqueio de rede,
 * HTTPS-first, isolamento de sessão). A lista é editável em Configurações (fpExempt).
 *
 * Também define GRUPOS de SSO: dentro de um grupo, o bloqueio de cookies de terceiros não
 * remove o Cookie (o login do Google sincroniza google.com <-> youtube.com por iframes).
 * Módulo puro — testável sem Electron.
 */
'use strict';

/** Hosts (e subdomínios) onde nada é injetado na página. */
const BUILTIN_AUTH_HOSTS = [
  // Google
  'accounts.google.com', 'accounts.google.com.br', 'myaccount.google.com', 'accounts.youtube.com',
  'gds.google.com', 'play.google.com', 'consent.google.com', 'consent.youtube.com',
  // Microsoft
  'login.microsoftonline.com', 'login.live.com', 'login.microsoft.com', 'account.microsoft.com',
  'account.live.com', 'aadcdn.msftauth.net', 'logincdn.msftauth.net',
  // Apple
  'appleid.apple.com', 'idmsa.apple.com', 'account.apple.com',
  // gov.br e bancos brasileiros (detecção de adulteração é comum)
  'acesso.gov.br', 'sso.acesso.gov.br',
  'itau.com.br', 'bb.com.br', 'bradesco.com.br', 'santander.com.br', 'caixa.gov.br',
  'nubank.com.br', 'inter.co', 'c6bank.com.br', 'sicredi.com.br', 'sicoob.com.br',
  // Outros provedores de login muito usados
  'github.com', 'gitlab.com', 'login.yahoo.com', 'id.atlassian.com', 'auth0.com', 'okta.com',
  'login.salesforce.com', 'paypal.com', 'mercadopago.com.br', 'mercadolivre.com.br'
];

/** Grupos de SSO: cookies entre estes sites NÃO são tratados como "de terceiros". */
const SSO_GROUPS = [
  ['google.com', 'google.com.br', 'youtube.com', 'gstatic.com', 'googleusercontent.com', 'youtube-nocookie.com', 'ggpht.com'],
  ['microsoftonline.com', 'microsoft.com', 'live.com', 'office.com', 'msftauth.net', 'office365.com', 'sharepoint.com', 'bing.com', 'msn.com'],
  ['apple.com', 'icloud.com'],
  ['gov.br']
];

function norm(h) { return String(h || '').trim().toLowerCase().replace(/\.$/, ''); }

function matches(host, domain) {
  const h = norm(host), d = norm(domain);
  return !!h && !!d && (h === d || h.endsWith('.' + d));
}

/** O host é página de login/identidade (nada de injeção)? `extra` = lista do usuário. */
function isAuthHost(host, extra) {
  const h = norm(host);
  if (!h) return false;
  for (const d of BUILTIN_AUTH_HOSTS) if (matches(h, d)) return true;
  if (Array.isArray(extra)) for (const d of extra) if (matches(h, d)) return true;
  return false;
}

/** Os dois hosts pertencem ao MESMO grupo de SSO? */
function sameSsoGroup(a, b) {
  const x = norm(a), y = norm(b);
  if (!x || !y) return false;
  for (const g of SSO_GROUPS) {
    if (g.some(d => matches(x, d)) && g.some(d => matches(y, d))) return true;
  }
  return false;
}

module.exports = { BUILTIN_AUTH_HOSTS, SSO_GROUPS, isAuthHost, sameSsoGroup, matches };

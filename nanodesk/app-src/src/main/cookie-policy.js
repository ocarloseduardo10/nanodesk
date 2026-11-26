/**
 * NanoDesk 1.9.2 — política de COOKIES DE TERCEIROS (pura, testável)
 * ------------------------------------------------------------------
 * Problemas da versão anterior (auditoria):
 *   (a) só removia o cabeçalho Cookie das REQUISIÇÕES; um Set-Cookie de terceiro continuava criando
 *       cookie no armazenamento do navegador;
 *   (b) decidia pelo Referer — com Referrer-Policy: no-referrer o host de referência ficava vazio e a
 *       regra "sem referência: não decide" deixava o cookie PASSAR.
 * Agora:
 *   - o "site de topo" vem da ABA dona da requisição (Referer só como último recurso);
 *   - cookies saem das requisições E os Set-Cookie são removidos das respostas de terceiros;
 *   - exceções explícitas: mesmo site, mesmo grupo de SSO e hosts de autenticação (login legítimo).
 * 1.9.3 — "contexto desconhecido" (service worker, requisição sem aba/frame/Referer) deixou de ser
 * tratado como se fosse primeira parte em silêncio: decide() devolve 'unknown', o app CONTA e REGISTRA
 * quando a proteção não pôde ser aplicada, e o modo estrito (thirdPartyCookiesStrict) bloqueia esses casos.
 * Limites honestos: localStorage/IndexedDB/Cache de iframes de terceiros NÃO são bloqueados aqui — o
 * Chromium moderno já os PARTICIONA por site de topo (storage partitioning), sem compartilhamento
 * entre sites; bloquear por completo exigiria API do Chromium que o Electron não expõe.
 */
'use strict';

function hostFromUrl(u) {
  try { return new URL(String(u)).hostname.toLowerCase().replace(/\.$/, ''); } catch (_) { return ''; }
}

/** Host do site de topo: aba dona (preferido) → Referer → '' (desconhecido). */
function topSiteHost(info) {
  const i = info || {};
  return hostFromUrl(i.tabUrl) || hostFromUrl(i.referrer) || '';
}

/**
 * Deve bloquear cookies nesta requisição?
 * @param {{reqHost:string, topHost:string, resourceType?:string}} r
 * @param {{sameSite:(a:string,b:string)=>boolean, sameSso?:(a:string,b:string)=>boolean, isAuth?:(h:string)=>boolean}} p
 */
function shouldBlock(r, p) {
  if (!r || r.resourceType === 'mainFrame') return false;           // navegação de topo é primeira parte
  const req = String(r.reqHost || '').toLowerCase();
  const top = String(r.topHost || '').toLowerCase();
  if (!req || !top) return false;                                   // sem informação: não decide
  if (p.sameSite(req, top)) return false;
  if (p.sameSso && p.sameSso(req, top)) return false;
  if (p.isAuth && (p.isAuth(req) || p.isAuth(top))) return false;   // fluxos de autenticação (SSO/OAuth/gov.br)
  return true;
}

/**
 * Decisão completa. action: 'block' | 'allow' | 'unknown'.
 *  - 'unknown' = não há como saber qual é o site de topo; com opts.strict vira 'block' (fail-closed).
 * @param {{reqHost:string, topHost:string, resourceType?:string}} r
 * @param {{sameSite:Function, sameSso?:Function, isAuth?:Function}} p
 * @param {{strict?:boolean}} [opts]
 * @returns {{action:'block'|'allow'|'unknown', reason:string, unknown:boolean}}
 */
function decide(r, p, opts) {
  const strict = !!(opts && opts.strict);
  if (!r) return { action: 'allow', reason: 'sem-requisicao', unknown: false };
  if (r.resourceType === 'mainFrame') return { action: 'allow', reason: 'primeira-parte', unknown: false };
  const req = String(r.reqHost || '').toLowerCase();
  const top = String(r.topHost || '').toLowerCase();
  if (!req || !top) return strict
    ? { action: 'block', reason: 'contexto-desconhecido-estrito', unknown: true }
    : { action: 'unknown', reason: 'contexto-desconhecido', unknown: true };
  if (p.sameSite(req, top)) return { action: 'allow', reason: 'mesmo-site', unknown: false };
  if (p.sameSso && p.sameSso(req, top)) return { action: 'allow', reason: 'grupo-sso', unknown: false };
  if (p.isAuth && (p.isAuth(req) || p.isAuth(top))) return { action: 'allow', reason: 'autenticacao', unknown: false };
  return { action: 'block', reason: 'terceiro', unknown: false };
}

function stripRequestCookie(headers) {
  let n = 0;
  for (const k of Object.keys(headers || {})) if (k.toLowerCase() === 'cookie') { delete headers[k]; n++; }
  return n;
}

/** Remove TODOS os Set-Cookie (qualquer caixa) de um objeto de cabeçalhos de resposta. */
function stripSetCookie(headers) {
  let n = 0;
  for (const k of Object.keys(headers || {})) {
    if (k.toLowerCase() === 'set-cookie') {
      n += Array.isArray(headers[k]) ? headers[k].length : 1;
      delete headers[k];
    }
  }
  return n;
}

module.exports = { hostFromUrl, topSiteHost, shouldBlock, decide, stripRequestCookie, stripSetCookie };

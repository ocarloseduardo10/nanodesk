/**
 * NanoDesk — Motor de listas "hosts" (1.6.0, FASE 4)
 * ==================================================================
 * Integra o StevenBlack/hosts (MIT) como terceira camada do
 * bloqueador nativo, além do EasyList/EasyPrivacy (Ghostery):
 *
 *  - parseHosts(text): parser puro do formato hosts (0.0.0.0 domínio),
 *    tolerante a comentários, linhas vazias e múltiplos apelidos por
 *    linha. Testável sem rede nem Electron.
 *  - fetchStevenBlack(): baixa a lista-base do upstream (MIT) em tempo
 *    de execução — NADA é embutido no pacote (a lista muda todo dia) e
 *    NADA é gravado no disco (fica só na RAM da sessão, como todo o
 *    resto). Falha de rede = camada fica apenas indisponível, com
 *    status honesto no painel de listas.
 *
 * O bloqueio por hosts acontece no MESMO listener onBeforeRequest do
 * adblock.js (limitação do Electron: um listener por canal) — este
 * módulo só produz/converte os dados.
 */
'use strict';
const netLimits = require('./net-limits');

const STEVENBLACK_URL = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts';
const STEVENBLACK_LICENSE = 'MIT (c) StevenBlack e contribuidores';
const MAX_DOMAINS = 400000;          // trava de memória (~lista inteira cabe)
const MAX_BYTES = 12 * 1024 * 1024;  // 12 MB: a lista base tem ~2,5 MB

/**
 * Parser do formato hosts (puro).
 * Aceita "0.0.0.0 dominio [apelidos…]" e "127.0.0.1 …"; ignora
 * comentários (#) e linhas malformadas. Nunca devolve localhost.
 * @returns {string[]} domínios únicos, minúsculos, sem ponto final
 */
function parseHosts(text) {
  const out = new Set();
  const lines = String(text || '').split(/\r?\n/);
  for (const line of lines.slice(0, 200000)) {
    let l = line.trim();
    if (!l || l.startsWith('#')) continue;
    const hash = l.indexOf('#');
    if (hash >= 0) l = l.slice(0, hash).trim();
    const parts = l.split(/\s+/).filter(Boolean);
    if (parts.length < 2) continue;
    const ip = parts[0].toLowerCase();
    if (ip !== '0.0.0.0' && ip !== '127.0.0.1' && ip !== '::1') continue;
    for (const raw of parts.slice(1)) {
      let d = raw.toLowerCase().replace(/\.$/, '');
      if (!d || d === 'localhost' || d.endsWith('.localhost')) continue;
      if (d.length > 253 || !d.includes('.')) continue;
      if (!/^[a-z0-9.-]+$/.test(d)) continue;
      out.add(d);
      if (out.size >= MAX_DOMAINS) break;
    }
    if (out.size >= MAX_DOMAINS) break;
  }
  return [...out];
}

/**
 * Baixa a lista-base do StevenBlack (best-effort).
 * @param {Function} fetchImpl  injetável para testes
 * @returns {{domains: string[], count: number, source: string, license: string}}
 */
async function fetchStevenBlack(fetchImpl = fetch, timeoutMs = 15000) {
  let signal;
  try { signal = AbortSignal.timeout(timeoutMs); } catch (_) { /* Node antigo */ }
  const res = await fetchImpl(STEVENBLACK_URL, { signal });
  if (!res.ok) throw new Error('StevenBlack respondeu HTTP ' + res.status);
  let text;
  try { text = await netLimits.readTextLimited(res, MAX_BYTES); }   // 1.9.2: teto em streaming
  catch (e) { if (e && e.code === 'BODY_TOO_LARGE') throw new Error('Lista StevenBlack grande demais.'); throw e; }
  const domains = parseHosts(text);
  if (!domains.length) throw new Error('Lista StevenBlack vazia ou ilegível.');
  return { domains, count: domains.length, source: STEVENBLACK_URL, license: STEVENBLACK_LICENSE };
}

/** Estado do motor hosts para o painel de listas. */
function describe(state) {
  return {
    id: 'stevenblack',
    name: 'StevenBlack hosts',
    license: STEVENBLACK_LICENSE,
    source: STEVENBLACK_URL,
    enabled: !!(state && state.enabled),
    count: state && state.domains ? state.domains.length : 0,
    blocked: (state && state.blocked) || 0,
    status: (state && state.status) || 'indisponivel'
  };
}

module.exports = { parseHosts, fetchStevenBlack, describe, STEVENBLACK_URL, STEVENBLACK_LICENSE, MAX_DOMAINS };

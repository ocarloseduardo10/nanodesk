/**
 * NanoDesk — Histórico da sessão (1.6.0, FASE 7)
 * ==================================================================
 * Histórico PESQUISÁVEL, exclusivamente em memória (coerente com o
 * princípio do NanoDesk: nada é gravado no PC — ao fechar, some).
 * Puro: sem Electron, coberto por testes unitários.
 */
'use strict';

const MAX_ENTRIES = 5000;

class HistoryStore {
  constructor(maxEntries = MAX_ENTRIES) {
    this.max = Math.min(50000, Math.max(100, Number(maxEntries) || MAX_ENTRIES));
    this.items = []; // { url, title, host, ts }
  }

  /** Registra uma navegação confirmada (ignora about:/data:/ndr://). */
  add(url, title) {
    const u = String(url || '');
    if (!/^https?:\/\//i.test(u)) return false;
    let host = '';
    try { host = new URL(u).hostname.toLowerCase(); } catch (_) { return false; }
    // dedupe: mesma URL em <2s não entra duas vezes (reload/redirect)
    const head = this.items[0];
    if (head && head.url === u && Date.now() - head.ts < 2000) return false;
    this.items.unshift({ url: u.slice(0, 2048), title: String(title || host).slice(0, 300), host, ts: Date.now() });
    if (this.items.length > this.max) this.items.length = this.max;
    return true;
  }

  /**
   * Busca por termo (URL, título e host; sem acento, case-insensitive).
   * @param {string} q  vazio = tudo
   * @param {object} [opts] { limit?: number, host?: string }
   */
  search(q, opts = {}) {
    const term = String(q || '').trim().toLowerCase();
    const limit = Math.min(500, Math.max(1, Number(opts.limit) || 200));
    let list = this.items;
    if (opts.host) {
      const h = String(opts.host).toLowerCase();
      list = list.filter(i => i.host === h || i.host.endsWith('.' + h));
    }
    if (!term) return list.slice(0, limit);
    const norm = (s) => s.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    const t = norm(term);
    const out = [];
    for (const it of list) {
      const hay = norm((it.url + ' ' + it.title + ' ' + it.host).toLowerCase());
      if (hay.includes(t)) { out.push(it); if (out.length >= limit) break; }
    }
    return out;
  }

  list(limit = 200) { return this.search('', { limit }); }
  size() { return this.items.length; }
  clear() { this.items = []; }
}

module.exports = { HistoryStore, MAX_ENTRIES };

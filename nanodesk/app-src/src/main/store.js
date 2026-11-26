/**
 * NanoDesk — Armazenamento EM MEMÓRIA (volátil)
 * ------------------------------------------------------------------
 * O NanoDesk nunca grava dados do usuário no PC. Esta classe mantém
 * a mesma API que o antigo JsonStore (get/set/flush), porém 100%
 * volátil: tudo vive apenas na RAM e desaparece quando o aplicativo
 * fecha — histórico, favoritos, configurações e listas de downloads.
 * Sem dependências externas, sem acesso ao sistema de arquivos.
 */
'use strict';

const UNSAFE_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

/**
 * Mescla profunda: prevalece o que está em `source`, mas chaves novas
 * presentes apenas em `target` (defaults) são preservadas. Arrays são
 * substituídos por inteiro.
 */
function deepMerge(target, source) {
  const out = { ...target };
  for (const k of Object.keys(source || {})) {
    if (UNSAFE_KEYS.has(k)) continue;
    const sv = source[k];
    const tv = out[k];
    if (
      sv && tv && typeof sv === 'object' && typeof tv === 'object' &&
      !Array.isArray(sv) && !Array.isArray(tv)
    ) {
      out[k] = deepMerge(tv, sv);
    } else {
      out[k] = sv;
    }
  }
  return out;
}

class MemoryStore {
  /**
   * @param {string} [label]  apenas informativo (logs); nada é gravado
   * @param {object} defaults valores padrão mesclados (profundo) ao estado
   */
  constructor(label = 'memory', defaults = {}) {
    this.label = label;
    this.file = null;          // compatibilidade: não há arquivo
    this.data = deepMerge({}, defaults);
  }

  get(key, fallback) {
    if (key == null) return this.data;
    const v = this.data[key];
    return v === undefined ? fallback : v;
  }

  set(key, value) {
    this.data[key] = value;
    return this.data;
  }

  /** Compatibilidade com a API antiga: não há nada para gravar. */
  flush() { /* intencionalmente vazio — nada vai para o disco */ }
}

module.exports = { MemoryStore };

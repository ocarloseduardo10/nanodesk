/**
 * NanoDesk — LibraryTranslate (1.7.0)
 * ==================================================================
 * Biblioteca de traduções do NanoDesk: o usuário seleciona um texto
 * em qualquer site → "Traduzir e salvar na Biblioteca" → o texto é
 * traduzido e a tradução fica guardada numa lista pesquisável,
 * copiável e exportável (painel Biblioteca).
 *
 * Motor de tradução (na ordem):
 *  1) LibreTranslate configurado pelo usuário (translateUrl) — se
 *     definido, é o preferido (pode ser LOCAL, 127.0.0.1);
 *  2) MyMemory (https://api.mymemory.translated.net) — serviço
 *     público gratuito SEM chave, para funcionar de imediato, com o
 *     MESMO diálogo de consentimento de sempre;
 *  3) idioma de origem detectado pelo LanguageTool (se ativo) ou
 *     "auto"/"en" como referência do par.
 *
 * Privacidade: nada sai do computador sem o diálogo de consentimento
 * (mesma regra do translate.js). A biblioteca vive SÓ NA RAM
 * (MemoryStore) — fecha o NanoDesk, some tudo, coerente com o resto
 * do navegador.
 *
 * Núcleo puro (testável): normalização de registro, par de idiomas,
 * payloads e leitura das respostas dos dois serviços.
 */
'use strict';

const MAX_RECORDS = 1000;
const MAX_TEXT = 500;       // MyMemory aceita ~500 bytes por consulta
const MAX_STORED_TEXT = 2000;

/** Novo registro normalizado (puro). */
function makeRecord({ text, translation, src, target, url, title }) {
  return {
    id: 't' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    text: String(text || '').slice(0, MAX_STORED_TEXT),
    translation: String(translation || '').slice(0, MAX_STORED_TEXT),
    src: String(src || 'auto').slice(0, 8),
    target: String(target || 'pt').slice(0, 8),
    url: String(url || '').slice(0, 500),
    title: String(title || '').slice(0, 200),
    date: new Date().toISOString()
  };
}

/** Adiciona um registro à lista com teto (puro, imutável na entrada). */
function addItem(items, rec) {
  const list = Array.isArray(items) ? items.slice() : [];
  list.unshift(rec);
  if (list.length > MAX_RECORDS) list.length = MAX_RECORDS;
  return list;
}

/** Busca simples por texto/tradução/título (puro). */
function search(items, query) {
  const q = String(query || '').trim().toLowerCase();
  const list = Array.isArray(items) ? items : [];
  if (!q) return list;
  return list.filter(r =>
    (r.text || '').toLowerCase().includes(q) ||
    (r.translation || '').toLowerCase().includes(q) ||
    (r.title || '').toLowerCase().includes(q));
}

/**
 * Par de idiomas para o MyMemory (puro).
 * CORREÇÃO 1.7.1: MyMemory NÃO aceita 'auto' como origem (responde
 * "'AUTO' IS AN INVALID SOURCE LANGUAGE"). Quando a detecção do
 * LanguageTool não rodou (desligada/fora do ar), a origem 'auto' agora
 * cai para 'en' — antes a consulta inteira ia pro chão e a tradução
 * "não funcionava de imediato" exatamente quando o LT estava caído.
 */
function langpair(src, target) {
  const raw = String(src || 'en').split('-')[0].toLowerCase();
  const s = (raw && raw !== 'auto') ? raw : 'en';
  const t = String(target || 'pt').split('-')[0].toLowerCase() || 'pt';
  return s === t ? 'en|' + t : s + '|' + t;
}

/** URL da API MyMemory (puro). */
function mymemoryUrl(text, src, target) {
  const q = String(text || '').slice(0, MAX_TEXT);
  if (!q.trim()) return null;
  return 'https://api.mymemory.translated.net/get?q=' + encodeURIComponent(q) +
    '&langpair=' + encodeURIComponent(langpair(src, target));
}

/** Tradução vinda do MyMemory (puro). */
function parseMymemory(json) {
  try {
    const t = json && json.responseData && json.responseData.translatedText;
    if (typeof t !== 'string' || !t.trim()) return '';
    if (/QUERY LENGTH LIMIT|INVALID|MYMEMORY WARNING/i.test(t)) return '';
    return t;
  } catch (_) { return ''; }
}

/** Corpo do /translate do LibreTranslate (puro) — reusa translate.js. */
function libretranslatePayload(text, target, source) {
  return {
    q: String(text || '').slice(0, MAX_TEXT),
    source: String(source || 'auto'),
    target: String(target || 'pt'),
    format: 'text',
    api_key: ''
  };
}

/** Tradução vinda do LibreTranslate (puro). */
function parseLibretranslate(json) {
  try {
    if (json && typeof json.translatedText === 'string') return json.translatedText;
    if (json && json.error) return '';
    return '';
  } catch (_) { return ''; }
}

module.exports = {
  MAX_RECORDS, MAX_TEXT, MAX_STORED_TEXT,
  makeRecord, addItem, search,
  langpair, mymemoryUrl, parseMymemory,
  libretranslatePayload, parseLibretranslate
};

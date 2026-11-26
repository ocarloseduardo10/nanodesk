/**
 * NanoDesk — Tradução privada (1.6.0, FASE 7)
 * ==================================================================
 * Referências: LibreTranslate (github.com/LibreTranslate/LibreTranslate,
 * AGPL-3.0) e Argos Translate (GPL-3.0). NENHUM código é copiado:
 * a integração é pelo API HTTP oficial do LibreTranslate, que o
 * usuário configura (servidor próprio OU instância pública escolhida
 * por ele). Por padrão a tradução vem DESLIGADA — sem endpoint não
 * há botão que "finge" traduzir.
 *
 * Regra de privacidade (da especificação): NUNCA enviar texto privado
 * a serviço externo sem informar o usuário e obter autorização.
 * Implementação: todo envio passa por um diálogo nativo mostrando
 * QUAL servidor receberá o texto (consentMessage()); a decisão é por
 * ação, nunca "lembrada" globalmente.
 *
 * Offline: Argos Translate gerencia MODELOS OFFLINE, mas é um pacote
 * Python separado — a integração oficial é servindo um LibreTranslate
 * local ("pip install libretranslate; libretranslate --host 127.0.0.1").
 * Um endpoint localhost é tratado como "processamento local" no
 * diálogo de consentimento.
 *
 * Núcleo puro (payloads, mensagens de consentimento, sanitização de
 * resposta) é testável sem rede; as chamadas HTTP ficam no main.js.
 */
'use strict';

const MAX_TEXT = 20000; // caracteres por chamada

function isLocalhost(endpoint) {
  try {
    const u = new URL(String(endpoint || ''));
    return /^(localhost|127\.\d+\.\d+\.\d+|\[::1\])$/.test(u.hostname);
  } catch (_) { return false; }
}

/** Mensagem de consentimento exibida antes de QUALQUER envio (puro). */
function consentMessage(endpoint, chars, kind) {
  const local = isLocalhost(endpoint);
  return (local
    ? 'Tradução LOCAL (processada no seu computador via ' +
      (endpoint || 'servidor local') + '). '
    : 'O texto será ENVIADO a um serviço externo: ' + (endpoint || 'servidor não configurado') + '. ') +
    chars + ' caractere(s) de ' + (kind || 'texto') + '. Continuar?';
}

/** Valida o endpoint configurado (só http/https; vazio = desligado). */
function normalizeEndpoint(v) {
  const s = String(v || '').trim().replace(/\/+$/, '');
  if (!s) return '';
  if (!/^https?:\/\/[a-z0-9.\-]+(:\d+)?(\/[^\s]*)?$/i.test(s)) return '';
  return s;
}

/** Corpo JSON para /translate (puro). */
function translatePayload(text, target, source) {
  return {
    q: String(text || '').slice(0, MAX_TEXT),
    source: String(source || 'auto'),
    target: String(target || 'pt'),
    format: 'html',
    api_key: '' // o main injeta a chave (env NANODESK_LT_KEY) se houver
  };
}

/** Parse tolerante da resposta do LibreTranslate (puro). */
function parseResponse(json) {
  if (!json) throw new Error('Resposta vazia do servidor de tradução.');
  if (typeof json.translatedText === 'string') return json.translatedText;
  if (json.error) throw new Error(String(json.error).slice(0, 200));
  throw new Error('Resposta do servidor sem translatedText.');
}

/** Idioma de destino default + lista exibida na interface (puro). */
const TARGET_LANGS = [
  ['pt', 'Português'], ['en', 'Inglês'], ['es', 'Espanhol'],
  ['fr', 'Francês'], ['de', 'Alemão'], ['it', 'Italiano'], ['ja', 'Japonês']
];

/**
 * Divide HTML longo em pedaços <= MAX_TEXT respeitando tags abertas
 * grosseiramente (corta em >: o servidor recebe HTML válido o suficiente).
 */
function splitHtml(html) {
  const s = String(html || '');
  if (s.length <= MAX_TEXT) return [s];
  const parts = [];
  let rest = s;
  while (rest.length) {
    if (rest.length <= MAX_TEXT) { parts.push(rest); break; }
    let cut = rest.lastIndexOf('>', MAX_TEXT - 1);
    if (cut < MAX_TEXT * 0.5) cut = MAX_TEXT - 1;
    parts.push(rest.slice(0, cut + 1));
    rest = rest.slice(cut + 1);
  }
  return parts;
}

module.exports = {
  MAX_TEXT, TARGET_LANGS,
  isLocalhost, consentMessage, normalizeEndpoint,
  translatePayload, parseResponse, splitHtml
};

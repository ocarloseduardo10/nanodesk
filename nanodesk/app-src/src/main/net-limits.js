/**
 * NanoDesk 1.9.2 — leitura de respostas HTTP COM TETO de bytes, em fluxo (streaming).
 * ------------------------------------------------------------------
 * Antes: vários pontos faziam `await res.arrayBuffer()/text()/json()` e só DEPOIS (ou só se o
 * servidor enviasse Content-Length) comparavam o tamanho. Um servidor hostil podia omitir ou
 * falsear Content-Length e fazer o processo principal alocar memória sem limite.
 * Agora: lê pedaço a pedaço, soma os bytes recebidos e CANCELA a conexão assim que passa do teto.
 * Funciona com Response real (corpo em stream) e com stubs de teste (arrayBuffer/json).
 */
'use strict';

class BodyTooLargeError extends Error {
  constructor(max) {
    super('Resposta maior que o limite permitido (' + Math.round(max / 1024) + ' KB).');
    this.name = 'BodyTooLargeError';
    this.code = 'BODY_TOO_LARGE';
    this.max = max;
  }
}

function cancelQuietly(res) {
  try { if (res && res.body && typeof res.body.cancel === 'function') { const p = res.body.cancel(); if (p && p.catch) p.catch(() => {}); } } catch (_) { /* ignorado */ }
}

/** @returns {Promise<Buffer>} */
async function readBodyLimited(res, maxBytes) {
  const max = Math.max(1, Number(maxBytes) || 1);
  const declared = Number(res && res.headers && typeof res.headers.get === 'function' ? res.headers.get('content-length') : NaN);
  if (Number.isFinite(declared) && declared > max) { cancelQuietly(res); throw new BodyTooLargeError(max); }
  if (res && res.body && typeof res.body.getReader === 'function') {
    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > max) { try { await reader.cancel(); } catch (_) { /* ignorado */ } throw new BodyTooLargeError(max); }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }
    return Buffer.concat(chunks, total);
  }
  if (res && typeof res.arrayBuffer === 'function') {          // stub/implementação sem stream
    const ab = await res.arrayBuffer();
    if (ab.byteLength > max) throw new BodyTooLargeError(max);
    return Buffer.from(ab);
  }
  throw new TypeError('Resposta sem corpo legível.');
}

async function readTextLimited(res, maxBytes) {
  if (res && !res.body && typeof res.text === 'function' && typeof res.arrayBuffer !== 'function') {
    const t = await res.text();
    if (Buffer.byteLength(t) > maxBytes) throw new BodyTooLargeError(maxBytes);
    return t;
  }
  return (await readBodyLimited(res, maxBytes)).toString('utf8');
}

async function readJsonLimited(res, maxBytes) {
  if (res && !res.body && typeof res.json === 'function' && typeof res.arrayBuffer !== 'function') return res.json();   // stub
  return JSON.parse(await readTextLimited(res, maxBytes));
}

module.exports = { BodyTooLargeError, readBodyLimited, readTextLimited, readJsonLimited };

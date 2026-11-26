/**
 * NanoDesk — Identidade do navegador (1.5.3)
 * ==================================================================
 * Objetivo: fazer a identidade HTTP do NanoDesk ficar COERENTE com um
 * Chrome real da mesma engine (process.versions.chrome). Isso resolve
 * dois problemas reais:
 *
 *  1. COMPATIBILIDADE — serviços como o login do Google tratam
 *     navegadores "não reconhecidos" como ambiente suspeito
 *     ("Este navegador ou app talvez não seja seguro"). Um
 *     User-Agent do Electron é um gatilho direto; desde a 1.5.1 o
 *     NanoDesk envia o UA do Chrome da própria engine. A sondagem
 *     feita no Electron 45.x real mostrou, porém, que o Electron
 *     NÃO ENVIA os cabeçalhos Sec-CH-UA* (todo Chrome real envia).
 *     Um UA do Chrome SEM client hints é uma inconsistência que
 *     serviços usam como sinal de automação. Esta versão completa a
 *     identidade enviando os client hints com as MESMAS marcas que a
 *     própria engine reporta (navigator.userAgentData), acrescidas da
 *     marca "Google Chrome" na posição do algoritmo do Chromium.
 *  2. PRIVACIDADE — o UA "NanoDesk/… Electron/45.x" é uma população
 *     minúscula (fingerprint raro). Chrome da engine instalada é a
 *     multidade mais comum que existe: menor superfície de rastreio.
 *
 * O que NÃO é feito (honestidade):
 *  - Nada é alterado no JavaScript da página (navigator.userAgentData
 *    continua reportando "Chromium" — a fronteira de contextoIsolation
 *    é preservada). O sinal decisivo para o login do Google são os
 *    cabeçalhos HTTP, e estes ficam completos e coerentes.
 *  - Nenhum IP, rota ou outro dado é falsificado.
 *
 * Módulo puro (sem Electron) — testável em unitários.
 */
'use strict';

/** Token de plataforma coerente com o UA do Chrome para cada SO. */
const UA_PLATFORM = {
  win32: 'Windows NT 10.0; Win64; x64',
  darwin: 'Macintosh; Intel Mac OS X 10_15_7',
  linux: 'X11; Linux x86_64'
};

/** Valor do cabeçalho Sec-CH-UA-Platform por SO (entre aspas). */
const CH_PLATFORM = {
  win32: '"Windows"',
  darwin: '"macOS"',
  linux: '"Linux"'
};

/**
 * User-Agent do Chrome da engine (sem marcas Electron/NanoDesk).
 * @param {string} chromeVersion  ex.: "156.0.8078.80" (process.versions.chrome)
 * @param {string} [platform]     process.platform (padrão: win32 — alvo do NanoDesk)
 */
function chromeUserAgent(chromeVersion, platform) {
  // 1.7.3: o Chrome real envia o UA REDUZIDO (maior.0.0.0) desde a v101. Enviar a versão
  // completa (156.0.8078.80) é um sinal de que não é um Chrome de verdade.
  const major = String(chromeVersion || '').replace(/[^0-9.]/g, '').split('.')[0] || '0';
  const plat = UA_PLATFORM[platform || 'win32'] || UA_PLATFORM.win32;
  return 'Mozilla/5.0 (' + plat + ') AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) Chrome/' + major + '.0.0.0 Safari/537.36';
}

/**
 * Accept-Language coerente com o idioma do sistema (o Electron envia
 * apenas "en-US" por padrão — incomum para um Chrome brasileiro).
 * Devolve a lista SEM q-values: o Electron calcula os pesos ao aplicar
 * (evita duplicação de ";q=..." na re-serialização).
 * @param {string} locale  app.getLocale(), ex.: "pt-BR"
 * @returns {string|null}  null quando o locale é inválido (não mexer)
 */
function acceptLanguages(locale) {
  const l = String(locale || '').trim();
  if (!/^[a-zA-Z]{2,3}(-[a-zA-Z0-9]{2,8})?$/.test(l)) return null;
  const base = l.split('-')[0].toLowerCase();
  const parts = base === l.toLowerCase() ? [l] : [l, base];
  if (base !== 'en') parts.push('en');
  return parts.join(',');
}

/**
 * Monta a lista de marcas para Sec-CH-UA a partir do que a PRÓPRIA
 * engine reporta (brands de navigator.userAgentData, repassado pela
 * interface confiável). Insere "Google Chrome" com a versão maior logo
 * após "Chromium" — a ordem do Chromium real é [grease, Chromium,
 * Google Chrome] quando a posição do grease é a primeira, e as marcas
 * Chromium/Google Chrome ficam sempre adjacentes.
 *
 * @param {Array<{brand:string,version:string}>|null} brands
 * @param {string} chromeVersion  versão completa da engine
 * @returns {Array<{brand:string,version:string}>|null} null = não dá para
 *        montar de forma coerente (mantém comportamento atual, sem CH)
 */
function chromeBrandList(brands, chromeVersion, opts) {
  if (!Array.isArray(brands) || !brands.length) return null;
  const major = String(chromeVersion || '').split('.')[0];
  if (!/^\d{1,4}$/.test(major)) return null;
  const list = [];
  let hasChromium = false;
  for (const b of brands.slice(0, 8)) {
    if (!b || typeof b.brand !== 'string' || typeof b.version !== 'string') continue;
    if (b.brand.length > 64 || b.version.length > 32) continue;
    if (!/^[\w .:()\-\/;=?]+$/.test(b.brand)) continue; // intervalo do grease do Chromium
    if (b.brand === 'Google Chrome') continue;           // inserimos a nossa abaixo
    if (b.brand === 'Chromium') hasChromium = true;
    list.push({ brand: b.brand, version: b.version });
  }
  if (!hasChromium) return null;
  // 1.7.3: por padrão NÃO acrescenta "Google Chrome": o JavaScript da página
  // (navigator.userAgentData.brands) só mostra o que a engine reporta; o cabeçalho com uma marca
  // a mais era uma INCONSISTÊNCIA entre cabeçalho e JS que o login do Google compara.
  if (opts && opts.addGoogleChrome === true) {
    const idx = list.findIndex(b => b.brand === 'Chromium');
    list.splice(idx + 1, 0, { brand: 'Google Chrome', version: major });
  }
  return list;
}

/**
 * Accept-CH: lista de client hints que o servidor pede (nomes em minúsculas, sem duplicatas).
 * @param {string} value  valor do cabeçalho de resposta Accept-CH
 */
function parseAcceptCh(value) {
  const out = new Set();
  for (const raw of String(value || '').split(',')) {
    const n = raw.trim().toLowerCase().replace(/^"|"$/g, '');
    if (/^sec-ch-[a-z0-9-]{1,48}$/.test(n)) out.add(n);
    if (out.size >= 24) break;
  }
  return out;
}

/** Valor de lista de marcas com versões completas (Sec-CH-UA-Full-Version-List). */
function serializeFullVersionList(list) {
  if (!Array.isArray(list) || !list.length) return '';
  return list.filter(b => b && typeof b.brand === 'string' && typeof b.version === 'string')
    .map(b => '"' + b.brand + '";v="' + b.version + '"').join(', ');
}

/**
 * Cabeçalhos de client hints de ALTA entropia pedidos via Accept-CH, com os MESMOS valores que a
 * engine entrega ao JavaScript (getHighEntropyValues, reportados pela interface). Sem isto o
 * servidor pedia e recebia nada — um Chrome real responde.
 * @param {Set<string>} requested  nomes pedidos (parseAcceptCh)
 * @param {object} high { fullVersionList, platformVersion, architecture, bitness, model, wow64, uaFullVersion }
 */
function buildHintHeaders(requested, high) {
  const h = {};
  if (!requested || !requested.size || !high || typeof high !== 'object') return h;
  const q = (v) => '"' + String(v == null ? '' : v).replace(/["\\]/g, '') + '"';
  if (requested.has('sec-ch-ua-full-version-list') && Array.isArray(high.fullVersionList)) {
    const v = serializeFullVersionList(high.fullVersionList);
    if (v) h['Sec-CH-UA-Full-Version-List'] = v;
  }
  if (requested.has('sec-ch-ua-platform-version') && high.platformVersion != null) h['Sec-CH-UA-Platform-Version'] = q(high.platformVersion);
  if (requested.has('sec-ch-ua-arch') && high.architecture != null) h['Sec-CH-UA-Arch'] = q(high.architecture);
  if (requested.has('sec-ch-ua-bitness') && high.bitness != null) h['Sec-CH-UA-Bitness'] = q(high.bitness);
  if (requested.has('sec-ch-ua-model')) h['Sec-CH-UA-Model'] = q(high.model || '');
  if (requested.has('sec-ch-ua-wow64')) h['Sec-CH-UA-WoW64'] = high.wow64 ? '?1' : '?0';
  if (requested.has('sec-ch-ua-full-version') && high.uaFullVersion) h['Sec-CH-UA-Full-Version'] = q(high.uaFullVersion);
  return h;
}

/**
 * Lista de marcas de fallback para Sec-CH-UA quando o renderer ainda não
 * reportou via `identity:report` (problema da 1.9.4: a primeira requisição
 * a um site saía SEM Sec-CH-UA, o que o YouTube detectava e respondia com
 * JSON em vez de HTML — "Só a janela de UI aparece em /json").
 * A marca "Not.A/Brand" segue o padrão GREASE do Chromium e a versão
 * "major" é coerente com a do UA (process.versions.chrome).
 * @param {string} chromeVersion  ex.: "156.0.8078.100"
 * @returns {Array<{brand:string,version:string}>}
 */
function fallbackBrandList(chromeVersion) {
  const major = String(chromeVersion || '').replace(/[^0-9.]/g, '').split('.')[0];
  if (!/^\d{1,4}$/.test(major)) return [];   // sem versão válida = sem Sec-CH-UA (não inventa)
  // GREASE real do Chrome 156 (varia por versão; este é um padrão válido).
  return [
    { brand: 'Not?A_Brand', version: '24' },
    { brand: 'Chromium', version: major },
    { brand: 'Google Chrome', version: major }
  ];
}

/** Serializa a lista no formato do cabeçalho: "Marca";v="1", "Outra";v="2". */
function serializeBrandList(list) {
  if (!Array.isArray(list) || !list.length) return '';
  return list.map(b => '"' + String(b.brand) + '";v="' + String(b.version) + '"').join(', ');
}

/**
 * Cabeçalhos de identidade para um request (camada de rede).
 * @param {object} requestHeaders  details.requestHeaders (mutável)
 * @param {object} identity { userAgent, acceptLanguage, secChUa|null, chPlatform }
 * @returns {object} o mesmo objeto, com a identidade aplicada
 */
function applyIdentityHeaders(requestHeaders, identity) {
  if (!requestHeaders || !identity) return requestHeaders;
  // Client hints do Chrome (a engine não os envia; um Chrome real sempre envia)
  if (identity.secChUa) {
    requestHeaders['Sec-CH-UA'] = identity.secChUa;
    requestHeaders['Sec-CH-UA-Mobile'] = identity.secChUaMobile || '?0';
    requestHeaders['Sec-CH-UA-Platform'] = identity.chPlatform || '"Windows"';
  }
  // Telemetria de variações do Chrome — o NanoDesk não tem nenhuma
  delete requestHeaders['X-Client-Data'];
  // Garantia final do UA coerente (workers/service workers caem aqui também)
  if (identity.userAgent && requestHeaders['User-Agent'] !== identity.userAgent) {
    requestHeaders['User-Agent'] = identity.userAgent;
  }
  return requestHeaders;
}

module.exports = {
  UA_PLATFORM,
  CH_PLATFORM,
  chromeUserAgent,
  acceptLanguages,
  chromeBrandList,
  fallbackBrandList,
  serializeBrandList,
  parseAcceptCh,
  serializeFullVersionList,
  buildHintHeaders,
  applyIdentityHeaders
};

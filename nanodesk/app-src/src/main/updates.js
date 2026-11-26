/**
 * NanoDesk — Verificação de atualizações (1.3.0)
 * ==================================================================
 * Executada no arranque do aplicativo e pelo menu Ferramentas.
 *  - Electron: consulta endoflife.date (API pública) e compara a
 *    versão do runtime com a mais recente da MESMA linha principal;
 *  - NanoDesk: consulta um feed configurável (variável de ambiente
 *    NANODESK_UPDATE_URL, ex.: API de releases do GitHub). Sem feed,
 *    a checagem informa que não há fonte configurada.
 *
 * O NanoDesk NÃO se atualiza sozinho: um navegador precisa de
 * instalador assinado e canal confiável para auto-update (roadmap
 * Fase 6). O que é atualizado automaticamente a cada partida são as
 * LISTAS de filtros do bloqueador (EasyList/EasyPrivacy via Ghostery),
 * que ficam apenas na pasta temporária da sessão.
 */
'use strict';
const netLimits = require('./net-limits');

const ELECTRON_EOL_URL = 'https://endoflife.date/api/electron.json';

/** Compara versões semver simples ("1.2.3"): -1, 0 ou 1. */
function compareVersions(a, b) {
  const pa = String(a || '').split(/[.\-+]/).map(x => parseInt(x, 10) || 0);
  const pb = String(b || '').split(/[.\-+]/).map(x => parseInt(x, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const xa = pa[i] || 0, xb = pb[i] || 0;
    if (xa > xb) return 1;
    if (xa < xb) return -1;
  }
  return 0;
}

function timeoutSignal(ms) {
  try { return AbortSignal.timeout(ms); } catch (_) { return undefined; }
}

/**
 * Verifica se existe versão mais recente do Electron na mesma linha
 * principal (major). Tolerante a falhas de rede.
 */
async function checkElectronUpdate(fetchImpl = fetch) {
  const current = process.versions && process.versions.electron
    ? process.versions.electron
    : String(process.env.NANODESK_ELECTRON_VERSION || '');
  if (!current) return { checked: false, reason: 'versão do Electron indisponível' };
  const major = current.split('.')[0];
  const res = await fetchImpl(ELECTRON_EOL_URL, { signal: timeoutSignal(8000) });
  if (!res.ok) throw new Error('endoflife.date respondeu ' + res.status);
  const data = await netLimits.readJsonLimited(res, 1024 * 1024);
  const row = Array.isArray(data) ? data.find(r => String(r.cycle) === String(major)) : null;
  if (!row || !row.latest) return { checked: false, reason: 'linha ' + major + ' não encontrada' };
  return {
    checked: true,
    component: 'electron',
    current,
    latest: String(row.latest),
    updateAvailable: compareVersions(current, String(row.latest)) < 0,
    url: 'https://releases.electronjs.org/release/v' + row.latest
  };
}

/**
 * Verifica atualização do próprio NanoDesk contra um feed JSON no
 * formato da API "releases/latest" do GitHub (tag_name + html_url).
 */
async function checkAppUpdate(currentVersion, fetchImpl = fetch) {
  const feed = process.env.NANODESK_UPDATE_URL || '';
  if (!feed) {
    return { checked: false, reason: 'sem feed de atualização configurado (NANODESK_UPDATE_URL)' };
  }
  const res = await fetchImpl(feed, { signal: timeoutSignal(8000) });
  if (!res.ok) throw new Error('feed respondeu ' + res.status);
  const data = await netLimits.readJsonLimited(res, 1024 * 1024);
  const latest = String((data && (data.tag_name || data.name)) || '')
    .replace(/^[^\d]*/, '') || '';
  if (!latest) return { checked: false, reason: 'feed sem tag_name' };
  return {
    checked: true,
    component: 'nanodesk',
    current: String(currentVersion || ''),
    latest,
    updateAvailable: compareVersions(currentVersion, latest) < 0,
    url: (data && data.html_url) || ''
  };
}

module.exports = {
  compareVersions,
  checkElectronUpdate,
  checkAppUpdate,
  updates: { checkElectronUpdate, checkAppUpdate }
};

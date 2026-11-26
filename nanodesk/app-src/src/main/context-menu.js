/**
 * NanoDesk — Menu de contexto das páginas (clique direito)
 * ------------------------------------------------------------------
 * Módulo puro: recebe os "params" do evento 'context-menu' do Electron e
 * um objeto `act` com as ações, e devolve o template do menu. Assim dá
 * para testar sem Electron. Só links http/https são abertos/baixados.
 *
 * 1.6.0: itens de TRADUÇÃO (LibreTranslate, com consentimento no main)
 * e de VÍDEO PRIVADO (FreeTube/Invidious/Piped/yt-dlp — FASE 8).
 */
'use strict';

const isHttp = (u) => typeof u === 'string' && /^https?:\/\//i.test(u);
// Alvos de leitor interno (1.5.0): PDF e ebooks abrem com o pdf.js /
// foliate-js do NanoDesk em vez de serem baixados ou renderizados a seco.
const READER_LINK_RX = /\.(pdf|epub|mobi|azw3?|fb2|cbz)($|[?#])/i;
const readerKindFor = (u) => {
  const m = READER_LINK_RX.exec(String(u || ''));
  if (!m) return null;
  return m[1].toLowerCase() === 'pdf' ? 'pdf' : 'ebook';
};
// '&' em rótulos de menu do Windows vira atalho (mnemônico): escapa
const esc = (s) => String(s).replace(/&/g, '&&');
const clip = (s, n) => (s.length > n ? s.slice(0, n - 1).trimEnd() + '…' : s);

const SEP = { type: 'separator' };

function buildTemplate(params, act) {
  const p = params || {};
  const flags = p.editFlags || {};
  const t = [];
  const selection = String(p.selectionText || '').trim();
  const hasLink = isHttp(p.linkURL);
  const hasImage = p.mediaType === 'image' && !!p.srcURL;

  // 1) correção ortográfica
  if (p.isEditable && p.misspelledWord) {
    const sug = (p.dictionarySuggestions || []).slice(0, 5);
    if (sug.length) sug.forEach(w => t.push({ label: esc(w), click: () => act.replaceMisspelling(w) }));
    else t.push({ label: 'Sem sugestões', enabled: false });
    t.push(SEP);
  }

  // 2) campos de texto
  if (p.isEditable) {
    t.push({ label: 'Desfazer', enabled: !!flags.canUndo, click: () => act.edit('undo') });
    t.push({ label: 'Refazer', enabled: !!flags.canRedo, click: () => act.edit('redo') });
    t.push(SEP);
    t.push({ label: 'Recortar', enabled: !!flags.canCut, click: () => act.edit('cut') });
    t.push({ label: 'Copiar', enabled: !!flags.canCopy, click: () => act.edit('copy') });
    t.push({ label: 'Colar', enabled: !!flags.canPaste, click: () => act.edit('paste') });
    t.push({ label: 'Selecionar tudo', enabled: !!flags.canSelectAll, click: () => act.edit('selectAll') });
    // 1.7.0 — gramática do campo inteiro (LanguageTool)
    if (typeof act.grammarCheck === 'function') {
      t.push(SEP);
      t.push({ label: 'Verificar gramática deste campo (LanguageTool)', click: () => act.grammarCheck('', true) });
    }
    t.push(SEP);
  } else if (selection) {
    t.push({ label: 'Copiar', click: () => act.edit('copy') });
  }

  // 3) pesquisar a seleção
  if (selection) {
    t.push({ label: 'Pesquisar “' + esc(clip(selection.replace(/\s+/g, ' '), 30)) + '” na web', click: () => act.search(selection) });
    if (typeof act.archivePage === 'function' && !p.isEditable) {
      t.push({ label: 'Salvar só a seleção (arquivo único)…', click: () => act.archivePage(true) });
    }
    if (typeof act.translate === 'function') {
      t.push({ label: 'Traduzir seleção (LibreTranslate)…', click: () => act.translate(selection) });
    }
    // 1.7.0 — LanguageTool + LibraryTranslate (com consentimento no main)
    if (typeof act.grammarCheck === 'function') {
      t.push({ label: 'Verificar gramática (LanguageTool)', click: () => act.grammarCheck(selection, false) });
    }
    if (typeof act.libraryTranslate === 'function') {
      t.push({ label: 'Traduzir e salvar na Biblioteca (LibraryTranslate)', click: () => act.libraryTranslate(selection) });
    }
    t.push(SEP);
  }

  // 3.5) vídeo (1.8.8) — apenas yt-dlp (FreeTube/Invidious/Piped removidos)
  const videoUrl = hasLink && isHttp(p.linkURL) ? p.linkURL : null;
  if (videoUrl && typeof act.videoDownload === 'function') {
    t.push({ label: 'Baixar com yt-dlp…', click: () => act.videoDownload(videoUrl) });
    t.push(SEP);
  }

  // 3.6) 1.9.5 — detecção de mídia: sempre disponível (em qualquer página http).
  // Mostra o painel e dispara a detecção. Itens individuais (download da mídia
  // clicada) viriam se params.mediaType fosse audio/video — mas o Electron já
  // trata isso no item 5 (imagens) e o yt-dlp cuida de vídeos do YouTube.
  if (typeof act.detectMedia === 'function' && p.pageURL && isHttp(p.pageURL)) {
    t.push({ label: 'Detectar mídia nesta página', click: () => act.detectMedia() });
  }
  // Item extra quando o clique foi sobre um <audio>/<video> (params.mediaType)
  if ((p.mediaType === 'audio' || p.mediaType === 'video') && isHttp(p.srcURL) && typeof act.download === 'function') {
    t.push({ label: 'Baixar esta mídia', click: () => act.download(p.srcURL) });
    if (typeof act.copyText === 'function') {
      t.push({ label: 'Copiar endereço da mídia', click: () => act.copyText(p.srcURL) });
    }
    t.push(SEP);
  }

  // 4) links
  if (hasLink) {
    const rk = readerKindFor(p.linkURL);
    if (rk === 'pdf') {
      t.push({ label: 'Abrir PDF no leitor do NanoDesk', click: () => act.openReader(p.linkURL) });
    } else if (rk === 'ebook') {
      t.push({ label: 'Ler este ebook no NanoDesk', click: () => act.openReader(p.linkURL) });
    }
    t.push({ label: 'Abrir link em nova aba', click: () => act.openTab(p.linkURL) });
    t.push({ label: 'Abrir link no navegador padrão', click: () => act.openExternal(p.linkURL) });
    t.push({ label: 'Copiar endereço do link', click: () => act.copyText(p.linkURL) });
    t.push(SEP);
  }

  // 5) imagens
  if (hasImage) {
    if (isHttp(p.srcURL)) {
      t.push({ label: 'Abrir imagem em nova aba', click: () => act.openTab(p.srcURL) });
      t.push({ label: 'Salvar imagem', click: () => act.download(p.srcURL) });
    }
    t.push({ label: 'Copiar imagem', click: () => act.copyImageAt(p.x, p.y) });
    if (isHttp(p.srcURL)) t.push({ label: 'Copiar endereço da imagem', click: () => act.copyText(p.srcURL) });
    t.push(SEP);
  }

  // 6) navegação (só quando o clique foi no "fundo" da página)
  if (!hasLink && !hasImage && !selection && !p.isEditable) {
    t.push({ label: 'Voltar', enabled: !!act.canGoBack(), click: () => act.back() });
    t.push({ label: 'Avançar', enabled: !!act.canGoForward(), click: () => act.forward() });
    t.push({ label: 'Recarregar', click: () => act.reload() });
    if (typeof act.saveLinkwarden === 'function' && p.pageURL && isHttp(p.pageURL)) {
      t.push({ label: 'Salvar página no Linkwarden', click: () => act.saveLinkwarden(p.pageURL) });
    }
    // 1.9.0 — arquivo único local (sem serviço externo)
    if (typeof act.archivePage === 'function' && p.pageURL && isHttp(p.pageURL)) {
      t.push({ label: 'Salvar página completa (arquivo único)…', click: () => act.archivePage(false) });
    }
    t.push(SEP);
  }

  // 7) sempre
  t.push({ label: 'Imprimir…', click: () => act.print() });
  t.push({ label: 'Inspecionar elemento', click: () => act.inspect(p.x, p.y) });

  return tidy(t);
}

/** Remove separadores duplicados, no início e no fim. */
function tidy(items) {
  const out = [];
  for (const it of items) {
    if (it.type === 'separator' && (!out.length || out[out.length - 1].type === 'separator')) continue;
    out.push(it);
  }
  while (out.length && out[out.length - 1].type === 'separator') out.pop();
  return out;
}

module.exports = { buildTemplate, tidy, isHttp, readerKindFor };

/**
 * NanoDesk — LanguageTool (1.7.0)
 * ==================================================================
 * Integra o LanguageTool (github.com/languagetool-org/languagetool,
 * LGPL-2.1) pela API HTTP oficial (/v2/check). Padrão: API pública
 * (api.languagetool.org). O usuário pode apontar um servidor PRÓPRIO
 * ou LOCAL (http://127.0.0.1:8081 — processamento no próprio PC) em
 * Configurações.
 *
 * Privacidade (regra do projeto): o texto só vai ao servidor quando
 * o usuário pede a verificação, e o destino é mostrado num diálogo
 * de consentimento (igual ao da tradução). Nada é enviado por conta
 * própria.
 *
 * Núcleo puro (testável): normalização do endpoint, montagem do corpo
 * form-urlencoded (formato que a API aceita), interpretação da
 * resposta, idiomas e o script do painel injetável on-demand.
 */
'use strict';

const MAX_TEXT = 20000;

const LANGS = [
  ['auto', 'Detectar automaticamente'],
  ['pt-BR', 'Português (Brasil)'],
  ['pt-PT', 'Português (Portugal)'],
  ['en-US', 'Inglês (EUA)'],
  ['en-GB', 'Inglês (Reino Unido)'],
  ['es', 'Espanhol'],
  ['fr', 'Francês'],
  ['de', 'Alemão'],
  ['it', 'Italiano']
];

/** Normaliza o endpoint da API (puro). */
function normalizeApi(v) {
  const s = String(v || '').trim().replace(/\/+$/, '');
  if (!s) return 'https://api.languagetool.org';
  if (!/^https?:\/\/[a-z0-9.\-]+(:\d+)?$/i.test(s)) return 'https://api.languagetool.org';
  return s;
}

/** Normaliza o idioma (puro). */
function normalizeLang(v) {
  const s = String(v || 'auto').trim();
  if (s === 'auto') return 'auto';
  return /^[a-z]{2}(-[A-Z]{2})?$/.test(s) ? s : 'auto';
}

/** Corpo form-urlencoded do /v2/check (puro) — a API exige form. */
function checkBody(text, lang) {
  const p = new URLSearchParams();
  p.set('text', String(text || '').slice(0, MAX_TEXT));
  p.set('language', normalizeLang(lang));
  p.set('enabledOnly', 'false');
  return p.toString();
}

/** Idioma detectado numa resposta (puro). */
function detectedLanguage(json) {
  try {
    const d = json && json.language && json.language.detectedLanguage;
    return d && d.code ? String(d.code) : '';
  } catch (_) { return ''; }
}

/**
 * Interpreta a resposta da API (puro).
 * @returns {Array<{offset:number,length:number,message:string,short:string,replacements:string[],rule:string}>}
 */
function parseMatches(json) {
  const list = json && Array.isArray(json.matches) ? json.matches : [];
  const out = [];
  for (const m of list) {
    try {
      out.push({
        offset: Number(m.offset) || 0,
        length: Number(m.length) || 0,
        message: String(m.message || ''),
        short: String(m.shortMessage || ''),
        replacements: (Array.isArray(m.replacements) ? m.replacements : [])
          .map(r => String(r && r.value || '')).filter(Boolean).slice(0, 3),
        rule: String((m.rule && (m.rule.description || m.rule.id)) || ''),
        context: (m.context && typeof m.context === 'object') ? {
          text: String(m.context.text || '').slice(0, 120),
          offset: Number(m.context.offset) || 0,
          length: Number(m.context.length) || 0
        } : { text: '', offset: 0, length: 0 }
      });
    } catch (_) { /* item inválido */ }
  }
  return out;
}

/**
 * Painel de correção injetado ON-DEMAND (mundo principal, via
 * executeJavaScript no menu de contexto). A consulta HTTP é feita NO
 * PROCESSO PRINCIPAL (navSession.fetch — não depende do CSP da página)
 * e este script só RENDERIZA os resultados: aplicar sugestão em campos
 * de texto ou copiar no texto comum.
 */
function buildPanelScript(payload) {
  const api = normalizeApi(payload && payload.api);
  const detected = String(payload && payload.detected || '');
  const matches = Array.isArray(payload && payload.matches) ? payload.matches : [];
  const error = String(payload && payload.error || '');
  const script = String.raw`
(function () {
  var API = ${JSON.stringify(api)};
  var DETECTED = ${JSON.stringify(detected)};
  var MATCHES = ${JSON.stringify(matches).replace(/<\//g, '<\\/')};
  var ERROR = ${JSON.stringify(error)};

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  var panel = null, shadow = null;
  function ensure() {
    if (panel) { panel.style.display = ''; return; }
    panel = document.createElement('div');
    panel.id = 'nd-lt-panel';
    panel.style.cssText = 'position:fixed;top:16px;right:16px;z-index:2147483647;';
    try { shadow = panel.attachShadow({ mode: 'open' }); } catch (_) { shadow = panel; }
    shadow.innerHTML =
      '<style>' +
      ':host{all:initial}' +
      '*{box-sizing:border-box;margin:0;padding:0;font-family:system-ui,-apple-system,"Segoe UI",sans-serif}' +
      '.card{width:360px;max-height:70vh;background:#12141f;color:#e8f0ff;border:1px solid #2a2e45;border-radius:14px;' +
      'box-shadow:0 18px 60px rgba(0,0,0,.55);display:flex;flex-direction:column;overflow:hidden}' +
      '.hd{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:#171a2b;border-bottom:1px solid #262a42}' +
      '.hd b{font-size:13px}.hd small{color:#8b93b8;font-size:11px;margin-left:8px}' +
      '.x{background:none;border:0;color:#8b93b8;font-size:15px;cursor:pointer;padding:2px 6px;border-radius:6px}' +
      '.x:hover{background:#262a42;color:#fff}' +
      '.bd{padding:10px 14px;overflow:auto;font-size:13px;line-height:1.45}' +
      '.empty{color:#8b93b8;padding:8px 0}.ok{color:#59d98c}' +
      '.iss{padding:9px 10px;border:1px solid #262a42;border-radius:10px;margin:8px 0;background:#151829}' +
      '.ctx{color:#8b93b8;font-size:11.5px;margin-bottom:6px;word-break:break-word}' +
      '.ctx mark{background:#3a2f12;color:#ffd479;border-radius:3px;padding:0 2px}' +
      '.chip{display:inline-block;background:#232946;color:#cdd6ff;border:1px solid #3a4266;border-radius:999px;' +
      'padding:3px 10px;margin:2px 4px 2px 0;font-size:12px;cursor:pointer}' +
      '.chip:hover{background:#7c5cff;border-color:#7c5cff;color:#fff}' +
      '.rule{color:#5b6288;font-size:10.5px;margin-top:4px}' +
      '.foot{padding:8px 14px;border-top:1px solid #262a42;color:#5b6288;font-size:10.5px}' +
      '</style>' +
      '<div class="card"><div class="hd"><b>LanguageTool</b><small id="nd-lt-lang"></small>' +
      '<button class="x" id="nd-lt-x">✕</button></div>' +
      '<div class="bd" id="nd-lt-bd"><div class="empty">Verificando…</div></div>' +
      '<div class="foot">Texto enviado a ' + esc(API) + ' sob o seu pedido.</div></div>';
    (document.body || document.documentElement).appendChild(panel);
    var x = shadow.getElementById('nd-lt-x');
    if (x) x.addEventListener('click', function () { panel.style.display = 'none'; });
  }
  function body(html) { try { shadow.getElementById('nd-lt-bd').innerHTML = html; } catch (_) {} }
  function langLabel(t) { try { shadow.getElementById('nd-lt-lang').textContent = t || ''; } catch (_) {} }

  function findField() {
    var el = document.activeElement;
    try {
      if (el && (el.tagName === 'TEXTAREA' ||
        (el.tagName === 'INPUT' && /^(text|search|url|email)$/i.test(el.type || 'text')))) {
        return el;
      }
    } catch (_) {}
    return null;
  }

  function applyFix(field, off, len, rep) {
    try {
      var v = String(field.value || '');
      if (off + len > v.length) return;
      field.value = v.slice(0, off) + rep + v.slice(off + len);
      field.dispatchEvent(new Event('input', { bubbles: true }));
      field.dispatchEvent(new Event('change', { bubbles: true }));
      field.focus();
      field.setSelectionRange(off + rep.length, off + rep.length);
    } catch (_) {}
  }

  ensure();
  langLabel(DETECTED);
  if (ERROR) { body('<div class="empty">' + esc(ERROR) + '</div>'); return 'nd-lt-err'; }
  try {
    var matches = MATCHES || [];
    if (!matches.length) { body('<div class="empty ok">✔ Nenhum problema encontrado.</div>'); return 'nd-lt-ok'; }
    var html = '';
    for (var i = 0; i < matches.length && i < 60; i++) {
      var m = matches[i];
      var c = m.context || { text: '', offset: 0, length: 0 };
      var before = esc(String(c.text).slice(Math.max(0, c.offset - 28), c.offset));
      var mid = esc(String(c.text).substr(c.offset, c.length));
      var after = esc(String(c.text).substr(c.offset + c.length, 28));
      var chips = '';
      var reps = (m.replacements || []).slice(0, 3);
      for (var k = 0; k < reps.length; k++) {
        chips += '<span class="chip" data-off="' + Number(m.offset) + '" data-len="' + Number(m.length) +
          '" data-rep="' + esc(reps[k]) + '">' + esc(reps[k]) + '</span> ';
      }
      html += '<div class="iss"><div>' + esc(m.shortMessage || m.message) + '</div>' +
        '<div class="ctx">' + before + '<mark>' + (mid || '…') + '</mark>' + after + '</div>' +
        (chips ? '<div>' + chips + '</div>' : '') +
        '<div class="rule">' + esc(m.rule || '') + '</div></div>';
    }
    if (matches.length > 60) html += '<div class="empty">… e mais ' + (matches.length - 60) + ' ocorrência(s).</div>';
    body(html);
    var chips2 = shadow.querySelectorAll('.chip');
    for (var cI = 0; cI < chips2.length; cI++) {
      chips2[cI].addEventListener('click', function (ev) {
        var el = ev.currentTarget;
        var f = findField();
        if (f) {
          applyFix(f, Number(el.getAttribute('data-off')), Number(el.getAttribute('data-len')), el.getAttribute('data-rep'));
        } else {
          try {
            navigator.clipboard.writeText(el.getAttribute('data-rep')).then(function () {
              var n = document.createElement('div');
              n.className = 'empty ok';
              n.textContent = '✔ Sugestão copiada — cole sobre o erro.';
              try { shadow.getElementById('nd-lt-bd').prepend(n); } catch (_) {}
              setTimeout(function () { try { n.remove(); } catch (_) {} }, 1800);
            });
          } catch (_) {}
        }
      });
    }
  } catch (_) { body('<div class="empty">Resposta inesperada do servidor.</div>'); }
  return 'nd-lt-ok';
})();
`;
  return script;
}

module.exports = {
  MAX_TEXT, LANGS,
  normalizeApi, normalizeLang, checkBody, detectedLanguage, parseMatches,
  buildPanelScript
};

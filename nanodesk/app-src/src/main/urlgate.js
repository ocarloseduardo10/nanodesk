/**
 * NanoDesk — Analisador de URLs (1.6.0, FASE 6 — Security Gateway)
 * ==================================================================
 * Conceitos do projeto aberto TrianguloY/URLCheck (CC-BY-4.0; correção
 * de licença na auditoria de 2026-11-26) e do
 * OWASP WSTG (4.1 "Test for Bypassing Authentication Schema"/análise
 * de entrada), reimplementados em código original (MIT NanoDesk):
 * heurística LOCAL de reputação de URL, sem consultar serviço
 * externo nenhum (a URL do usuário nunca sai do computador).
 *
 * Sinais analisados (puros, testáveis):
 *  - TLDs de baixa reputação/abuso (.zip, .mov, .tk, .top, .gq…);
 *  - punycode/IDN (xn--) — homoglifos;
 *  - host literal em IP;
 *  - credenciais na URL;
 *  - palavras de phishing no host (login/secure/verify/conta/banco…);
 *  - encurtadores conhecidos (bit.ly, t.co…);
 *  - parâmetros que escondem outro URL (url=, u=, next=…);
 *  - subdomínios em excesso, URL/host longos demais;
 *  - dupla extensão perigosa no caminho (.pdf.exe);
 *  - porta incomum; texto puro (sem HTTPS).
 *
 * Resultado: score 0–100 + nível (ok | atencao | critico) + motivos.
 * A decisão de navegar é SEMPRE do usuário: o NanoDesk mostra um
 * diálogo nativo antes de seguir, com opção "confiar neste site na
 * sessão" (allowlist só em memória).
 */
'use strict';

/**
 * TLDs de abuso, com pesos diferentes (CORREÇÃO 1.6.7):
 *  - alto (25): concentração histórica documentada de abuso;
 *  - moderado (12): TLDs baratos também usados por serviços legítimos —
 *    sozinhos não devem abrir diálogo (com HTTP somavam 30 = diálogo).
 */
const RISKY_TLDS_HIGH = new Set(['zip', 'mov', 'tk', 'ml', 'gq', 'cf', 'top']);
const RISKY_TLDS = new Set([...RISKY_TLDS_HIGH,
  'cyou', 'cfd', 'sbs', 'buzz', 'rest', 'surf', 'cam', 'quest', 'click', 'link', 'icu'
]);

/** Encurtadores de URL conhecidos (público, documentado). */
const SHORTENERS = new Set([
  'bit.ly', 't.co', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly',
  'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'bl.ink',
  's.id', 'shorte.st', 'adf.ly', 'curli.cat', 't.ly', 'gg.gg', 'urlz.fr',
  'cut.li', 'shrtco.de', 'loxa.kr', 'url.ie', 'v.gd', 'shorturl.dev'
]);

/** Palavras de phishing no host (peso quando combinadas). */
const PHISH_WORDS = [
  'login', 'signin', 'sign-in', 'verify', 'secure', 'account', 'update',
  'confirm', 'wallet', 'invoice', 'payment', 'banco', 'bancobrasil',
  'itau', 'bradesco', 'santander', 'caixa', 'pagar', 'conta', 'senha',
  'recover', 'unlock', 'suspended', 'limit'
];

/** Marcas que NUNCA deveriam aparecer em subdomínio de terceiros.
 * Tokens com ponto ("gov.br") são tratados como sufixo de domínio;
 * tokens simples casam por RÓTULO (ver labelHasBrand) — substring no host
 * inteiro marcava "notgoogle.com" ou "google-agency-parceiro.com" como
 * golpe, e era exatamente o que a 1.6.2 tentava resolver para domínios
 * oficiais (agora resolvido para TODOS os casos). */
const BRAND_TOKENS = [
  'google', 'facebook', 'instagram', 'whatsapp', 'amazon', 'netflix',
  'nubank', 'paypal', 'apple', 'microsoft', 'outlook', 'hotmail',
  'gov.br', 'receita', 'bb.com', 'itau', 'bradesco', 'santander'
];

const REDIRECT_PARAM_NAMES = new Set([
  'url', 'u', 'next', 'continue', 'redirect', 'redirect_uri',
  'redirect_to', 'return', 'returnurl', 'return_to', 'dest',
  'destination', 'goto', 'target', 'r', 'redir', 'link', 'out',
  'deeplink', 'callback'
]);

/**
 * Domínios OFICIAIS das marcas monitoradas (host igual ou subdomínio).
 * 1.6.1: a verificação anterior exigia que o host TERMINASSE no nome da marca
 * ("google"), então até accounts.google.com / mail.google.com / drive.google.com
 * eram marcados como "marca em domínio que não é dela".
 * CORREÇÃO 1.6.7: propriedades oficiais que faltavam (googleapis/
 * googleusercontent/googlevideo/ytimg, youtube-nocookie, xbox/skype/
 * sharepoint/github, aws/amazonaws/primevideo, regionais da Apple e Amazon)
 * recebiam "Marca em domínio que não é dela" (+30 = diálogo) em navegação
 * 100% legítima.
 */
const OFFICIAL_DOMAINS = [
  'google.com', 'google.com.br', 'gmail.com', 'youtube.com', 'gstatic.com',
  'googleapis.com', 'googleusercontent.com', 'googlevideo.com', 'ytimg.com',
  'googletagmanager.com', 'googletagservices.com', 'googleadservices.com',
  'googlesyndication.com', 'youtube-nocookie.com', 'gvt1.com', 'gvt2.com',
  'android.com', 'chromium.org', 'goog.io', 'withgoogle.com', 'googlegroups.com',
  'goog.le', 'g.co',
  'facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com', 'whatsapp.net', 'meta.com',
  'amazon.com', 'amazon.com.br', 'amazon.co.uk', 'amazon.de', 'amazon.es',
  'amazon.fr', 'amazon.it', 'amazon.ca', 'amazon.co.jp', 'amazon.com.mx',
  'amazonaws.com', 'primevideo.com', 'audible.com', 'awsstatic.com',
  'netflix.com', 'nubank.com.br', 'paypal.com', 'paypal.me',
  'apple.com', 'apple.com.br', 'icloud.com', 'me.com', 'mzstatic.com', 'cdn-apple.com',
  'microsoft.com', 'live.com', 'office.com', 'outlook.com', 'hotmail.com',
  'microsoftonline.com', 'office365.com', 'msn.com', 'bing.com',
  'sharepoint.com', 'xbox.com', 'skype.com', 'azure.com', 'github.com',
  'githubusercontent.com', 'github.io', 'visualstudio.com', 'microsoftedgeinsider.com',
  'gov.br', 'itau.com.br', 'bb.com.br', 'bradesco.com.br', 'santander.com.br',
  'caixa.gov.br'
];

function isOfficialHost(host) {
  return OFFICIAL_DOMAINS.some(d => host === d || host.endsWith('.' + d));
}

/**
 * CORREÇÃO 1.6.7: um token de marca casa quando ele é um RÓTULO do host,
 * ou um segmento delimitado por hífens dentro de um rótulo —
 *  - "paypal.seguranca-x.tk"  → rótulo "paypal" ✓ (phishing de verdade)
 *  - "google-login.evil.tk"   → segmento "google" ✓ (phishing de verdade)
 *  - "notgoogle.com"          → ✗ (nenhum rótulo/segmento é "google")
 *  - "bloggoogle.example.com" → ✗ (antes marcava por substring)
 * Tokens com ponto ("gov.br", "bb.com") continuam por sufixo de domínio.
 */
function labelHasBrand(host, token) {
  const t = String(token || '').toLowerCase();
  if (!t) return false;
  if (t.includes('.')) return host === t || host.endsWith('.' + t);
  return host.split('.').some(label =>
    label === t || label.split('-').includes(t));
}

/** Domínio registrável (eTLD+1) do host; sem tldts cai nos 2 últimos rótulos. */
let _tldtsParse;
function registrable(host) {
  if (_tldtsParse === undefined) {
    try { _tldtsParse = require('tldts-experimental').parse; } catch (_) { _tldtsParse = null; }
  }
  try {
    if (_tldtsParse) {
      const r = _tldtsParse(host);
      if (r && r.domain) return r.domain;
    }
  } catch (_) { /* usa o fallback */ }
  const parts = String(host || '').split('.');
  return parts.slice(-2).join('.');
}

/** Serviço onion: criptografado de ponta a ponta pela própria rede Tor. */
function isOnionHost(host) {
  return /\.onion$/.test(String(host || ''));
}

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch (e) { return ''; }
}

function tldOf(host) {
  const parts = String(host || '').split('.');
  return parts.length >= 2 ? parts[parts.length - 1] : '';
}

/**
 * Analisa uma URL.
 * @param {string} url
 * @param {object} [opts] { trustedHosts?: string[] }
 * @returns {{ score:number, level:'ok'|'atencao'|'critico', reasons:string[], host:string }}
 */
function analyze(url, opts = {}) {
  const out = { score: 0, level: 'ok', reasons: [], host: '' };
  let u;
  try { u = new URL(String(url || '')); } catch (_) {
    out.reasons.push('URL inválida');
    out.level = 'atencao';
    out.score = 40;
    return out;
  }
  const host = u.hostname.toLowerCase();
  out.host = host;
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    out.reasons.push('Esquema não é HTTP/HTTPS');
    out.score += 60;
  } else {
    const trusted = (opts.trustedHosts || []).some(d => {
      const s = String(d || '').toLowerCase();
      return s && (host === s || host.endsWith('.' + s));
    });
    if (trusted) return out; // usuário confiou nesta sessão: nada a apontar

    // 1.6.2: máquina local / rede privada (localhost, 127.x, 10.x, 192.168.x, 172.16-31.x,
    // ::1, *.local) não é alvo de phishing: servidores de desenvolvimento/roteador/NAS em
    // IP:porta eram marcados como "IP literal + porta incomum" a cada link ou redirect.
    const privateHost = host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') ||
      /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}(\.\d{1,3})?$/.test(host) ||
      host === '[::1]';
    if (privateHost && !u.username && !u.password) return out;

    // 1.6.1: domínio oficial da marca (ex.: accounts.google.com) — nenhum sinal
    // baseado em palavras/marca se aplica; só os sinais estruturais abaixo.
    const official = isOfficialHost(host);
    const onion = isOnionHost(host);

    // 1) TLD arriscado — peso conforme a lista (alto 25 / moderado 12)
    const tld = tldOf(host);
    if (RISKY_TLDS_HIGH.has(tld)) {
      out.score += 25;
      out.reasons.push('Domínio de topo "."' + tld + ' muito usado em abuso');
    } else if (RISKY_TLDS.has(tld)) {
      out.score += 12;
      out.reasons.push('Domínio de topo "."' + tld + ' de reputação mista');
    }

    // 2) punycode / homoglifos
    if (host.split('.').some(l => l.startsWith('xn--'))) {
      out.score += 30;
      out.reasons.push('Nome internacional (punycode) — pode imitar outro domínio');
    }

    // 3) IP literal
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[')) {
      out.score += 25;
      out.reasons.push('Endereço é um IP literal, não um domínio');
    }

    // 4) credenciais na URL
    if (u.username || u.password) {
      out.score += 25;
      out.reasons.push('URL contém usuário/senha embutidos');
    }

    // 5) palavras de phishing combinadas — por SEGMENTO de rótulo (hífens
    // contam como separadores): "secure-login" casa; "contabilidade" e
    // "limits.py" não casam mais (falsos positivos da substring).
    const hostWords = (official || onion) ? [] : PHISH_WORDS.filter(w =>
      host.split('.').some(label => label.split('-').includes(w)));
    if (hostWords.length >= 2) {
      out.score += 20;
      out.reasons.push('Palavras suspeitas no domínio (' + hostWords.slice(0, 3).join(', ') + ')');
    } else if (hostWords.length === 1 && !host.startsWith('www.')) {
      out.score += 8;
      out.reasons.push('Palavra sensível no domínio ("' + hostWords[0] + '")');
    }

    // 6) marca conhecida em subdomínio de terceiro (ex.: paypal.seguranca-x.tk)
    // CORREÇÃO 1.6.7: comparação por rótulo/segmento (labelHasBrand) em vez de
    // substring — propriedades oficiais novas e nomes que apenas CONTÊM a
    // marca não geram mais diálogo.
    if (!official && !onion) {
      const brand = BRAND_TOKENS.find(b => labelHasBrand(host, b));
      if (brand && !isOfficialHost(host)) {
        out.score += 30;
        out.reasons.push('Marca ("' + brand + '") em domínio que não é dela');
      }
    }

    // 7) encurtador
    if (SHORTENERS.has(host.replace(/^www\./, ''))) {
      out.score += 20;
      out.reasons.push('Encurtador de URLs — destino real escondido');
    }

    // 8) parâmetro que carrega outra URL
    // 1.6.1: redirecionar para o MESMO site (mesmo domínio registrável) é rotina
    // de login (ex.: accounts.google.com?continue=https://drive.google.com/).
    const ownReg = registrable(host);
    const redirectParam = [...u.searchParams.keys()].find(k => {
      if (!REDIRECT_PARAM_NAMES.has(k.toLowerCase())) return false;
      const val = u.searchParams.get(k) || '';
      if (!/^https?:\/\//i.test(val) && !/https?%3a/i.test(val)) return false;
      let target = '';
      try { target = new URL(decodeURIComponent(val)).hostname.toLowerCase(); } catch (_) { return true; }
      if (!target) return true;
      if (registrable(target) === ownReg) return false;
      return !(official && isOfficialHost(target));
    });
    if (redirectParam) {
      out.score += 12;
      out.reasons.push('Parâmetro "' + redirectParam + '" redireciona para outro site');
    }

    // 9) subdomínios em excesso
    const labels = host.split('.').length;
    if (labels >= 5) {
      out.score += 10;
      out.reasons.push('Muitos subdomínios (' + labels + ' níveis)');
    }

    // 10) tamanhos anormais
    if (u.href.length > 500) { out.score += 5; out.reasons.push('URL muito longa'); }
    if (host.length > 60) { out.score += 10; out.reasons.push('Domínio anormalmente longo'); }

    // 11) dupla extensão perigosa — praticamente sempre malware
    const path = u.pathname.toLowerCase();
    if (/\.(pdf|jpg|jpeg|png|doc|docx|xls|xlsx|txt)\.(exe|msi|scr|bat|cmd|js|vbs|lnk)$/.test(path)) {
      out.score += 60;
      out.reasons.push('Arquivo com dupla extensão enganosa');
    }

    // 12) porta incomum
    if (u.port && !['80', '443', '8080', '8443'].includes(u.port)) {
      out.score += 5;
      out.reasons.push('Porta incomum (' + u.port + ')');
    }

    // 13) sem TLS
    if (u.protocol === 'http:' && !onion) {   // 1.6.1: .onion via HTTP é protegido pelo Tor
      const local = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host);
      if (!local) { out.score += 5; out.reasons.push('Conexão sem criptografia (HTTP)'); }
    }
  }

  out.score = Math.min(100, out.score);
  out.level = out.score >= 60 ? 'critico' : out.score >= 30 ? 'atencao' : 'ok';
  return out;
}

/** Frase curta para o diálogo nativo. */
function headline(level) {
  if (level === 'critico') return 'Site potencialmente perigoso';
  if (level === 'atencao') return 'Site suspeito — verifique antes de continuar';
  return 'Site verificado';
}

module.exports = {
  RISKY_TLDS, RISKY_TLDS_HIGH, SHORTENERS, PHISH_WORDS, BRAND_TOKENS, OFFICIAL_DOMAINS,
  isOfficialHost, isOnionHost, labelHasBrand,
  analyze, headline, tldOf
};

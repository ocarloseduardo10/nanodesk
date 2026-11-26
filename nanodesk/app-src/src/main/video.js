/**
 * NanoDesk — Área de vídeo (1.8.8)
 * ==================================================================
 * Núcleo enxuto: apenas classificação de URLs do YouTube e montagem
 * de argumentos para o yt-dlp (binário embutido em resources/bin).
 *
 * 1.8.8: o sistema de vídeo NATIVO Piped/Invidious/FreeTube foi
 * REMOVIDO completamente — o NanoDesk agora abre o YouTube comum
 * (protegido pelo bloqueador, SponsorBlock e ytguard) e mantém
 * apenas o yt-dlp para download sob demanda do usuário.
 *
 *  - yt-dlp (Unlicense): binário embutido em resources/bin (ou no
 *    PATH) — usado sob demanda do usuário ("Baixar vídeo"), SEMPRE
 *    com nota de que o download é responsabilidade do usuário
 *    (conteúdos autorizados apenas).
 *
 * Núcleo puro: classificação de URLs e montagem de argumentos
 * — testável sem rede/Electron. Os spawns ficam no main.js.
 */
'use strict';

/** Hosts do YouTube (com subdomínios). */
const YT_HOSTS = new Set(['youtube.com', 'youtu.be', 'm.youtube.com', 'www.youtube.com', 'music.youtube.com', 'youtube-nocookie.com']);

/** A URL é de vídeo do YouTube? (puro) */
function isYoutubeUrl(url) {
  try {
    const u = new URL(String(url || ''));
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    const host = u.hostname.toLowerCase();
    const ok = [...YT_HOSTS].some(h => host === h || host.endsWith('.' + h));
    if (!ok) return false;
    if (u.hostname.toLowerCase() === 'youtu.be') return true;
    return u.pathname === '/watch' || u.pathname.startsWith('/shorts/') ||
           u.pathname.startsWith('/embed/') || u.pathname.startsWith('/live/');
  } catch (_) { return false; }
}

/** Extrai o ID do vídeo (puro). */
function videoId(url) {
  try {
    const u = new URL(String(url || ''));
    const host = u.hostname.toLowerCase();
    if (host === 'youtu.be') return u.pathname.split('/')[1] || '';
    if (u.pathname === '/watch') return u.searchParams.get('v') || '';
    const m = u.pathname.match(/^\/(?:shorts|embed|live)\/([A-Za-z0-9_-]{6,})/);
    return m ? m[1] : '';
  } catch (_) { return ''; }
}

/**
 * Argumentos do yt-dlp (puro).
 * @param {object} opts { quality?: 'best'|'1080'|'720'|'audio', outPath?: string,
 *                        hasFfmpeg?: boolean (padrão true), ffmpegPath?: string,
 *                        jsRuntime?: string, skipJsRuntime?: boolean,
 *                        subtitles?: boolean, thumbnail?: boolean,
 *                        cookiesFile?: string, sleepRequests?: number }
 * 1.6.3: SEM ffmpeg o yt-dlp não consegue juntar vídeo+áudio nem converter
 * para mp3 — usa formatos únicos (já com áudio) em vez de deixar dois
 * arquivos soltos/erro.
 * 1.8.8: --merge-output-format mp4 garante um único .mp4 quando há merge.
 *        ytdlpSubtitles/ytdlpThumbnail adicionam legendas/thumbnail embutido.
 * 1.9.4: --cookies + --sleep-requests 1 — YouTube agora exige cookies de
 *        sessão autenticada e ritmo humano para não disparar o desafio
 *        "Sign in to confirm you're not a bot" (correção incorporada do
 *        yt-dlp 8.x). Sem cookies o YouTube cada vez mais devolve JSON
 *        ou bloqueia o IP.
 */
function ytdlpArgs(url, opts = {}) {
  const args = ['--no-playlist', '--no-warnings', '--newline', '--merge-output-format', 'mp4'];
  // 1.9.4: cookies da sessão do NanoDesk (exportados para cookies.txt pelo main).
  // Só aceita caminho ABSOLUTO dentro de SESSION_TMP para nunca ler cookies arbitrários do disco.
  if (opts.cookiesFile && /^\/|^[A-Za-z]:[\\/]/.test(String(opts.cookiesFile))) {
    args.push('--cookies', String(opts.cookiesFile));
  }
  // 1.9.4: ritmo humano (1 s entre requests) — reduz a chance do YouTube
  // classificar a sessão como bot. Não muda a experiência do usuário.
  if (opts.sleepRequests && Number(opts.sleepRequests) > 0) {
    args.push('--sleep-requests', String(Number(opts.sleepRequests)));
  }
  const q = String(opts.quality || 'best');
  const ff = opts.hasFfmpeg !== false;
  if (q === 'audio') {
    if (ff) args.push('-x', '--audio-format', 'mp3');
    else args.push('-f', 'ba[ext=m4a]/ba/b');
  } else if (q === '1080') {
    args.push('-f', ff ? 'bv*[height<=1080]+ba/b[height<=1080]/b' : 'b[height<=1080][ext=mp4]/b[height<=1080]/b[ext=mp4]/b');
  } else if (q === '720') {
    args.push('-f', ff ? 'bv*[height<=720]+ba/b[height<=720]/b' : 'b[height<=720][ext=mp4]/b[height<=720]/b[ext=mp4]/b');
  } else {
    args.push('-f', ff ? 'bv*+ba/b' : 'b[ext=mp4]/b');
  }
  if (ff && opts.ffmpegPath) args.push('--ffmpeg-location', String(opts.ffmpegPath));
  if (opts.jsRuntime && opts.skipJsRuntime !== true) args.push('--js-runtimes', 'node:' + String(opts.jsRuntime));
  // 1.8.8: legendas + thumbnail embutidos (no .mp4 final, quando há ffmpeg)
  // 1.8.10: removido --convert-subs srt (era contraditório com --embed-subs:
  // --embed-subs já embute as legendas no mp4; --convert-subs srt geraria
  // também um arquivo .srt lateral, que não é o que o checkbox do UI promete).
  if (ff && opts.subtitles === true) {
    args.push('--write-subs', '--write-auto-subs', '--sub-langs', 'all,-live_chat',
              '--embed-subs', '--sub-format', 'srt/vtt/best');
  }
  if (ff && opts.thumbnail === true) {
    args.push('--write-thumbnail', '--embed-thumbnail');
  }
  // 1.8.11: proxy SOCKS (Tor) — socks5h = DNS resolvido PELO proxy (sem vazamento de DNS).
  // Só aceita 127.0.0.1/localhost para nunca apontar o tráfego para fora da máquina.
  if (opts.proxy && /^socks5h?:\/\/(127\.0\.0\.1|localhost):\d{1,5}$/.test(String(opts.proxy))) {
    args.push('--proxy', String(opts.proxy));
  }
  if (opts.outPath) args.push('-o', String(opts.outPath));
  args.push('--print', 'after_move:filepath');
  // 1.8.11: '--' encerra as opções — a URL nunca pode ser lida como flag do yt-dlp.
  args.push('--', String(url || ''));
  return args;
}

/**
 * A saída indica que ESTA versão do yt-dlp não conhece uma das opções usadas?
 * (puro) — dispara o fallback sem --js-runtimes no main.
 */
function ytdlpUnknownOption(output) {
  return /no such option|--js-runtimes: (unknown|não)/i.test(String(output || ''));
}

/**
 * Interpreta uma linha de progresso do yt-dlp (puro) — ex.: "[download] 47%"
 * ou "Downloading 50% of 12 MiB". Devolve {percent, speed} ou null.
 */
function parseProgressLine(line) {
  const s = String(line || '');
  const m = s.match(/\b(\d{1,3}(?:\.\d)?)%/);
  if (!m) return null;
  const percent = Math.max(0, Math.min(100, Number(m[1])));
  let speed = '';
  const sm = s.match(/at\s+([0-9.]+\s*[KMGT]?i?B\/s)/i) ||
             s.match(/([0-9.]+\s*[KMGT]?i?B\/s)/i);
  if (sm) speed = sm[1].trim();
  return { percent, speed };
}

/** Procura um executável: pastas extras (pacote embutido), PATH e locais comuns. */
function findTool(name, existsSync = require('fs').existsSync, env = process.env, extraDirs = []) {
  const win = process.platform === 'win32';
  const sep = win ? '\\' : '/';
  const exe = win ? name + '.exe' : name;
  const cands = [];
  for (const d of extraDirs || []) if (d) cands.push(String(d).replace(/[\\/]+$/, '') + sep + exe);
  const pathVar = env[win ? 'Path' : 'PATH'] || env.PATH || env.Path || '';
  for (const d of String(pathVar).split(win ? ';' : ':')) {
    const dir = d.trim().replace(/^"|"$/g, '');
    if (dir) cands.push(dir.replace(/[\\/]+$/, '') + sep + exe);
  }
  if (win) {
    const pf = env['ProgramFiles'] || 'C:\\Program Files';
    const lf = env['LOCALAPPDATA'] || '';
    cands.push(`${pf}\\${name}\\${exe}`, `${lf}\\${name}\\${exe}`, `C:\\${name}\\${exe}`,
      `${lf}\\Microsoft\\WinGet\\Links\\${exe}`);
  } else {
    cands.push('/usr/bin/' + name, '/usr/local/bin/' + name, '/opt/homebrew/bin/' + name);
  }
  for (const c of cands) { try { if (c && existsSync(c)) return c; } catch (_) { /* segue */ } }
  return null;
}

/** Procura yt-dlp (pacote embutido, PATH, locais comuns). */
function findYtDlp(existsSync = require('fs').existsSync, env = process.env, extraDirs = []) {
  return findTool('yt-dlp', existsSync, env, extraDirs);
}

/** Procura ffmpeg (necessário para juntar vídeo+áudio e converter para mp3). */
function findFfmpeg(existsSync = require('fs').existsSync, env = process.env, extraDirs = []) {
  return findTool('ffmpeg', existsSync, env, extraDirs);
}

/** Última linha "ERROR:" da saída do yt-dlp (puro) — vira a mensagem mostrada ao usuário. */
function ytdlpErrorLine(output) {
  const lines = String(output || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const err = [...lines].reverse().find(l => /^ERROR:/i.test(l)) || lines[lines.length - 1] || '';
  return err.replace(/^ERROR:\s*/i, '').replace(/\[[a-z:0-9]+\]\s*/i, '').slice(0, 220);
}

module.exports = {
  YT_HOSTS,
  isYoutubeUrl, videoId,
  ytdlpArgs, ytdlpUnknownOption, parseProgressLine,
  findTool, findYtDlp, findFfmpeg, ytdlpErrorLine
};

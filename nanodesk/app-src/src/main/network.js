/**
 * NanoDesk — Network Manager (1.6.0, FASE 5)
 * ==================================================================
 * Referências estudadas (sem copiar código e SEM VPN fictícia):
 *  - Mullvad (mullvadvpn-app, GPL-3.0): cliente VPN EXTERNO — o
 *    NanoDesk apenas DETECTA o túnel ativo (interfaces WireGuard/
 *    Mullvad/OpenVPN/Tailscale) e indica o estado na interface.
 *    Não há (e não haverá) VPN embutida.
 *  - Tor desktop (Tor Project): suportado como PROXY SOCKS5 local
 *    (127.0.0.1:9050) que o usuário roda por fora; quando ativo, o
 *    NanoDesk cria uma SESSÃO ISOLADA exclusiva (partição separada,
 *    sem cookies/compartilhamento com a sessão normal).
 *    Orbot (Android) NÃO é apresentado como cliente Windows.
 *  - Pi-hole/AdGuard Home/PiVPN: infraestrutura de rede — fora do
 *    escopo do navegador; o que cabe aqui é o DNS SEGURO (DoH).
 *
 * Funcionalidades reais implementadas:
 *  1. detectVpnTunnel() — interfaces de rede do SO → indicador visual;
 *  2. DoH — app.commandLine.appendSwitch antes do app ficar pronto
 *     (modo "secure" com template Cloudflare/Quad9/Google/custom);
 *  3. Proxy Tor SOCKS5 por sessão (session.setProxy);
 *  4. Verificação de IP público PELO CAMINHO ATUAL (a consulta usa a
 *     própria sessão, então mostra o efeito real do VPN/Tor) — ação
 *     explícita do usuário, nenhum serviço é consultado por conta
 *     própria;
 *  5. Aviso de vazamento: Tor ativo + WebRTC sem proteção → alerta.
 *
 * Núcleo puro (detecção por nome de interface, switches DoH) é
 * testável sem Electron; as chamadas de sessão ficam no main.js.
 */
'use strict';

const os = require('os');

/** Padrões de interface que indicam túnel VPN (nome → rótulo). */
const VPN_PATTERNS = [
  { rx: /mullvad/i, label: 'Mullvad VPN (WireGuard)' },
  { rx: /nordlynx/i, label: 'NordLynx (WireGuard)' },
  { rx: /tailscale|^ts\d/i, label: 'Tailscale (WireGuard)' },
  { rx: /^wg\d?$|wireguard/i, label: 'WireGuard' },
  { rx: /openvpn|tap-windows|tun\d?$|^utun/i, label: 'OpenVPN/tun' },
  { rx: /proton|pvpn/i, label: 'Proton VPN' },
  { rx: /expressvpn|edtunnel/i, label: 'ExpressVPN' },
  { rx: /^ppp\d?$/i, label: 'Túnel PPP' }
];

/**
 * Detecta túnel VPN ativo pelas interfaces de rede (puro).
 * @param {Function} [networkInterfaces] injetável (os.networkInterfaces)
 * @returns {{connected:boolean, kind:string, interfaces:string[]}}
 */
function detectVpnTunnel(networkInterfaces = os.networkInterfaces) {
  let nets;
  try { nets = networkInterfaces(); } catch (_) { return { connected: false, kind: '', interfaces: [] }; }
  const names = Object.keys(nets || {});
  const hits = [];
  let kind = '';
  for (const name of names) {
    for (const p of VPN_PATTERNS) {
      if (p.rx.test(name)) {
        // interface existe; considera conectada se tem algum endereço IPv4/IPv6
        const addrs = (nets[name] || []).filter(a => a && !a.internal);
        if (addrs.length) {
          hits.push(name);
          if (!kind) kind = p.label;
        }
        break;
      }
    }
  }
  return { connected: hits.length > 0, kind, interfaces: hits };
}

/** Templates DoH conhecidos. */
const DOH_TEMPLATES = {
  cloudflare: 'https://cloudflare-dns.com/dns-query',
  cloudflare_family: 'https://family.cloudflare-dns.com/dns-query',
  google: 'https://dns.google/dns-query',
  quad9: 'https://dns.quad9.net/dns-query'
};

/**
 * Argumentos de linha de comando do Chromium para DNS-over-HTTPS.
 * Puro e testável. Aplicado em app.commandLine.appendSwitch ANTES do
 * app ficar pronto (não dá para mudar depois).
 * @param {object} cfg { provider: 'off'|'cloudflare'|…|'custom', customUrl?, strict? }
 */
function dohSwitches(cfg) {
  if (!cfg || !cfg.provider || cfg.provider === 'off') return [];
  const template = cfg.provider === 'custom'
    ? String(cfg.customUrl || '')
    : DOH_TEMPLATES[cfg.provider] || '';
  if (!/^https:\/\/[a-z0-9.-]+/i.test(template)) return [];
  return [
    ['enable-features', 'DnsOverHttps'],
    ['dns-over-https-mode', cfg.strict ? 'secure' : 'automatic'],
    ['dns-over-https-templates', template]
  ];
}

/** Regras de proxy para a sessão Tor (puro). */
function torProxyRules(port) {
  const p = Math.min(65535, Math.max(1024, Number(port) || 9050));
  return 'socks5://127.0.0.1:' + p;
}

/**
 * Risco de vazamento para o painel (puro).
 */
function leakWarnings(state) {
  const warns = [];
  if (state && state.tor && state.tor.active && state.webrtcProtected === false) {
    warns.push('Tor ativo SEM proteção WebRTC: o IP real pode vazar por WebRTC. Ative "Proteção WebRTC" nas configurações.');
  }
  if (state && state.tor && state.tor.active && !state.tor.isolated) {
    warns.push('Tor ativo sem sessão isolada: cookies da navegação normal podem ser compartilhados.');
  }
  return warns;
}

module.exports = { VPN_PATTERNS, detectVpnTunnel, DOH_TEMPLATES, dohSwitches, torProxyRules, leakWarnings };

# LICENSES.md — Licenças e avaliações de projetos (NanoDesk 1.6.0)

> **Auditoria de cadeia de suprimentos (2026-11-26)**: licenças re-verificadas
> nas fontes oficiais; correções aplicadas abaixo. Estado atual e canônico:
> THIRD_PARTY_NOTICES.md (atribuições), DEPENDENCIES.md (inventário) e
> sbom.cdx.json (SBOM CycloneDX 1.5).

A especificação do NanoDesk exige verificar licença, obrigações de
distribuição e compatibilidade ANTES de incorporar qualquer projeto.
Abaixo, o destino dado a cada projeto citado. Princípios aplicados:

1. **Código GPL/AGPL NÃO é copiado** para os módulos do NanoDesk — os
   projetos são usados como referência conceitual (a arquitetura não é
   protegida por direitos autorais) ou como **processo/binário/serviço
   externo**, o que não cria obra derivada.
2. Listas de dados usadas conforme a licença, com atribuição.
3. Bibliotecas npm executadas dentro do app mantêm seus avisos.

## 1. Executado dentro do pacote (dependências reais)

| Projeto | Licença | Uso |
| --- | --- | --- |
| Electron 45.4.1 | MIT | runtime (corrigido de 45.2.3 na auditoria de 2026-11-26) |
| @ghostery/adblocker (+ electron) | MPL-2.0 | motor EasyList/EasyPrivacy + filtros cosméticos |
| electron-dl | MIT | gerenciador de downloads |
| pdf.js (mozilla/pdfjs-dist 3.11.174) | Apache-2.0 | leitor de PDF (src/readers/pdf) |
| foliate-js (johnfactotum) 1.0.1 | MIT | leitor de EPUB/MOBI/FB2/CBZ (src/readers/epub) |
| tldts-experimental | MIT | eTLD+1 (cookies de terceiros, cosméticos) |

## 2. Listas de filtro (dados, com atribuição)

| Lista | Licença | Fonte |
| --- | --- | --- |
| EasyList | GPL-3.0+ OU CC-BY-SA-3.0+ (uso sob CC BY-SA 3.0+) | https://easylist.to/ — atribuição: "The EasyList authors" |
| EasyPrivacy | GPL-3.0+ OU CC-BY-SA-3.0+ (uso sob CC BY-SA 3.0+) | https://easylist.to/ — idem |
| Listas uBlock ×11 (uAssets: filters, 2020–2025, badware, privacy, resource-abuse, quick-fixes, unbreak) | GPL-3.0 | https://github.com/uBlockOrigin/uAssets — redistribuídas verbatim em resources/filters/ |
| resources.json (uBO) | MPL-2.0 (via assets do @ghostery/adblocker) | GitHub ghostery/adblocker |
| StevenBlack/hosts | MIT | https://github.com/StevenBlack/hosts — baixado em tempo de execução, só em RAM, NÃO distribuído no pacote |

## 3. Estudados como referência conceitual (nenhuma linha copiada)

| Projeto | Licença | Contribuição conceitual | Implementação NanoDesk |
| --- | --- | --- | --- |
| uBlock Origin (gorhill) | GPL-3.0 | gestão de listas, estatísticas de bloqueio | módulos próprios (adblock.js) |
| ClearURLs (Addon) | LGPL-3.0 (corrigido de GPL-3.0 na auditoria de 2026-11-26) | remoção de parâmetros de rastreamento | urlclean.js — regras originais próprias |
| CanvasBlocker (kkapsner) | MPL-2.0 (corrigido de GPL-3.0 na auditoria de 2026-11-26) | proteção de canvas/WebGL/áudio | fingerprint.js — ruído LSB determinístico + GPU genérica (redução, sem randomização) |
| Traceveil (ManuGrig) | MIT | estudos de superfície de identificação | princípio de consistência aplicado no fingerprint.js |
| Camoufox (daijro) | MPL-2.0 | anti-fingerprinting de navegador | referência de limites (não randomizar indiscriminadamente) |
| URLCheck (TrianguloY) | CC-BY-4.0 (corrigido de MPL-2.0 na auditoria de 2026-11-26) | análise de URL antes de abrir | urlgate.js — heurística original, 100% local |
| RedirectGuard (dikshanagvekar) | MIT — NÃO VERIFICADO (repositório não localizado na auditoria de 2026-11-26) | cortar redes de redirecionamento | redirect-guard.js (desde 1.5.1) |
| Popup-Blocker-Pro (madjeek-web / Fabien Conéjéro) | MIT (confirmado por texto bruto do LICENSE) | bloquear pop-ups sem interação | popup-blocker.js (desde 1.5.1) |
| PopUpOFF (RomanistHere) | Apache-2.0 (corrigido de MIT na auditoria de 2026-11-26) | bloqueio de modais/overlays de DOM | popup-off.js — porta da LÓGICA v2.1.3, sem código verbatim (desde 1.9.6) |
| Popup Blocker (strict) (schomery) | MPL-2.0 (corrigido de GPL-3.0 na auditoria de 2026-11-26) | interceptar window.open/click/submit + iframes | popup-blocker-strict.js (desde 1.8.8) |
| Blanc (bnfy) | MIT | permissões por prompt nativo; snapshot offline de listas | permissions.js, filters-bundle.js |
| FreshRSS / miniflux / rsspresso | AGPL-3.0/… | leitor de feeds minimalista + limpeza de links | reader.js (desde 1.4.0, código próprio) |
| OWASP WSTG | CC BY-SA 4.0 (doc) | checklist de testes de segurança | matriz de testes (tests/) e heurísticas do urlgate |

## 4. Integrações por meio OFICIAL (processo/CLI/API externos)

| Projeto | Licença | Integração |
| --- | --- | --- |
| Bitwarden (clients) | GPL-3.0 | via **CLI oficial `bw`** instalada pelo usuário; o NanoDesk não copia código nem armazena segredos |
| LibreTranslate | AGPL-3.0 | via **API HTTP** do servidor configurado pelo usuário (local ou próprio); sem endpoint, a função fica desligada |
| Argos Translate | GPL-3.0 | offline via LibreTranslate local (`pip install libretranslate`); sem modelos embutidos |
| ClamAV (Cisco-Talos) | GPL-2.0 (corrigido de GPL-3.0 na auditoria de 2026-11-26) | EMBUTIDO no build Windows desde 1.8.8 (resources/clamav/ — clamscan/freshclam + libclamav); base de assinaturas baixada em runtime; LICENSE incluído no dist pela auditoria |
| YARA (VirusTotal) | BSD-3-Clause | binário externo + regras do usuário (NANODESK_YARA_RULES); NÃO distribuído |
| yt-dlp | Unlicense | EMBUTIDO no build Windows desde 1.8.8 (resources/bin/yt-dlp.exe 2026.10.26, release oficial, sha256 documentado) |
| aria2 (Tatsuhiro Tsujikawa) | GPL-2.0 + OpenSSL exception | binário embutido no build Windows desde 1.9.5 (resources/aria2/aria2c.exe 1.37.0), RPC 127.0.0.1 com token efêmero; LICENSE + LICENSE.OpenSSL no dist |
| FFmpeg (BtbN lgpl-shared) | LGPL-3.0 | binário embutido no build Windows desde 1.8.8 (resources/bin/: ffmpeg.exe 8.1 + 7 DLLs), junção 1080p+/MP3; FFMPEG-LICENSE.txt no dist |
| Tor (The Tor Project) | BSD-3-Clause | binário embutido no build Windows desde 1.5.3 (resources/tor/ — expert bundle 16.0, sha256 conferido contra somas oficiais ASSINADAS); avisos em resources/tor/win/docs/ |
| SearXNG | AGPL-3.0 | serviço externo — instância configurável pelo usuário (campo em Configurações) |
| FreeTube | AGPL-3.0 | app externo — aberto via deep link `freetube://` |
| Invidious / Piped | AGPL-3.0 | instâncias web configuráveis (redirecionamento opcional) |
| Mullvad VPN | GPL-3.0 | cliente VPN externo — apenas DETECTADO pelas interfaces do SO |
| OpenVPN/WireGuard/Tailscale | vários | idem — detecção passiva por nome de interface |
| Pi-hole / AdGuard Home | EUPL/… | infraestrutura de rede; o análogo no navegador é a camada hosts/DoH |
| PiVPN | MIT | infraestrutura de servidor — fora do escopo do desktop; documentado |
| Orbot (guardianproject) | GPL-3.0 | Android — NÃO é apresentado como cliente Windows (usa-se o Tor desktop) |
| Osprey (OspreyProject) | MIT | estudos de varredura; a varredura real usa ClamAV/YARA externos |
| Visilant (ikskoder) | MIT | estudos de telemetria; não incorporado |
| LibRedirect | MPL-2.0 | inspiração para a política de redirecionamento de vídeo |
| DeArrow (ajayyy) | GPL-3.0 | INCOMPATÍVEL nativamente no Electron (é extensão MV3) — limitação documentada, sem botão fictício |
| Min Browser (minbrowser) | Apache-2.0 | referência de interface minimalista |
| WebLibre (fafre) | GPL-3.0 | referência de leitores/privacidade |
| DuckDuckGo/Startpage/Brave | serviços | buscadores configuráveis (links normais) |
| ifconfig.co | serviço | verificação de IP SOMENTE sob clique do usuário |

## 5. Compatibilidade de licenças (resumo)

- O pacote NanoDesk é **MIT**; suas dependências embarcadas são MIT/Apache-
  2.0/MPL-2.0 — todas compatíveis com distribuição binária com avisos
  preservados (LICENSES.chromium.html acompanha o runtime do Electron).
- Nenhum código GPL/AGPL foi incorporado ao código do NanoDesk; os
  projetos GPL/AGPL entram como **binários separados** no build Windows
  (aria2, ClamAV, FFmpeg, Tor; yt-dlp Unlicense), **serviços**
  (LibreTranslate, SearXNG, Invidious/Piped), **dados independentes**
  (listas uAssets GPL-3.0 em resources/filters/) ou **referência
  conceitual** — sem obra derivada de código.
- EasyList/EasyPrivacy (CC BY-SA 3.0) exigem atribuição — mantida no
  README, no manifesto do pacote offline (resources/filters/manifest.json)
  e neste arquivo.

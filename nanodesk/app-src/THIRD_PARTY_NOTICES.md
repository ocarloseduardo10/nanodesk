# THIRD_PARTY_NOTICES — NanoDesk 1.9.6

Atualizado pela auditoria de cadeia de suprimentos em 2026-11-26. Documento canônico de atribuição; o histórico de decisões de licença está em LICENSES.md.

**Método e evidência**: cada licença abaixo foi conferida por (a) API do registry npm (218/218 pacotes), (b) texto bruto dos arquivos LICENSE nos repositórios oficiais, (c) páginas oficiais (easylist.to), ou (d) metadados de procedência do projeto (arquivos *ORIGEM.txt com SHA-256). Informações que não puderam ser confirmadas estão marcadas **NÃO VERIFICADO** — nada foi inventado.

**Nota de compatibilidade**: o NanoDesk é MIT. As dependências npm embutidas são MIT/ISC/BSD/Apache-2.0/MPL-2.0/BlueOak/CC0 (todas compatíveis com distribuição com avisos). Código GPL/AGPL não é incorporado; projetos GPL/AGPL aparecem apenas como: dados redistribuídos em arquivos independentes (listas de filtro), binários separados comunicando por processo/RPC, serviços remotos ou referências conceituais reimplementadas — sem linkagem, sem obra derivada de código.

## A. Dependências npm executadas no aplicativo (runtime)

3 dependências diretas + 37 transitivas (40 pacotes no total; inventário completo com versões em DEPENDENCIES.md e no sbom.cdx.json).

### A.1 Diretas

| Pacote | Versão | Licença | Repositório |
| --- | --- | --- | --- |
| `@ghostery/adblocker-electron` | 2.20.3 | MPL-2.0 | git+ssh://git@github.com/ghostery/adblocker.git |
| `electron` | 45.4.1 | MIT | git+https://github.com/electron/electron.git |
| `electron-dl` | 5.0.0 | MIT | git+https://github.com/sindresorhus/electron-dl.git |

### A.2 Transitivas

| Pacote | Versão | Licença | Repositório |
| --- | --- | --- | --- |
| `@electron-internal/extract-zip` | 1.0.9 | MIT | git+https://github.com/electron/extract-zip.git |
| `@electron/get` | 5.1.0 | MIT | git+https://github.com/electron/get.git |
| `@ghostery/adblocker` | 2.20.3 | MPL-2.0 | git+ssh://git@github.com/ghostery/adblocker.git |
| `@ghostery/adblocker-content` | 2.20.3 | MPL-2.0 | git+ssh://git@github.com/ghostery/adblocker.git |
| `@ghostery/adblocker-electron-preload` | 2.20.3 | MPL-2.0 | git+ssh://git@github.com/ghostery/adblocker.git |
| `@ghostery/adblocker-extended-selectors` | 2.20.3 | MPL-2.0 | git+ssh://git@github.com/ghostery/adblocker.git |
| `@ghostery/url-parser` | 1.3.1 | MPL-2.0 | git+https://github.com/ghostery/url-parser.git |
| `@remusao/guess-url-type` | 2.1.0 | MPL-2.0 | git+https://github.com/remusao/mono.git |
| `@remusao/small` | 2.1.0 | MPL-2.0 | git+https://github.com/remusao/mono.git |
| `@remusao/smaz` | 2.2.0 | MPL-2.0 | git+https://github.com/remusao/mono.git |
| `@remusao/smaz-compress` | 2.2.0 | MPL-2.0 | git+https://github.com/remusao/mono.git |
| `@remusao/smaz-decompress` | 2.2.0 | MPL-2.0 | git+https://github.com/remusao/mono.git |
| `@remusao/trie` | 2.1.0 | MPL-2.0 | git+https://github.com/remusao/mono.git |
| `@types/node` | 24.19.4 | MIT | https://github.com/DefinitelyTyped/DefinitelyTyped.git |
| `debug` | 4.4.3 | MIT | git://github.com/debug-js/debug.git |
| `env-paths` | 3.0.0 | MIT | git+https://github.com/sindresorhus/env-paths.git |
| `escape-goat` | 4.0.0 | MIT | git+https://github.com/sindresorhus/escape-goat.git |
| `escape-string-regexp` | 5.0.0 | MIT | git+https://github.com/sindresorhus/escape-string-regexp.git |
| `ext-list` | 2.2.2 | MIT | git+https://github.com/kevva/ext-list.git |
| `ext-name` | 5.0.0 | MIT | git+https://github.com/kevva/ext-name.git |
| `graceful-fs` | 4.2.12 | BlueOak-1.0.0 | git+https://github.com/isaacs/node-graceful-fs.git |
| `is-plain-obj` | 1.1.0 | MIT | https://github.com/sindresorhus/is-plain-obj |
| `is-safe-filename` | 0.1.1 | MIT | git+https://github.com/sindresorhus/is-safe-filename.git |
| `mime-db` | 1.54.0 | MIT | git+https://github.com/jshttp/mime-db.git |
| `ms` | 2.1.3 | MIT | git+https://github.com/vercel/ms.git |
| `path-exists` | 5.0.0 | MIT | git+https://github.com/sindresorhus/path-exists.git |
| `progress` | 2.0.3 | MIT | git://github.com/visionmedia/node-progress.git |
| `pupa` | 3.3.0 | MIT | git+https://github.com/sindresorhus/pupa.git |
| `semver` | 7.8.6 | ISC | git+https://github.com/npm/node-semver.git |
| `sort-keys` | 1.1.2 | MIT | git+https://github.com/sindresorhus/sort-keys.git |
| `sort-keys-length` | 1.0.1 | MIT | https://github.com/kevva/sort-keys-length |
| `sumchecker` | 3.0.1 | Apache-2.0 | git+https://github.com/malept/sumchecker.git |
| `tldts-core` | 7.5.6 | MIT | git+ssh://git@github.com/remusao/tldts.git |
| `tldts-experimental` | 7.4.19 | MIT | git+ssh://git@github.com/remusao/tldts.git |
| `undici` | 7.30.2 | MIT | git+https://github.com/nodejs/undici.git |
| `undici-types` | 7.24.6 | MIT | git+https://github.com/nodejs/undici.git |
| `unused-filename` | 4.0.1 | MIT | git+https://github.com/sindresorhus/unused-filename.git |

Obrigação: preservar os avisos de copyright/licença — cumprido pois os pacotes npm são empacotados com seus arquivos LICENSE dentro de app.asar, e o resumo está neste documento e em NOTICE.md.

## B. Código vendido no repositório (leitor de PDF e EPUB)

| Projeto | Autor | Site | Repositório | Versão | Licença | Uso | Modificações | Obrigações |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **pdf.js (pdfjs-dist)** | Mozilla Foundation | https://mozilla.org | https://github.com/mozilla/pdf.js | 3.11.174 | Apache-2.0 | https://www.apache.org/licenses/LICENSE-2.0 | VENDIDO (código) em src/readers/pdf/build + web (visualizador completo, fontes standard e cmaps). | NÃO modificado — build oficial 3.11.174 confirmado em web/viewer.js. Arquivos próprios do NanoDesk no visualizador: web/pdf-enhance.js e web/pdf-init.js. |
| **foliate-js** | John Factotum | https://johnfactotum.github.io/foliate-js/ | https://github.com/johnfactotum/foliate-js | NÃO VERIFICADO (sem número de versão no vendor) | MIT | https://github.com/johnfactotum/foliate-js/blob/main/LICENSE | VENDIDO (código) em src/readers/epub/foliate/ (EPUB/MOBI/FB2/CBZ). | NÃO modificado; LICENSE (MIT © 2022 John Factotum) acompanhando o vendor → licenses/MIT-foliate-js.txt. |
| **zip.js** | Gildas Lormeau | https://gildas-lormeau.github.io/ | https://github.com/gildas-lormeau/zip.js | NÃO VERIFICADO (dist minificada sem banner) | BSD-3-Clause | https://github.com/gildas-lormeau/zip.js/blob/master/LICENSE | VENDIDO (código) em src/readers/epub/foliate/vendor/zip.js (usado pelo foliate-js). | NÃO modificado, mas a distribuição minificada não contém banner de licença → aviso dado aqui e em NOTICE.md. |
| **fflate** | Arjun Barrett (101arrowz) | https://101arrowz.github.io/fflate/ | https://github.com/101arrowz/fflate | NÃO VERIFICADO (dist minificada sem banner) | MIT | https://github.com/101arrowz/fflate/blob/master/LICENSE | VENDIDO (código) em src/readers/epub/foliate/vendor/fflate.js (usado pelo foliate-js). | NÃO modificado, sem banner na dist minificada → aviso dado aqui e em NOTICE.md. |

Textos das licenças: licenses/Apache-2.0.txt, licenses/MIT-foliate-js.txt, licenses/BSD-3-Clause-zip.js.txt, licenses/MIT.txt.

## C. Dados de filtros redistribuídos (adblock/hosts)

| Lista | Autor | Site | Fonte | Versão | Licença | Uso | Modificações | Obrigações |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **EasyList** | The EasyList authors | https://easylist.to/ | https://github.com/easylist/easylist | snapshot de 2026-11-12 (versão 202611121943) | GPL-3.0+ OU CC-BY-SA-3.0+ (dual) | https://easylist.to/pages/licence.html | DADOS redistribuídos verbatim: resources/filters/easylist.txt. | NÃO modificado (sha256 no manifest.json do pacote). |
| **EasyPrivacy** | The EasyList authors | https://easylist.to/ | https://github.com/easylist/easylist | snapshot de 2026-11-12 (versão 202611121939) | GPL-3.0+ OU CC-BY-SA-3.0+ (dual) | https://easylist.to/pages/licence.html | DADOS redistribuídos verbatim: resources/filters/easyprivacy.txt. | NÃO modificado (sha256 no manifest.json). |
| **uBlock filters (9 listas: filters.txt, 2020–2025, badware, privacy, resource-abuse, quick-fixes, unbreak)** | uBlockOrigin / uAssets contributors | https://github.com/uBlockOrigin/uAssets | https://github.com/uBlockOrigin/uAssets | snapshot de 2026-11-12 | GPL-3.0 | https://github.com/uBlockOrigin/uAssets/blob/master/LICENSE | DADOS redistribuídos verbatim em resources/filters/ (ublock.txt, ublock-2020..2025.txt, badware.txt, privacy.txt, resource-abuse.txt, quick-fixes.txt, unbreak.txt). | NÃO modificado (sha256 no manifest.json). |
| **resources.json (scriptlets uBO compilados pelo adblocker)** | Ghostery | https://www.ghostery.com/ | https://github.com/ghostery/adblocker | snapshot de 2026-11-12 (assets master) | MPL-2.0 | https://github.com/ghostery/adblocker/blob/main/LICENSE | DADOS redistribuídos verbatim: resources/filters/resources.json (asset oficial do @ghostery/adblocker). | NÃO modificado (sha256 no manifest.json). |
| **StevenBlack/hosts** | StevenBlack | https://github.com/StevenBlack/hosts | https://github.com/StevenBlack/hosts | baixado em tempo de execução (só RAM) | MIT | https://github.com/StevenBlack/hosts/blob/master/license.txt | Baixado em tempo de execução e mantido apenas em memória — NÃO distribuído no pacote. | Parser próprio; nenhum dado redistribuído. |

Integridade dos arquivos: SHA-256 de cada lista em resources/filters/manifest.json.

## D. Binários de terceiros redistribuídos (build Windows — NÃO presentes no código-fonte)

| Binário | Autor | Site | Repositório | Versão | Licença | Uso no build | Modificações | Obrigações |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **aria2** | Tatsuhiro Tsujikawa | https://aria2.github.io/ | https://github.com/aria2/aria2 | 1.37.0 (win-64bit-build1) | GPL-2.0 com OpenSSL exception | https://github.com/aria2/aria2/blob/master/COPYING | BINÁRIO redistribuído no build Windows: resources/aria2/aria2c.exe (spawado via RPC 127.0.0.1 com token efêmero). | NÃO modificado; NÃO reassinado (assinatura do autor original preservada). |
| **ClamAV (clamscan, freshclam, libclamav e DLLs)** | Cisco-Talos | https://www.clamav.net/ | https://github.com/Cisco-Talos/clamav | 1.5.4 (build oficial Windows x64) | GPL-2.0 | https://docs.clamav.net/#license | BINÁRIOS redistribuídos no build Windows: resources/clamav/ (motor + freshclam; base de assinaturas baixada em runtime). | NÃO modificado (binários do instalador oficial clamav.net). |
| **FFmpeg (ffmpeg.exe + 7 DLLs shared)** | FFmpeg contributors; build por BtbN | https://ffmpeg.org/ | https://github.com/BtbN/FFmpeg-Builds | 8.1 (win64 lgpl-shared) | LGPL-3.0 | https://www.gnu.org/licenses/lgpl-3.0.html | BINÁRIOS redistribuídos no build Windows: resources/bin/ffmpeg.exe, avcodec-62, avformat-62, avutil-60, avdevice-62, avfilter-11, swresample-6, swscale-9 (junção de vídeo/áudio 1080p+ e conversão MP3). | NÃO modificado (build lgpl-shared oficial do BtbN). |
| **yt-dlp** | yt-dlp contributors | https://github.com/yt-dlp/yt-dlp | https://github.com/yt-dlp/yt-dlp | 2026.10.26 (release oficial) | Unlicense | https://github.com/yt-dlp/yt-dlp/blob/master/LICENSE | BINÁRIO redistribuído no build Windows: resources/bin/yt-dlp.exe (download sob ação explícita do usuário). | NÃO modificado (release oficial, sha256 documentado em bin/LEIA-ME.txt). |
| **Tor (expert bundle: tor.exe + libevent + zlib + openssl)** | The Tor Project | https://www.torproject.org/ | https://gitlab.torproject.org/tpo/core/tor | 16.0 (tor 0.4.9.15) | BSD-3-Clause (e licenças dos componentes) | https://gitlab.torproject.org/tpo/core/tor/-/blob/main/LICENSE | BINÁRIOS redistribuídos no build Windows: resources/tor/win/ (SOCKS local; auto-start controlado pelo usuário). | NÃO modificado; pacote oficial tor-expert-bundle-windows-x86_64-16.0 conferido contra sha256sums ASSINADO do Tor Project (TOR-ORIGEM.txt). |
| **Microsoft Visual C++ Runtime (vcruntime140, msvcp140, concrt140)** | Microsoft | https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist | — | conforme instalador oficial do ClamAV 1.5.4 | Licença de redistribuição Microsoft (não-OSI) | https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist | DLLs de runtime empacotadas junto ao instalador oficial do ClamAV (resources/clamav/). | NÃO modificado. |

Procedência e SHA-256 de cada binário: resources/*/*ORIGEM.txt e resources/bin/LEIA-ME.txt (no build). Nenhum destes binários está no repositório de código-fonte — entram apenas na distribuição do build Windows.

## E. Referências conceituais reimplementadas (sem código copiado)

| Projeto | Autor | Site | Repositório | Licença (verificada) | Uso | Correções da auditoria | Obrigações |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **PopUpOFF** | RomanistHere | https://romanisthere.github.io/PopUpOFF-Website/ | https://github.com/RomanistHere/PopUpOFF | Apache-2.0 | https://github.com/RomanistHere/PopUpOFF/blob/develop/LICENSE | REFERÊNCIA REIMPLEMENTADA — porta da LÓGICA (modos, limites de área, listas de palavras e whitelist) em src/main/popup-off.js, sem código verbatim. | Reimplementação própria; **CORRIGIDO nesta auditoria: a licença era documentada como MIT; o LICENSE oficial do repositório (branch develop) é Apache-2.0.** |
| **Popup Blocker (strict)** | schomery (Jeremy Schomery) | https://github.com/schomery/popup-blocker | https://github.com/schomery/popup-blocker | MPL-2.0 | https://github.com/schomery/popup-blocker/blob/master/LICENSE | REFERÊNCIA REIMPLEMENTADA (conceito: interceptar window.open/click/submit) em src/main/popup-blocker-strict.js. | Reimplementação própria; **CORRIGIDO nesta auditoria: documentado como GPL-3.0; o LICENSE oficial é MPL-2.0.** |
| **Popup-Blocker-Pro** | Fabien Conéjéro / MADJEEK (madjeek-web) | https://madjeek.com/ | https://github.com/madjeek-web/Popup-Blocker-Pro | MIT | https://github.com/madjeek-web/Popup-Blocker-Pro/blob/main/LICENSE | REFERÊNCIA REIMPLEMENTADA (conceito de bloqueio sem interação) em src/main/popup-blocker.js. | Reimplementação própria; licença MIT CONFIRMADA por texto bruto (© 2026 Fabien Conéjéro / MADJEEK). |
| **Consent-O-Matic** | CAVI — Aarhus University (Janus Bager Kristensen, Rolf Bagge) | https://consentomatic.au.dk/ | https://github.com/cavi-au/Consent-O-Matic | MIT | https://github.com/cavi-au/Consent-O-Matic/blob/master/LICENSE | REFERÊNCIA REIMPLEMENTADA (sempre negar rastreadores, nível máximo de privacidade) em src/main/consentomatic.js. | Reimplementação própria; **CORRIGIDO nesta auditoria: documentado como MPL-2.0; o LICENSE oficial é MIT (© 2019–2022 CAVI/Aarhus University).** |
| **CanvasBlocker** | kkapsner | https://canvasblocker.kkapsner.de/ | https://github.com/kkapsner/CanvasBlocker | MPL-2.0 | https://github.com/kkapsner/CanvasBlocker | REFERÊNCIA REIMPLEMENTADA (redução de superfície de fingerprinting com consistência) em src/main/fingerprint.js. | Reimplementação própria; **CORRIGIDO nesta auditoria: documentado como GPL-3.0; a licença oficial (GitHub) é MPL-2.0.** |
| **ClearURLs** | ClearURLs project | https://docs.clearurls.xyz/ | https://github.com/ClearURLs/Addon | LGPL-3.0 | https://github.com/ClearURLs/Addon/blob/master/LICENSE | REFERÊNCIA REIMPLEMENTADA (remoção de parâmetros de rastreamento) em src/main/urlclean.js — regras originais próprias. | Reimplementação própria; **CORRIGIDO nesta auditoria: documentado como GPL-3.0; o LICENSE oficial é LGPL-3.0.** |
| **URLCheck** | TrianguloY | https://github.com/TrianguloY/URLCheck | https://github.com/TrianguloY/URLCheck | CC-BY-4.0 | https://github.com/TrianguloY/URLCheck/blob/master/LICENSE | REFERÊNCIA REIMPLEMENTADA (análise de URL antes de abrir; heurísticas 100% locais) em src/main/urlgate.js. | Reimplementação própria; **CORRIGIDO nesta auditoria: documentado como MPL-2.0; o LICENSE oficial é CC-BY-4.0.** |
| **RedirectGuard** | NÃO VERIFICADO (referência citada: "dikshanagvekar/RedirectGuard") | — | — | NÃO VERIFICADO | — | REFERÊNCIA declarada em src/main/redirect-guard.js (conceito de cortar redes de redirecionamento). | Reimplementação própria. **O repositório citado NÃO FOI LOCALIZADO (404 em dikshanagvekar/Redirect-Guard e /RedirectGuard em 2026-11-26); a busca retorna apenas rdevz-ph/RedirectGuard (projeto diferente, Android).** |
| **uBlock Origin** | Raymond Hill (gorhill) e contribuidores | https://ublockorigin.com/ | https://github.com/gorhill/uBlock | GPL-3.0 | https://github.com/gorhill/uBlock/blob/master/LICENSE.txt | REFERÊNCIA REIMPLEMENTADA (gestão de listas, estatísticas de bloqueio) em src/main/adblock.js; o MOTOR de filtragem é o @ghostery/adblocker (MPL-2.0), não código do uBO. | Reimplementação própria; sem código copiado. |
| **OWASP WSTG** | OWASP Foundation | https://owasp.org/www-project-web-security-testing-guide/ | https://github.com/OWASP/wstg | CC-BY-4.0 | https://github.com/OWASP/wstg/blob/master/LICENSE | REFERÊNCIA DOCUMENTAL (checklist de segurança aplicado em heurísticas próprias e matriz de testes). | Nenhum texto redistribuído. |
| **Outras referências conceituais do LICENSES.md (Traceveil, Camoufox, Blanc, FreshRSS/miniflux/rsspresso, Min Browser, WebLibre, LibRedirect, DeArrow, Osprey, Visilant, Mullvad, Pi-hole, Orbot, Bitwarden, Argos Translate, SearXNG, FreeTube, Invidious/Piped)** | ver LICENSES.md | — | ver LICENSES.md | NÃO RE-VERIFICADO NESTA AUDITORIA | — | Referências documentais/externas sem código ou dados incorporados (afirmado pelo próprio projeto). | — |


## F. Serviços remotos e APIs (nada redistribuído)

| Serviço | Operador | Licença/termos | Uso |
| --- | --- | --- | --- |
| **SponsorBlock (API sponsor.ajay.app)** | Ajay Ramachandran e comunidade | GPL-3.0 (servidor) | https://github.com/ajayyy/SponsorBlock/blob/master/LICENSE |
| **LibreTranslate** | LibreTranslate (utopia-rise/comunitário) | AGPL-3.0 | https://github.com/LibreTranslate/LibreTranslate/blob/main/LICENSE |
| **LanguageTool (API)** | LanguageTool (languagetool.org) | NÃO VERIFICADO NESTA AUDITORIA (servidor LGPL-2.1+ segundo o projeto) | — |
| **SearXNG / Invidious / Piped / FreeTube / DuckDuckGo / Startpage / Brave / ifconfig.co** | projetos respectivos | vários (serviços) | — |


## G. Somente desenvolvimento (não distribuídos ao usuário final)

electron-packager 17.1.2 (MIT), rcedit 4.x (MIT), jsdom 31.x (MIT), @playwright/test 1.56.x (Apache-2.0), node/npm (runtools). Licenças individuais no sbom.cdx.json (propriedade `dev`).

## H. Platforma runtime embutida no build

**Electron 45.4.1** (OpenJS Foundation — MIT) — empacota Chromium, Node.js e V8, cujas licenças e avisos acompanham o runtime oficial (LICENSES.chromium.html). Versões internas do Chromium/Node: NÃO VERIFICADO individualmente nesta auditoria (documentadas no pacote oficial do Electron).

## I. Textos de licenças armazenados

licenses/Apache-2.0.txt · MPL-2.0.txt · GPL-2.0.txt · GPL-2.0-ClamAV.txt · GPL-3.0.txt · LGPL-3.0.txt · Unlicense.txt · MIT.txt · MIT-foliate-js.txt · MIT-Popup-Blocker-Pro.txt · MIT-Consent-O-Matic.txt · BSD-3-Clause-zip.js.txt · aria2-OpenSSL-exception.txt

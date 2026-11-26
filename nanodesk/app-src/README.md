# NanoDesk 1.9.3 — Navegador ultraleve, privado e auditável

> **Versão atual: 1.9.3.** Histórico completo em `CHANGELOG.md`. Resumo desde a 1.7.3:
> - **1.8.x** — auditoria de segurança: cofre (casamento de host estrito), Tor + yt-dlp/ClamAV sem vazar o IP,
>   SponsorBlock k-anônimo (desligado por padrão), Fuses do Electron, instaladores seguros.
> - **1.9.0** — **Arquivar página** (arquivo único `.html`, nativo e privado) — `ARQUIVAR-PAGINA.md`.
> - **1.9.1** — **Teclado e senhas**: guarda anti-keylogger de página, teclado virtual, captura segura de
>   login — `PROTECAO-TECLADO.md`.
> - **1.9.3** — **Terceira auditoria**: perda de `settings.json`/`favorites.json` com perfil ligado (ordem de arranque);
>   leitura sem teto restante; saída dos scanners externos limitada; cookies com contexto desconhecido contados e modo
>   estrito; painel de motores de varredura; `Verificar-NanoDesk.ps1` e guia de assinatura (`ASSINATURA.md`) —
>   `RELATORIO-DE-CORRECOES-1.9.3.txt`.
> - **1.9.2** — **Segunda auditoria**: leitura de respostas com teto em *streaming*; pop-ups por origem
>   completa; cookies de terceiros (requisição **e** `Set-Cookie`); botão do cofre sem canal forjável;
>   senha-mestra de 14+ caracteres; scanner nativo com parser PE real; ClamAV com base persistente
>   opcional e download pelo Tor — `RELATORIO-DE-CORRECOES-1.9.2.txt`.
>
> **Instalação (Windows x64):** extraia o `.rar` completo, rode `Install-NanoDesk.ps1` (ou execute
> `NanoDesk.exe`) e confira `SHA256SUMS.txt` (`node tools/make-sha256sums.js --check .` no código-fonte).
> O pacote **não é assinado** (Authenticode): o SmartScreen vai avisar.

> **Novo na 1.7.0:** vídeo **NATIVO** — todo link do YouTube abre no
> Piped/Invidious automaticamente (com failover de instâncias),
> **SponsorBlock** embutido (pula patrocínios sozinho),
> **Consent-O-Matic** embutido (sempre NEGAR rastreadores, nível máximo),
> **LanguageTool** (clique direito → verificar gramática) e
> **LibraryTranslate** (traduz e salva numa biblioteca consultável).
> Detalhes em `CHANGELOG.md` e `RELATORIO-DE-CORRECOES-1.7.0.txt`.

Projeto acadêmico (Ciência da Computação / Segurança de Redes).
Mini "computador de navegação": uma aplicação de desktop com identidade
visual própria, focada **exclusivamente em navegação web**, priorizando
máquinas modestas (baixa RAM/CPU/armazenamento). Não é um sistema
operacional; não usa virtualização; não executa outros sistemas.

**1.6.0 — Projeto "Navegador de Privacidade e Segurança" (9 fases):**
esta versão implementa a especificação completa por fases — núcleo
modernizado (abas em WebContentsView com sandbox e **sessões isoladas
por contêiner**), **Security Gateway** (alerta antes de sites suspeitos,
quarentena de downloads com tipo real por magic bytes, inspeção de ZIP
sem extrair e adaptadores externos **ClamAV**/**YARA** quando instalados),
**Network Manager** (detecção de VPN, **Tor SOCKS5** em sessão isolada,
**DNS seguro/DoH**, verificação de IP), privacidade ativa (**ClearURLs**
para parâmetros de rastreamento, anti-fingerprinting estilo
**CanvasBlocker** com redução de superfície — sem randomização —,
**StevenBlack hosts** na camada de bloqueio, cookies de terceiros,
WebRTC sem vazamento, HTTPS-first), produtividade (**SearXNG**/**Brave**
na busca, favoritos com **pastas e etiquetas**, **histórico pesquisável**
só em RAM, **Bitwarden** via CLI oficial, **LibreTranslate** com
consentimento) e **vídeo privado** (FreeTube/Invidious/Piped/yt-dlp como
adaptadores externos). Perfil local (configurações+favoritos) é
**opcional e desligado por padrão** — o princípio "zero dados gravados"
permanece.

## Arquitetura (resumo)

```
┌─────────────────────────────────────────────────────────────┐
│ Núcleo Chromium/Electron 45 — WebContentsView por aba,      │
│ sandbox:true, contextIsolation, IPC validado por origem,    │
│ sessões 100% em memória (partição sem persistência)         │
└─────────────────────────────────────────────────────────────┘
│ Privacidade: bloqueio nativo + Ghostery (EasyList/EasyPrivacy)
│   + StevenBlack hosts; ClearURLs; anti-fingerprinting; cookies 3p
│ Rede protegida: detecção de VPN, Tor SOCKS5 isolado, DoH, WebRTC
│ Segurança: URL Gate heurístico; quarentena de downloads;
│   ClamAV/YARA (processos externos opcionais); log de eventos
│ Produtividade: SearXNG/Brave, favoritos c/ pastas+etiquetas,
│   histórico pesquisável, Bitwarden (CLI), LibreTranslate,
│   pdf.js + foliate-js, RSS, vídeo privado
└ Serviços locais e adaptadores: electron-dl, yt-dlp, clamscan,
    yara, bw — TODOS opcionais e externos ao pacote
```

## Como rodar (desenvolvimento)

```bash
npm install          # depende de Node >= 22
npm start            # abre o NanoDesk
npm run selftest     # auto-teste de inicialização (CI)
npm test             # testes unitários (node --test)
npm run test:e2e     # E2E Playwright (opcional)
npm run dist:win     # empacota para Windows x64
```

## Funcionalidades (1.6.0)

### Núcleo e sessões (FASE 2)
- Abas em **WebContentsView** (processo principal), suspensão automática,
  busca na página, zoom, impressão, DevTools.
- **Sessões isoladas (contêineres)**: até 8 sessões com cookies/armazenamento
  próprios — tudo em RAM. Menu de contexto da aba: "Nova aba nesta sessão",
  "Mover para sessão…". Marcador colorido na aba.
- **Perfil local opcional** (desligado por padrão): mantém apenas
  configurações e favoritos entre sessões (arquivos pequenos em `userData`,
  gravação atômica). Histórico, cookies e dados de sites **nunca** são
  gravados — nem com o perfil ligado.
- Downloads via `electron-dl`: limite de 2 GB/5 simultâneos, confirmação
  de executáveis (nada toca o disco antes), SHA-256 de integridade.

### Segurança Electron (FASE 3)
- `sandbox: true`, `contextIsolation: true`, `nodeIntegration: false` em
  TODAS as janelas e abas; sem tag `<webview>`.
- **HTTPS-first**: endereços `http://` são tentados em `https://` primeiro;
  em erro de TLS cai para HTTP uma única vez com aviso explícito.
- **Certificados inválidos sempre rejeitados** (evento registrado no painel).
- **Cookies de terceiros bloqueados** (Cookie de saída e Set-Cookie de
  entrada, por eTLD+1 via tldts).
- **WebRTC**: política `disable_non_proxied_udp` (sem vazamento de IP).
- Permissões negadas por padrão; câmera/microfone/localização/notificações/
  MIDI pedem em diálogo nativo (decisão só na sessão).
- IPC validado por origem (arquivo do renderer + frame de topo; leitores
  validados por `ndr://readers/` + aba-leitor real).

### Privacidade ativa (FASE 4)
- **Bloqueio de anúncios/rastreadores** em 3 camadas no MESMO listener de
  webRequest: motor nativo (domínios+padrões), **Ghostery
  (@ghostery/adblocker)** com EasyList+EasyPrivacy (online com fallback
  offline verificado por SHA-256) e **StevenBlack hosts** (MIT, baixado em
  tempo de execução — nada é embutido nem gravado). Filtros cosméticos CSS.
  Allowlist por host que NÃO libera rastreadores de terceiros.
- **Limpeza de parâmetros de rastreamento** (conceito ClearURLs, código
  original): utm_*, fbclid, gclid, `si` do YouTube, `t`/`s` do X, `trk` do
  LinkedIn, amazon `tag/ref_*`… aplicado ao digitar e ao clicar links.
- **Anti-fingerprinting** (conceito CanvasBlocker, redução sem
  randomização): canvas com ruído LSB determinístico e visualmente
  idêntico; WebGL `UNMASKED_*` responde GPU genérica popular ("Intel
  Iris"); áudio com ruído de 1e-7 (inaudível). Injetado em todas as frames
  da sessão por preload (main world via `webFrame.executeJavaScript`),
  idempotente e desligável nas configurações. UA/timezone/idioma NÃO são
  alterados (consistência entre APIs).
- **Gestão de listas**: painel mostra status de cada lista (nativa,
  EasyList/EasyPrivacy, StevenBlack) com licenças e fontes.

### Rede, VPN e Tor (FASE 5)
- **Detecção de VPN** por interfaces do SO (WireGuard/Mullvad/OpenVPN/
  Tailscale/NordLynx/Proton…) — indicador visual na barra. Nenhuma VPN
  fictícia: o Mullvad é tratado como cliente externo.
- **Tor SOCKS5** (127.0.0.1:9050 configurável) aplicado à sessão via
  `session.setProxy` — DNS resolvido pelo proxy (sem vazamento). O
  NanoDesk NÃO instala nem gerencia o Tor: o cliente desktop é do usuário.
  Orbot (Android) não é apresentado como cliente Windows.
- **DNS seguro (DoH)**: Cloudflare/Cloudflare Family/Quad9/Google/template
  próprio, modo automático ou **restrito** (aplica ao reiniciar).
- **Verificação de IP** sob demanda (ifconfig.co pela própria sessão —
  mostra o efeito real do VPN/Tor). Nada é consultado por conta própria.
- Aviso de vazamento: Tor ativo + WebRTC desprotegido.

### Security Gateway (FASE 6)
- **Análise heurística de URLs** (conceito URLCheck, código original,
  100% local): punycode/homoglifos, TLDs de abuso, encurtadores, marca em
  domínio de terceiro, IP literal, dupla extensão (`.pdf.exe` → crítico),
  parâmetros que escondem outro URL… Diálogo nativo antes de navegar com
  "Voltar / Navegar mesmo assim / Confiar nesta sessão".
- **Downloads verificados**: tipo REAL por magic bytes (pega executável
  disfarçado de .pdf), inspeção de ZIP/CBZ/EPUB sem extrair (executáveis
  dentro, zip bomb, path traversal), SHA-256, e adaptadores opcionais
  **ClamAV** e **YARA** (binários do usuário; nunca distribuídos junto).
- **Quarentena**: arquivos suspeitos vão para
  `Downloads\NanoDesk-Quarantine`; liberar/excluir pela interface.
- Veredito conservador: "nada encontrado" NUNCA é apresentado como
  garantia de segurança. Log de eventos (certificados, URL Gate,
  varreduras, quarentena) só em RAM.

### Busca e produtividade (FASE 7)
- Buscadores: DuckDuckGo, Startpage, **Brave**, **SearXNG** (instância
  própria), Bing, Google.
- Favoritos com **pastas e etiquetas**, busca, export/import JSON (arquivo
  escolhido pelo usuário).
- **Histórico pesquisável** (só RAM, some ao fechar).
- **Bitwarden** via CLI oficial (`bw`): busca logins do site atual e
  preenche o formulário; NADA é armazenado pelo NanoDesk; exige cofre
  destravado (`BW_SESSION`).
- **LibreTranslate**: servidor configurável (local = processamento no PC);
  traduz seleção (menu de contexto) ou página (via pipeline do Modo
  Leitura); SEM consentimento nada é enviado.
- Leitores internos: **pdf.js** (PDF) e **foliate-js** (EPUB/MOBI/AZW3/
  FB2/CBZ) com CSP restritiva; Modo Leitura; leitor RSS/Atom com OPML.

### Vídeo privado (FASE 8)
- **FreeTube** (app externo, deep link `freetube://`),
  **Invidious**/**Piped** (instâncias configuráveis, redirecionamento
  automático opcional), **yt-dlp** (binário externo; download sob demanda —
  somente conteúdos autorizados). DeArrow: incompatível nativamente no
  Electron (limitação documentada — não há botão fictício).

## Segurança do Electron (obrigatório da especificação)
`nodeIntegration: false` · `contextIsolation: true` · `sandbox: true` ·
`webSecurity: true` · CSP restritiva na interface e nos leitores · IPC
validado por origem · permissões negadas por padrão · navegação controlada
(somente HTTP/HTTPS) · sem APIs de Node para páginas externas · logs sem
dados sensíveis.

## Testes
- **50 testes unitários** (`npm test`): limpeza de URLs, fingerprint,
  parser de hosts, URL Gate, magic bytes/ZIP/veredito, rede (DoH/Tor/VPN),
  histórico, perfil, Bitwarden, tradução, vídeo, validações + regressão
  1.5.2.
- **selftest** (`npm run selftest`): auto-teste de inicialização usado na
  validação do build.
- **E2E** (`tests/e2e-electron.js`): fluxo de abas/leitores em Electron
  real (opcional, requer binário do Electron).

## Licenças (resumo — veja THIRD_PARTY_NOTICES.md para o inventário completo e auditado)
- Código próprio: MIT.
- Executado dentro do app: Electron 45.4.1 (MIT), @ghostery/adblocker (MPL-2.0),
  electron-dl (MIT), pdf.js 3.11.174 (Apache-2.0), foliate-js (MIT),
  zip.js (BSD-3), fflate (MIT), tldts (MIT).
- Listas de filtro: EasyList/EasyPrivacy (GPL-3.0+ OU CC-BY-SA-3.0+; uso sob
  CC-BY-SA-3.0+), listas uBlock/uAssets ×11 (GPL-3.0), StevenBlack hosts (MIT).
- Estudados como REFERÊNCIA (sem copiar código): uBlock Origin (GPL-3.0),
  PopUpOFF (Apache-2.0), Popup Blocker strict (MPL-2.0), ClearURLs (LGPL-3.0),
  CanvasBlocker (MPL-2.0), URLCheck (CC-BY-4.0), RedirectGuard (MIT — não
  verificado), Popup-Blocker-Pro (MIT), Consent-O-Matic (MIT), Bitwarden
  (GPL-3.0, referência histórica — substituído pelo cofre nativo),
  LibreTranslate (AGPL-3.0, via API HTTP), Mullvad (GPL-3.0),
  FreeTube/Invidious/Piped (AGPL-3.0, apps/serviços externos),
  SponsorBlock (GPL-3.0, API).
- Binários no build Windows (não no repositório): aria2 1.37.0 (GPL-2.0 +
  OpenSSL exception), ClamAV 1.5.4 (GPL-2.0), FFmpeg 8.1 (LGPL-3.0,
  build lgpl-shared), yt-dlp 2026.10.26 (Unlicense), Tor 16.0 (BSD-3-Clause),
  YARA (BSD-3, binário externo). Procedência SHA-256 em *ORIGEM.txt.

## O que é gravado em disco (honesto)
O NanoDesk usa partições de sessão **sem persistência** (cookies, localStorage e IndexedDB ficam só em RAM).
Mas "100 % em memória" **não** significa "nada no disco". O que existe:

| O quê | Onde | Quando some |
|---|---|---|
| Pasta de sessão `nanodesk-session-*` (cache de rede do Chromium, shaders/GPU, dados do Tor, base do ClamAV, atualização do yt-dlp, dumps de crash) | pasta temporária do Windows (`%TEMP%`) | apagada ao fechar; resíduos de sessões que terminaram mal são apagados na abertura seguinte |
| Cofre de senhas `nanodesk-vault.json` (cifrado AES-256-GCM, PBKDF2 600 mil) | `userData` | só você apaga — ou ligue o **cofre temporário** (só RAM) |
| Cache do bloqueador `cache-filtros/` | `userData` | opção "Guardar o cache do bloqueador em disco" (ligada por padrão; desligue para não deixar nada) |
| Base do ClamAV (~300 MB) | `userData/clamav-db` **só** se você ligar "Guardar a base do antivírus"; senão fica na pasta de sessão | quando você apagar |
| Downloads e páginas arquivadas | pasta que **você** escolhe | — |
| Perfil local (favoritos, histórico, configurações) | `userData` | só com "perfil local" ligado (desligado por padrão) |

Dados que estiveram em RAM podem ir parar no arquivo de paginação do Windows ou em dumps de memória — o NanoDesk
não controla isso.

## Notas de privacidade honestas
- O modo privado do NanoDesk protege dados no SEU computador. Não esconde
  seu tráfego do provedor; para isso use VPN (externa) ou Tor (cliente
  desktop + modo Tor nas configurações).
- "Nenhuma ameaça detectada" em varreduras não significa arquivo seguro. Sem a base do ClamAV (por exemplo
  com o Tor em uso) o download aparece como **"SEM varredura antivírus"**: a análise local é só heurística.
- Tradução com servidor externo envia o texto ao servidor configurado —
  sempre com consentimento explícito por ação.

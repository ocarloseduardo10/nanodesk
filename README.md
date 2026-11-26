# NanoDesk 1.9.6 — Navegador ultraleve, privado e auditável

Projeto acadêmico (Ciência da Computação / Segurança de Redes): uma aplicação
de desktop com identidade visual própria, focada **exclusivamente em navegação
web**, priorizando máquinas modestas (baixa RAM/CPU/armazenamento). Não é um
sistema operacional; não usa virtualização.

> **Status:** código-fonte publicado para transparência, com auditoria de
> segurança e de cadeia de suprimentos documentada. O repositório contém o
> código — os binários do build (Electron, ClamAV, FFmpeg, aria2, yt-dlp, Tor)
> **não são redistribuídos aqui**; a proveniência de cada um está documentada
> em [`nanodesk/app-src/THIRD_PARTY_NOTICES.md`](nanodesk/app-src/THIRD_PARTY_NOTICES.md).

## O que o NanoDesk faz

- **Sessões 100% em memória** — cookies, localStorage e IndexedDB só em RAM
  (partição sem persistência); perfil local é opcional e desligado por padrão.
- **Privacidade ativa** — bloqueio nativo + Ghostery/EasyList/EasyPrivacy,
  StevenBlack hosts, limpeza de URLs estilo ClearURLs, anti-fingerprinting por
  redução de superfície (sem randomização), cookies de terceiros bloqueados,
  WebRTC sem vazamento, HTTPS-first.
- **Security Gateway** — alerta antes de sites suspeitos, quarentena de
  downloads com tipo real por *magic bytes*, inspeção de ZIP sem extrair,
  ClamAV/YARA como adaptadores externos opcionais.
- **Rede protegida** — detecção de VPN, **Tor SOCKS5** em sessão isolada,
  DNS seguro/DoH, verificação de IP.
- **Vídeo privado** — YouTube via Piped/Invidious com failover, SponsorBlock
  (k-anônimo, desligado por padrão), yt-dlp/FreeTube como adaptadores externos.
- **Produtividade** — SearXNG/Brave na busca, favoritos com pastas e etiquetas,
  histórico pesquisável só em RAM, pdf.js + foliate-js, RSS, cofre de senhas
  nativo, LibreTranslate com consentimento.
- **Teclado e senhas (1.9.1)** — guarda anti-keylogger de página, teclado
  virtual e captura segura de login.
- **Arquivar página (1.9.0)** — snapshot completo em arquivo `.html` único,
  nativo e privado.

## Estrutura do repositório

| Caminho | Conteúdo |
| --- | --- |
| [`nanodesk/app-src/`](nanodesk/app-src/README.md) | Código-fonte completo (main process, preload, renderer) |
| `nanodesk/app-src/tools/` | Utilitários de build (`set-pe-version.js`, `make-sha256sums.js`) |
| `nanodesk/app-src/tests/` | Matriz de testes (WSTG) e roteiros manuais |
| `nanodesk/app-src/sbom.cdx.json` | SBOM CycloneDX 1.5 das dependências npm |

## Documentação

- [README completo — recursos, arquitetura, build e changelog](nanodesk/app-src/README.md)
- [THIRD_PARTY_NOTICES — inventário auditado de terceiros](nanodesk/app-src/THIRD_PARTY_NOTICES.md)
- [DEPENDENCIES — 218 pacotes npm classificados por licença](nanodesk/app-src/DEPENDENCIES.md)
- [LICENSES — licenças de referências conceituais](nanodesk/app-src/LICENSES.md)
- [NOTICE — avisos resumidos](nanodesk/app-src/NOTICE.md)
- `nanodesk/app-src/CHANGELOG.md` — histórico de versões

## Auditoria de cadeia de suprimentos (2026-11-26)

- 218 pacotes npm conferidos um a um contra o registry (nome, versão,
  licença, integridade) — inventário em `DEPENDENCIES.md` e SBOM.
- Proveniência e SHA-256 de todo binário redistribuído (aria2, ClamAV, FFmpeg,
  yt-dlp, Tor) documentados nos arquivos `*ORIGEM.txt`.
- Licenças de todas as referências conceituais verificadas na fonte
  (correções registradas em `THIRD_PARTY_NOTICES.md`).
- Busca de segredos (gitleaks) e verificação de endpoints/telemetria:
  nenhuma ocorrência.
- CI proposto: `npm audit`, Dependency Review, gitleaks e validação de SBOM
  (`.github/workflows/supply-chain.yml` — aguardando permissão `workflow` do
  token para publicar).

## Build (Windows x64, a partir de `nanodesk/app-src/`)

```bash
npm install
npm run dist:win        # electron-packager
npm run postdist:win    # grava versão nos metadados PE + gera SHA256SUMS.txt
npm run verify:sums     # confere o hash de todos os arquivos do build
```

## Licença

[MIT](LICENSE) — código próprio do projeto. Componentes de terceiros seguem
suas próprias licenças, inventariadas em
[`THIRD_PARTY_NOTICES.md`](nanodesk/app-src/THIRD_PARTY_NOTICES.md).

> **Aviso:** projeto acadêmico sem afiliação com os autores das referências.
> Os binários do build **não são assinados** (Authenticode): o SmartScreen do
> Windows avisará ao executar. Use por sua conta e risco.

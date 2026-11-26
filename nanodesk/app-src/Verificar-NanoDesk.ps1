<#
.SYNOPSIS
  Verifica a integridade do pacote NanoDesk (SHA256SUMS.txt) e mostra o estado da assinatura Authenticode.
.DESCRIPTION
  1.9.3. Confere TODOS os arquivos listados em SHA256SUMS.txt e acusa:
    - DIFERENTE: o conteúdo mudou desde que o pacote foi gerado;
    - AUSENTE: arquivo listado que não existe;
    - NÃO LISTADO: arquivo presente que não está na lista (possível DLL plantada ao lado do exe).
  ATENÇÃO: o SHA256SUMS.txt NÃO é assinado. Quem consegue alterar o pacote também consegue alterar a lista.
  Compare o hash do próprio SHA256SUMS.txt com o publicado num canal separado (ver ASSINATURA.md).
.PARAMETER Dir         Pasta do pacote (padrão: a pasta deste script).
.PARAMETER AllowExtra  Não falha por arquivos NÃO LISTADOS (ex.: você guardou algo na pasta).
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Verificar-NanoDesk.ps1
#>
[CmdletBinding()]
param(
  [string]$Dir = $PSScriptRoot,
  [switch]$AllowExtra
)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Dir)) { $Dir = (Get-Location).Path }
$root = (Resolve-Path -LiteralPath $Dir).Path.TrimEnd('\', '/')
$sums = Join-Path $root 'SHA256SUMS.txt'
if (-not (Test-Path -LiteralPath $sums -PathType Leaf)) { Write-Error "SHA256SUMS.txt não encontrado em $root"; exit 2 }

$listed = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$ok = 0; $bad = 0; $missing = 0; $extra = 0
foreach ($line in (Get-Content -LiteralPath $sums -Encoding UTF8)) {
  if ([string]::IsNullOrWhiteSpace($line)) { continue }
  if ($line -notmatch '^([0-9a-fA-F]{64})\s+\*?(.+)$') { Write-Warning "Linha inválida em SHA256SUMS.txt: $line"; $bad++; continue }
  $want = $Matches[1].ToLowerInvariant()
  $rel = $Matches[2].Trim()
  # nunca sai da pasta do pacote (nem por .. nem por caminho absoluto)
  if ($rel -match '(^|[\\/])\.\.([\\/]|$)' -or [System.IO.Path]::IsPathRooted($rel)) { Write-Warning "Caminho recusado: $rel"; $bad++; continue }
  [void]$listed.Add(($rel -replace '\\', '/'))
  $file = Join-Path $root $rel
  if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { Write-Warning "AUSENTE:    $rel"; $missing++; continue }
  $got = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($got -ne $want) { Write-Warning "DIFERENTE:  $rel"; $bad++ } else { $ok++ }
}

# arquivos presentes que a lista não conhece
$prefixLen = $root.Length + 1
foreach ($f in (Get-ChildItem -LiteralPath $root -Recurse -File -Force)) {
  $rel = ($f.FullName.Substring($prefixLen)) -replace '\\', '/'
  if ($rel -ieq 'SHA256SUMS.txt') { continue }
  if (-not $listed.Contains($rel)) { Write-Warning "NÃO LISTADO: $rel"; $extra++ }
}

Write-Host ("Conferidos: {0} OK, {1} diferentes/inválidos, {2} ausentes, {3} não listados." -f $ok, $bad, $missing, $extra)
$sumsHash = (Get-FileHash -LiteralPath $sums -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "SHA-256 do próprio SHA256SUMS.txt: $sumsHash"
Write-Host "  (compare com o valor publicado em um canal SEPARADO; a lista, sozinha, não prova autenticidade)"

$exe = Join-Path $root 'NanoDesk.exe'
if (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue) {
  $sig = Get-AuthenticodeSignature -LiteralPath $exe
  if ($sig.Status -eq 'Valid') { Write-Host "Assinatura Authenticode de NanoDesk.exe: VÁLIDA ($($sig.SignerCertificate.Subject))" }
  elseif ($sig.Status -eq 'NotSigned') { Write-Warning "NanoDesk.exe NÃO é assinado (Authenticode). O SmartScreen vai avisar; a integridade acima é a única garantia." }
  else { Write-Warning "Assinatura Authenticode de NanoDesk.exe: $($sig.Status) — NÃO confie." }
} else {
  Write-Host "Authenticode: verificação indisponível neste sistema (só no Windows)."
}

if ($bad -gt 0 -or $missing -gt 0 -or ($extra -gt 0 -and -not $AllowExtra)) { Write-Host 'RESULTADO: FALHOU'; exit 1 }
Write-Host 'RESULTADO: pacote íntegro'
exit 0

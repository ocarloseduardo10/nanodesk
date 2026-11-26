<#
.SYNOPSIS
  Instala o NanoDesk para o usuário atual, sem privilégios administrativos.
.DESCRIPTION
  Copia a distribuição para %LOCALAPPDATA%\Programs\NanoDesk e cria atalhos.
#>
[CmdletBinding()]
param(
  [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\NanoDesk'),
  [switch]$NoLaunch
)
$ErrorActionPreference = 'Stop'

$sourceDir = $PSScriptRoot
$sourceExe = Join-Path $sourceDir 'NanoDesk.exe'
if (-not (Test-Path -LiteralPath $sourceExe -PathType Leaf)) {
  throw "NanoDesk.exe não foi encontrado em: $sourceDir. Extraia o ZIP completo antes de instalar."
}

$sourceFull = [IO.Path]::GetFullPath($sourceDir).TrimEnd('\')
$targetFull = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
# 1.8.11: GUARDA DE SEGURANCA. Antes, -InstallDir apontando para uma pasta existente (ex.: Documentos)
# movia a pasta para .__backup e depois a APAGAVA. Agora so substitui uma pasta que ja seja uma
# instalacao do NanoDesk (contem NanoDesk.exe) ou que esteja vazia/inexistente.
if ($sourceFull -ne $targetFull) {
  if ([IO.Path]::GetPathRoot($targetFull).TrimEnd('\') -eq $targetFull) {
    throw "Caminho de instalacao invalido (raiz de unidade): $targetFull"
  }
  if ($sourceFull.StartsWith($targetFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "A pasta de instalacao nao pode conter a pasta de origem: $targetFull"
  }
  if (Test-Path -LiteralPath $targetFull) {
    $hasContent = @(Get-ChildItem -LiteralPath $targetFull -Force -ErrorAction SilentlyContinue).Count -gt 0
    $isNano = Test-Path -LiteralPath (Join-Path $targetFull 'NanoDesk.exe') -PathType Leaf
    if ($hasContent -and -not $isNano) {
      throw "A pasta $targetFull ja existe e NAO e uma instalacao do NanoDesk. Escolha outra pasta ou uma vazia (nada foi alterado)."
    }
  }
  $running = Get-Process -Name 'NanoDesk' -ErrorAction SilentlyContinue
  if ($running) {
    Write-Host 'Fechando a versão em execução...'
    $running | Stop-Process -Force
    Start-Sleep -Milliseconds 500
  }
  $parentDir = Split-Path -Parent $targetFull
  New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
  $stagingDir = $targetFull + '.__staging'
  $backupDir = $targetFull + '.__backup'
  if (Test-Path -LiteralPath $stagingDir) { Remove-Item -LiteralPath $stagingDir -Recurse -Force }
  New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
  try {
    Get-ChildItem -LiteralPath $sourceDir -Force | ForEach-Object {
      Copy-Item -LiteralPath $_.FullName -Destination $stagingDir -Recurse -Force
    }
    if (Test-Path -LiteralPath $backupDir) { Remove-Item -LiteralPath $backupDir -Recurse -Force }
    if (Test-Path -LiteralPath $targetFull) { Move-Item -LiteralPath $targetFull -Destination $backupDir }
    try {
      Move-Item -LiteralPath $stagingDir -Destination $targetFull
      if (Test-Path -LiteralPath $backupDir) { Remove-Item -LiteralPath $backupDir -Recurse -Force }
    } catch {
      if ((Test-Path -LiteralPath $backupDir) -and -not (Test-Path -LiteralPath $targetFull)) { Move-Item -LiteralPath $backupDir -Destination $targetFull }
      throw
    }
  } catch {
    if (Test-Path -LiteralPath $stagingDir) { Remove-Item -LiteralPath $stagingDir -Recurse -Force }
    throw
  }
}

$exe = Join-Path $targetFull 'NanoDesk.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'A cópia do executável falhou.' }
$desktop = [Environment]::GetFolderPath('Desktop')
$startMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
New-Item -ItemType Directory -Path $startMenu -Force | Out-Null
$wsh = New-Object -ComObject WScript.Shell
foreach ($shortcutPath in @((Join-Path $desktop 'NanoDesk.lnk'), (Join-Path $startMenu 'NanoDesk.lnk'))) {
  $shortcut = $wsh.CreateShortcut($shortcutPath)
  $shortcut.TargetPath = $exe
  $shortcut.WorkingDirectory = $targetFull
  $shortcut.Description = 'NanoDesk — navegador leve'
  $icon = Join-Path $targetFull 'nanodesk.ico'
  if (Test-Path -LiteralPath $icon) { $shortcut.IconLocation = "$icon,0" }
  $shortcut.Save()
}
Write-Host "NanoDesk instalado em: $targetFull" -ForegroundColor Green
if (-not $NoLaunch) { Start-Process -FilePath $exe -WorkingDirectory $targetFull }

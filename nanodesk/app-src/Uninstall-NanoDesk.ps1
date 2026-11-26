<#
.SYNOPSIS
  NanoDesk - Desinstalador para o usuário atual.
.DESCRIPTION
  Remove atalhos e a pasta de instalação. O perfil local é opcional.
#>
[CmdletBinding()]
param([string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\NanoDesk'))
$ErrorActionPreference = 'Stop'

$desktopShortcut = Join-Path ([Environment]::GetFolderPath('Desktop')) 'NanoDesk.lnk'
$startShortcut = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\NanoDesk.lnk'
foreach ($shortcut in @($desktopShortcut, $startShortcut)) {
  if (Test-Path -LiteralPath $shortcut) { Remove-Item -LiteralPath $shortcut -Force }
}

Get-Process -Name 'NanoDesk' -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500
if (Test-Path -LiteralPath $InstallDir) {
  $resolvedInstall = [IO.Path]::GetFullPath($InstallDir)
  $localPrograms = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Programs'))
  $allowedPrefix = $localPrograms.TrimEnd('\') + [IO.Path]::DirectorySeparatorChar
  if (-not $resolvedInstall.StartsWith($allowedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Por segurança, o desinstalador só remove caminhos dentro de LocalAppData\Programs.'
  }
  # 1.8.11: so remove se a pasta for mesmo uma instalacao do NanoDesk
  if (-not (Test-Path -LiteralPath (Join-Path $resolvedInstall 'NanoDesk.exe') -PathType Leaf)) {
    throw "Por seguranca, '$resolvedInstall' nao parece uma instalacao do NanoDesk (NanoDesk.exe ausente). Nada foi removido."
  }
  Remove-Item -LiteralPath $resolvedInstall -Recurse -Force
}

$profileDir = Join-Path $env:APPDATA 'NanoDesk'
if (Test-Path -LiteralPath $profileDir) {
  $answer = Read-Host 'Também apagar o perfil local (histórico, favoritos, configurações e downloads)? [s/N]'
  if ($answer -match '^[sSyY]') {
    Remove-Item -LiteralPath $profileDir -Recurse -Force
    Write-Host 'Perfil local removido.'
  }
}
Write-Host 'NanoDesk desinstalado.' -ForegroundColor Green

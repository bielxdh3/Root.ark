param(
  [Parameter(Mandatory = $true)]
  [string]$PickerScriptPath
)

$ErrorActionPreference = 'Stop'
$fixtureBase = if ($env:ROOTARK_TEST_ROOT) { [IO.Path]::GetFullPath($env:ROOTARK_TEST_ROOT) } else { [IO.Path]::GetTempPath() }
$scratch = Join-Path $fixtureBase ('issue66-picker-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -ErrorAction Stop | Out-Null
try {
  $config = Join-Path $scratch 'config.json'
  $folder = Join-Path $scratch 'sync-data'
  $selected = Join-Path $folder 'docs\real.txt'
  $stale = Join-Path $scratch 'stale-working-directory'
  New-Item -ItemType Directory -Path (Split-Path -Parent $selected) -Force | Out-Null
  New-Item -ItemType Directory -Path $stale -Force | Out-Null
  Set-Content -LiteralPath $config -Value '{"localFolder":"sync-data"}' -Encoding UTF8
  Set-Content -LiteralPath $selected -Value 'signed and hydrated bytes' -Encoding UTF8

  $global:Issue66CapturedExplorerArgs = @()
  $global:Issue66CapturedExplorerExe = $null
  function node {
    $global:LASTEXITCODE = 0
    if ($args[1] -eq 'browse') {
      return '{"objects":[{"selectedOnDevice":true,"tombstone":false,"metadata":{"path":"docs/real.txt","contentType":"text/plain","size":25}}],"nextCursor":null}'
    }
    if ($args[1] -eq 'hydrate') { return '{"action":"hydrate","result":true}' }
    throw 'Unexpected fake Node CLI invocation'
  }
  function Out-GridView {
    [CmdletBinding()]
    param([string]$Title, [string]$OutputMode, [Parameter(ValueFromPipeline = $true)]$InputObject)
    process { if ($OutputMode -ne 'Single') { throw 'Picker must request single selection' }; $InputObject }
  }
  function Start-Process {
    param([string]$FilePath, [string[]]$ArgumentList)
    $global:Issue66CapturedExplorerArgs = @($ArgumentList)
    $global:Issue66CapturedExplorerExe = $FilePath
  }

  Push-Location -LiteralPath $stale
  try { & $PickerScriptPath -Config $config }
  finally { Pop-Location }

  $expected = '/select,"' + $selected + '"'
  if ($global:Issue66CapturedExplorerArgs.Count -ne 1 -or
      -not [string]::Equals($global:Issue66CapturedExplorerArgs[0], $expected, [StringComparison]::OrdinalIgnoreCase)) {
    throw ('Picker resolved a path relative to the working directory or selected an unexpected target. expected=' + $expected + ', actual=' + ($global:Issue66CapturedExplorerArgs -join ','))
  }
  if (-not $global:Issue66CapturedExplorerExe.EndsWith('\explorer.exe', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Picker did not reveal the file using Explorer'
  }
  Write-Output 'PASS: picker selects config-relative, hydrated target even from stale cwd, without launching Node'
} finally {
  if ($scratch.StartsWith($fixtureBase.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -and
      (Split-Path -Leaf $scratch) -match '^issue66-picker-[0-9a-f]{32}$') {
    Remove-Item -LiteralPath $scratch -Recurse -Force
  } else {
    throw 'Unsafe scratch cleanup path'
  }
}

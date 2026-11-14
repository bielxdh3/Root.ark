# Windows Explorer-assisted Files On-Demand. This is a picker, not a CFAPI provider.
param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$Config
)

function Resolve-RootArkPath([string]$base, [string]$target) {
  if ([string]::IsNullOrWhiteSpace($target)) { return $base }
  $cleanTarget = $target.Replace('/', '\')
  $isFullyQualified = if ($null -ne [IO.Path].GetMethod('IsPathFullyQualified', [type[]]@([string]))) {
    [IO.Path]::IsPathFullyQualified($cleanTarget)
  } else {
    $cleanTarget -match '^[A-Za-z]:\\' -or $cleanTarget -match '^\\\\'
  }
  if ($isFullyQualified) {
    return [IO.Path]::GetFullPath($cleanTarget)
  }
  if ($cleanTarget -match '^\\') {
    $driveRoot = [IO.Path]::GetPathRoot($base)
    if ([string]::IsNullOrEmpty($driveRoot)) { $driveRoot = '\' }
    return [IO.Path]::GetFullPath([IO.Path]::Combine($driveRoot, $cleanTarget.TrimStart('\')))
  }
  if ($cleanTarget -match '^([A-Za-z]:)(.*)$') {
    $drive = $Matches[1]
    $relativePart = $Matches[2].TrimStart('\')
    $baseDrive = if ($base -match '^([A-Za-z]:)') { $Matches[1] } else { '' }
    if ($baseDrive -and $drive.Equals($baseDrive, [System.StringComparison]::OrdinalIgnoreCase)) {
      return [IO.Path]::GetFullPath([IO.Path]::Combine($base, $relativePart))
    }
    return [IO.Path]::GetFullPath([IO.Path]::Combine("$drive\", $relativePart))
  }
  return [IO.Path]::GetFullPath([IO.Path]::Combine($base, $cleanTarget))
}

$Config = Resolve-RootArkPath (Get-Location).ProviderPath $Config

$ErrorActionPreference = 'Stop'
$previousOutputEncoding = [Console]::OutputEncoding
try {
# Windows PowerShell 5.1 otherwise decodes Node's UTF-8 JSON using the OEM
# codepage, corrupting signed remote filenames before the hydrate lookup.
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$syncCli = Join-Path $PSScriptRoot 'rootark-sync-v2.js'
$files = New-Object 'System.Collections.Generic.List[object]'
$seenCursors = New-Object 'System.Collections.Generic.HashSet[string]'
$cursor = $null
$complete = $false

for ($pageNumber = 0; $pageNumber -lt 1024; $pageNumber++) {
  $arguments = @($syncCli, 'browse', '--config', $Config, '--limit', '64')
  if ($null -ne $cursor) { $arguments += @('--cursor', $cursor) }
  $json = & node @arguments
  if ($LASTEXITCODE -ne 0) { throw 'Root.ark metadata inventory failed; no file was hydrated.' }
  $page = ($json -join "`n") | ConvertFrom-Json
  if ($null -eq $page -or $null -eq $page.objects) { throw 'Invalid remote metadata page.' }
  $records = @($page.objects)
  if ($records.Count -gt 64 -or ($records.Count -eq 0 -and $null -ne $page.nextCursor)) {
    throw 'Invalid remote metadata pagination.'
  }
  foreach ($record in $records) {
    if ($record.selectedOnDevice -ne $true -or $record.tombstone -eq $true -or
      $record.metadata.contentType -eq 'inode/directory' -or
      [string]::IsNullOrWhiteSpace($record.metadata.path)) { continue }
    $files.Add([pscustomobject]@{ Path = [string]$record.metadata.path; Size = $record.metadata.size })
  }
  if ($null -eq $page.nextCursor) { $complete = $true; break }
  $next = $page.nextCursor
  if ($next -isnot [string] -or $next.Length -gt 4096 -or $next.Length -eq 0 -or
    $next.StartsWith('--') -or -not $seenCursors.Add($next)) {
    throw 'Invalid or repeated remote metadata cursor.'
  }
  $cursor = $next
}

if (-not $complete) { throw 'Remote metadata inventory exceeds 65536 entries.' }
if ($files.Count -eq 0) { Write-Output 'No remote files in the selected device scope.'; return }
if (-not (Get-Command Out-GridView -ErrorAction SilentlyContinue)) {
  throw 'Out-GridView requires Windows PowerShell with the GraphicalTools feature.'
}

$chosen = @($files | Out-GridView -Title 'Root.ark - select a remote file to hydrate' -PassThru)
if ($chosen.Count -eq 0) { return }
if ($chosen.Count -ne 1) { throw 'Select exactly one file.' }

# Only the existing engine may turn advisory metadata into bytes; it rechecks
# remote identity, signed authorization, AEAD, journal and local overwrite safety.
$hydratedJson = & node $syncCli hydrate --config $Config ('--path=' + [string]$chosen[0].Path)
if ($LASTEXITCODE -ne 0) { throw 'Root.ark refused hydration; Explorer was not opened.' }
$hydrated = ($hydratedJson -join "`n") | ConvertFrom-Json
if ($hydrated.action -ne 'hydrate' -or $hydrated.result -isnot [bool] -or $hydrated.result -ne $true) {
  throw 'Root.ark hydration did not confirm a file.'
}

# Reveal only. Opening an associated app automatically could execute remote content.
$localFolder = [string]((Get-Content -LiteralPath $Config -Raw -Encoding UTF8 | ConvertFrom-Json).localFolder)
if ([string]::IsNullOrWhiteSpace($localFolder)) { throw 'Local sync folder unavailable.' }
$configDir = Split-Path -Parent $Config
$root = Resolve-RootArkPath $configDir $localFolder
$target = [IO.Path]::GetFullPath((Join-Path $root ([string]$chosen[0].Path -replace '/', '\')))
$rootPrefix = $root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
if (-not $target.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
  -not (Test-Path -LiteralPath $target -PathType Leaf)) {
  throw 'Hydrated file is missing or outside the local sync folder.'
}
Start-Process -FilePath (Join-Path $env:WINDIR 'explorer.exe') -ArgumentList @(('/select,"' + $target + '"')) | Out-Null
} finally {
  [Console]::OutputEncoding = $previousOutputEncoding
}

param(
  [Parameter(Mandatory=$true)][ValidateSet('protect','verify')][string]$Action,
  [Parameter(Mandatory=$true)][string]$Directory
)

# Invoked only on Windows by the opt-in legacy evidence scanner. The process
# MUST finish successfully before the caller may put any SQLite bytes here.
$ErrorActionPreference = 'Stop'
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User
$system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$trusted = @($me.Value, $system.Value, $admins.Value)
$installer = (New-Object Security.Principal.NTAccount('NT SERVICE', 'TrustedInstaller')).Translate(
  [Security.Principal.SecurityIdentifier]).Value
$trustedOwners = @($me.Value, $system.Value, $admins.Value, $installer)

function Assert-Directory([string]$name, [bool]$isSnapshot, [bool]$isDirectParent) {
  $info = New-Object IO.DirectoryInfo($name)
  if (-not $info.Exists -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Untrusted directory or reparse point'
  }
  $acl = [IO.Directory]::GetAccessControl($info.FullName)
  $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($owner -notin $trustedOwners) { throw 'Untrusted directory owner' }
  if ($isSnapshot -and (-not $acl.AreAccessRulesProtected -or $owner -ne $me.Value)) {
    throw 'Private snapshot DACL is not protected'
  }

  # Explicit delete/overwrite/privilege-changing rights PLUS raw Windows
  # GENERIC_ALL (0x10000000) and GENERIC_WRITE (0x40000000), which can
  # survive as generic mask bits rather than FILE_* expansions. Treat both
  # as unsafe even when the low-level FILE_WRITE masks are absent.
  # InheritOnly ACEs on the direct parent still affect newly created children.
  # CreateSubdirectories/AppendData alone may create an unrelated sibling;
  # a random O_EXCL snapshot name cannot be replaced without the listed rights.
  $unsafe = [long]0x500D0152
  $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
  foreach ($ace in $rules) {
    if ($ace.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
    $identity = $ace.IdentityReference.Value
    if ($identity -in $trusted) { continue }
    if ($isSnapshot) { throw 'Private snapshot DACL granted an outside principal' }
    $inheritedOnly = [bool]($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)
    if ($inheritedOnly -and (-not $isDirectParent -or
      -not ($ace.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ContainerInherit))) {
      continue
    }
    if (([long]$ace.FileSystemRights -band $unsafe) -ne 0) {
      throw 'Untrusted ancestor grants destructive or privilege-changing access'
    }
  }
}

try {
  $target = [IO.Path]::GetFullPath($Directory)
  $item = New-Object IO.DirectoryInfo($target)
  if (-not $item.Exists) { throw 'Snapshot directory missing' }

  # Verify *all* ancestors, including the volume root. No special treatment
  # for the default Windows TEMP; a hostile inherited Modify ACE is rejected.
  $parent = $item.Parent
  $directParent = $true
  while ($null -ne $parent) {
    Assert-Directory $parent.FullName $false $directParent
    $directParent = $false
    $parent = $parent.Parent
  }

  if ($Action -eq 'protect') {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($me)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($me, $system, $admins)) {
      $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        $sid, [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow)
      $acl.AddAccessRule($rule)
    }
    [IO.Directory]::SetAccessControl($target, $acl)
  }
  Assert-Directory $target $true $false
  exit 0
} catch {
  # No raw path or ACL details escape through stderr (could reveal user info).
  [Console]::Error.WriteLine('ZK_LEGACY_PRIVATE_SNAPSHOT_ACL_REJECTED')
  exit 3
}

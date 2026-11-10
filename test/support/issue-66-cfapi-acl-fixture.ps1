param([string]$Target, [string]$Expose)
$ErrorActionPreference = 'Stop'
$phase = 'INIT'
try {
  if ($Expose -notin @('0', '1', '2')) { throw 'INVALID_FIXTURE_MODE' }
  # This helper is intentionally destructive only inside this test's own
  # random, disposable Node mkdtemp directory. Refuse arbitrary input paths.
  $targetInfo = [System.IO.DirectoryInfo]::new($Target)
  $parent = $targetInfo.Parent
  if (-not $parent -or
      $parent.Name -notmatch '^rootark-cfapi-(acl|privilege|phase)-test-[A-Za-z0-9_-]{6,}$' -or
      $targetInfo.Name -notin @('owner-only', 'broad-access', 'inherited-access') -or
      ($parent.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
      ($targetInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'INVALID_DISPOSABLE_FIXTURE'
  }
  $owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  # The root exists only inside Node's disposable mkdtemp workspace. Build a
  # new descriptor so inherited runner ACLs and SACLs are never read/copied.
  $acl = [System.Security.AccessControl.DirectorySecurity]::new()
  $phase = 'OWNER'
  $acl.SetOwner($owner)
  $phase = 'PROTECT'
  $acl.SetAccessRuleProtection($true, $false)
  $phase = 'RULES'
  $access = [System.Security.AccessControl.FileSystemRights]::FullControl
  $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  $none = [System.Security.AccessControl.PropagationFlags]::None
  $allow = [System.Security.AccessControl.AccessControlType]::Allow
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($owner, $access, $inherit, $none, $allow))
  if ($Expose -eq '1') {
    $world = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($world, $access, $inherit, $none, $allow))
  }
  if ($Expose -eq '2') { $acl.SetAccessRuleProtection($false, $true) }
  $phase = 'WRITE'
  # Persist only the owner/DACL sections changed by this disposable fixture.
  # This avoids Set-Acl's broad security-section handling on hosted runners.
  [System.IO.Directory]::SetAccessControl($Target, $acl)
} catch {
  # Never leak PowerShell errors, SIDs, access rules or filesystem paths in CI.
  [Console]::Error.WriteLine("ROOTARK_CFAPI_FIXTURE_V1 phase=$phase")
  exit 41
}

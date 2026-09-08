param([string] $SeedPath, [string] $Mode)
$ErrorActionPreference = 'Stop'
$owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object System.Security.AccessControl.FileSecurity
$acl.SetOwner($owner)
$acl.SetAccessRuleProtection($true, $false)
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$full = [System.Security.AccessControl.FileSystemRights]::FullControl
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($owner, $full, $allow)))
switch ($Mode) {
    'private' { }
    'broad' {
        $world = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($world, 'Read', $allow)))
    }
    'inherited-broad' {
        $parent = Split-Path -Parent $SeedPath
        $parentAcl = Get-Acl -LiteralPath $parent
        $world = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($world, 'Read', 'ObjectInherit', 'None', $allow)
        $parentAcl.AddAccessRule($rule)
        Set-Acl -LiteralPath $parent -AclObject $parentAcl
        $acl.SetAccessRuleProtection($false, $true)
    }
    'wrong-owner' {
        $administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $acl.SetOwner($administrators)
    }
    'null' {
        $acl.SetSecurityDescriptorSddlForm("O:$($owner.Value)D:NO_ACCESS_CONTROL")
    }
    'deny' {
        $world = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($world, 'Write', 'Deny')))
    }
    default { throw 'Unknown fixture ACL mode' }
}
Set-Acl -LiteralPath $SeedPath -AclObject $acl

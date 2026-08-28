@(
    # go-adpwsh ACL endpoint helpers. A ConstrainedLanguage endpoint installs these
    # as -FunctionDefinitions, so each runs FullLanguage inside the CLM session and
    # can construct the .NET ACL types the CLM caller cannot. Mirrors
    # ops/acl_{grant,read,revoke}.ps1. SINGLE SOURCE OF TRUTH: the provider's
    # New-AdProviderEndpoint.ps1 embeds a verbatim copy, guarded by a drift test.
    @{ Name = 'Set-AdAce'; ScriptBlock = {
        param([Parameter(Mandatory)]$Target,[Parameter(Mandatory)]$Server,[pscredential]$Credential,[Parameter(Mandatory)]$Aces)
        $credOnly = @{}; if ($Credential) { $credOnly['Credential'] = $Credential }
        $dn = (Get-ADObject -Identity $Target -Properties distinguishedName -Server $Server @credOnly).DistinguishedName
        $drive = "TFAD$PID"
        $null = New-PSDrive -Name $drive -PSProvider ActiveDirectory -Root '' -Server $Server @credOnly -ErrorAction Stop
        try {
            $path = "$($drive):$dn"
            $acl = Get-Acl -Path $path
            foreach ($ace in $Aces) {
                $sid     = [System.Security.Principal.SecurityIdentifier]::new([string]$ace.trustee)
                $rights  = [System.DirectoryServices.ActiveDirectoryRights](@($ace.rights) -join ', ')
                $type    = [System.Security.AccessControl.AccessControlType][string]$ace.type
                $inh     = [System.DirectoryServices.ActiveDirectorySecurityInheritance][string]$ace.inheritance
                $objType = if ($ace.objectType) { [Guid][string]$ace.objectType } else { [Guid]::Empty }
                $inhType = if ($ace.inheritedObjectType) { [Guid][string]$ace.inheritedObjectType } else { [Guid]::Empty }
                $rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($sid,$rights,$type,$objType,$inh,$inhType)
                $acl.AddAccessRule($rule)
            }
            Set-Acl -Path $path -AclObject $acl
            $obj = Get-ADObject -Identity $dn -Properties objectGUID -Server $Server @credOnly
            [ordered]@{ granted = $true; guid = $obj.ObjectGUID.ToString() }
        } finally { Remove-PSDrive -Name $drive -ErrorAction SilentlyContinue }
    }}
    @{ Name = 'Remove-AdAce'; ScriptBlock = {
        param([Parameter(Mandatory)]$Target,[Parameter(Mandatory)]$Server,[pscredential]$Credential,[Parameter(Mandatory)]$Aces)
        $credOnly = @{}; if ($Credential) { $credOnly['Credential'] = $Credential }
        $dn = (Get-ADObject -Identity $Target -Properties distinguishedName -Server $Server @credOnly).DistinguishedName
        $drive = "TFAD$PID"
        $null = New-PSDrive -Name $drive -PSProvider ActiveDirectory -Root '' -Server $Server @credOnly -ErrorAction Stop
        try {
            $path = "$($drive):$dn"
            $acl = Get-Acl -Path $path
            foreach ($ace in $Aces) {
                $sid     = [System.Security.Principal.SecurityIdentifier]::new([string]$ace.trustee)
                $rights  = [System.DirectoryServices.ActiveDirectoryRights](@($ace.rights) -join ', ')
                $type    = [System.Security.AccessControl.AccessControlType][string]$ace.type
                $inh     = [System.DirectoryServices.ActiveDirectorySecurityInheritance][string]$ace.inheritance
                $objType = if ($ace.objectType) { [Guid][string]$ace.objectType } else { [Guid]::Empty }
                $inhType = if ($ace.inheritedObjectType) { [Guid][string]$ace.inheritedObjectType } else { [Guid]::Empty }
                $rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($sid,$rights,$type,$objType,$inh,$inhType)
                $null = $acl.RemoveAccessRule($rule)
            }
            Set-Acl -Path $path -AclObject $acl
            $obj = Get-ADObject -Identity $dn -Properties objectGUID -Server $Server @credOnly
            [ordered]@{ revoked = $true; guid = $obj.ObjectGUID.ToString() }
        } finally { Remove-PSDrive -Name $drive -ErrorAction SilentlyContinue }
    }}
    @{ Name = 'Get-AdAce'; ScriptBlock = {
        param([Parameter(Mandatory)]$Target,[Parameter(Mandatory)]$Server,[pscredential]$Credential)
        $credOnly = @{}; if ($Credential) { $credOnly['Credential'] = $Credential }
        $dn = (Get-ADObject -Identity $Target -Properties distinguishedName -Server $Server @credOnly).DistinguishedName
        $drive = "TFAD$PID"
        $null = New-PSDrive -Name $drive -PSProvider ActiveDirectory -Root '' -Server $Server @credOnly -ErrorAction Stop
        try {
            $acl = Get-Acl -Path "$($drive):$dn"
            $aces = foreach ($a in $acl.Access) {
                $sid = try { $a.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $a.IdentityReference.Value }
                [ordered]@{
                    trustee             = $sid
                    type                = $a.AccessControlType.ToString()
                    rights              = @($a.ActiveDirectoryRights.ToString() -split ',\s*')
                    objectType          = $a.ObjectType.ToString()
                    inheritedObjectType = $a.InheritedObjectType.ToString()
                    inheritance         = $a.InheritanceType.ToString()
                    inherited           = [bool]$a.IsInherited
                }
            }
            [ordered]@{ aces = @($aces) }
        } finally { Remove-PSDrive -Name $drive -ErrorAction SilentlyContinue }
    }}
)

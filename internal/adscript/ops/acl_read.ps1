        $dn = (Get-ADObject -Identity $p.target -Properties distinguishedName @common).DistinguishedName
        $drive = "TFAD$PID"
        $null = New-PSDrive -Name $drive -PSProvider ActiveDirectory -Root '' -Server $common['Server'] @credOnly -ErrorAction Stop
        try {
            $acl = Get-Acl -Path "$($drive):$dn"
            $aces = foreach ($a in $acl.Access) {
                $sid = try { $a.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
                       catch { $a.IdentityReference.Value }
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
        } finally {
            Remove-PSDrive -Name $drive -ErrorAction SilentlyContinue
        }

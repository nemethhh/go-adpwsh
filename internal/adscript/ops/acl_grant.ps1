        $dn = $p.target
        $drive = "TFAD$PID"
        $null = New-PSDrive -Name $drive -PSProvider ActiveDirectory -Root '' -Server $common['Server'] @credOnly -ErrorAction Stop
        try {
            $path = "$($drive):$dn"
            $acl = Get-Acl -Path $path
            foreach ($ace in $p.aces) {
                $sid     = [System.Security.Principal.SecurityIdentifier]::new($ace.trustee)
                $rights  = [System.DirectoryServices.ActiveDirectoryRights]($ace.rights -join ', ')
                $type    = [System.Security.AccessControl.AccessControlType]$ace.type
                $inh     = [System.DirectoryServices.ActiveDirectorySecurityInheritance]$ace.inheritance
                $objType = if ($ace.objectType) { [Guid]$ace.objectType } else { [Guid]::Empty }
                $inhType = if ($ace.inheritedObjectType) { [Guid]$ace.inheritedObjectType } else { [Guid]::Empty }
                $rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($sid, $rights, $type, $objType, $inh, $inhType)
                $acl.AddAccessRule($rule)
            }
            Set-Acl -Path $path -AclObject $acl
            $obj = Get-ADObject -Identity $dn -Properties objectGUID @common
            [ordered]@{ granted = $true; guid = $obj.ObjectGUID.ToString() }
        } finally {
            Remove-PSDrive -Name $drive -ErrorAction SilentlyContinue
        }

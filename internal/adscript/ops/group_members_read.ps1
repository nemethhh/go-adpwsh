        $g = Get-ADGroup -Identity $p.identity @common
        $dns = New-Object System.Collections.Generic.List[string]
        $low = 0
        $step = 1500
        while ($true) {
            $attr = "member;range=$low-$($low + $step - 1)"
            $o = Get-ADObject -Identity $g.DistinguishedName -Properties $attr @common
            $prop = $o.PSObject.Properties | Where-Object { $_.Name -like 'member;range=*' } | Select-Object -First 1
            if ($null -eq $prop) { break }
            foreach ($v in $prop.Value) { $dns.Add($v) }
            if ($prop.Name -like '*-`*') { break }
            $low += $step
        }
        $members = foreach ($dn in $dns) {
            $mo = Get-ADObject -Identity $dn -Properties objectSid @common
            [ordered]@{
                objectGUID        = $mo.ObjectGUID.ToString()
                distinguishedName = $mo.DistinguishedName
                objectClass       = $mo.ObjectClass
                sid               = $mo.objectSid.Value
            }
        }
        [ordered]@{ members = @($members) }

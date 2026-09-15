        $t = Get-AdDacl $p.target
        foreach ($spec in $p.aces) { $t.sd.DiscretionaryAcl.Insert(0, (New-AdAceFromSpec $spec)) }
        Set-AdDacl $p.target $t.sd
        [ordered]@{ granted = $true; guid = $t.guid }

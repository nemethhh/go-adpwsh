        $t = Get-AdDacl $p.target
        foreach ($spec in $p.aces) {
            $want = New-AdAceFromSpec $spec
            # The ACE read back from the DC is a different instance from the one
            # built from the spec, so the match is on value, not identity. The
            # object type is part of the match when the spec carries one: a
            # delegation ACE differs from a full-control ACE for the same trustee
            # only in that GUID.
            $wantOt = "$(Get-AdPropValue $want 'ObjectAceType')"
            $match = @($t.sd.DiscretionaryAcl | Where-Object {
                "$($_.Sid)" -eq "$($want.Sid)" -and
                "$($_.AceType)" -eq "$($want.AceType)" -and
                [uint32]$_.AccessMask -eq [uint32]$want.AccessMask -and
                "$(Get-AdPropValue $_ 'ObjectAceType')" -eq $wantOt })
            foreach ($m in $match) { $null = $t.sd.DiscretionaryAcl.Remove($m) }
        }
        Set-AdDacl $p.target $t.sd
        [ordered]@{ revoked = $true; guid = $t.guid }

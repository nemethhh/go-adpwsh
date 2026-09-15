        $g = Get-OpenADGroup @common -Identity $p.identity
        foreach ($mid in $p.members) {
            # The catch is not defensive padding: it makes the add idempotent,
            # so a member already present is not an error. The ADWS dialect
            # does the same.
            try { Add-OpenADGroupMember @common -Identity $g.DistinguishedName -Members $mid }
            catch { if (-not (Test-AdMember $g $mid)) { throw } }
        }
        [ordered]@{ added = $true; guid = $g.ObjectGuid.ToString() }

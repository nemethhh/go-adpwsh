        $g = Get-OpenADGroup @common -Identity $p.identity
        foreach ($mid in $p.members) {
            try { Remove-OpenADGroupMember @common -Identity $g.DistinguishedName -Members $mid }
            catch { if (Test-AdMember $g $mid) { throw } }
        }
        [ordered]@{ removed = $true; guid = $g.ObjectGuid.ToString() }

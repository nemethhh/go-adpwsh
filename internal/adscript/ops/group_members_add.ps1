        $g = Get-ADGroup -Identity $p.identity @common
        foreach ($mid in $p.members) {
            try { $null = Add-ADGroupMember -Identity $g -Members $mid -Confirm:$false @common }
            catch { if (-not (Test-AdMember $g $mid)) { throw } }
        }
        [ordered]@{ added = $true; guid = $g.ObjectGUID.ToString() }

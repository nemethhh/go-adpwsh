        $g = Get-ADGroup -Identity $p.identity @common
        foreach ($mid in $p.members) {
            try { $null = Remove-ADGroupMember -Identity $g -Members $mid -Confirm:$false @common }
            catch { if (Test-AdMember $g $mid) { throw } }
        }
        [ordered]@{ removed = $true; guid = $g.ObjectGUID.ToString() }

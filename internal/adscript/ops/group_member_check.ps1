        $g = Get-ADGroup -Identity $p.group @common
        [ordered]@{ member = (Test-AdMember $g $p.member) }

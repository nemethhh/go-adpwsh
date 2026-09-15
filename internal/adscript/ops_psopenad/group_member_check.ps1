        $g = Get-OpenADGroup @common -Identity $p.group
        [ordered]@{ member = (Test-AdMember $g $p.member) }

        $null = Remove-ADComputer -Identity $p.identity -Confirm:$false @common
        [ordered]@{ deleted = $true; verify = (Test-AdPresence $p.identity) }

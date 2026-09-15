        Remove-OpenADObject @common -Identity $p.identity
        [ordered]@{ deleted = $true; verify = (Test-AdPresence $p.identity) }

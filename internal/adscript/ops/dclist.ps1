        $dcs = @(Get-ADDomainController -Filter * @common)
        [ordered]@{ hostNames = @($dcs | ForEach-Object { $_.HostName }) }

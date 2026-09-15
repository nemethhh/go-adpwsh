        $r = @(Get-OpenADGroup @common -LDAPFilter $p.filter -SearchBase $p.searchBase -SearchScope $p.scope -Properties $p.project)
        if ($p.sizeLimit -and $p.sizeLimit -gt 0) { $r = @($r | Select-Object -First $p.sizeLimit) }
        [ordered]@{ results = @($r | ForEach-Object { Convert-AdGroup $_ }) }

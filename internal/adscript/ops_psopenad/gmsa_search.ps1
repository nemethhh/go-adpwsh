        $r = @(Get-OpenADServiceAccount @common -LDAPFilter $p.filter -SearchBase $p.searchBase -SearchScope $p.scope -Properties $AD_PROPS_GMSA)
        if ($p.sizeLimit -and $p.sizeLimit -gt 0) { $r = @($r | Select-Object -First $p.sizeLimit) }
        [ordered]@{ results = @($r | ForEach-Object { Convert-AdServiceAccount $_ }) }

        # PSOpenAD has no -ResultSetSize, so the cap is applied client-side and
        # only after the search: ResultSetSize caps returned objects, it is not a
        # server-side size limit.
        $r = @(Get-OpenADObject @common -LDAPFilter $p.filter -SearchBase $p.searchBase -SearchScope $p.scope -Properties $AD_PROPS_OU -SecurityMask Dacl)
        if ($p.sizeLimit -and $p.sizeLimit -gt 0) { $r = @($r | Select-Object -First $p.sizeLimit) }
        [ordered]@{ results = @($r | ForEach-Object { Convert-AdOU $_ }) }

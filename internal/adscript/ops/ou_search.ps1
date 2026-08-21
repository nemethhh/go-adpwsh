        $r = @(Get-ADOrganizationalUnit -LDAPFilter $p.filter -SearchBase $p.searchBase `
                 -SearchScope $p.scope -ResultSetSize $p.sizeLimit -Properties $p.project @common)
        [ordered]@{ results = @($r | ForEach-Object { Convert-AdOU $_ }) }

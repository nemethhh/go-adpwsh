        $m = @(Get-OpenADObject @common -LDAPFilter $p.filter -SearchBase $p.searchBase `
                 -IncludeDeletedObjects -Properties lastKnownParent,isDeleted)
        [ordered]@{ matches = @($m | ForEach-Object {
            [ordered]@{
                objectGUID        = $_.ObjectGuid.ToString()
                distinguishedName = $_.DistinguishedName
                lastKnownParent   = (Get-AdPropValue $_ 'LastKnownParent')
            } }) }

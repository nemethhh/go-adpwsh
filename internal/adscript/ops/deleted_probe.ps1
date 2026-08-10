        $m = @(Get-ADObject -LDAPFilter $p.filter -SearchBase $p.searchBase `
                 -IncludeDeletedObjects -Properties lastKnownParent,isDeleted @common)
        [ordered]@{ matches = @($m | ForEach-Object {
            [ordered]@{
                objectGUID        = $_.ObjectGUID.ToString()
                distinguishedName = $_.DistinguishedName
                lastKnownParent   = $_.lastKnownParent
            } }) }

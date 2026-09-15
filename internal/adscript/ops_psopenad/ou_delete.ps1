        # PSOpenAD's OneLevel scope may include the base object, unlike the AD
        # cmdlets' -SearchScope OneLevel. The filter is harmless if it does not
        # and load-bearing if it does.
        $children = @(Get-OpenADObject @common -SearchBase $p.dn -SearchScope OneLevel -LDAPFilter '(objectClass=*)' |
                      Where-Object { $_.DistinguishedName -ne $p.dn })
        if ($children.Count -gt 0) {
            [ordered]@{ deleted = $false; childCount = $children.Count }
        } else {
            # GAP: $p.unprotect is not honoured yet; it is a Deny ACE.
            Remove-OpenADObject @common -Identity $p.identity
            [ordered]@{ deleted = $true; childCount = 0; verify = (Test-AdPresence $p.identity) }
        }

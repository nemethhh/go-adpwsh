        $children = @(Get-ADObject -SearchBase $p.dn -SearchScope OneLevel -LDAPFilter '(objectClass=*)' @common)
        if ($children.Count -gt 0) {
            [ordered]@{ deleted = $false; childCount = $children.Count }
        } else {
            if ($p.unprotect) {
                $null = Set-ADOrganizationalUnit -Identity $p.identity -ProtectedFromAccidentalDeletion $false @common
            }
            $null = Remove-ADOrganizationalUnit -Identity $p.identity -Confirm:$false @common
            [ordered]@{ deleted = $true; childCount = 0; verify = (Test-AdPresence $p.identity) }
        }

        # Get-ADGroupMember -Recursive resolves nesting on the DC and returns leaf
        # security principals (users/computers, and empty groups) — intermediate
        # non-empty groups are traversed but not returned. The returned ADPrincipal
        # objects already carry objectGUID/distinguishedName/objectClass/SID, so
        # there is no per-member re-fetch: the output contract matches
        # group_members_read.ps1. Primary-group-only membership is not included.
        $members = foreach ($m in (Get-ADGroupMember -Identity $p.identity -Recursive @common)) {
            [ordered]@{
                objectGUID        = $m.objectGUID.ToString()
                distinguishedName = $m.distinguishedName
                objectClass       = $m.objectClass
                sid               = $m.SID.Value
            }
        }
        [ordered]@{ members = @($members) }

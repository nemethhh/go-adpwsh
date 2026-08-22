        # Get-ADGroupMember -Recursive resolves nesting on the DC and returns the
        # leaf security principals (users and computers) reachable through the
        # hierarchy. Group objects are traversed but never returned — not even an
        # empty nested group (confirmed against a real domain). The returned
        # ADPrincipal objects already carry objectGUID/distinguishedName/objectClass/SID,
        # so there is no per-member re-fetch: the output contract matches
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

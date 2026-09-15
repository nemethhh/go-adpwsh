        # -Recursive uses LDAP_MATCHING_RULE_IN_CHAIN on the DC and returns the
        # leaf principals reachable through the hierarchy. Group objects are
        # traversed but not returned, matching the ADWS dialect's contract.
        $members = foreach ($m in (Get-OpenADGroupMember @common -Identity $p.identity -Recursive)) {
            [ordered]@{
                objectGUID        = $m.ObjectGuid.ToString()
                distinguishedName = $m.DistinguishedName
                objectClass       = @($m.ObjectClass)[-1]
                sid               = $(if ($m.SID) { $m.SID.Value } else { $null })
            }
        }
        [ordered]@{ members = @($members) }

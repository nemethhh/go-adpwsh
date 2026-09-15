        # PSOpenAD pages ranged multivalued attributes, so member is complete
        # for a group of any size. Never request member;range= explicitly.
        $g = Get-OpenADGroup @common -Identity $p.identity -Properties member
        $members = foreach ($dn in @($g.Member)) {
            $mo = Get-OpenADObject @common -Identity $dn -Properties objectSid,objectClass
            [ordered]@{
                objectGUID        = $mo.ObjectGuid.ToString()
                distinguishedName = $mo.DistinguishedName
                # objectClass is multivalued in LDAP and the AD cmdlets return
                # the most specific value, which is the last element.
                objectClass       = @($mo.ObjectClass)[-1]
                # A contact has no objectSid, so this tolerates null.
                sid               = $(if ($mo.SID) { $mo.SID.Value } else { $null })
            }
        }
        [ordered]@{ members = @($members) }

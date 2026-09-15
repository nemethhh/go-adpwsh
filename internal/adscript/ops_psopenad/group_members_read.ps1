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
                # Get-OpenADObject returns an OpenADObject, which has no SID
                # property - that is OpenADPrincipal's - so the attribute is read
                # under the name it surfaces as. A contact has no objectSid at
                # all, so null is tolerated.
                sid               = $(
                    $__sid = Get-AdPropValue $mo 'ObjectSid'
                    if ($__sid) { $__sid.Value } else { $null })
            }
        }
        [ordered]@{ members = @($members) }

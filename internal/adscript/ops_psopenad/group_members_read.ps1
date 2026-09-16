        # PSOpenAD pages ranged multivalued attributes, so member is complete
        # for a group of any size. Never request member;range= explicitly.
        $g = Get-OpenADGroup @common -Identity $p.identity -Properties member
        # @($null) has length one, so an EMPTY group would run this body once with
        # a null $dn and hand it to -Identity. The ADWS fragment iterates the bare
        # property, which runs zero times; ConvertTo-AdArray is this dialect's
        # existing answer to the same trap.
        $members = foreach ($dn in @(ConvertTo-AdArray $g.Member)) {
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

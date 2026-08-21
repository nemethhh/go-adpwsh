        # The ActiveDirectory module performs ranged retrieval of a multivalued
        # attribute internally, so -Properties member returns the whole member set
        # for a group of any size. The LDAP ranged-retrieval attribute option is an
        # ADSI/LDAP feature the cmdlets reject (Get-ADObject throws
        # System.ArgumentException), so it must never appear in -Properties.
        $g = Get-ADGroup -Identity $p.identity -Properties member @common
        $members = foreach ($dn in $g.member) {
            $mo = Get-ADObject -Identity $dn -Properties objectSid @common
            [ordered]@{
                objectGUID        = $mo.ObjectGUID.ToString()
                distinguishedName = $mo.DistinguishedName
                objectClass       = $mo.ObjectClass
                sid               = $mo.objectSid.Value
            }
        }
        [ordered]@{ members = @($members) }

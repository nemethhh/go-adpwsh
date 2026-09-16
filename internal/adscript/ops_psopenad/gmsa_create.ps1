        $c = $p.create
        $uac = 4096
        if ($c.ContainsKey('Enabled') -and -not $c.Enabled) { $uac = $uac -bor 0x2 }
        if ($c.ContainsKey('TrustedForDelegation') -and $c.TrustedForDelegation) { $uac = $uac -bor 0x80000 }
        $attrs = @{
            sAMAccountName     = (ConvertTo-AdComputerSamAccountName $c.SamAccountName)
            userAccountControl = $uac
            dNSHostName        = $c.DNSHostName
        }
        # msDS-ManagedPasswordInterval is the class's only systemMustContain
        # attribute, so it is written unconditionally: New-ADServiceAccount
        # supplies AD's own default when the caller omits one, and a raw LDAP add
        # without it is refused with 0x207C OBJ_CLASS_VIOLATION. 30 is that
        # default, and the provider documents reading it back.
        $attrs['msDS-ManagedPasswordInterval'] =
            if ($c.ContainsKey('ManagedPasswordIntervalInDays') -and $null -ne $c.ManagedPasswordIntervalInDays) {
                [int]$c.ManagedPasswordIntervalInDays
            } else { 30 }
        foreach ($pair in @(@('Description','description'), @('DisplayName','displayName'))) {
            if ($c.ContainsKey($pair[0]) -and $c[$pair[0]]) { $attrs[$pair[1]] = $c[$pair[0]] }
        }
        if ($c.ServicePrincipalNames) { $attrs['servicePrincipalName'] = @($c.ServicePrincipalNames) }
        if ($c.ContainsKey('KerberosEncryptionType')) {
            $attrs['msDS-SupportedEncryptionTypes'] = (ConvertTo-AdEncTypeBits $c.KerberosEncryptionType)
        }
        if ($c.ContainsKey('AccountExpirationDate')) {
            $attrs['accountExpires'] = (ConvertTo-AdAccountExpires $c.AccountExpirationDate)
        }
        if ($c.ContainsKey('PrincipalsAllowedToRetrieveManagedPassword')) {
            $attrs['msDS-GroupMSAMembership'] =
                (New-AdPrincipalSd $c.PrincipalsAllowedToRetrieveManagedPassword)
        }
        $new = New-OpenADObject @common -Name $c.Name -Type 'msDS-GroupManagedServiceAccount' -Path $c.Path -OtherAttributes $attrs -PassThru
        Convert-AdServiceAccount (Get-OpenADServiceAccount @common -Identity $new.ObjectGuid -Properties $AD_PROPS_GMSA)

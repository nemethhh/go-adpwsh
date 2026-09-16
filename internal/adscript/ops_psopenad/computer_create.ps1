        $c = $p.create
        # 4096 is WORKSTATION_TRUST_ACCOUNT. A computer needs no password to be
        # enabled, so unlike a user it can be created in its final UAC state.
        $uac = 4096
        if ($c.ContainsKey('Enabled') -and -not $c.Enabled) { $uac = $uac -bor 0x2 }
        if ($c.ContainsKey('TrustedForDelegation') -and $c.TrustedForDelegation) { $uac = $uac -bor 0x80000 }
        $attrs = @{
            sAMAccountName     = (ConvertTo-AdComputerSamAccountName $c.SamAccountName)
            userAccountControl = $uac
        }
        foreach ($pair in @(
            @('DNSHostName','dNSHostName'), @('Description','description'),
            @('DisplayName','displayName'), @('Location','location'),
            @('ManagedBy','managedBy'))) {
            if ($c.ContainsKey($pair[0]) -and $c[$pair[0]]) { $attrs[$pair[1]] = $c[$pair[0]] }
        }
        if ($c.ServicePrincipalNames) { $attrs['servicePrincipalName'] = @($c.ServicePrincipalNames) }
        if ($c.ContainsKey('KerberosEncryptionType')) {
            $attrs['msDS-SupportedEncryptionTypes'] = (ConvertTo-AdEncTypeBits $c.KerberosEncryptionType)
        }
        if ($c.ContainsKey('AccountExpirationDate')) {
            $attrs['accountExpires'] = (ConvertTo-AdAccountExpires $c.AccountExpirationDate)
        }
        # OtherAttributes carries msDS-AllowedToDelegateTo under its raw LDAP
        # name, because New-ADComputer has no friendly parameter for it.
        if ($c.OtherAttributes) {
            foreach ($k in $c.OtherAttributes.Keys) { $attrs[$k] = $c.OtherAttributes[$k] }
        }
        if ($c.ContainsKey('PrincipalsAllowedToDelegateToAccount')) {
            $attrs['msDS-AllowedToActOnBehalfOfOtherIdentity'] =
                (New-AdPrincipalSd $c.PrincipalsAllowedToDelegateToAccount)
        }
        $new = New-OpenADObject @common -Name $c.Name -Type computer -Path $c.Path -OtherAttributes $attrs -PassThru
        Convert-AdComputer (Get-OpenADComputer @common -Identity $new.ObjectGuid -Properties $AD_PROPS_COMPUTER)

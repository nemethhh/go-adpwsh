        if ($p.set) {
            $s = $p.set
            $repl = @{}
            foreach ($pair in @(
                @('DNSHostName','dNSHostName'), @('Description','description'),
                @('DisplayName','displayName'), @('SamAccountName','sAMAccountName'))) {
                if ($s.ContainsKey($pair[0])) { $repl[$pair[1]] = $s[$pair[0]] }
            }
            if ($s.ContainsKey('ServicePrincipalNames')) {
                $spn = $s.ServicePrincipalNames
                if ($spn -is [System.Collections.IDictionary]) {
                    if ($spn.ContainsKey('Replace')) { $repl['servicePrincipalName'] = @($spn.Replace) }
                } else {
                    $repl['servicePrincipalName'] = @($spn)
                }
            }
            if ($s.ContainsKey('KerberosEncryptionType')) {
                $repl['msDS-SupportedEncryptionTypes'] = (ConvertTo-AdEncTypeBits $s.KerberosEncryptionType)
            }
            if ($s.ContainsKey('AccountExpirationDate')) {
                $repl['accountExpires'] = (ConvertTo-AdAccountExpires $s.AccountExpirationDate)
            }
            if ($s.ContainsKey('Enabled') -or $s.ContainsKey('TrustedForDelegation')) {
                $cur = Get-OpenADServiceAccount @common -Identity $p.identity -Properties userAccountControl
                $uac = [int]$cur.UserAccountControl
                if ($s.ContainsKey('Enabled')) {
                    if ($s.Enabled) { $uac = $uac -band (-bnot 0x2) } else { $uac = $uac -bor 0x2 }
                }
                if ($s.ContainsKey('TrustedForDelegation')) {
                    if ($s.TrustedForDelegation) { $uac = $uac -bor 0x80000 } else { $uac = $uac -band (-bnot 0x80000) }
                }
                $repl['userAccountControl'] = $uac
            }
            # msDS-ManagedPasswordInterval is write-once at creation; a change
            # attempt is refused by the DC and classifies as KindConstraint.
            # That refusal is left to the DC, matching the ADWS dialect.
            if ($s.ContainsKey('PrincipalsAllowedToRetrieveManagedPassword')) {
                $repl['msDS-GroupMSAMembership'] =
                    (New-AdPrincipalSd $s.PrincipalsAllowedToRetrieveManagedPassword)
            }
            Set-AdAttributes $p.identity $s $repl
        }
        if ($p.rename) { $r = $p.rename; Rename-OpenADObject @common -Identity $r.Identity -NewName $r.NewName }
        if ($p.move)   { $m = $p.move;   Move-OpenADObject   @common -Identity $m.Identity -TargetPath $m.TargetPath }
        Convert-AdServiceAccount (Get-OpenADServiceAccount @common -Identity $p.identity -Properties $AD_PROPS_GMSA)

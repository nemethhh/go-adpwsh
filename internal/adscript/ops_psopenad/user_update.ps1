        if ($p.set) {
            $s = $p.set
            $repl = @{}
            foreach ($pair in @(
                @('Description','description'), @('DisplayName','displayName'),
                @('GivenName','givenName'), @('Surname','sn'),
                @('UserPrincipalName','userPrincipalName'),
                @('SamAccountName','sAMAccountName'))) {
                if ($s.ContainsKey($pair[0])) { $repl[$pair[1]] = $s[$pair[0]] }
            }
            if ($s.ContainsKey('AccountExpirationDate')) {
                $repl['accountExpires'] = (ConvertTo-AdAccountExpires $s.AccountExpirationDate)
            }
            if ($s.ContainsKey('ChangePasswordAtLogon')) {
                $repl['pwdLastSet'] = if ($s.ChangePasswordAtLogon) { '0' } else { '-1' }
            }
            if ($s.ContainsKey('Enabled') -or $s.ContainsKey('PasswordNeverExpires')) {
                $cur = Get-OpenADUser @common -Identity $p.identity -Properties userAccountControl
                $uac = [int]$cur.UserAccountControl
                if ($s.ContainsKey('Enabled')) {
                    if ($s.Enabled) { $uac = $uac -band (-bnot 0x2) } else { $uac = $uac -bor 0x2 }
                }
                if ($s.ContainsKey('PasswordNeverExpires')) {
                    if ($s.PasswordNeverExpires) { $uac = $uac -bor 0x10000 } else { $uac = $uac -band (-bnot 0x10000) }
                }
                $repl['userAccountControl'] = $uac
            }
            # GAP: $s.CannotChangePassword is not honoured yet; it is a Deny ACE.
            Set-AdAttributes $p.identity $s $repl
        }
        if ($p.rename) { $r = $p.rename; Rename-OpenADObject @common -Identity $r.Identity -NewName $r.NewName }
        if ($p.move)   { $m = $p.move;   Move-OpenADObject   @common -Identity $m.Identity -TargetPath $m.TargetPath }
        Convert-AdUser (Get-OpenADUser @common -Identity $p.identity -Properties $p.project)

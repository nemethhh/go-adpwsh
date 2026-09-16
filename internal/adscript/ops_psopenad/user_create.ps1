        $c = $p.create
        $attrs = @{ sAMAccountName = $c.SamAccountName }
        foreach ($pair in @(
            @('Description','description'), @('DisplayName','displayName'),
            @('GivenName','givenName'), @('Surname','sn'),
            @('UserPrincipalName','userPrincipalName'))) {
            if ($c.ContainsKey($pair[0]) -and $c[$pair[0]]) { $attrs[$pair[1]] = $c[$pair[0]] }
        }
        if ($c.ContainsKey('AccountExpirationDate')) {
            $attrs['accountExpires'] = (ConvertTo-AdAccountExpires $c.AccountExpirationDate)
        }
        # Create disabled; the password must exist before ACCOUNTDISABLE can clear,
        # or AD answers 0000052D WILL_NOT_PERFORM.
        $attrs['userAccountControl'] = 0x202
        $new = New-OpenADObject @common -Name $c.Name -Type user -Path $c.Path -OtherAttributes $attrs -PassThru

        if ($p.password) {
            $pw = [System.Text.Encoding]::Unicode.GetBytes('"' + $p.password + '"')
            Set-OpenADObject @common -Identity $new.ObjectGuid -Replace @{unicodePwd = $pw}
        }
        # Disabled unless the caller explicitly asks otherwise, which is
        # New-ADUser's own default. Enabling an account that has no password is
        # refused by AD with 0000052D WILL_NOT_PERFORM, so defaulting to enabled
        # would make every passwordless create fail.
        $uac = 0x200
        if (-not ($c.ContainsKey('Enabled') -and $c.Enabled)) { $uac = $uac -bor 0x2 }
        if ($c.ContainsKey('PasswordNeverExpires') -and $c.PasswordNeverExpires) { $uac = $uac -bor 0x10000 }
        Set-OpenADObject @common -Identity $new.ObjectGuid -Replace @{userAccountControl = $uac}

        # pwdLastSet must be written after the password, which sets it to now.
        # 0 forces a change at next logon; -1 means "just now" and is how the
        # flag is turned off.
        if ($c.ContainsKey('ChangePasswordAtLogon')) {
            $pls = if ($c.ChangePasswordAtLogon) { '0' } else { '-1' }
            Set-OpenADObject @common -Identity $new.ObjectGuid -Replace @{pwdLastSet = $pls}
        }
        if ($c.ContainsKey('CannotChangePassword')) {
            Set-AdCannotChangePassword $new.ObjectGuid ([bool]$c.CannotChangePassword)
        }

        Convert-AdUser (Get-OpenADUser @common -Identity $new.ObjectGuid -Properties $AD_PROPS_USER -SecurityMask Dacl)

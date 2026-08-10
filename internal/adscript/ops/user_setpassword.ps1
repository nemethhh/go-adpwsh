        $secnew = ConvertTo-SecureString $p.password -AsPlainText -Force
        $null = Set-ADAccountPassword -Identity $p.identity -Reset -NewPassword $secnew @common
        [ordered]@{ reset = $true }

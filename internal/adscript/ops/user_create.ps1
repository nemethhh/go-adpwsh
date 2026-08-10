        $c = $p.create
        if ($p.password) { $c['AccountPassword'] = ConvertTo-SecureString $p.password -AsPlainText -Force }
        $new = New-ADUser @c @common -PassThru
        Convert-AdUser (Get-ADUser -Identity $new.ObjectGUID -Properties $p.project @common)

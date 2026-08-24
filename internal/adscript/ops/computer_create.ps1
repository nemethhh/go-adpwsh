        $c = $p.create
        $new = New-ADComputer @c @common -PassThru
        Convert-AdComputer (Get-ADComputer -Identity $new.ObjectGUID -Properties $p.project @common)

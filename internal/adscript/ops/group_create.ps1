        $c = $p.create
        $new = New-ADGroup @c @common -PassThru
        Convert-AdGroup (Get-ADGroup -Identity $new.ObjectGUID -Properties $p.project @common)

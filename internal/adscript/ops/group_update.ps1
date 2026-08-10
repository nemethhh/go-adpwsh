        if ($p.set)    { $s = $p.set;    $null = Set-ADGroup @s @common }
        if ($p.rename) { $r = $p.rename; $null = Rename-ADObject @r @common }
        if ($p.move)   { $m = $p.move;   $null = Move-ADObject @m @common }
        Convert-AdGroup (Get-ADGroup -Identity $p.identity -Properties $p.project @common)

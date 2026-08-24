        if ($p.set)    { $s = $p.set;    $null = Set-ADComputer @s @common }
        if ($p.rename) { $r = $p.rename; $null = Rename-ADObject @r @common }
        if ($p.move)   { $m = $p.move;   $null = Move-ADObject @m @common }
        Convert-AdComputer (Get-ADComputer -Identity $p.identity -Properties $p.project @common)

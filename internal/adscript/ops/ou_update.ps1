        if ($p.set)    { $s = $p.set;    $null = Set-ADOrganizationalUnit @s @common }
        if ($p.rename) { $r = $p.rename; $null = Rename-ADObject @r @common }
        if ($p.move)   { $m = $p.move;   $null = Move-ADObject @m @common }
        Convert-AdOU (Get-ADOrganizationalUnit -Identity $p.identity -Properties $p.project @common)

        if ($p.set)    { $s = $p.set;    $null = Set-ADOrganizationalUnit @s @common }
        if ($p.rename) { $r = $p.rename; $null = Rename-ADObject @r @common }
        if ($p.move) {
            # ProtectedFromAccidentalDeletion denies Delete on the OU, and a move
            # is authorised through that right, so a protected OU cannot be moved
            # until the flag is lifted. Rename is unaffected and needs none of this.
            if ($p.unprotectBeforeMove) {
                $null = Set-ADOrganizationalUnit -Identity $p.identity -ProtectedFromAccidentalDeletion $false @common
            }
            $m = $p.move; $null = Move-ADObject @m @common
        }
        # After the move, never before: applied first, it would deny that move.
        if ($null -ne $p.protect) {
            $null = Set-ADOrganizationalUnit -Identity $p.identity -ProtectedFromAccidentalDeletion ([bool]$p.protect) @common
        }
        Convert-AdOU (Get-ADOrganizationalUnit -Identity $p.identity -Properties $p.project @common)

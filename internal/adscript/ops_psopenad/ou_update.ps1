        if ($p.set) {
            $s = $p.set
            $repl = @{}
            if ($s.ContainsKey('Description')) { $repl['description'] = $s.Description }
            Set-AdAttributes $p.identity $s $repl
        }
        if ($p.rename) { $r = $p.rename; Rename-OpenADObject @common -Identity $r.Identity -NewName $r.NewName }
        if ($p.move) {
            # The protection flag is a Deny of Delete, and a move is authorised
            # through that same right, so it is lifted before the move.
            if ($p.unprotectBeforeMove) { Set-AdProtected $p.identity $false }
            $m = $p.move; Move-OpenADObject @common -Identity $m.Identity -TargetPath $m.TargetPath
        }
        # After the move, never before: applied first, it would deny that move.
        if ($null -ne $p.protect) { Set-AdProtected $p.identity ([bool]$p.protect) }
        Convert-AdOU (Get-OpenADObject @common -Identity $p.identity -Properties $AD_PROPS_OU -SecurityMask Dacl)

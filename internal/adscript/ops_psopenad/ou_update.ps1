        if ($p.set) {
            $s = $p.set
            $repl = @{}
            if ($s.ContainsKey('Description')) { $repl['description'] = $s.Description }
            Set-AdAttributes $p.identity $s $repl
        }
        if ($p.rename) { $r = $p.rename; Rename-OpenADObject @common -Identity $r.Identity -NewName $r.NewName }
        # GAP: $p.unprotectBeforeMove and $p.protect are not honoured yet. The
        # protection flag is a Deny ACE, so it lands with the ACL helpers, which
        # must also restore the ordering the ADWS fragment has: lift before the
        # move, reapply after, never before.
        if ($p.move)   { $m = $p.move;   Move-OpenADObject   @common -Identity $m.Identity -TargetPath $m.TargetPath }
        Convert-AdOU (Get-OpenADObject @common -Identity $p.identity -Properties $p.project)

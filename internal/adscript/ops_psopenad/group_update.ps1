        if ($p.set) {
            $s = $p.set
            $repl = @{}
            if ($s.ContainsKey('Description'))    { $repl['description']    = $s.Description }
            if ($s.ContainsKey('ManagedBy'))      { $repl['managedBy']      = $s.ManagedBy }
            if ($s.ContainsKey('SamAccountName')) { $repl['sAMAccountName'] = $s.SamAccountName }
            if ($s.ContainsKey('GroupScope') -or $s.ContainsKey('GroupCategory')) {
                $cur = Get-OpenADGroup @common -Identity $p.identity -Properties groupType
                $gt  = [int]$cur.GroupType
                if ($s.ContainsKey('GroupScope')) {
                    $bit = switch ("$($s.GroupScope)".ToLowerInvariant()) {
                        'domainlocal' { 4 }
                        'universal'   { 8 }
                        default       { 2 }
                    }
                    $gt = $gt -band (-bnot 14)
                    $gt = $gt -bor $bit
                }
                if ($s.ContainsKey('GroupCategory')) {
                    if ("$($s.GroupCategory)".ToLowerInvariant() -eq 'distribution') { $gt = $gt -band (-bnot 0x80000000) }
                    else { $gt = $gt -bor 0x80000000 }
                }
                $repl['groupType'] = [int]$gt
            }
            # A scope change between global and domainlocal is illegal without
            # passing through universal. The DC enforces that and the error
            # classifies as KindConstraint; it is deliberately not pre-validated
            # here, matching the ADWS dialect.
            Set-AdAttributes $p.identity $s $repl
        }
        if ($p.rename) { $r = $p.rename; Rename-OpenADObject @common -Identity $r.Identity -NewName $r.NewName }
        if ($p.move)   { $m = $p.move;   Move-OpenADObject   @common -Identity $m.Identity -TargetPath $m.TargetPath }
        Convert-AdGroup (Get-OpenADGroup @common -Identity $p.identity -Properties $AD_PROPS_GROUP)

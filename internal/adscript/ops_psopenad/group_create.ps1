        $c = $p.create
        $attrs = @{ sAMAccountName = $c.SamAccountName }
        if ($c.Description) { $attrs['description'] = $c.Description }
        if ($c.ManagedBy)   { $attrs['managedBy']   = $c.ManagedBy }
        # groupType: 0x80000000 security, plus scope bits 2 global, 4 domainlocal, 8 universal.
        $scope = switch ("$($c.GroupScope)".ToLowerInvariant()) {
            'domainlocal' { 4 } 'universal' { 8 } default { 2 }
        }
        $gt = [uint32]$scope
        if ("$($c.GroupCategory)".ToLowerInvariant() -ne 'distribution') { $gt = $gt -bor 0x80000000 }
        $attrs['groupType'] = (ConvertTo-AdGroupTypeInt32 $gt)
        $new = New-OpenADObject @common -Name $c.Name -Type group -Path $c.Path -OtherAttributes $attrs -PassThru
        Convert-AdGroup (Get-OpenADGroup @common -Identity $new.ObjectGuid -Properties $AD_PROPS_GROUP)

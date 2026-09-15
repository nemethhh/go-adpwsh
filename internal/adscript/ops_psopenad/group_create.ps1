        $c = $p.create
        $attrs = @{ sAMAccountName = $c.SamAccountName }
        if ($c.Description) { $attrs['description'] = $c.Description }
        if ($c.ManagedBy)   { $attrs['managedBy']   = $c.ManagedBy }
        $scope = switch ("$($c.GroupScope)".ToLowerInvariant()) {
            'domainlocal' { $AD_GT_DOMAINLOCAL }
            'universal'   { $AD_GT_UNIVERSAL }
            default       { $AD_GT_GLOBAL }
        }
        $gt = [uint32]$scope
        if ("$($c.GroupCategory)".ToLowerInvariant() -ne 'distribution') { $gt = $gt -bor $AD_GT_SECURITY }
        $attrs['groupType'] = (ConvertTo-AdGroupTypeValue $gt)
        $new = New-OpenADObject @common -Name $c.Name -Type group -Path $c.Path -OtherAttributes $attrs -PassThru
        Convert-AdGroup (Get-OpenADGroup @common -Identity $new.ObjectGuid -Properties $AD_PROPS_GROUP)

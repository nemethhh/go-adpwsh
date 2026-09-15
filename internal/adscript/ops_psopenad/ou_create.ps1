        $c = $p.create
        $attrs = @{}
        if ($c.Description) { $attrs['description'] = $c.Description }
        # GAP: $c.ProtectedFromAccidentalDeletion is not honoured yet. It is a
        # Deny ACE, so it lands with the ACL helpers.
        $new = New-OpenADObject @common -Name $c.Name -Type organizationalUnit -Path $c.Path -OtherAttributes $attrs -PassThru
        Convert-AdOU (Get-OpenADObject @common -Identity $new.ObjectGuid -Properties $p.project)

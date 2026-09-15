        $root     = Get-OpenADRootDSE @common
        $schemaNC = $root.SchemaNamingContext
        $configNC = $root.ConfigurationNamingContext
        $resolved = [ordered]@{}
        foreach ($ref in $p.refs) {
            if ($ref.kind -eq 'extended_right') {
                $o = @(Get-OpenADObject @common -SearchBase "CN=Extended-Rights,$configNC" `
                         -LDAPFilter $ref.filter -Properties rightsGUID) | Select-Object -First 1
                $resolved[$ref.name] = $(if ($o) { Get-AdPropValue $o 'RightsGUID' } else { $null })
            } else {
                # The cast is a no-op on a Guid and a parse on a string, so it
                # emits the same canonical form either way - which matters,
                # because these GUIDs feed the ACL object-type fields.
                $o = @(Get-OpenADObject @common -SearchBase $schemaNC `
                         -LDAPFilter $ref.filter -Properties schemaIDGUID) | Select-Object -First 1
                $resolved[$ref.name] = $(if ($o) { ([Guid](Get-AdPropValue $o 'SchemaIDGUID')).ToString() } else { $null })
            }
        }
        [ordered]@{ resolved = $resolved }

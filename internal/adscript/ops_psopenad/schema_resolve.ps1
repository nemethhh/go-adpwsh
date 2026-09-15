        $root     = Get-OpenADRootDSE @common
        $schemaNC = $root.SchemaNamingContext
        $configNC = $root.ConfigurationNamingContext
        $resolved = [ordered]@{}
        foreach ($ref in $p.refs) {
            if ($ref.kind -eq 'extended_right') {
                $o = @(Get-OpenADObject @common -SearchBase "CN=Extended-Rights,$configNC" `
                         -LDAPFilter $ref.filter -Properties rightsGUID) | Select-Object -First 1
                $resolved[$ref.name] = $(if ($o) { ConvertTo-AdGuidString (Get-AdPropValue $o 'RightsGUID') } else { $null })
            } else {
                $o = @(Get-OpenADObject @common -SearchBase $schemaNC `
                         -LDAPFilter $ref.filter -Properties schemaIDGUID) | Select-Object -First 1
                $resolved[$ref.name] = $(if ($o) { ConvertTo-AdGuidString (Get-AdPropValue $o 'SchemaIDGUID') } else { $null })
            }
        }
        [ordered]@{ resolved = $resolved }

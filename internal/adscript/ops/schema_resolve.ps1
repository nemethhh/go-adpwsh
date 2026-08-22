        $root     = Get-ADRootDSE @common
        $schemaNC = $root.schemaNamingContext
        $configNC = $root.configurationNamingContext
        $resolved = [ordered]@{}
        foreach ($ref in $p.refs) {
            switch ($ref.kind) {
                'extended_right' {
                    $o = Get-ADObject -SearchBase "CN=Extended-Rights,$configNC" `
                        -LDAPFilter $ref.filter -Properties rightsGUID @common | Select-Object -First 1
                    $resolved[$ref.name] = if ($o) { $o.rightsGUID } else { $null }
                }
                default {
                    $o = Get-ADObject -SearchBase $schemaNC `
                        -LDAPFilter $ref.filter -Properties schemaIDGUID @common | Select-Object -First 1
                    $resolved[$ref.name] = if ($o) { ([Guid]$o.schemaIDGUID).ToString() } else { $null }
                }
            }
        }
        [ordered]@{ resolved = $resolved }

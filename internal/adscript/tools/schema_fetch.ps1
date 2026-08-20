        # One execution, not one per class. The schema holds hundreds of classes
        # and thousands of attributes; a query per class is hundreds of round
        # trips, each paying its own Import-Module ActiveDirectory. Both
        # collections come back in full and the inheritance closure is resolved
        # in Go, where it is testable without a domain.

        # @($null) is a one-element array containing $null, which would decode as
        # [null] rather than []. Piping is what makes an absent multi-valued
        # attribute an empty array.
        function Convert-AdSchemaNames($v) {
            return @($v | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
        }

        $root     = Get-ADRootDSE @common
        $schemaNC = $root.schemaNamingContext
        $domain   = Get-ADDomain @common
        $forest   = Get-ADForest @common
        $schemaCn = Get-ADObject -Identity $schemaNC -Properties objectVersion @common

        $attrs = @(Get-ADObject -SearchBase $schemaNC -SearchScope OneLevel `
            -LDAPFilter '(objectClass=attributeSchema)' `
            -Properties lDAPDisplayName,attributeID,attributeSyntax,oMSyntax,isSingleValued,systemOnly,rangeLower,rangeUpper,searchFlags,linkID @common)

        $classes = @(Get-ADObject -SearchBase $schemaNC -SearchScope OneLevel `
            -LDAPFilter '(objectClass=classSchema)' `
            -Properties lDAPDisplayName,objectClassCategory,subClassOf,auxiliaryClass,systemAuxiliaryClass,mayContain,systemMayContain,mustContain,systemMustContain @common)

        [ordered]@{
            source = [ordered]@{
                domain        = $domain.DNSRoot
                forestMode    = $forest.ForestMode.ToString()
                schemaNC      = $schemaNC
                objectVersion = [int]$schemaCn.objectVersion
            }
            attributes = @($attrs | ForEach-Object { [ordered]@{
                name         = [string]$_.lDAPDisplayName
                oid          = [string]$_.attributeID
                syntax       = [string]$_.attributeSyntax
                omSyntax     = [int]$_.oMSyntax
                singleValued = [bool]$_.isSingleValued
                systemOnly   = [bool]$_.systemOnly
                rangeLower   = $_.rangeLower
                rangeUpper   = $_.rangeUpper
                searchFlags  = [int]$_.searchFlags
                linkId       = $_.linkID
            } })
            classes = @($classes | ForEach-Object { [ordered]@{
                name                 = [string]$_.lDAPDisplayName
                category             = [int]$_.objectClassCategory
                subClassOf           = [string]$_.subClassOf
                # PowerShell unwraps a one-element array across a function
                # return: Convert-AdSchemaNames's own @() only guarantees an
                # array inside the function, and a single surviving name comes
                # back out as a bare string. The array has to be re-established
                # here, at the point where the JSON object is built -- the same
                # reason attributes/classes above are wrapped in @() too.
                auxiliaryClass       = @(Convert-AdSchemaNames $_.auxiliaryClass)
                systemAuxiliaryClass = @(Convert-AdSchemaNames $_.systemAuxiliaryClass)
                mayContain           = @(Convert-AdSchemaNames $_.mayContain)
                systemMayContain     = @(Convert-AdSchemaNames $_.systemMayContain)
                mustContain          = @(Convert-AdSchemaNames $_.mustContain)
                systemMustContain    = @(Convert-AdSchemaNames $_.systemMustContain)
            } })
        }

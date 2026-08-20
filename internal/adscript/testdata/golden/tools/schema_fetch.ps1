$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
Import-Module ActiveDirectory -ErrorAction Stop
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json -AsHashtable

$common = @{}
if ($p.server) { $common['Server'] = $p.server }
if ($p.credential) {
    $secpw = ConvertTo-SecureString $p.credential.password -AsPlainText -Force
    $common['Credential'] = [System.Management.Automation.PSCredential]::new($p.credential.username, $secpw)
}
$credOnly = @{}
if ($common.ContainsKey('Credential')) { $credOnly['Credential'] = $common['Credential'] }

function ConvertTo-AdIsoTime($v) {
    if ($null -eq $v) { return $null }
    return ([datetime]$v).ToUniversalTime().ToString('o')
}

function Convert-AdOU($o) {
    return [ordered]@{
        objectGUID        = $o.ObjectGUID.ToString()
        distinguishedName = $o.DistinguishedName
        name              = $o.Name
        description       = $o.Description
        protected         = [bool]$o.ProtectedFromAccidentalDeletion
    }
}

function Convert-AdGroup($o) {
    return [ordered]@{
        objectGUID        = $o.ObjectGUID.ToString()
        distinguishedName = $o.DistinguishedName
        name              = $o.Name
        samAccountName    = $o.SamAccountName
        scope             = $o.GroupScope.ToString().ToLowerInvariant()
        category          = $o.GroupCategory.ToString().ToLowerInvariant()
        description       = $o.Description
        managedBy         = $o.ManagedBy
        sid               = $o.SID.Value
    }
}

function Convert-AdUser($o) {
    return [ordered]@{
        objectGUID            = $o.ObjectGUID.ToString()
        distinguishedName     = $o.DistinguishedName
        name                  = $o.Name
        samAccountName        = $o.SamAccountName
        userPrincipalName     = $o.UserPrincipalName
        displayName           = $o.DisplayName
        givenName             = $o.GivenName
        surname               = $o.Surname
        description           = $o.Description
        enabled               = [bool]$o.Enabled
        sid                   = $o.SID.Value
        changePasswordAtLogon = ($o.pwdLastSet -eq 0)
        canChangePassword     = (-not $o.CannotChangePassword)
        passwordExpires       = (-not $o.PasswordNeverExpires)
        accountExpirationDate = (ConvertTo-AdIsoTime $o.AccountExpirationDate)
    }
}

# Test-AdPresence reports whether an object is still resolvable, and when it is
# not, hands the exception back for classification in Go. Treating any failure
# as "gone" would let a server-down error look like a successful delete.
function Test-AdPresence($id) {
    try {
        $null = Get-ADObject -Identity $id @common -ErrorAction Stop
        return [ordered]@{ found = $true }
    } catch {
        return [ordered]@{
            found     = $false
            type      = $_.Exception.GetType().FullName
            errorCode = $_.Exception.PSObject.Properties['ErrorCode']?.Value
            message   = $_.Exception.Message
        }
    }
}

try {
    $data = & {
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
                auxiliaryClass       = (Convert-AdSchemaNames $_.auxiliaryClass)
                systemAuxiliaryClass = (Convert-AdSchemaNames $_.systemAuxiliaryClass)
                mayContain           = (Convert-AdSchemaNames $_.mayContain)
                systemMayContain     = (Convert-AdSchemaNames $_.systemMayContain)
                mustContain          = (Convert-AdSchemaNames $_.mustContain)
                systemMustContain    = (Convert-AdSchemaNames $_.systemMustContain)
            } })
        }
    }
    $out = @{ ok = $true; data = $data }
} catch {
    $out = @{ ok = $false; error = @{
        type               = $_.Exception.GetType().FullName
        message            = $_.Exception.Message
        category           = $_.CategoryInfo.Category.ToString()
        targetName         = $_.CategoryInfo.TargetName
        fqid               = $_.FullyQualifiedErrorId
        errorCode          = $_.Exception.PSObject.Properties['ErrorCode']?.Value
        serverErrorMessage = $_.Exception.PSObject.Properties['ServerErrorMessage']?.Value
    } }
}
Write-Output '<<<TFAD:BEGIN>>>'
Write-Output ($out | ConvertTo-Json -Depth 6 -Compress)
Write-Output '<<<TFAD:END>>>'

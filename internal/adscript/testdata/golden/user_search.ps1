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

function Convert-AdServiceAccount($o) {
    $principals = @()
    foreach ($dn in @($o.PrincipalsAllowedToRetrieveManagedPassword)) {
        if ($dn) { $principals += (Get-ADObject -Identity $dn @common).ObjectGUID.ToString() }
    }
    $kerb = @()
    if ($null -ne $o.KerberosEncryptionType) {
        foreach ($k in ($o.KerberosEncryptionType.ToString() -split ',\s*')) { if ($k) { $kerb += $k.Trim() } }
    }
    return [ordered]@{
        objectGUID                    = $o.ObjectGUID.ToString()
        distinguishedName             = $o.DistinguishedName
        name                          = $o.Name
        samAccountName                = $o.SamAccountName
        sid                           = $o.SID.Value
        dnsHostName                   = $o.DNSHostName
        description                   = $o.Description
        displayName                   = $o.DisplayName
        enabled                       = [bool]$o.Enabled
        trustedForDelegation          = [bool]$o.TrustedForDelegation
        principalsAllowed             = @($principals)
        servicePrincipalNames         = @($o.ServicePrincipalNames)
        kerberosEncryptionType        = @($kerb)
        managedPasswordIntervalInDays = [int](@($o.ManagedPasswordIntervalInDays)[0])
        accountExpirationDate         = (ConvertTo-AdIsoTime $o.AccountExpirationDate)
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

# Test-AdMember reports whether $memberId is a direct member of $group without
# enumerating the group: a base-scoped search on the group for that one member's
# DN. The member DN is RFC 4515 escaped (backslash first) before it enters the
# filter, so a DN containing filter metacharacters cannot break the query.
function Test-AdMember($group, $memberId) {
    $m = Get-ADObject -Identity $memberId @common
    $dn = $m.DistinguishedName -replace '\\','\5c' -replace '\(','\28' -replace '\)','\29' -replace '\*','\2a'
    $hit = @(Get-ADObject -SearchBase $group.DistinguishedName -SearchScope Base `
               -LDAPFilter "(member=$dn)" @common)
    return ($hit.Count -gt 0)
}

try {
    $data = & {
        $r = @(Get-ADUser -LDAPFilter $p.filter -SearchBase $p.searchBase `
                 -SearchScope $p.scope -ResultSetSize $p.sizeLimit -Properties $p.project @common)
        [ordered]@{ results = @($r | ForEach-Object { Convert-AdUser $_ }) }
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

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
Import-Module ActiveDirectory -ErrorAction Stop
# JSON parsing's hashtable-output switch (see below) needs PowerShell 6+, and
# operations splat the payload (New-ADOrganizationalUnit @c), which a
# PSCustomObject cannot do. So the object graph 5.1 returns is converted to
# hashtables here.
function ConvertTo-AdHashtable($o) {
    if ($null -eq $o) { return $null }
    # Scalars first. In Windows PowerShell a string satisfies -is [PSCustomObject]
    # (the accelerator resolves to PSObject, which wraps everything), so without
    # this a string would be walked as an object and become a hashtable of its
    # members.
    if ($o -is [string] -or $o -is [System.ValueType]) { return $o }
    if ($o -is [System.Collections.IDictionary]) {
        $h = @{}
        foreach ($k in $o.Keys) { $h[$k] = ConvertTo-AdHashtable $o[$k] }
        return $h
    }
    if ($o -is [object[]]) {
        # Membership payloads carry thousands of distinguished names; an
        # all-scalar array needs no walk at all.
        $needsWalk = $false
        foreach ($item in $o) {
            if (-not ($null -eq $item -or $item -is [string] -or $item -is [System.ValueType])) {
                $needsWalk = $true
                break
            }
        }
        if (-not $needsWalk) { return $o }
        return @($o | ForEach-Object { ConvertTo-AdHashtable $_ })
    }
    if ($o -is [System.Management.Automation.PSCustomObject]) {
        $h = @{}
        foreach ($pr in $o.PSObject.Properties) { $h[$pr.Name] = ConvertTo-AdHashtable $pr.Value }
        return $h
    }
    return $o
}

# Get-AdPropValue stands in for null-conditional property access, which is
# PowerShell 7 only.
function Get-AdPropValue($obj, $name) {
    if ($null -eq $obj) { return $null }
    $pr = $obj.PSObject.Properties[$name]
    if ($pr) { return $pr.Value }
    return $null
}

$p = ConvertTo-AdHashtable ([Console]::In.ReadToEnd() | ConvertFrom-Json)

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

# Convert-KerberosEncType normalizes a KerberosEncryptionType /
# msDS-SupportedEncryptionTypes value to its string-list form. AD hands this
# back as a single comma-joined "flags" string (e.g. "AES128, AES256") rather
# than a real array, so every reader that surfaces it splits the same way.
function Convert-KerberosEncType($k) {
    $out = @()
    foreach ($part in ("$k" -split ',\s*')) { if ($part) { $out += $part.Trim() } }
    return $out
}

function Convert-AdServiceAccount($o) {
    $principals = @()
    foreach ($dn in @($o.PrincipalsAllowedToRetrieveManagedPassword)) {
        if ($dn) { $principals += (Get-ADObject -Identity $dn @common).ObjectGUID.ToString() }
    }
    $kerb = @()
    foreach ($k in @($o.KerberosEncryptionType)) { $kerb += (Convert-KerberosEncType $k) }
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

# Convert-AdComputer resolves msDS-AllowedToDelegateTo's RBCD companion
# (PrincipalsAllowedToDelegateToAccount) from the DNs AD hands back to the
# objectGUIDs the provider stores, mirroring Convert-AdServiceAccount's
# principal resolution above.
function Convert-AdComputer($c) {
    $princ = @()
    foreach ($dn in @($c.PrincipalsAllowedToDelegateToAccount)) {
        if ($dn) { $princ += (Get-ADObject -Identity $dn @common).ObjectGUID.ToString() }
    }
    $ket = @()
    foreach ($k in @($c.KerberosEncryptionType)) { $ket += (Convert-KerberosEncType $k) }
    return [ordered]@{
        ObjectGUID             = $c.ObjectGUID.ToString()
        DistinguishedName      = $c.DistinguishedName
        Name                   = $c.Name
        SamAccountName         = $c.SamAccountName
        SID                    = $c.SID.Value
        Enabled                = [bool]$c.Enabled
        DNSHostName            = $c.DNSHostName
        Description            = $c.Description
        DisplayName            = $c.DisplayName
        Location               = $c.Location
        ManagedBy              = $c.ManagedBy
        TrustedForDelegation   = [bool]$c.TrustedForDelegation
        ServicePrincipalNames  = @($c.ServicePrincipalNames)
        AllowedToDelegateTo    = @($c.'msDS-AllowedToDelegateTo')
        PrincipalsAllowed      = @($princ)
        KerberosEncryptionType = @($ket)
        AccountExpirationDate  = (ConvertTo-AdIsoTime $c.AccountExpirationDate)
        OperatingSystem            = $c.OperatingSystem
        OperatingSystemVersion     = $c.OperatingSystemVersion
        OperatingSystemServicePack = $c.OperatingSystemServicePack
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
            errorCode = (Get-AdPropValue $_.Exception 'ErrorCode')
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
        foreach ($t in $p.targets) {
            $null = Sync-ADObject -Object $p.identity -Source $p.source -Destination $t @credOnly
        }
        [ordered]@{ synced = $true }
    }
    $out = @{ ok = $true; data = $data }
} catch {
    $out = @{ ok = $false; error = @{
        type               = $_.Exception.GetType().FullName
        message            = $_.Exception.Message
        category           = $_.CategoryInfo.Category.ToString()
        targetName         = $_.CategoryInfo.TargetName
        fqid               = $_.FullyQualifiedErrorId
        errorCode          = (Get-AdPropValue $_.Exception 'ErrorCode')
        serverErrorMessage = (Get-AdPropValue $_.Exception 'ServerErrorMessage')
    } }
}
Write-Output '<<<TFAD:BEGIN>>>'
Write-Output ($out | ConvertTo-Json -Depth 6 -Compress)
Write-Output '<<<TFAD:END>>>'

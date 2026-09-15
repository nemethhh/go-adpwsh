$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
if (-not (Get-Module PSOpenAD)) { Import-Module PSOpenAD -ErrorAction Stop }

# This dialect targets PowerShell 7.4+, so the 5.1 workarounds the ADWS
# preamble carries are unnecessary here.
$__adRaw = if ($null -ne $__adPayload) { $__adPayload } else { [Console]::In.ReadToEnd() }
$p = $__adRaw | ConvertFrom-Json -AsHashtable

$common = @{}
if ($p.server) { $common['Server'] = $p.server }
if ($p.credential) {
    $secpw = ConvertTo-SecureString $p.credential.password -AsPlainText -Force
    $common['Credential'] = [System.Management.Automation.PSCredential]::new($p.credential.username, $secpw)
}

function Get-AdPropValue($obj, $name) {
    if ($null -eq $obj) { return $null }
    $pr = $obj.PSObject.Properties[$name]
    if ($pr) { return $pr.Value }
    return $null
}

# PSOpenAD decodes interval attributes to DateTimeOffset. FILETIME 0 decodes to
# 1601-01-01 and 0x7FFFFFFFFFFFFFFF to MaxValue; both mean "never".
function ConvertTo-AdIsoTime($v) {
    if ($null -eq $v) { return $null }
    if ($v -is [DateTimeOffset]) {
        if ($v.UtcDateTime.Year -le 1601 -or $v -eq [DateTimeOffset]::MaxValue) { return $null }
        return $v.UtcDateTime.ToString('o')
    }
    $i = [int64]$v
    if ($i -eq 0 -or $i -eq 0x7FFFFFFFFFFFFFFF) { return $null }
    return ([DateTimeOffset]::FromFileTimeUtc($i)).UtcDateTime.ToString('o')
}

# Description arrives as an array on some classes and a scalar on others. The Go
# DTO expects a scalar, so flatten before it reaches the envelope.
function ConvertTo-AdScalar($v) {
    if ($null -eq $v) { return $null }
    if ($v -is [string]) { return $v }
    if ($v -is [System.Collections.IEnumerable]) {
        foreach ($item in $v) { return [string]$item }
        return $null
    }
    return [string]$v
}

$CHANGE_PASSWORD_RIGHT = [Guid]'ab721a53-1e2f-11d0-9819-00aa0040529b'

function Test-AdDenyAce($sd, [Guid]$objectType, [string[]]$trustees) {
    if ($null -eq $sd -or $null -eq $sd.DiscretionaryAcl) { return $false }
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ("$($ace.AceType)" -notlike 'AccessDenied*') { continue }
        if ($trustees -and ("$($ace.Sid)" -notin $trustees)) { continue }
        if ($objectType -ne [Guid]::Empty) {
            $ot = Get-AdPropValue $ace 'ObjectAceType'
            if ($null -eq $ot -or $ot -ne $objectType) { continue }
        }
        return $true
    }
    return $false
}

function Convert-AdOU($o) {
    $sd = Get-AdPropValue $o 'NTSecurityDescriptor'
    return [ordered]@{
        objectGUID        = $o.ObjectGuid.ToString()
        distinguishedName = $o.DistinguishedName
        name              = $o.Name
        description       = (ConvertTo-AdScalar (Get-AdPropValue $o 'Description'))
        protected         = (Test-AdDenyAce $sd ([Guid]::Empty) @('S-1-1-0'))
    }
}

function Convert-AdGroup($o) {
    return [ordered]@{
        objectGUID        = $o.ObjectGuid.ToString()
        distinguishedName = $o.DistinguishedName
        name              = $o.Name
        samAccountName    = $o.SamAccountName
        scope             = "$($o.GroupScope)".ToLowerInvariant()
        category          = "$($o.GroupCategory)".ToLowerInvariant()
        description       = (ConvertTo-AdScalar (Get-AdPropValue $o 'Description'))
        managedBy         = (Get-AdPropValue $o 'ManagedBy')
        sid               = $o.SID.Value
    }
}

function Convert-AdUser($o) {
    $uac = [int](Get-AdPropValue $o 'UserAccountControl')
    $sd  = Get-AdPropValue $o 'NTSecurityDescriptor'
    return [ordered]@{
        objectGUID            = $o.ObjectGuid.ToString()
        distinguishedName     = $o.DistinguishedName
        name                  = $o.Name
        samAccountName        = $o.SamAccountName
        userPrincipalName     = (Get-AdPropValue $o 'UserPrincipalName')
        displayName           = (Get-AdPropValue $o 'DisplayName')
        givenName             = (Get-AdPropValue $o 'GivenName')
        surname               = (Get-AdPropValue $o 'Surname')
        description           = (ConvertTo-AdScalar (Get-AdPropValue $o 'Description'))
        enabled               = [bool]$o.Enabled
        sid                   = $o.SID.Value
        changePasswordAtLogon = ((Get-AdPropValue $o 'PwdLastSet') -eq 0)
        canChangePassword     = (-not (Test-AdDenyAce $sd $CHANGE_PASSWORD_RIGHT @('S-1-1-0','S-1-5-10')))
        passwordExpires       = (($uac -band 0x10000) -eq 0)
        accountExpirationDate = (ConvertTo-AdIsoTime (Get-AdPropValue $o 'AccountExpires'))
    }
}

function Convert-KerberosEncType($k) {
    $out = @()
    foreach ($part in ("$k" -split ',\s*')) { if ($part) { $out += $part.Trim() } }
    return $out
}

function Convert-AdComputer($c) {
    $princ = @()
    foreach ($sdv in @(Get-AdPropValue $c 'MsDS-AllowedToActOnBehalfOfOtherIdentity')) {
        if ($null -eq $sdv -or $null -eq $sdv.DiscretionaryAcl) { continue }
        foreach ($ace in $sdv.DiscretionaryAcl) {
            $o = Get-OpenADObject -Session $session -LDAPFilter "(objectSid=$($ace.Sid))" -ErrorAction SilentlyContinue
            if ($o) { $princ += $o.ObjectGuid.ToString() }
        }
    }
    $ket = @()
    foreach ($k in @(Get-AdPropValue $c 'MsDS-SupportedEncryptionTypes')) { $ket += (Convert-KerberosEncType $k) }
    $uac = [int](Get-AdPropValue $c 'UserAccountControl')
    return [ordered]@{
        ObjectGUID             = $c.ObjectGuid.ToString()
        DistinguishedName      = $c.DistinguishedName
        Name                   = $c.Name
        SamAccountName         = $c.SamAccountName
        SID                    = $c.SID.Value
        Enabled                = [bool]$c.Enabled
        DNSHostName            = (Get-AdPropValue $c 'DNSHostName')
        Description            = (ConvertTo-AdScalar (Get-AdPropValue $c 'Description'))
        DisplayName            = (Get-AdPropValue $c 'DisplayName')
        Location               = (Get-AdPropValue $c 'Location')
        ManagedBy              = (Get-AdPropValue $c 'ManagedBy')
        TrustedForDelegation   = (($uac -band 0x80000) -ne 0)
        ServicePrincipalNames  = @(Get-AdPropValue $c 'ServicePrincipalName')
        AllowedToDelegateTo    = @(Get-AdPropValue $c 'MsDS-AllowedToDelegateTo')
        PrincipalsAllowed      = @($princ)
        KerberosEncryptionType = @($ket)
        AccountExpirationDate  = (ConvertTo-AdIsoTime (Get-AdPropValue $c 'AccountExpires'))
        OperatingSystem            = (Get-AdPropValue $c 'OperatingSystem')
        OperatingSystemVersion     = (Get-AdPropValue $c 'OperatingSystemVersion')
        OperatingSystemServicePack = (Get-AdPropValue $c 'OperatingSystemServicePack')
    }
}

function Convert-AdServiceAccount($o) {
    $principals = @()
    $mem = Get-AdPropValue $o 'MsDS-GroupMSAMembership'
    if ($mem -and $mem.DiscretionaryAcl) {
        foreach ($ace in $mem.DiscretionaryAcl) {
            $t = Get-OpenADObject -Session $session -LDAPFilter "(objectSid=$($ace.Sid))" -ErrorAction SilentlyContinue
            if ($t) { $principals += $t.ObjectGuid.ToString() }
        }
    }
    $kerb = @()
    foreach ($k in @(Get-AdPropValue $o 'MsDS-SupportedEncryptionTypes')) { $kerb += (Convert-KerberosEncType $k) }
    $uac = [int](Get-AdPropValue $o 'UserAccountControl')
    return [ordered]@{
        objectGUID                    = $o.ObjectGuid.ToString()
        distinguishedName             = $o.DistinguishedName
        name                          = $o.Name
        samAccountName                = $o.SamAccountName
        sid                           = $o.SID.Value
        dnsHostName                   = (Get-AdPropValue $o 'DNSHostName')
        description                   = (ConvertTo-AdScalar (Get-AdPropValue $o 'Description'))
        displayName                   = (Get-AdPropValue $o 'DisplayName')
        enabled                       = [bool]$o.Enabled
        trustedForDelegation          = (($uac -band 0x80000) -ne 0)
        principalsAllowed             = @($principals)
        servicePrincipalNames         = @(Get-AdPropValue $o 'ServicePrincipalName')
        kerberosEncryptionType        = @($kerb)
        managedPasswordIntervalInDays = [int](@(Get-AdPropValue $o 'MsDS-ManagedPasswordInterval')[0])
        accountExpirationDate         = (ConvertTo-AdIsoTime (Get-AdPropValue $o 'AccountExpires'))
    }
}

function Test-AdPresence($id) {
    try {
        $null = Get-OpenADObject -Session $session -Identity $id -ErrorAction Stop
        return [ordered]@{ found = $true }
    } catch {
        return [ordered]@{
            found     = $false
            type      = $_.Exception.psobject.TypeNames[0]
            errorCode = (Get-AdPropValue $_.Exception 'ResultCode')
            message   = $_.Exception.Message
        }
    }
}

# Reports direct membership without enumerating the group: a base-scoped search
# on the group for that one member's DN, RFC 4515 escaped.
function Test-AdMember($group, $memberId) {
    $m = Get-OpenADObject -Session $session -Identity $memberId
    $dn = $m.DistinguishedName -replace '\\','\5c' -replace '\(','\28' -replace '\)','\29' -replace '\*','\2a'
    $hit = @(Get-OpenADObject -Session $session -SearchBase $group.DistinguishedName -SearchScope Base `
               -LDAPFilter "(member=$dn)" -ErrorAction SilentlyContinue)
    return ($hit.Count -gt 0)
}

try {
    $sessionParams = @{}
    if ($p.server) { $sessionParams['ComputerName'] = $p.server }
    if ($common.ContainsKey('Credential')) { $sessionParams['Credential'] = $common['Credential'] }
    $session = New-OpenADSession @sessionParams -ErrorAction Stop
    $common['Session'] = $session
    $common.Remove('Server') | Out-Null
    $common.Remove('Credential') | Out-Null

    $data = & {

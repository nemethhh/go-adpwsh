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
# $common's Credential is replaced by the session once one is open. An op that
# has to reach a second DC - replication verification - opens its own session
# and needs the credential on its own, so it is captured here.
$credOnly = @{}
if ($common.ContainsKey('Credential')) { $credOnly['Credential'] = $common['Credential'] }

# $p.project is the ActiveDirectory module's property vocabulary, and several of
# its entries are synthetic rather than LDAP attributes:
# ProtectedFromAccidentalDeletion, CannotChangePassword, PasswordNeverExpires,
# GroupScope, GroupCategory, KerberosEncryptionType, AccountExpirationDate,
# PrincipalsAllowedTo*. PSOpenAD validates -Properties against the real schema
# and rejects those outright, so this dialect ignores $p.project and requests
# the underlying attributes its own converters read.
#
# Properties the OpenAD* classes already carry - SamAccountName, SID, Enabled,
# UserPrincipalName, GivenName, Surname, GroupScope, GroupCategory,
# userAccountControl - are fetched by the cmdlet regardless and are not listed.
# Every list below that names nTSecurityDescriptor obliges its call sites to
# pass -SecurityMask Dacl; see Get-AdDacl for why an unmasked read returns null
# rather than failing.
$AD_PROPS_OU    = @('description', 'nTSecurityDescriptor')
$AD_PROPS_GROUP = @('description', 'managedBy')
$AD_PROPS_USER  = @('description', 'displayName', 'pwdLastSet', 'accountExpires',
                    'nTSecurityDescriptor')
$AD_PROPS_COMPUTER = @('description', 'displayName', 'location', 'managedBy',
                       'servicePrincipalName', 'msDS-AllowedToDelegateTo',
                       'msDS-AllowedToActOnBehalfOfOtherIdentity',
                       'msDS-SupportedEncryptionTypes', 'accountExpires',
                       'operatingSystem', 'operatingSystemVersion',
                       'operatingSystemServicePack')
$AD_PROPS_GMSA  = @('dNSHostName', 'description', 'displayName', 'servicePrincipalName',
                    'msDS-GroupMSAMembership', 'msDS-SupportedEncryptionTypes',
                    'msDS-ManagedPasswordInterval', 'accountExpires')

function Get-AdPropValue($obj, $name) {
    if ($null -eq $obj) { return $null }
    $pr = $obj.PSObject.Properties[$name]
    if ($pr) { return $pr.Value }
    return $null
}

# PSOpenAD spells the SPN property differently per class: Get-OpenADComputer
# surfaces ServicePrincipalName, Get-OpenADServiceAccount surfaces
# ServicePrincipalNames. Reading only one of them returns $null for the other
# class and emits an empty set - which Terraform reports as an inconsistent
# result after apply, saying nothing about SPNs at all.
function Get-AdSpnValue($o) {
    $v = Get-AdPropValue $o 'ServicePrincipalName'
    if ($null -eq $v) { $v = Get-AdPropValue $o 'ServicePrincipalNames' }
    return $v
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

# pwdLastSet is an interval attribute too, so PSOpenAD decodes it the same way:
# the FILETIME 0 that means "must change at next logon" arrives as a
# DateTimeOffset of 1601-01-01, never as the integer 0. Comparing it to 0
# therefore never matched, and changePasswordAtLogon read back false whatever
# the directory held - the account was flagged, the DTO said it was not.
#
# The integer branch stays because the attribute is a FILETIME by definition and
# a future module version handing back the raw value must keep working.
function Test-AdMustChangePassword($v) {
    if ($null -eq $v) { return $true }
    if ($v -is [DateTimeOffset]) { return ($v.UtcDateTime.Year -le 1601) }
    return ([int64]$v -eq 0)
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

# schemaIDGUID is an octet string, so it arrives as a PSObject-wrapped byte
# array rather than a Guid or a string; rightsGUID is a plain string attribute.
# Both normalise to the canonical 8-4-4-4-12 form the ACL object-type fields
# expect, which is what the AD cmdlets emit.
function ConvertTo-AdGuidString($v) {
    if ($null -eq $v) { return $null }
    if ($v -is [Guid]) { return $v.ToString() }
    if ($v -is [string]) { return ([Guid]$v).ToString() }
    return ([Guid]::new([byte[]]@($v))).ToString()
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

# groupType bits, per MS-ADTS 2.2.12. These are written as [uint32] constants
# rather than hex literals on purpose: PowerShell parses a hex literal that sets
# bit 31 as a negative Int32, so 0x80000000 is -2147483648 and every subsequent
# conversion of it is wrong in a different way.
$AD_GT_GLOBAL      = [uint32]2        # 0x00000002
$AD_GT_DOMAINLOCAL = [uint32]4        # 0x00000004
$AD_GT_UNIVERSAL   = [uint32]8        # 0x00000008
$AD_GT_SCOPE_MASK  = [uint32]14       # the three scope bits together
$AD_GT_SECURITY    = [uint32]2147483648 # 0x80000000

# AD stores groupType as a 32-bit signed integer, and LDAP carries it as a
# decimal string. The value is handed over as that string: it is unambiguous,
# and it sidesteps both PowerShell's numeric promotion and whatever conversion
# the module applies to an -OtherAttributes value.
function ConvertTo-AdGroupTypeValue([uint32]$bits) {
    return [string][BitConverter]::ToInt32([BitConverter]::GetBytes($bits), 0)
}

# Scope and category are derived from the raw groupType bits, which are the same
# bits the create and update fragments write, rather than from PSOpenAD's
# GroupScope and GroupCategory properties.
#
# This was found the hard way: that property switched on the whole groupType
# value instead of masking the scope bits, so a security group - which always
# carries IsSecurity, 0x80000000 - never matched Global or DomainLocal and read
# back as Universal. A fix is landing on the fork's main. Reading the bits
# directly is correct either way and keeps the emitted contract independent of
# how the module chooses to present them, so it stays after the fix lands.
function Convert-AdGroup($o) {
    $gt = [uint32](Get-AdPropValue $o 'GroupType')
    if (($gt -band 0x4) -ne 0)      { $scope = 'domainlocal' }
    elseif (($gt -band 0x2) -ne 0)  { $scope = 'global' }
    else                            { $scope = 'universal' }
    $category = if (($gt -band 0x80000000) -ne 0) { 'security' } else { 'distribution' }
    return [ordered]@{
        objectGUID        = $o.ObjectGuid.ToString()
        distinguishedName = $o.DistinguishedName
        name              = $o.Name
        samAccountName    = $o.SamAccountName
        scope             = $scope
        category          = $category
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
        changePasswordAtLogon = (Test-AdMustChangePassword (Get-AdPropValue $o 'PwdLastSet'))
        canChangePassword     = (-not (Test-AdDenyAce $sd $CHANGE_PASSWORD_RIGHT @('S-1-1-0','S-1-5-10')))
        passwordExpires       = (($uac -band 0x10000) -eq 0)
        accountExpirationDate = (ConvertTo-AdIsoTime (Get-AdPropValue $o 'AccountExpires'))
    }
}

# PSOpenAD decodes msDS-SupportedEncryptionTypes into its own enum, whose names
# are the full Kerberos spellings (Rc4Hmac, Aes256CtsHmacSha196). The ADWS
# dialect emits the ActiveDirectory module's short names, and that is the frozen
# contract, so the names are mapped back. ConvertTo-AdEncTypeBits accepts either
# spelling on the way in, so a value read from one dialect can be written to the
# other.
function Convert-KerberosEncType($k) {
    $out = @()
    foreach ($part in ("$k" -split ',\s*')) {
        $t = $part.Trim()
        if (-not $t) { continue }
        switch -Regex ($t) {
            '^(Rc4Hmac|RC4.*)$'   { $out += 'RC4'; break }
            '^Aes128'             { $out += 'AES128'; break }
            '^Aes256'             { $out += 'AES256'; break }
            '^DesCbcCrc$'         { $out += 'DES-CBC-CRC'; break }
            '^DesCbcMd5$'         { $out += 'DES-CBC-MD5'; break }
            default               { $out += $t }
        }
    }
    return $out
}

# An attribute with no values must emit an empty list, not a one-element list
# holding a null: @($null) has length one, and the Go DTO renders that as [""].
# Every call site wraps the result in @(), so this returns the elements and lets
# that wrapping rebuild the array - returning ,$out here would nest one inside
# another.
function ConvertTo-AdArray($v) {
    $out = @()
    foreach ($item in @($v)) {
        if ($null -eq $item) { continue }
        if ("$item" -eq '') { continue }
        $out += $item
    }
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
        ServicePrincipalNames  = @(ConvertTo-AdArray (Get-AdSpnValue $c))
        AllowedToDelegateTo    = @(ConvertTo-AdArray (Get-AdPropValue $c 'MsDS-AllowedToDelegateTo'))
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
        servicePrincipalNames         = @(ConvertTo-AdArray (Get-AdSpnValue $o))
        kerberosEncryptionType        = @($kerb)
        managedPasswordIntervalInDays = [int](@(Get-AdPropValue $o 'MsDS-ManagedPasswordInterval')[0])
        accountExpirationDate         = (ConvertTo-AdIsoTime (Get-AdPropValue $o 'AccountExpires'))
    }
}

# msDS-SupportedEncryptionTypes bits, per MS-KILE 2.2.7. The Go side sends the
# names AD's KerberosEncryptionType enum uses; the longer Kerberos spellings are
# accepted too so a value read back from one dialect can be written to the other.
function ConvertTo-AdEncTypeBits($values) {
    $v = 0
    foreach ($k in @($values)) {
        switch -Regex ("$k".ToUpperInvariant().Trim()) {
            '^DES-CBC-CRC$'      { $v = $v -bor 1 }
            '^DES-CBC-MD5$'      { $v = $v -bor 2 }
            '^(RC4|RC4-HMAC.*)$' { $v = $v -bor 4 }
            '^AES128'            { $v = $v -bor 8 }
            '^AES256'            { $v = $v -bor 16 }
        }
    }
    return $v
}

# A computer-class sAMAccountName - computer or gMSA - must end in "$".
# New-ADComputer and New-ADServiceAccount append it themselves, so the Go side
# deliberately never does (see the comment on Computer.Update, which compares
# the suffixed value read back against the unsuffixed config value).
# New-OpenADObject writes exactly what it is handed, and AD refuses an
# unsuffixed name with 0x523 ERROR_INVALID_ACCOUNT_NAME.
function ConvertTo-AdComputerSamAccountName($v) {
    if ($null -eq $v -or "$v" -eq '') { return $v }
    if ("$v".EndsWith('$')) { return "$v" }
    return "$v" + '$'
}

# $p.set carries two kinds of entry. The typed fields arrive under Microsoft
# cmdlet parameter names and each fragment maps those per class, because the
# mapping differs per class. Add/Remove/Replace/Clear arrive under raw LDAP
# attribute names from the Go side's AttrOps, and pass straight through, because
# Set-OpenADObject takes them under exactly those parameter names.
#
# Dropping them is not an option: clearing a description is expressed as
# Clear=@('description'), not as an empty Replace, so a fragment that forwarded
# only its own $repl would silently ignore every clear.
function Set-AdAttributes($identity, $s, $repl) {
    $splat = @{}
    if ($s.ContainsKey('Replace') -and $s.Replace) {
        foreach ($k in $s.Replace.Keys) { $repl[$k] = $s.Replace[$k] }
    }
    if ($repl.Count -gt 0) { $splat['Replace'] = $repl }
    foreach ($k in @('Add','Remove','Clear')) {
        if ($s.ContainsKey($k) -and $s[$k]) { $splat[$k] = $s[$k] }
    }
    if ($splat.Count -eq 0) { return }
    Set-OpenADObject @common -Identity $identity @splat
}

# accountExpires is a FILETIME string; 0 means "never". The Go side sends an
# RFC3339 string or a null.
function ConvertTo-AdAccountExpires($v) {
    if ($null -eq $v) { return '0' }
    return "$(([datetime]$v).ToUniversalTime().ToFileTimeUtc())"
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

# AD rejects unmapped generic bits with 0x20A2, so full control is written as
# the mapped mask rather than GenericAll.
$AD_RIGHTS_FULL = 0xF01FF

# ActiveDirectorySecurityInheritance maps onto ACE flags exactly as
# System.DirectoryServices does it, so an ACE written here is indistinguishable
# from one written by the ADWS dialect:
#
#   None             -> (none)
#   All              -> ContainerInherit
#   Descendents      -> ContainerInherit | InheritOnly
#   SelfAndChildren  -> ContainerInherit | NoPropagateInherit
#   Children         -> ContainerInherit | NoPropagateInherit | InheritOnly
#
# NoPropagateInherit is what distinguishes the two "children" forms from the two
# "descendents" forms; ObjectInherit plays no part, because every AD object is a
# container as far as inheritance is concerned.
# ActiveDirectoryRights is a uint, and the generic bits - GenericRead is
# 0x80000000 - do not fit a signed Int32, so an access mask is always compared
# as [uint32]. [int] on one throws outright on any ACE that carries a generic
# right, which a real DACL may well do.
function New-AdAceFromSpec($spec) {
    $sid    = [PSOpenAD.Security.SecurityIdentifier]::new([string]$spec.trustee)
    $rights = [PSOpenAD.Security.ActiveDirectoryRights](@($spec.rights) -join ', ')
    $type   = if ("$($spec.type)" -eq 'Deny') { 'AccessDenied' } else { 'AccessAllowed' }
    $flags  = [PSOpenAD.Security.AceFlags]::None
    switch ("$($spec.inheritance)") {
        'All'             { $flags = [PSOpenAD.Security.AceFlags]'ContainerInherit' }
        'Descendents'     { $flags = [PSOpenAD.Security.AceFlags]'ContainerInherit, InheritOnly' }
        'SelfAndChildren' { $flags = [PSOpenAD.Security.AceFlags]'ContainerInherit, NoPropagateInherit' }
        'Children'        { $flags = [PSOpenAD.Security.AceFlags]'ContainerInherit, NoPropagateInherit, InheritOnly' }
    }
    $ot  = if ($spec.objectType)          { [Guid]$spec.objectType }          else { [Guid]::Empty }
    $iot = if ($spec.inheritedObjectType) { [Guid]$spec.inheritedObjectType } else { [Guid]::Empty }
    if ($ot -ne [Guid]::Empty -or $iot -ne [Guid]::Empty) {
        $oflags = [PSOpenAD.Security.ObjectAceFlags]::None
        if ($ot  -ne [Guid]::Empty) { $oflags = $oflags -bor [PSOpenAD.Security.ObjectAceFlags]::ObjectAceTypePresent }
        if ($iot -ne [Guid]::Empty) { $oflags = $oflags -bor [PSOpenAD.Security.ObjectAceFlags]::InheritedObjectAceTypePresent }
        $t = if ($type -eq 'AccessDenied') { 'AccessDeniedObject' } else { 'AccessAllowedObject' }
        return [PSOpenAD.Security.ObjectAce]::new(
            [PSOpenAD.Security.AceType]$t, $flags, $rights, $sid, $null, $oflags, $ot, $iot)
    }
    return [PSOpenAD.Security.Ace]::new([PSOpenAD.Security.AceType]$type, $flags, $rights, $sid, $null)
}

# The inverse. objectType and inheritedObjectType are emitted as the all-zero
# GUID when absent, which is what the AD cmdlets emit and what the Go side
# normalises back to "".
function ConvertTo-AdAceSpec($a) {
    $CONTAINER_INHERIT = 0x02
    $NO_PROPAGATE      = 0x04
    $INHERIT_ONLY      = 0x08
    $INHERITED         = 0x10

    $f = [int]$a.AceFlags
    $inh = 'None'
    if (($f -band $CONTAINER_INHERIT) -ne 0) {
        if (($f -band $NO_PROPAGATE) -ne 0) {
            $inh = if (($f -band $INHERIT_ONLY) -ne 0) { 'Children' } else { 'SelfAndChildren' }
        } else {
            $inh = if (($f -band $INHERIT_ONLY) -ne 0) { 'Descendents' } else { 'All' }
        }
    }

    # ObjectAceType is only meaningful when its presence flag is set.
    $ot     = [Guid]::Empty
    $iot    = [Guid]::Empty
    $oflags = Get-AdPropValue $a 'ObjectAceFlags'
    if ($null -ne $oflags) {
        if (([int]$oflags -band 1) -ne 0) { $ot  = [Guid](Get-AdPropValue $a 'ObjectAceType') }
        if (([int]$oflags -band 2) -ne 0) { $iot = [Guid](Get-AdPropValue $a 'InheritedObjectAceType') }
    }

    return [ordered]@{
        trustee             = "$($a.Sid)"
        type                = $(if ("$($a.AceType)" -like 'AccessDenied*') { 'Deny' } else { 'Allow' })
        rights              = @("$($a.AccessMask)" -split ',\s*' | Where-Object { $_ })
        objectType          = $ot.ToString()
        inheritedObjectType = $iot.ToString()
        inheritance         = $inh
        inherited           = (($f -band $INHERITED) -ne 0)
    }
}

# -SecurityMask Dacl on the READ is not symmetry with Set-AdDacl below, it is a
# correctness requirement of its own. A read that names no mask asks for all
# four parts of the descriptor, the SACL included; a caller without
# SeSecurityPrivilege is not refused it -- AD returns the attribute EMPTY and
# PSOpenAD surfaces $null. That is invisible on a Domain Admin and breaks on
# every least-privileged service account: .Insert() on the null DACL throws, and
# the converters read every Deny ACE as absent.
function Get-AdDacl($identity) {
    $o = Get-OpenADObject @common -Identity $identity -Properties nTSecurityDescriptor -SecurityMask Dacl
    return @{ dn = $o.DistinguishedName; guid = $o.ObjectGuid.ToString(); sd = $o.NTSecurityDescriptor }
}

# -SecurityMask Dacl states that the write applies to the DACL alone, and the
# value has to agree with that: a descriptor still carrying a SACL is refused
# with 0000053A CONSTRAINT_ATT_TYPE, because writing a SACL needs
# SeSecurityPrivilege and was not what the mask asked for. Get-OpenADObject
# returns the whole descriptor - owner, group, DACL and SACL - so a
# read-modify-write has to narrow it back down before sending it.
#
# So the value written is rebuilt as DACL-only. The DACL's own control bits are
# carried over, because they are part of what the DACL means: dropping
# DiscretionaryAclAutoInherited or DiscretionaryAclProtected would silently
# change how inheritance applies to the object.
#
# The descriptor is passed as an object. Never pass a byte[] through -Replace: a
# PSObject-wrapped array was silently stringified before the fork's fix, and the
# object is the correct API regardless.
$AD_DACL_CONTROL_BITS = 0x0004 -bor 0x0008 -bor 0x0040 -bor 0x0100 -bor 0x0400 -bor 0x1000

function Set-AdDacl($identity, $sd) {
    $out = [PSOpenAD.Security.CommonSecurityDescriptor]::new()
    $keep = ([int]$sd.Flags) -band $AD_DACL_CONTROL_BITS
    $out.Flags = [PSOpenAD.Security.ControlFlags](
        $keep -bor [int][PSOpenAD.Security.ControlFlags]::SelfRelative -bor
                   [int][PSOpenAD.Security.ControlFlags]::DiscretionaryAclPresent)
    $out.DiscretionaryAcl = $sd.DiscretionaryAcl
    Set-OpenADObject @common -Identity $identity -Replace @{nTSecurityDescriptor = $out} -SecurityMask Dacl
}

# ProtectedFromAccidentalDeletion is an explicit Deny of Delete and DeleteTree
# for Everyone (S-1-1-0). 0x10000 is the Delete right.
function Set-AdProtected($identity, [bool]$on) {
    $cur = Get-AdDacl $identity
    $sd  = $cur.sd
    $existing = @($sd.DiscretionaryAcl | Where-Object {
        "$($_.AceType)" -like 'AccessDenied*' -and "$($_.Sid)" -eq 'S-1-1-0' -and
        (([uint32]$_.AccessMask) -band 0x10000) -ne 0 })
    if ($on -and $existing.Count -eq 0) {
        $ace = [PSOpenAD.Security.Ace]::new(
            [PSOpenAD.Security.AceType]::AccessDenied, [PSOpenAD.Security.AceFlags]::None,
            ([PSOpenAD.Security.ActiveDirectoryRights]'Delete, DeleteTree'),
            [PSOpenAD.Security.SecurityIdentifier]::new('S-1-1-0'), $null)
        $sd.DiscretionaryAcl.Insert(0, $ace)
        Set-AdDacl $identity $sd
    } elseif (-not $on -and $existing.Count -gt 0) {
        foreach ($e in $existing) { $null = $sd.DiscretionaryAcl.Remove($e) }
        Set-AdDacl $identity $sd
    }
}

# CannotChangePassword is a Deny of the change-password extended right for both
# Everyone and Principal Self - the same pair Set-ADUser writes, and the same
# pair Convert-AdUser reads back as canChangePassword.
function Set-AdCannotChangePassword($identity, [bool]$on) {
    $trustees = @('S-1-1-0', 'S-1-5-10')
    $cur = Get-AdDacl $identity
    $sd  = $cur.sd
    $isChangePwdAce = {
        param($ace, $wantDeny)
        $ot = Get-AdPropValue $ace 'ObjectAceType'
        if ($null -eq $ot -or [Guid]$ot -ne $CHANGE_PASSWORD_RIGHT) { return $false }
        if ("$($ace.Sid)" -notin $trustees) { return $false }
        $isDeny = "$($ace.AceType)" -like 'AccessDenied*'
        return ($isDeny -eq $wantDeny)
    }
    $changed = $false
    if ($on) {
        foreach ($t in $trustees) {
            $have = @($sd.DiscretionaryAcl | Where-Object {
                (& $isChangePwdAce $_ $true) -and "$($_.Sid)" -eq $t })
            if ($have.Count -gt 0) { continue }
            $sd.DiscretionaryAcl.Insert(0, [PSOpenAD.Security.ObjectAce]::new(
                [PSOpenAD.Security.AceType]::AccessDeniedObject,
                [PSOpenAD.Security.AceFlags]::None,
                [PSOpenAD.Security.ActiveDirectoryRights]::ExtendedRight,
                [PSOpenAD.Security.SecurityIdentifier]::new($t), $null,
                [PSOpenAD.Security.ObjectAceFlags]::ObjectAceTypePresent,
                $CHANGE_PASSWORD_RIGHT, [Guid]::Empty))
            $changed = $true
        }
    } else {
        foreach ($e in @($sd.DiscretionaryAcl | Where-Object { & $isChangePwdAce $_ $true })) {
            $null = $sd.DiscretionaryAcl.Remove($e)
            $changed = $true
        }
    }
    if ($changed) { Set-AdDacl $identity $sd }
}

# Builds the descriptor AD stores in msDS-AllowedToActOnBehalfOfOtherIdentity
# and msDS-GroupMSAMembership: owner and group Domain Admins, one allow ACE per
# principal. Rights must be the mapped full-control mask; AD rejects generic bits.
function New-AdPrincipalSd([string[]]$principalIds) {
    $dnc       = (Get-OpenADRootDSE @common).DefaultNamingContext
    $domainSid = (Get-OpenADObject @common -Identity $dnc -Properties objectSid).ObjectSid.Value
    $admins    = [PSOpenAD.Security.SecurityIdentifier]::new("$domainSid-512")
    $sd = [PSOpenAD.Security.CommonSecurityDescriptor]::new()
    $sd.Flags = [PSOpenAD.Security.ControlFlags]'DiscretionaryAclPresent, SelfRelative'
    $sd.Owner = $admins
    $sd.Group = $admins
    $dacl = [PSOpenAD.Security.DiscretionaryAcl]::new([PSOpenAD.Security.AclRevision]::Revision)
    foreach ($g in @($principalIds)) {
        $o = Get-OpenADObject @common -Identity $g -Properties objectSid
        $dacl.Add([PSOpenAD.Security.Ace]::new(
            [PSOpenAD.Security.AceType]::AccessAllowed, [PSOpenAD.Security.AceFlags]::None,
            ([PSOpenAD.Security.ActiveDirectoryRights]$AD_RIGHTS_FULL), $o.ObjectSid, $null))
    }
    $sd.DiscretionaryAcl = $dacl
    return $sd
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

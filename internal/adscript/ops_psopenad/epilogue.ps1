    }
    $out = @{ ok = $true; data = $data }
} catch {
    # Per MS-ADTS 3.1.1.3.1.9 the first eight characters of an LDAP
    # errorMessage are the Win32 code in hex. PSOpenAD surfaces that string as
    # DiagnosticsMessage on LDAPException. Cmdlet-level errors (an -Identity
    # that matched nothing) carry no DiagnosticsMessage and are classified on
    # their type and FullyQualifiedErrorId instead.
    $ex   = $_.Exception
    $diag = (Get-AdPropValue $ex 'DiagnosticsMessage')
    $code = $null
    if ($diag -and $diag -match '^([0-9A-Fa-f]{8})') {
        $code = [Convert]::ToInt64($Matches[1], 16)
    }
    $out = @{ ok = $false; error = @{
        type               = $ex.psobject.TypeNames[0]
        message            = $ex.Message
        category           = $_.CategoryInfo.Category.ToString()
        targetName         = $_.CategoryInfo.TargetName
        fqid               = $_.FullyQualifiedErrorId
        errorCode          = $code
        serverErrorMessage = $diag
    } }
} finally {
    if ($session) { $session | Remove-OpenADSession -ErrorAction SilentlyContinue }
}
Write-Output '<<<TFAD:BEGIN>>>'
Write-Output ($out | ConvertTo-Json -Depth 6 -Compress)
Write-Output '<<<TFAD:END>>>'

        if (-not (Get-Command Set-AdAce -ErrorAction SilentlyContinue)) {
            throw "This ConstrainedLanguage endpoint has no ACL helpers; register it with scripts/host/New-AdProviderEndpoint.ps1 -Capability acl -Sandbox."
        }
        Set-AdAce -Target $p.target -Server $common['Server'] -Credential $common['Credential'] -Aces $p.aces

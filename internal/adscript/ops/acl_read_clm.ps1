        if (-not (Get-Command Get-AdAce -ErrorAction SilentlyContinue)) {
            throw "This ConstrainedLanguage endpoint has no ACL helpers; register it with scripts/host/New-AdProviderEndpoint.ps1 -Capability acl -Sandbox."
        }
        Get-AdAce -Target $p.target -Server $common['Server'] -Credential $common['Credential']

        # There is no Get-OpenADDomainController. Every DC has an nTDSDSA object
        # in the configuration NC whose parent server object carries dNSHostName,
        # so the DC set is exactly the set of nTDSDSA parents.
        $root   = Get-OpenADRootDSE @common
        $config = $root.ConfigurationNamingContext
        $names  = @()
        foreach ($dsa in (Get-OpenADObject @common -SearchBase "CN=Sites,$config" -SearchScope Subtree `
                            -LDAPFilter '(objectClass=nTDSDSA)' -Properties distinguishedName)) {
            # The nTDSDSA object's RDN is the constant "CN=NTDS Settings", so the
            # parent server DN is that fixed prefix removed. Stripping a known
            # constant avoids parsing a DN whose other RDNs may contain escaped
            # commas.
            $serverDn = $dsa.DistinguishedName
            if ($serverDn -like 'CN=NTDS Settings,*') {
                $serverDn = $serverDn.Substring('CN=NTDS Settings,'.Length)
            } else {
                $serverDn = ($serverDn -split ',', 2)[1]
            }
            $srv = Get-OpenADObject @common -Identity $serverDn -Properties dNSHostName
            $hn = Get-AdPropValue $srv 'DNSHostName'
            if ($hn) { $names += $hn }
        }
        [ordered]@{ hostNames = @($names | Sort-Object -Unique) }

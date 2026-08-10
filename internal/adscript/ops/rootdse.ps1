        $r = Get-ADRootDSE @common
        [ordered]@{
            dnsHostName          = $r.dnsHostName
            defaultNamingContext = $r.defaultNamingContext
            schemaNamingContext  = $r.schemaNamingContext
        }

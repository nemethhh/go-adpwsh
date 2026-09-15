        $r = Get-OpenADRootDSE @common
        [ordered]@{
            dnsHostName          = $r.DnsHostName
            defaultNamingContext = $r.DefaultNamingContext
            schemaNamingContext  = $r.SchemaNamingContext
        }

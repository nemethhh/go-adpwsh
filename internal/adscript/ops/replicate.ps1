        foreach ($t in $p.targets) {
            $null = Sync-ADObject -Object $p.identity -Source $p.source -Destination $t @credOnly
        }
        [ordered]@{ synced = $true }

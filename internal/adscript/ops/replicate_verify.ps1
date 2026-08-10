        $results = @(foreach ($t in $p.targets) {
            $present = $true
            try { $null = Get-ADObject -Identity $p.identity -Server $t @credOnly -ErrorAction Stop }
            catch { $present = $false }
            [ordered]@{ target = $t; present = $present }
        })
        [ordered]@{ results = @($results) }

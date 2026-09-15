        # A session is pinned to one DC, so verifying that an object reached
        # every other DC means opening a session per target.
        $results = @(foreach ($t in $p.targets) {
            $present = $true
            $ts = $null
            try {
                $ts = New-OpenADSession -ComputerName $t @credOnly -ErrorAction Stop
                $null = Get-OpenADObject -Session $ts -Identity $p.identity -ErrorAction Stop
            } catch { $present = $false }
            finally { if ($ts) { $ts | Remove-OpenADSession -ErrorAction SilentlyContinue } }
            [ordered]@{ target = $t; present = $present }
        })
        [ordered]@{ results = @($results) }

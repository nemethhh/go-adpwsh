        # unicodePwd is written as UTF-16LE with surrounding quotes, over the
        # session's sealed connection. A -Replace is the reset form; -Remove
        # then -Add would be the "change with old password" form, which this op
        # does not express.
        $pw = [System.Text.Encoding]::Unicode.GetBytes('"' + $p.password + '"')
        Set-OpenADObject @common -Identity $p.identity -Replace @{unicodePwd = $pw}
        [ordered]@{ reset = $true }

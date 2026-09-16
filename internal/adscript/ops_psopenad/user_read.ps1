        Convert-AdUser (Get-OpenADUser @common -Identity $p.identity -Properties $AD_PROPS_USER -SecurityMask Dacl)

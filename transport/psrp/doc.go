// Package psrp runs go-adpwsh's PowerShell commands over PSRP/WinRM using
// github.com/smnsjas/go-psrp. It implements the adpwsh.Transport interface and
// changes no go-adpwsh script, preamble, or epilogue.
package psrp

import _ "github.com/smnsjas/go-psrp/client"

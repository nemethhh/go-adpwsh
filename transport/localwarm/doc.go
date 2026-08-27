// Package localwarm runs go-adpwsh operations in a persistent local PowerShell 7
// runspace (pwsh -SSHServerMode) driven over the out-of-proc adapter, pooled by
// internal/warm. It is the local+warm cell of the transport × execution-mode
// matrix: startup and Import-Module ActiveDirectory are paid once per pooled
// process, then amortized across every operation that reuses it — unlike
// transport/local, which pays that tax on every op with a fresh pwsh child.
//
// Concurrency comes from the pool of processes, never MaxRunspaces>1: payload
// delivery rides [Console]::SetIn, which is process-global, so each pooled warm
// connection must be its own pwsh child.
package localwarm

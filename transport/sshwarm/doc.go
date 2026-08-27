// Package sshwarm runs go-adpwsh operations in a persistent pwsh -sshs runspace
// on a Windows jump box, reached over an SSH subsystem channel and driven by the
// out-of-proc adapter, pooled by internal/warm. It reuses transport/ssh's dialer
// for connection + auth and shares the runspace executor with local+warm via
// internal/psrun. A subsystem (not an exec) is required: a plain exec of
// pwsh -sshs is corrupted by the remote cmd.exe.
package sshwarm

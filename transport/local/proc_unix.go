//go:build !windows

package local

import (
	"os"
	"syscall"
)

// sysProcAttr puts the child in its own process group so killTree can signal
// the whole tree rather than pwsh alone.
func sysProcAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }

// killTree kills the child and everything it started. This is a correctness
// requirement and not only orphan hygiene: a surviving grandchild holds the
// stdout pipe open, and Wait does not return until every writer is gone.
func killTree(p *os.Process) {
	if p == nil {
		return
	}
	// A negative pid is the process group. If the group is already gone,
	// fall back to the process itself.
	if err := syscall.Kill(-p.Pid, syscall.SIGKILL); err != nil {
		_ = p.Kill()
	}
}

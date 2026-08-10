//go:build windows

package local

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// createNewProcessGroup is CREATE_NEW_PROCESS_GROUP. Naming the constant here
// keeps golang.org/x/sys/windows out of this module's dependencies for one flag.
const createNewProcessGroup = 0x00000200

func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: createNewProcessGroup}
}

// killTree kills the child and its descendants. Windows has no process-group
// signal, so taskkill /T is the tree walk; killing the process directly is the
// fallback for a host where taskkill is unavailable.
func killTree(p *os.Process) {
	if p == nil {
		return
	}
	kill := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(p.Pid))
	if err := kill.Run(); err != nil {
		_ = p.Kill()
	}
}

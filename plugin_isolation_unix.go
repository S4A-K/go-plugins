//go:build unix

package goplugins

import (
	"os/exec"
	"syscall"
)

// configureProcAttr configures process attributes for Unix systems
func configureProcAttr(cmd *exec.Cmd, processGroup bool) {
	if processGroup {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true,
		}
	}
}

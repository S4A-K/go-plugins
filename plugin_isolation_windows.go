//go:build windows

package goplugins

import (
	"os/exec"
	"syscall"
)

// configureProcAttr configures process attributes for Windows systems
func configureProcAttr(cmd *exec.Cmd, processGroup bool) {
	if processGroup {
		// On Windows, we use CREATE_NEW_PROCESS_GROUP instead of Setpgid
		cmd.SysProcAttr = &syscall.SysProcAttr{
			CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
		}
	}
}

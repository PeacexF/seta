//go:build !windows

package plugin

import (
	"os/exec"
	"syscall"
)

// killGroup makes a timeout kill the plugin's children too (curl started by
// a shell script), not just the plugin.
func killGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}

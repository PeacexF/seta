package plugin

import "os/exec"

// killGroup leaves the default: kill the plugin only. Its children are cut
// off by WaitDelay closing the pipes.
func killGroup(*exec.Cmd) {}

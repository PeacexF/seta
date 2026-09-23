//go:build !windows

package cli

import "os"

func enableVirtualTerminal(*os.File) bool { return true }

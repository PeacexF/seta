package checktest

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// InstallSelf links the running test binary into dir as seta-plugin-<name>,
// for tests whose TestMain turns the binary into a fake plugin when invoked
// under that name.
func InstallSelf(tb testing.TB, dir string, names ...string) {
	tb.Helper()
	self, err := os.Executable()
	if err != nil {
		tb.Fatal(err)
	}
	for _, n := range names {
		dst := filepath.Join(dir, "seta-plugin-"+n)
		if runtime.GOOS == "windows" {
			dst += ".exe"
		}
		if os.Symlink(self, dst) == nil {
			continue
		}
		// Windows needs privileges for symlinks.
		if err := copyFile(self, dst); err != nil {
			tb.Fatal(err)
		}
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// PluginName returns the fake plugin the test binary was invoked as.
func PluginName() (string, bool) {
	base := filepath.Base(os.Args[0])
	if runtime.GOOS == "windows" {
		base = base[:len(base)-len(filepath.Ext(base))]
	}
	const prefix = "seta-plugin-"
	if len(base) > len(prefix) && base[:len(prefix)] == prefix {
		return base[len(prefix):], true
	}
	return "", false
}

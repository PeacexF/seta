package plugin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	maxStdout = 4 << 20
	maxStderr = 64 << 10
	// waitDelay bounds how long a killed plugin's children may hold its
	// output pipes open.
	waitDelay = 2 * time.Second
)

var errOutputTooLarge = fmt.Errorf("plugin wrote more than %d MiB to stdout", maxStdout>>20)

// invoke runs the plugin with one argument, feeding it stdin. A non-zero
// exit is an error that carries the end of stderr, the plugin's own account
// of what went wrong.
func invoke(ctx context.Context, path, arg string, stdin []byte, env []string) (stdout, stderr []byte, err error) {
	cmd := exec.CommandContext(ctx, path, arg)
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(stdin)
	out := &capped{max: maxStdout}
	logs := &capped{max: maxStderr}
	cmd.Stdout, cmd.Stderr = out, logs
	cmd.WaitDelay = waitDelay
	killGroup(cmd)

	err = cmd.Run()
	switch {
	case ctx.Err() != nil:
		return nil, logs.Bytes(), ctx.Err()
	case out.over:
		return nil, logs.Bytes(), errOutputTooLarge
	case err != nil:
		if ee, ok := errors.AsType[*exec.ExitError](err); ok {
			err = fmt.Errorf("plugin exited with status %d", ee.ExitCode())
		}
		if last := lastLine(logs.Bytes()); last != "" {
			err = fmt.Errorf("%w: %s", err, last)
		}
		return nil, logs.Bytes(), err
	}
	return out.Bytes(), logs.Bytes(), nil
}

// capped keeps the first max bytes and silently drops the rest, so a
// chatty plugin can't exhaust memory or fail on a closed pipe.
type capped struct {
	bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.Len(); len(p) > room {
		c.over = true
		c.Buffer.Write(p[:max(room, 0)])
		return len(p), nil
	}
	return c.Buffer.Write(p)
}

func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return truncate(strings.TrimSpace(lines[len(lines)-1]), 300)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

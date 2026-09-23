// Command seta monitors the public posture of your domains.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/PeacexF/seta/checks/email"
	"github.com/PeacexF/seta/internal/cli"
	"github.com/PeacexF/seta/internal/registry"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	app := &cli.App{
		Registry: registry.Default,
		Stdin:    os.Stdin,
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
	}
	code := app.Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

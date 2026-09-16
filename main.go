// Command prongs scans networks for exposed and insecurely configured services.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/thomaslaurenson/prongs/cmd"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := cmd.NewRootCmd(os.Stdout, os.Stderr)
	if err := root.ExecuteContext(ctx); err != nil {
		// Ask the context rather than the error: an interrupted probe reports its
		// own symptom (a dial timeout, a short read) rather than the cancellation.
		if errors.Is(ctx.Err(), context.Canceled) {
			os.Exit(130)
		}
		var ec *cmd.ExitCodeError
		if errors.As(err, &ec) {
			os.Exit(ec.Code)
		}
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
}

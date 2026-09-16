// Package cmd wires up prongs's subcommands with Cobra. It handles argument
// parsing, environment lookup and dispatch only; target expansion and the
// scanning itself live under internal/.
package cmd

import (
	"fmt"
	"io"
	"log/slog"

	"github.com/spf13/cobra"
)

const rootLong = `prongs probes networks for exposed and insecurely configured services.

Targets are CIDR ranges or single IPs. Each selected scanner is run against
every host the targets expand to, and every confirmed finding is printed as it
arrives.

New here? Run this sequence:
  prongs scan --help                         see the scanners and the flags
  prongs scan --all --target 192.168.0.0/24  scan a network, one record per line
  prongs scan --all --target 192.168.0.0/24 --output pretty
                                             read the same scan as a person`

// ExitCodeError is returned by a command that has already produced its output
// and needs to set the process exit code itself.
type ExitCodeError struct{ Code int }

func (e *ExitCodeError) Error() string { return "" }

// App holds the dependencies shared by every subcommand.
type App struct {
	debug bool
}

// NewRootCmd builds prongs's command tree, writing results to out and
// diagnostics to errw.
func NewRootCmd(out, errw io.Writer) *cobra.Command {
	a := &App{}

	root := &cobra.Command{
		Use:           "prongs",
		Short:         "Fast, custom security scanner",
		Long:          rootLong,
		SilenceErrors: true,
		SilenceUsage:  true,
		Version:       Version,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprint(cmd.ErrOrStderr(), cmd.UsageString())
			return &ExitCodeError{Code: 1}
		},
	}
	root.SetOut(out)
	root.SetErr(errw)

	root.PersistentFlags().BoolVar(&a.debug, "debug", false, "log diagnostics to stderr")

	root.AddCommand(
		a.newScanCmd(),
		newVersionCmd(),
	)
	return root
}

// newLogger builds the diagnostic logger: Debug level under --debug, and Warn
// otherwise so a successful run logs nothing and stays usable in a script.
func newLogger(w io.Writer, debug bool) *slog.Logger {
	level := slog.LevelWarn
	if debug {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

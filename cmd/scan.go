package cmd

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/thomaslaurenson/prongs/internal/config"
	"github.com/thomaslaurenson/prongs/internal/engine"
	"github.com/thomaslaurenson/prongs/internal/scanner"
	"github.com/thomaslaurenson/prongs/internal/target"
)

// targetEnv names the environment variable consulted when neither --target nor
// --target-file is given.
const targetEnv = "TARGET_CIDRS"

// The two accepted --output values.
const (
	outputText   = "text"
	outputPretty = "pretty"
)

const scanLong = `Run one or more scanners against one or more target networks.

Targets are CIDR ranges or single IPs, provided via --target (repeatable
and/or comma-separated) or --target-file (a file, one entry per line). The
two flags are mutually exclusive. If neither is provided, the TARGET_CIDRS
environment variable (comma-separated) is used as a fallback.

Findings go to stdout, one per line. Progress and diagnostics go to stderr,
and progress is suppressed when stderr is not a terminal, so a redirected run
captures the findings and nothing else.

Examples:
  # Run one scanner against a single network
  prongs scan --scanner password-ssh --target 192.168.0.0/24

  # Run all default scanners against multiple networks
  prongs scan --all --target 192.168.0.0/24 --target 10.0.0.0/24

  # Multiple networks as a single comma-separated value
  prongs scan --all --target 192.168.0.0/24,10.0.0.0/24

  # Load targets from a file
  prongs scan --all --target-file targets.txt

  # Pretty-print output
  prongs scan --all --target 192.168.0.0/24 --output pretty

  # Limit the number of concurrent probes
  prongs scan --all --target 192.168.0.0/24 --concurrency 50

  # Use the TARGET_CIDRS environment variable (comma-separated)
  TARGET_CIDRS=192.168.0.0/24,10.0.0.0/24 prongs scan --all`

func (a *App) newScanCmd() *cobra.Command {
	var (
		targetArgs  []string
		targetFile  string
		scannerArgs []string
		all         bool
		output      string
		concurrency int
	)

	c := &cobra.Command{
		Use:   "scan",
		Short: "Run scanners against target CIDRs",
		Long:  scanLong,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger := newLogger(cmd.ErrOrStderr(), a.debug)

			active, err := selectScanners(all, scannerArgs)
			if err != nil {
				return err
			}
			if output != outputText && output != outputPretty {
				return fmt.Errorf("--output must be %q or %q, got %q", outputText, outputPretty, output)
			}
			if concurrency < 1 {
				return fmt.Errorf("--concurrency must be at least 1, got %d", concurrency)
			}
			if len(targetArgs) > 0 && targetFile != "" {
				return errors.New("--target and --target-file are mutually exclusive")
			}

			cidrs, err := target.Resolve(targetArgs, targetFile, os.Getenv(targetEnv))
			if err != nil {
				if errors.Is(err, target.ErrNoTargets) {
					return fmt.Errorf("%w: pass --target, --target-file, or set %s", err, targetEnv)
				}
				return err
			}

			hosts, err := target.Expand(cidrs)
			if err != nil {
				return err
			}
			if len(hosts) == 0 {
				return errors.New("targets expanded to no host addresses")
			}
			logger.Debug("targets expanded",
				slog.Int("cidrs", len(cidrs)), slog.Int("hosts", len(hosts)))

			return engine.Run(cmd.Context(), engine.Options{
				Scanners:    active,
				Hosts:       hosts,
				Concurrency: concurrency,
				Pretty:      output == outputPretty,
				Out:         cmd.OutOrStdout(),
				Progress:    progressWriter(cmd),
				Logger:      logger,
			})
		},
	}

	c.Flags().StringArrayVar(&targetArgs, "target", nil,
		"CIDR or IP to scan (repeatable, comma-separated)")
	c.Flags().StringVar(&targetFile, "target-file", "",
		"path to a file of CIDRs or IPs, one per line")
	c.Flags().StringArrayVar(&scannerArgs, "scanner", nil,
		fmt.Sprintf("scanner to run (repeatable), one of: %s", strings.Join(scannerNames(), ", ")))
	c.Flags().BoolVar(&all, "all", false, "run every default-enabled scanner")
	c.Flags().StringVar(&output, "output", outputText,
		fmt.Sprintf("output format, %q (tab-separated) or %q (human-readable)", outputText, outputPretty))
	c.Flags().IntVarP(&concurrency, "concurrency", "c", config.DefaultConcurrency,
		"maximum concurrent probes")

	a.registerScanCompletions(c)
	return c
}

// selectScanners resolves --all and --scanner into the scanners to run.
func selectScanners(all bool, names []string) ([]scanner.Scanner, error) {
	if all && len(names) > 0 {
		return nil, errors.New("--all and --scanner are mutually exclusive")
	}
	if all {
		return scanner.Defaults(), nil
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no scanner selected: pass --all, or --scanner with one of: %s",
			strings.Join(scannerNames(), ", "))
	}

	var active []scanner.Scanner
	for _, name := range names {
		s, ok := scanner.ByName[name]
		if !ok {
			return nil, fmt.Errorf("unknown scanner %q, expected one of: %s",
				name, strings.Join(scannerNames(), ", "))
		}
		active = append(active, s)
	}
	return active, nil
}

// scannerNames lists every registered scanner name in registration order.
func scannerNames() []string {
	names := make([]string, 0, len(scanner.All))
	for _, s := range scanner.All {
		names = append(names, s.Name())
	}
	return names
}

// progressWriter returns the writer the scan reports progress to: the command's
// error stream when stderr is a terminal, and io.Discard otherwise. Whether a
// stream is a terminal is a fact about the process, so it is settled here rather
// than pushed down into the engine.
func progressWriter(cmd *cobra.Command) io.Writer {
	if term.IsTerminal(int(os.Stderr.Fd())) {
		return cmd.ErrOrStderr()
	}
	return io.Discard
}

package engine

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thomaslaurenson/prongs/internal/scanner"
)

// progressInterval is how often the progress line is redrawn.
const progressInterval = 500 * time.Millisecond

// resultBuffer lets a burst of findings queue up so a worker is not held behind
// the writer for an ordinary run. A scan that finds faster than the writer can
// keep up still blocks once the buffer fills, which is the back pressure that
// keeps findings in the order they arrived.
const resultBuffer = 100

// Options configures a single scan run. Out, Progress and Logger may be left
// nil, in which case the run produces no output of that kind.
type Options struct {
	// Scanners are run against every host, in this order.
	Scanners []scanner.Scanner
	// Hosts are the addresses to probe.
	Hosts []net.IP
	// Concurrency is the number of probes in flight at once.
	Concurrency int
	// Pretty selects the human-readable finding format over the tab-separated one.
	Pretty bool
	// Out receives the findings, which are the answer the user asked for.
	Out io.Writer
	// Progress receives the progress line and the closing counts. The caller
	// decides whether anybody is watching; see cmd.
	Progress io.Writer
	// Logger receives diagnostics.
	Logger *slog.Logger
}

// job is one scanner paired with one host.
type job struct {
	ip      net.IP
	scanner scanner.Scanner
}

// Run probes every host with every scanner, writing each finding to o.Out as it
// arrives. It returns ctx.Err() when the run was cancelled before it finished,
// and nil otherwise; a host that answers nothing is not an error.
func Run(ctx context.Context, o Options) error {
	o = o.withDefaults()
	if len(o.Hosts) == 0 || len(o.Scanners) == 0 {
		return nil
	}

	total := int64(len(o.Hosts)) * int64(len(o.Scanners))
	o.Logger.Debug("scan starting",
		slog.Int("hosts", len(o.Hosts)),
		slog.Int("scanners", len(o.Scanners)),
		slog.Int64("probes", total),
		slog.Int("concurrency", o.Concurrency))

	jobs := make(chan job)
	results := make(chan scanner.Result, resultBuffer)
	var processed atomic.Int64

	// Feed the queue from a goroutine rather than filling it before the workers
	// start: a /8 expands to sixteen million jobs, and a channel buffered to hold
	// them all would have to be allocated in full before the first probe ran.
	go func() {
		defer close(jobs)
		for _, ip := range o.Hosts {
			for _, s := range o.Scanners {
				select {
				case jobs <- job{ip: ip, scanner: s}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup
	for range o.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if r, found := j.scanner.Run(ctx, j.ip); found {
					select {
					case results <- r:
					case <-ctx.Done():
						return
					}
				}
				processed.Add(1)
			}
		}()
	}

	// Close results once every worker has finished, so the drain below terminates.
	go func() {
		wg.Wait()
		close(results)
	}()

	stop := startProgress(o.Progress, total, &processed)

	var findings int
	for r := range results {
		writeResult(o.Out, r, o.Pretty)
		findings++
	}
	stop()

	done := processed.Load()
	fmt.Fprintf(o.Progress, "[*] Probed %d of %d, hosts %d, findings %d\n",
		done, total, len(o.Hosts), findings)
	o.Logger.Debug("scan complete",
		slog.Int64("probed", done), slog.Int64("probes", total), slog.Int("findings", findings))

	return ctx.Err()
}

// withDefaults fills in the writers and logger a caller left nil, so a zero
// Options runs silently rather than panicking, and floors Concurrency at one so
// a pool always has a worker in it.
func (o Options) withDefaults() Options {
	if o.Out == nil {
		o.Out = io.Discard
	}
	if o.Progress == nil {
		o.Progress = io.Discard
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Concurrency < 1 {
		o.Concurrency = 1
	}
	return o
}

// startProgress redraws a progress line on w until the returned function is
// called, which waits for the drawing goroutine to exit. The goroutine has to
// be waited for rather than merely signalled: it shares w with the closing
// counts, and a line still being written would interleave with them.
func startProgress(w io.Writer, total int64, processed *atomic.Int64) func() {
	ticker := time.NewTicker(progressInterval)
	stop := make(chan struct{})
	stopped := make(chan struct{})

	go func() {
		defer close(stopped)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fmt.Fprintf(w, "\r[*] Probed %d of %d", processed.Load(), total)
			case <-stop:
				return
			}
		}
	}()

	return func() {
		close(stop)
		<-stopped
		fmt.Fprint(w, "\r")
	}
}

// writeResult prints one finding to w: a marked line in pretty mode, otherwise
// a tab-separated record of timestamp, IP, scanner and port.
func writeResult(w io.Writer, r scanner.Result, pretty bool) {
	if pretty {
		fmt.Fprintf(w, "[!] %s:%d - %s\n", r.IP, r.Port, r.ScanType)
		return
	}
	fmt.Fprintf(w, "%s\t%s\t%s\t%d\n",
		r.Timestamp.UTC().Format(time.RFC3339), r.IP, r.ScanType, r.Port)
}

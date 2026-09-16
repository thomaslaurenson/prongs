package engine_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thomaslaurenson/prongs/internal/engine"
	"github.com/thomaslaurenson/prongs/internal/scanner"
)

// stub is a scanner that probes nothing. It reports a finding for the addresses
// named in hits and counts every call, so a test can assert both what the engine
// printed and how much work it did without touching the network.
type stub struct {
	name  string
	port  int
	hits  map[string]bool
	calls atomic.Int64
	// block, when set, is waited on before each probe returns, so a test can hold
	// the pool open long enough to cancel it.
	block chan struct{}
}

var _ scanner.Scanner = (*stub)(nil)

func (s *stub) Name() string         { return s.name }
func (s *stub) DefaultEnabled() bool { return true }

func (s *stub) Run(ctx context.Context, ip net.IP) (scanner.Result, bool) {
	s.calls.Add(1)
	if s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
			return scanner.Result{}, false
		}
	}
	if !s.hits[ip.String()] {
		return scanner.Result{}, false
	}
	return scanner.Result{
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		IP:        ip,
		ScanType:  s.name,
		Port:      s.port,
	}, true
}

// hosts parses addrs into the host list the engine takes.
func hosts(t *testing.T, addrs ...string) []net.IP {
	t.Helper()

	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			t.Fatalf("ParseIP(%q) = nil", a)
		}
		out = append(out, ip)
	}
	return out
}

// lines returns the non-blank lines of s.
func lines(s string) []string {
	var out []string
	for line := range strings.SplitSeq(s, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

func TestRunWritesFindings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		pretty bool
		// check validates the single finding line the run is expected to produce.
		check func(t *testing.T, line string)
	}{
		{
			name:   "text output is a tab-separated record",
			pretty: false,
			check: func(t *testing.T, line string) {
				t.Helper()
				fields := strings.Split(line, "\t")
				if len(fields) != 4 {
					t.Fatalf("line %q has %d fields, want 4", line, len(fields))
				}
				if _, err := time.Parse(time.RFC3339, fields[0]); err != nil {
					t.Errorf("field 0 %q is not RFC3339", fields[0])
				}
				if fields[1] != "10.0.0.1" {
					t.Errorf("field 1 = %q, want the probed address", fields[1])
				}
				if fields[2] != "stub" {
					t.Errorf("field 2 = %q, want the scanner name", fields[2])
				}
				if fields[3] != strconv.Itoa(22) {
					t.Errorf("field 3 = %q, want the port", fields[3])
				}
			},
		},
		{
			name:   "pretty output is a marked human-readable line",
			pretty: true,
			check: func(t *testing.T, line string) {
				t.Helper()
				if want := "[!] 10.0.0.1:22 - stub"; line != want {
					t.Errorf("pretty line = %q, want %q", line, want)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			s := &stub{name: "stub", port: 22, hits: map[string]bool{"10.0.0.1": true}}

			err := engine.Run(context.Background(), engine.Options{
				Scanners:    []scanner.Scanner{s},
				Hosts:       hosts(t, "10.0.0.1", "10.0.0.2"),
				Concurrency: 2,
				Pretty:      tc.pretty,
				Out:         &out,
			})
			if err != nil {
				t.Fatalf("Run returned error: %v", err)
			}

			got := lines(out.String())
			if len(got) != 1 {
				t.Fatalf("Run wrote %d finding lines, want 1: %q", len(got), out.String())
			}
			tc.check(t, got[0])
			if n := s.calls.Load(); n != 2 {
				t.Errorf("scanner ran %d times, want one per host (2)", n)
			}
		})
	}
}

func TestRunProbesEveryScannerOnEveryHost(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	a := &stub{name: "a", port: 1, hits: map[string]bool{"10.0.0.1": true, "10.0.0.2": true}}
	b := &stub{name: "b", port: 2, hits: map[string]bool{"10.0.0.2": true}}

	err := engine.Run(context.Background(), engine.Options{
		Scanners:    []scanner.Scanner{a, b},
		Hosts:       hosts(t, "10.0.0.1", "10.0.0.2", "10.0.0.3"),
		Concurrency: 4,
		Out:         &out,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if got := len(lines(out.String())); got != 3 {
		t.Errorf("Run wrote %d finding lines, want 3: %q", got, out.String())
	}
	for _, s := range []*stub{a, b} {
		if n := s.calls.Load(); n != 3 {
			t.Errorf("scanner %q ran %d times, want once per host (3)", s.name, n)
		}
	}
}

func TestRunWritesNothingWithNoWork(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		opts engine.Options
	}{
		{
			name: "no hosts",
			opts: engine.Options{
				Scanners:    []scanner.Scanner{&stub{name: "stub"}},
				Concurrency: 4,
			},
		},
		{
			name: "no scanners",
			opts: engine.Options{
				Hosts:       []net.IP{net.ParseIP("10.0.0.1")},
				Concurrency: 4,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out, progress bytes.Buffer
			opts := tc.opts
			opts.Out = &out
			opts.Progress = &progress

			if err := engine.Run(context.Background(), opts); err != nil {
				t.Fatalf("Run returned error: %v", err)
			}
			if out.Len() != 0 {
				t.Errorf("Run wrote %q to out, want nothing", out.String())
			}
			// Nothing was probed, so there is no progress to report either.
			if progress.Len() != 0 {
				t.Errorf("Run wrote %q to progress, want nothing", progress.String())
			}
		})
	}
}

func TestRunReportsProgressAndCounts(t *testing.T) {
	t.Parallel()
	var out, progress bytes.Buffer
	s := &stub{name: "stub", port: 22, hits: map[string]bool{"10.0.0.1": true}}

	err := engine.Run(context.Background(), engine.Options{
		Scanners:    []scanner.Scanner{s},
		Hosts:       hosts(t, "10.0.0.1", "10.0.0.2"),
		Concurrency: 2,
		Out:         &out,
		Progress:    &progress,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// The closing counts go to the progress stream, never to out: out carries the
	// findings and nothing else, so a redirected run captures only those.
	if !strings.Contains(progress.String(), "findings 1") {
		t.Errorf("progress = %q, want it to report the finding count", progress.String())
	}
	if !strings.HasPrefix(progress.String(), "\r[*] ") && !strings.Contains(progress.String(), "[*] Probed") {
		t.Errorf("progress = %q, want a marked progress report", progress.String())
	}
	if strings.Contains(out.String(), "Probed") {
		t.Errorf("out = %q, want no commentary on the findings stream", out.String())
	}
}

func TestRunStopsOnCancellation(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	block := make(chan struct{})
	s := &stub{name: "stub", port: 22, block: block}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel once the pool is definitely underway. Every probe is held on block,
	// so the run cannot finish on its own and only the cancellation ends it.
	go func() {
		for s.calls.Load() == 0 {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()

	err := engine.Run(ctx, engine.Options{
		Scanners:    []scanner.Scanner{s},
		Hosts:       hosts(t, "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"),
		Concurrency: 2,
		Out:         &out,
	})

	if !errors.Is(err, context.Canceled) {
		t.Errorf("Run returned %v, want context.Canceled", err)
	}
	if out.Len() != 0 {
		t.Errorf("Run wrote %q, want nothing from a cancelled run", out.String())
	}
}

// TestRunDeliversMoreFindingsThanTheBuffer overruns the result buffer many
// times over. A worker that blocked sending into a full buffer while the drain
// loop waited on something else would lose findings or hang here.
func TestRunDeliversMoreFindingsThanTheBuffer(t *testing.T) {
	t.Parallel()
	const n = 1000

	addrs := make([]net.IP, 0, n)
	hits := make(map[string]bool, n)
	for i := range n {
		ip := net.IPv4(10, 0, byte(i>>8), byte(i))
		addrs = append(addrs, ip)
		hits[ip.String()] = true
	}

	var out bytes.Buffer
	err := engine.Run(context.Background(), engine.Options{
		Scanners:    []scanner.Scanner{&stub{name: "stub", port: 22, hits: hits}},
		Hosts:       addrs,
		Concurrency: 32,
		Out:         &out,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if got := len(lines(out.String())); got != len(hits) {
		t.Errorf("Run delivered %d findings, want %d", got, len(hits))
	}
}

// syncBuffer is a writer the test goroutine can read while the engine's progress
// goroutine is still writing to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestRunTicksProgressDuringAScan checks the progress line is redrawn while the
// scan is still running, not only once it finishes. Holding the probes open is
// what makes the run outlast one tick; a run that completes inside the interval
// never exercises the ticker at all.
func TestRunTicksProgressDuringAScan(t *testing.T) {
	t.Parallel()
	block := make(chan struct{})
	progress := &syncBuffer{}

	done := make(chan error, 1)
	go func() {
		done <- engine.Run(context.Background(), engine.Options{
			Scanners:    []scanner.Scanner{&stub{name: "stub", port: 22, block: block}},
			Hosts:       hosts(t, "10.0.0.1", "10.0.0.2"),
			Concurrency: 1,
			Out:         io.Discard,
			Progress:    progress,
		})
	}()

	deadline := time.After(10 * time.Second)
	for !strings.Contains(progress.String(), "Probed") {
		select {
		case err := <-done:
			t.Fatalf("Run finished before drawing any progress (err %v, progress %q)",
				err, progress.String())
		case <-deadline:
			t.Fatalf("no progress drawn within the deadline, progress %q", progress.String())
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	close(block)
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// The in-flight line is redrawn in place, so it is prefixed with a carriage
	// return rather than ending in a newline.
	if !strings.Contains(progress.String(), "\r[*] Probed") {
		t.Errorf("progress = %q, want an in-place progress line", progress.String())
	}
	if !strings.Contains(progress.String(), "findings 0\n") {
		t.Errorf("progress = %q, want the closing counts", progress.String())
	}
}

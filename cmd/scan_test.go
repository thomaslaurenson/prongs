package cmd

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// closedTarget is a single loopback address. Probing it needs no network and no
// listener: the scanners this file selects target ports nothing is bound to, so
// every probe is refused immediately.
const closedTarget = "127.0.0.1/32"

// writeTargets writes lines to a file in a temporary directory and returns its
// path, so a --target-file case has a real file to read.
func writeTargets(t *testing.T, lines string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte(lines), 0o600); err != nil {
		t.Fatalf("write targets file: %v", err)
	}
	return path
}

func TestScanRejectsBadInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
		// wantInErr is a fragment the error must name, so the case proves the flag
		// reached the check rather than merely that something failed.
		wantInErr string
	}{
		{
			name:      "no scanner selected",
			args:      []string{"scan", "--target", closedTarget},
			wantInErr: "no scanner selected",
		},
		{
			name:      "unknown scanner",
			args:      []string{"scan", "--scanner", "no-such-scanner", "--target", closedTarget},
			wantInErr: "no-such-scanner",
		},
		{
			name:      "all and scanner together",
			args:      []string{"scan", "--all", "--scanner", "accessible-rdp", "--target", closedTarget},
			wantInErr: "mutually exclusive",
		},
		{
			name:      "unknown output format",
			args:      []string{"scan", "--all", "--output", "yaml", "--target", closedTarget},
			wantInErr: "yaml",
		},
		{
			name:      "concurrency below one",
			args:      []string{"scan", "--all", "--concurrency", "0", "--target", closedTarget},
			wantInErr: "--concurrency",
		},
		{
			name:      "target and target-file together",
			args:      []string{"scan", "--all", "--target", closedTarget, "--target-file", "targets.txt"},
			wantInErr: "mutually exclusive",
		},
		{
			name:      "unparseable target",
			args:      []string{"scan", "--all", "--target", "not-a-cidr"},
			wantInErr: "not-a-cidr",
		},
		{
			name:      "missing target file",
			args:      []string{"scan", "--all", "--target-file", "/nonexistent/targets.txt"},
			wantInErr: "/nonexistent/targets.txt",
		},
		{
			name:      "positional argument",
			args:      []string{"scan", "192.168.0.0/24"},
			wantInErr: "192.168.0.0/24",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stdout, _, err := run(t, tc.args...)

			if err == nil {
				t.Fatalf("args %v returned nil error", tc.args)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("error = %q, want it to name %q", err, tc.wantInErr)
			}
			// A command that fails must leave stdout clean: stdout is the answer,
			// and a partial answer is worse than none.
			if stdout != "" {
				t.Errorf("stdout = %q, want empty on failure", stdout)
			}
		})
	}
}

func TestScanTargetFileIsRead(t *testing.T) {
	t.Parallel()
	// An invalid entry in the file is what proves the file reached the parser: a
	// --target-file that was silently ignored would fall through to the
	// environment and report a different error.
	path := writeTargets(t, "# a comment\n\n10.0.0.0/33\n")
	_, _, err := run(t, "scan", "--all", "--target-file", path)

	if err == nil {
		t.Fatal("invalid entry in targets file returned nil error")
	}
	if !strings.Contains(err.Error(), "10.0.0.0/33") {
		t.Errorf("error = %q, want it to name the invalid entry", err)
	}
}

func TestScanEmptyTargetFile(t *testing.T) {
	t.Parallel()
	path := writeTargets(t, "\n   \n")
	_, _, err := run(t, "scan", "--all", "--target-file", path)

	if err == nil {
		t.Fatal("empty targets file returned nil error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error = %q, want it to name the file", err)
	}
}

func TestScanFindingsAreWellFormed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
		// check validates one finding line, whatever format the flags asked for.
		check func(t *testing.T, line string)
	}{
		{
			name: "default text output is tab separated",
			args: []string{"scan", "--scanner", "accessible-rdp", "--target", closedTarget},
			check: func(t *testing.T, line string) {
				t.Helper()
				fields := strings.Split(line, "\t")
				if len(fields) != 4 {
					t.Fatalf("line %q has %d tab-separated fields, want 4", line, len(fields))
				}
				if _, err := time.Parse(time.RFC3339, fields[0]); err != nil {
					t.Errorf("field 0 %q is not an RFC3339 timestamp", fields[0])
				}
				if _, err := strconv.Atoi(fields[3]); err != nil {
					t.Errorf("field 3 %q is not a port number", fields[3])
				}
			},
		},
		{
			name: "pretty output is marked",
			args: []string{"scan", "--scanner", "accessible-rdp", "--target", closedTarget, "--output", "pretty"},
			check: func(t *testing.T, line string) {
				t.Helper()
				if !strings.HasPrefix(line, "[!] ") {
					t.Errorf("pretty line %q does not carry the warning marker", line)
				}
				if strings.Contains(line, "\t") {
					t.Errorf("pretty line %q is tab separated, want human-readable", line)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stdout, _, err := run(t, tc.args...)

			if err != nil {
				t.Fatalf("args %v returned error: %v", tc.args, err)
			}
			// Nothing is expected to be listening on the probed port, so an empty
			// stdout is the normal result. Assert the shape of whatever did arrive
			// rather than requiring a finding the environment cannot guarantee.
			for line := range strings.SplitSeq(strings.TrimSpace(stdout), "\n") {
				if line == "" {
					continue
				}
				tc.check(t, line)
			}
		})
	}
}

func TestScanDebugFlag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		args      []string
		wantDebug bool
	}{
		{
			name:      "quiet by default",
			args:      []string{"scan", "--scanner", "accessible-rdp", "--target", closedTarget},
			wantDebug: false,
		},
		{
			name:      "debug reports the expansion",
			args:      []string{"--debug", "scan", "--scanner", "accessible-rdp", "--target", closedTarget},
			wantDebug: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, stderr, err := run(t, tc.args...)

			if err != nil {
				t.Fatalf("args %v returned error: %v", tc.args, err)
			}
			if got := strings.Contains(stderr, "level=DEBUG"); got != tc.wantDebug {
				t.Errorf("debug output present = %v, want %v (stderr %q)", got, tc.wantDebug, stderr)
			}
		})
	}
}

// TestScanTargetEnvFallback covers the TARGET_CIDRS fallback. t.Setenv mutates
// process-wide state, so this test and its subtests cannot be parallel.
func TestScanTargetEnvFallback(t *testing.T) {
	t.Run("value is used", func(t *testing.T) {
		t.Setenv(targetEnv, "10.0.0.0/33")
		_, _, err := run(t, "scan", "--all")

		if err == nil {
			t.Fatal("invalid environment target returned nil error")
		}
		if !strings.Contains(err.Error(), "10.0.0.0/33") {
			t.Errorf("error = %q, want it to name the environment target", err)
		}
	})

	t.Run("empty value reports no targets", func(t *testing.T) {
		t.Setenv(targetEnv, "")
		_, _, err := run(t, "scan", "--all")

		if err == nil {
			t.Fatal("no target source returned nil error")
		}
		if !strings.Contains(err.Error(), targetEnv) {
			t.Errorf("error = %q, want it to name %s", err, targetEnv)
		}
	})
}

func TestScanCompletionsAreRegistered(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		flag string
		want string
	}{
		{name: "scanner names", flag: "scanner", want: "password-ssh"},
		{name: "output formats", flag: "output", want: outputPretty},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stdout, _, err := run(t, "__complete", "scan", "--"+tc.flag, "")

			if err != nil {
				t.Fatalf("completing --%s returned error: %v", tc.flag, err)
			}
			if !strings.Contains(stdout, tc.want) {
				t.Errorf("--%s completions = %q, want them to offer %q", tc.flag, stdout, tc.want)
			}
		})
	}
}

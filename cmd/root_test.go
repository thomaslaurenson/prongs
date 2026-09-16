package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// run builds a fresh command tree and executes it with args, returning what
// each stream received. A fresh tree per call keeps flag state from leaking
// between cases, which a shared tree would carry over after Execute.
func run(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	var out, errOut bytes.Buffer
	root := NewRootCmd(&out, &errOut)
	root.SetArgs(args)
	err = root.Execute()

	return out.String(), errOut.String(), err
}

func TestBareRoot(t *testing.T) {
	t.Parallel()
	stdout, stderr, err := run(t)

	var ec *ExitCodeError
	if !errors.As(err, &ec) || ec.Code != 1 {
		t.Errorf("bare invocation error = %v, want ExitCodeError{1}", err)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("bare invocation stderr = %q, want usage text", stderr)
	}
	if stdout != "" {
		t.Errorf("bare invocation stdout = %q, want empty", stdout)
	}
}

func TestUnknownCommand(t *testing.T) {
	t.Parallel()
	stdout, _, err := run(t, "bogus")

	if err == nil {
		t.Error("unknown command returned nil error")
	}
	if stdout != "" {
		t.Errorf("unknown command stdout = %q, want empty", stdout)
	}
}

func TestExitCodeErrorMessageIsEmpty(t *testing.T) {
	t.Parallel()
	// A command returning this has already written its own output, so main must
	// have nothing left to print.
	if got := (&ExitCodeError{Code: 3}).Error(); got != "" {
		t.Errorf("ExitCodeError.Error() = %q, want empty", got)
	}
}

func TestNewLoggerLevel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		debug     bool
		wantDebug bool
	}{
		{name: "default suppresses debug", debug: false, wantDebug: false},
		{name: "debug flag enables debug", debug: true, wantDebug: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			newLogger(&buf, tc.debug).Debug("probe")

			if got := strings.Contains(buf.String(), "probe"); got != tc.wantDebug {
				t.Errorf("debug line emitted = %v, want %v (output %q)", got, tc.wantDebug, buf.String())
			}
		})
	}
}

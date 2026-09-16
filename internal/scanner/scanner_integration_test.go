//go:build integration

package scanner_test

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/thomaslaurenson/prongs/internal/scanner"
)

// hostEnv names the environment variable holding the address of a host with SSH
// password authentication enabled and no RDP or database port exposed.
// scanme.nmap.org (45.33.32.156) is one such host.
const hostEnv = "PRONGS_TEST_HOST"

// testHost returns the address to probe, skipping when none is configured.
func testHost(t *testing.T) net.IP {
	t.Helper()

	host := os.Getenv(hostEnv)
	if host == "" {
		t.Skipf("%s not set", hostEnv)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("%s = %q, want an IP address", hostEnv, host)
	}
	return ip
}

// TestPasswordSSHAgainstRealHost is the primary regression test for the SSH
// probe: it catches any breakage in how the advertised auth methods are read
// back out of the handshake error.
//
// It can fail for reasons that are nothing to do with this code. Against
// scanme.nmap.org from the far side of the Pacific the dial takes about 150ms
// and the handshake about 915ms, so the probe sits at roughly half its budget
// (config.DefaultTimeout bounds each of the two steps separately). A dropped
// SYN pushes the dial past that budget and the probe reports nothing. Confirm a
// failure repeats before treating it as a defect, and see the note on a
// timeout flag in the README before shortening the budget further.
func TestPasswordSSHAgainstRealHost(t *testing.T) {
	t.Parallel()
	ip := testHost(t)

	s := &scanner.PasswordSSH{}
	r, found := s.Run(context.Background(), ip)
	if !found {
		t.Fatalf("password-ssh reported no finding for %s, want one", ip)
	}
	if r.Port != 22 {
		t.Errorf("finding port = %d, want 22", r.Port)
	}
	if r.ScanType != s.Name() {
		t.Errorf("finding scan type = %q, want %q", r.ScanType, s.Name())
	}
}

// TestClosedPortsAgainstRealHost is the negative case: the port probes must not
// report a finding for a service the host does not run.
func TestClosedPortsAgainstRealHost(t *testing.T) {
	t.Parallel()
	ip := testHost(t)

	for _, s := range []scanner.Scanner{&scanner.AccessibleRDP{}, &scanner.AccessibleDB{}} {
		t.Run(s.Name(), func(t *testing.T) {
			t.Parallel()
			if _, found := s.Run(context.Background(), ip); found {
				t.Errorf("%s reported a finding for %s, want none", s.Name(), ip)
			}
		})
	}
}

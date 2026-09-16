package scanner_test

import (
	"context"
	"net"
	"testing"

	"github.com/thomaslaurenson/prongs/internal/scanner"
)

// loopback is probed by the cancellation cases. Nothing has to be listening on
// it: a cancelled context fails the dial before the address matters.
var loopback = net.ParseIP("127.0.0.1")

func TestScannerMetadata(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		s             scanner.Scanner
		wantDefaultOn bool
	}{
		{name: "password-ssh", s: &scanner.PasswordSSH{}, wantDefaultOn: true},
		{name: "accessible-rdp", s: &scanner.AccessibleRDP{}, wantDefaultOn: false},
		{name: "accessible-db", s: &scanner.AccessibleDB{}, wantDefaultOn: true},
		{name: "insecure-http", s: &scanner.InsecureHTTP{}, wantDefaultOn: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.s.Name(); got != tc.name {
				t.Errorf("Name() = %q, want %q", got, tc.name)
			}
			if got := tc.s.DefaultEnabled(); got != tc.wantDefaultOn {
				t.Errorf("DefaultEnabled() = %v, want %v", got, tc.wantDefaultOn)
			}
		})
	}
}

// TestScannersHonourCancellation checks every scanner stops on a cancelled
// context rather than probing anyway. Without it a Ctrl-C during a large scan
// would still work through every remaining host.
func TestScannersHonourCancellation(t *testing.T) {
	t.Parallel()
	for _, s := range scanner.All {
		t.Run(s.Name(), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			if _, found := s.Run(ctx, loopback); found {
				t.Errorf("%s reported a finding on a cancelled context", s.Name())
			}
		})
	}
}

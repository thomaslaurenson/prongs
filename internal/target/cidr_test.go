package target_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/thomaslaurenson/prongs/internal/target"
)

func TestExpand(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input []string
		// wantCount is the number of hosts expected. wantHosts, when set, is the
		// exact list, for the cases where which addresses are returned matters as
		// well as how many.
		wantCount int
		wantHosts []string
	}{
		{
			name:      "bare IP needs no prefix length",
			input:     []string{"45.33.32.156"},
			wantCount: 1,
			wantHosts: []string{"45.33.32.156"},
		},
		{
			name:      "a /32 is one host, not none",
			input:     []string{"45.33.32.156/32"},
			wantCount: 1,
			wantHosts: []string{"45.33.32.156"},
		},
		{
			name:      "a /31 keeps both addresses",
			input:     []string{"192.168.1.0/31"},
			wantCount: 2,
			wantHosts: []string{"192.168.1.0", "192.168.1.1"},
		},
		{
			name:      "a /30 drops network and broadcast",
			input:     []string{"192.168.1.0/30"},
			wantCount: 2,
			wantHosts: []string{"192.168.1.1", "192.168.1.2"},
		},
		{
			name:      "a /24 has 254 usable hosts",
			input:     []string{"192.168.1.0/24"},
			wantCount: 254,
		},
		{
			name:      "several targets are concatenated",
			input:     []string{"192.168.1.0/31", "10.0.0.1"},
			wantCount: 3,
			wantHosts: []string{"192.168.1.0", "192.168.1.1", "10.0.0.1"},
		},
		{
			name:      "an empty entry is skipped",
			input:     []string{""},
			wantCount: 0,
		},
		{
			name:      "a comment is skipped",
			input:     []string{"# this is a comment", "192.168.1.1"},
			wantCount: 1,
			wantHosts: []string{"192.168.1.1"},
		},
		{
			name:      "a repeated CIDR is not expanded twice",
			input:     []string{"192.168.1.0/30", "192.168.1.0/30"},
			wantCount: 2,
		},
		{
			name:      "an overlapping CIDR adds only its new hosts",
			input:     []string{"192.168.1.0/30", "192.168.1.0/24"},
			wantCount: 254,
		},
		{
			name:      "a repeated bare IP appears once",
			input:     []string{"10.0.0.1", "10.0.0.1"},
			wantCount: 1,
		},
		{
			name:      "an IPv6 address is accepted",
			input:     []string{"2001:db8::1"},
			wantCount: 1,
			wantHosts: []string{"2001:db8::1"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hosts, err := target.Expand(tc.input)
			if err != nil {
				t.Fatalf("Expand(%v) returned error: %v", tc.input, err)
			}
			if len(hosts) != tc.wantCount {
				t.Fatalf("Expand(%v) returned %d hosts, want %d", tc.input, len(hosts), tc.wantCount)
			}
			if tc.wantHosts == nil {
				return
			}
			got := make([]string, 0, len(hosts))
			for _, ip := range hosts {
				got = append(got, ip.String())
			}
			if !slices.Equal(got, tc.wantHosts) {
				t.Errorf("Expand(%v) = %v, want %v", tc.input, got, tc.wantHosts)
			}
		})
	}
}

func TestExpandInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
	}{
		{name: "not an address at all", input: "not-a-cidr"},
		{name: "prefix length out of range", input: "10.0.0.0/33"},
		{name: "missing prefix length", input: "10.0.0.0/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := target.Expand([]string{tc.input})
			if err == nil {
				t.Fatalf("Expand(%q) returned nil error", tc.input)
			}
			// The message has to name the offending entry: a scan may pass hundreds.
			if !strings.Contains(err.Error(), tc.input) {
				t.Errorf("error = %q, want it to name %q", err, tc.input)
			}
		})
	}
}

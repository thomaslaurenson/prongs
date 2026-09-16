package scanner

import (
	"context"
	"net"
	"strconv"
	"time"
)

// Result is a single confirmed finding.
type Result struct {
	Timestamp time.Time
	IP        net.IP
	ScanType  string
	Port      int
}

// Scanner is a single probe against one host.
type Scanner interface {
	// Name returns the scanner identifier used in --scanner flags and output.
	Name() string

	// DefaultEnabled reports whether --all selects this scanner.
	DefaultEnabled() bool

	// Run probes a single IP. It returns (result, true) on a finding and
	// (zero, false) otherwise, including when ctx is already cancelled.
	Run(ctx context.Context, ip net.IP) (Result, bool)
}

// finding builds a Result for a confirmed finding by s against ip on port.
func finding(s Scanner, ip net.IP, port int) Result {
	return Result{
		Timestamp: time.Now().UTC(),
		IP:        ip,
		ScanType:  s.Name(),
		Port:      port,
	}
}

// dialable reports whether a TCP connection to ip:port can be established
// within timeout. The connection is closed immediately: reachability is the
// whole question these port probes ask.
func dialable(ctx context.Context, ip net.IP, port int, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr(ip, port))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// addr renders ip and port as a dial address, bracketing an IPv6 literal.
func addr(ip net.IP, port int) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(port))
}

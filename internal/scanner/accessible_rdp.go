package scanner

import (
	"context"
	"net"

	"github.com/thomaslaurenson/prongs/internal/config"
)

// rdpPort is the TCP port RDP listens on.
const rdpPort = 3389

// AccessibleRDP reports whether RDP is reachable on a host.
type AccessibleRDP struct{}

var _ Scanner = (*AccessibleRDP)(nil)

func (s *AccessibleRDP) Name() string { return "accessible-rdp" }

// DefaultEnabled returns false: an exposed RDP port is common enough on an
// internal network that including it in --all buries the other findings.
func (s *AccessibleRDP) DefaultEnabled() bool { return false }

func (s *AccessibleRDP) Run(ctx context.Context, ip net.IP) (Result, bool) {
	if !dialable(ctx, ip, rdpPort, config.DefaultTimeout) {
		return Result{}, false
	}
	return finding(s, ip, rdpPort), true
}

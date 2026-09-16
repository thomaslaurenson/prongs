package scanner

import (
	"context"
	"net"

	"github.com/thomaslaurenson/prongs/internal/config"
)

// dbPorts are the database ports checked per host, tried in order. The first
// one that answers is reported, so the finding names the port that was actually
// reachable rather than whichever the loop ended on.
var dbPorts = []int{3306, 5432}

// AccessibleDB reports whether a common database port is reachable on a host.
type AccessibleDB struct{}

var _ Scanner = (*AccessibleDB)(nil)

func (s *AccessibleDB) Name() string         { return "accessible-db" }
func (s *AccessibleDB) DefaultEnabled() bool { return true }

func (s *AccessibleDB) Run(ctx context.Context, ip net.IP) (Result, bool) {
	for _, port := range dbPorts {
		if dialable(ctx, ip, port, config.DefaultTimeout) {
			return finding(s, ip, port), true
		}
	}
	return Result{}, false
}

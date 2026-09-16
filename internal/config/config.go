// Package config holds the built-in defaults shared by the command layer and
// the scanners. Values a user can override arrive as arguments instead; these
// are only the fallbacks those arguments default to.
package config

import "time"

// DefaultConcurrency is the number of probes run at once when --concurrency is
// not given.
const DefaultConcurrency = 200

// DefaultTimeout bounds each network operation a probe makes, so a probe that
// both dials and handshakes can spend it twice. It is deliberately short: a scan
// of a whole network spends most of its time waiting on hosts that never answer.
const DefaultTimeout = 2 * time.Second

// Package engine runs a set of scanners against a set of hosts. It owns the
// worker pool and the order findings are printed in, and it writes to the
// writers it is given rather than to the process streams.
package engine

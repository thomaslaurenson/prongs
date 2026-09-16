// Package scanner holds the individual probes prongs runs against a host. Each
// one implements Scanner: given a context and an address it reports a single
// confirmed finding or nothing at all. A closed port is not a failure, so a
// probe returns no error; only a finding is worth reporting upwards.
package scanner

// Package target turns the CIDR ranges and single IPs a user supplies into the
// flat list of host addresses a scan runs against. Resolve chooses between the
// inline values, a file and the value read from the environment by the command
// layer; Expand parses the result and enumerates the hosts.
package target

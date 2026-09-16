package target

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrNoTargets reports that no source supplied a target. Callers match it to
// add the wording that names the flags a user could have passed.
var ErrNoTargets = errors.New("no targets")

// Resolve returns a flat list of CIDR and IP strings from the given sources, in
// priority order: the inline values, then the file, then env. env is the value
// the command layer read from the environment; this package never reads it
// itself. It returns ErrNoTargets when no source supplied anything, and an error
// naming the file when the file it was given holds no entries.
func Resolve(targets []string, file, env string) ([]string, error) {
	// Each branch either yields at least one entry or reports why not, so a
	// caller never has to treat an empty list and a nil error as a failure.
	if len(targets) > 0 {
		if out := splitList(targets); len(out) > 0 {
			return out, nil
		}
		return nil, ErrNoTargets
	}
	if file != "" {
		return readFile(file)
	}
	if out := splitList([]string{env}); len(out) > 0 {
		return out, nil
	}
	return nil, ErrNoTargets
}

// splitList flattens comma-separated values into one entry per target,
// discarding blanks and surrounding whitespace.
func splitList(args []string) []string {
	var out []string
	for _, a := range args {
		for _, cidr := range strings.Split(a, ",") {
			if cidr = strings.TrimSpace(cidr); cidr != "" {
				out = append(out, cidr)
			}
		}
	}
	return out
}

// readFile reads one target per line from path, discarding blank lines.
func readFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read targets file %q: %w", path, err)
	}
	var out []string
	for line := range strings.SplitSeq(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("targets file %q holds no entries", path)
	}
	return out, nil
}

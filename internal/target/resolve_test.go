package target_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/thomaslaurenson/prongs/internal/target"
)

func TestResolveFromArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		targets []string
		want    []string
	}{
		{
			name:    "single CIDR",
			targets: []string{"192.168.0.0/24"},
			want:    []string{"192.168.0.0/24"},
		},
		{
			name:    "comma-separated CIDRs in one arg",
			targets: []string{"192.168.0.0/24,10.0.0.0/8"},
			want:    []string{"192.168.0.0/24", "10.0.0.0/8"},
		},
		{
			name:    "multiple args",
			targets: []string{"192.168.0.0/24", "10.0.0.0/8"},
			want:    []string{"192.168.0.0/24", "10.0.0.0/8"},
		},
		{
			name:    "whitespace trimmed",
			targets: []string{"192.168.0.0/24, 10.0.0.0/8"},
			want:    []string{"192.168.0.0/24", "10.0.0.0/8"},
		},
		{
			name:    "trailing comma ignored",
			targets: []string{"192.168.0.0/24,"},
			want:    []string{"192.168.0.0/24"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := target.Resolve(tc.targets, "", "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("Resolve(%v) = %v, want %v", tc.targets, got, tc.want)
			}
		})
	}
}

func TestResolveFromFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		contents string
		want     []string
	}{
		{
			name:     "simple file",
			contents: "192.168.0.0/24\n10.0.0.0/8\n",
			want:     []string{"192.168.0.0/24", "10.0.0.0/8"},
		},
		{
			name:     "blank lines skipped",
			contents: "192.168.0.0/24\n\n10.0.0.0/8\n",
			want:     []string{"192.168.0.0/24", "10.0.0.0/8"},
		},
		{
			name:     "whitespace-only lines skipped",
			contents: "192.168.0.0/24\n   \n10.0.0.0/8",
			want:     []string{"192.168.0.0/24", "10.0.0.0/8"},
		},
		{
			name:     "file with single entry and no trailing newline",
			contents: "10.0.0.1",
			want:     []string{"10.0.0.1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "targets.txt")
			if err := os.WriteFile(path, []byte(tc.contents), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			got, err := target.Resolve(nil, path, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("Resolve(nil, file) = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolveFromFileMissing(t *testing.T) {
	t.Parallel()
	_, err := target.Resolve(nil, "/nonexistent/targets.txt", "")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestResolveFromEnv(t *testing.T) {
	t.Parallel()
	got, err := target.Resolve(nil, "", "192.168.0.0/24,10.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"192.168.0.0/24", "10.0.0.0/8"}
	if !slices.Equal(got, want) {
		t.Errorf("Resolve from env = %v, want %v", got, want)
	}
}

func TestResolvePriority(t *testing.T) {
	t.Parallel()
	// Inline values outrank the environment, so a run with both uses the flag.
	got, err := target.Resolve([]string{"192.168.0.0/24"}, "", "10.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := []string{"192.168.0.0/24"}; !slices.Equal(got, want) {
		t.Errorf("Resolve with args and env = %v, want %v", got, want)
	}
}

func TestResolveNoTargets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		targets []string
		env     string
	}{
		{name: "no source at all"},
		{name: "inline values are all separators", targets: []string{","}},
		{name: "inline values are all whitespace", targets: []string{" ", "\t"}},
		{name: "environment value is all separators", env: ",,"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Resolve must report this rather than returning an empty list with a
			// nil error, which would leave the caller blaming CIDR expansion for
			// input that never parsed.
			got, err := target.Resolve(tc.targets, "", tc.env)
			if !errors.Is(err, target.ErrNoTargets) {
				t.Errorf("Resolve(%v, \"\", %q) error = %v, want ErrNoTargets", tc.targets, tc.env, err)
			}
			if got != nil {
				t.Errorf("Resolve returned %v alongside the error, want nil", got)
			}
		})
	}
}

func TestResolveEmptyFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("\n  \n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := target.Resolve(nil, path, "")
	if err == nil {
		t.Fatal("expected error for a file with no entries, got nil")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error = %q, want it to name the file", err)
	}
}

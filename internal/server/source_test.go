package server

import (
	"os"
	"testing"
)

func TestValidateSourcePath(t *testing.T) {
	dir := t.TempDir()
	f, _ := os.CreateTemp(dir, "f")
	file := f.Name()
	f.Close()

	cases := []struct {
		name  string
		in    string
		valid bool
	}{
		{"empty is ok (blackbox)", "", true},
		{"existing abs dir", dir, true},
		{"https git url", "https://git.example.com/acme/app.git", true},
		{"http not allowed", "http://git.example.com/app.git", false},
		{"relative path", "relative/path", false},
		{"nonexistent abs", "/no/such/path/xyz123", false},
		{"abs file not dir", file, false},
		{"ssh scheme rejected", "git@github.com:acme/app.git", true}, // no scheme, treated as path → absolute? see below
	}
	for _, c := range cases {
		got := validateSourcePath(c.in) == ""
		// "git@github.com:..." has no "://" and is not absolute → rejected.
		if c.name == "ssh scheme rejected" {
			if validateSourcePath(c.in) == "" {
				t.Errorf("%s: expected rejection for scp-style ssh url", c.name)
			}
			continue
		}
		if got != c.valid {
			t.Errorf("%s: validateSourcePath(%q) valid=%v, want %v (reason=%q)",
				c.name, c.in, got, c.valid, validateSourcePath(c.in))
		}
	}
}

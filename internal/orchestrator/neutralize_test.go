package orchestrator

import (
	"strings"
	"testing"
)

func TestScrubStripsAnsiAndCollapsesSpace(t *testing.T) {
	cases := []struct{ in, want string }{
		{"\x1b[33m302\x1b[0m Found", "302 Found"},
		{"[33mwarn[0m: slow", "warn: slow"},
		{"a    b\t\tc", "a b c"},
		{"  trimmed  ", "trimmed"},
		{"no codes here", "no codes here"},
	}
	for _, c := range cases {
		if got := Scrub(c.in); got != c.want {
			t.Errorf("Scrub(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	if got := Scrub("Header: User-Agent: Mozilla/5.0"); !strings.Contains(got, "User-Agent") {
		t.Errorf("Scrub corrupted User-Agent: %q", got)
	}
}

func TestFriendlyModule(t *testing.T) {
	cases := map[string]string{
		"cyp_send_request":   "HTTP Probe",
		"cyp_create_finding": "Bulgu Motoru",
		"bash":               "Yerel Görev",
		"read":               "Analiz",
	}
	for in, want := range cases {
		if got := friendlyModule(in); got != want {
			t.Errorf("friendlyModule(%q) = %q, want %q", in, got, want)
		}
	}
}

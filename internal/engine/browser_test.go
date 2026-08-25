package engine

import "testing"

func TestBrowserToolsExposed(t *testing.T) {
	names := map[string]bool{}
	for _, d := range toolDefs() {
		if n, ok := d["name"].(string); ok {
			names[n] = true
		}
	}
	for _, want := range []string{
		"cyp_browser_navigate", "browser_navigate",
		"cyp_browser_eval", "browser_eval",
		"cyp_browser_dom", "browser_dom",
		"cyp_browser_screenshot", "browser_screenshot",
	} {
		if !names[want] {
			t.Errorf("toolDefs is missing exposed browser tool %q", want)
		}
	}
}

func TestBrowserNavigateScope(t *testing.T) {
	b := &Browser{eng: New([]string{"in-scope.test"}, nil)}
	if _, err := b.Navigate("https://evil.example.com/x", 10, 0); err == nil {
		t.Fatal("expected out-of-scope navigate to be refused, got nil error")
	}
}

func TestEnsureScheme(t *testing.T) {
	cases := map[string]string{
		"example.com/x":         "https://example.com/x",
		"http://example.com":    "http://example.com",
		"https://example.com/a": "https://example.com/a",
		"  example.com  ":       "https://example.com",
	}
	for in, want := range cases {
		if got := ensureScheme(in); got != want {
			t.Errorf("ensureScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

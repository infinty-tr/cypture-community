package server

import "testing"

func TestScopeWildcardForms(t *testing.T) {

	for _, pat := range []string{"*.example.com", "*example.com"} {
		s := ScopeSet{Includes: normalizePatterns([]string{pat})}
		in := []string{"example.com", "avantaj.example.com", "x.y.example.com", "www.example.com"}
		for _, h := range in {
			if !s.Allows(h) {
				t.Errorf("pattern %q should allow %q", pat, h)
			}
		}
		for _, h := range []string{"evil.com", "example.org", "notexample.com"} {
			if s.Allows(h) {
				t.Errorf("pattern %q should NOT allow %q", pat, h)
			}
		}
	}
}

func TestScopeExactAndCIDR(t *testing.T) {
	s := ScopeSet{Includes: normalizePatterns([]string{"api.acme.com", "10.0.0.0/24"})}
	if !s.Allows("api.acme.com") || !s.Allows("10.0.0.5") {
		t.Fatal("exact host / CIDR should match")
	}
	if s.Allows("sub.api.acme.com") || s.Allows("10.0.1.5") {
		t.Fatal("exact host must not match subdomain; CIDR must respect range")
	}
}

func TestScopeExcludeWins(t *testing.T) {
	s := ScopeSet{
		Includes: normalizePatterns([]string{"*example.com"}),
		Excludes: normalizePatterns([]string{"legacy.example.com"}),
	}
	if s.Allows("legacy.example.com") {
		t.Fatal("exclude must win over include")
	}
	if !s.Allows("avantaj.example.com") {
		t.Fatal("non-excluded subdomain should be allowed")
	}
}

func TestDeriveSeed(t *testing.T) {
	if got := deriveSeed(normalizePatterns([]string{"*example.com"})); got != "example.com" {
		t.Fatalf("seed from wildcard = %q, want example.com", got)
	}
	if got := deriveSeed(normalizePatterns([]string{"*.acme.com", "api.acme.com"})); got != "api.acme.com" {
		t.Fatalf("seed should prefer concrete host, got %q", got)
	}
}

func TestScopePortPreservedAndTolerant(t *testing.T) {

	pats := normalizePatterns([]string{"api.acme.com:8443"})
	if len(pats) != 1 || pats[0] != "api.acme.com:8443" {
		t.Fatalf("normalizePattern should keep :port, got %v", pats)
	}
	if got := deriveSeed(pats); got != "api.acme.com:8443" {
		t.Fatalf("seed should carry the port, got %q", got)
	}
	s := ScopeSet{Includes: pats}

	if !s.Allows("api.acme.com") {
		t.Fatal("port-bearing pattern should match a bare host (host-only matching)")
	}
	if !s.Allows("https://api.acme.com:8443/x") {
		t.Fatal("a URL with the port should also match")
	}
	if s.Allows("evil.com") {
		t.Fatal("unrelated host must not match")
	}
}

func TestDeriveSeedTargetPreservesPath(t *testing.T) {
	cases := map[string]string{
		"203.0.113.10/admin/login":      "203.0.113.10/admin/login",
		"https://api.site.com/v1/users": "api.site.com/v1/users",
		"site.com:8443/login":           "site.com:8443/login",
		"example.com":                   "example.com",
		"example.com/":                  "example.com",
		"*.example.com":                 "example.com",
	}
	for in, want := range cases {
		if got := deriveSeedTarget([]string{in}); got != want {
			t.Errorf("deriveSeedTarget(%q) = %q, want %q", in, got, want)
		}
	}

	s := ScopeSet{Includes: []string{"203.0.113.10"}}
	if !s.Allows("203.0.113.10/admin/login") {
		t.Fatal("host-scope must allow a path-bearing seed for the same host")
	}
}

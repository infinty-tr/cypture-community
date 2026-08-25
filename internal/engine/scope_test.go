package engine

import "testing"

func TestEngineInScopeWildcard(t *testing.T) {

	for _, pat := range []string{"*.example.com", "*example.com"} {
		e := New([]string{pat}, nil)
		for _, h := range []string{"example.com", "avantaj.example.com", "a.b.example.com"} {
			if !e.InScope(h) {
				t.Errorf("pattern %q: %q should be in scope", pat, h)
			}
		}
		if e.InScope("evil.com") || e.InScope("example.org") {
			t.Errorf("pattern %q: out-of-scope host leaked", pat)
		}
	}
}

func TestEngineExcludeAndExact(t *testing.T) {
	e := New([]string{"*example.com"}, []string{"legacy.example.com"})
	if e.InScope("legacy.example.com") {
		t.Fatal("exclude must win")
	}
	if !e.InScope("https://avantaj.example.com/path") {
		t.Fatal("URL form should normalize and be in scope")
	}
}

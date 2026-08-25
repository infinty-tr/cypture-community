package config

import "testing"

func TestResolveModel(t *testing.T) {
	const def = "openai/gpt-4o"
	cases := []struct {
		label, want string
	}{
		{"free", "openai/gpt-4o-mini"},
		{"fast", "openai/gpt-4o-mini"},
		{"strong", "openai/gpt-4o"},
		{"STRONG", "openai/gpt-4o"},
		{"frontier", "openai/gpt-4o"},
		{" fast ", "openai/gpt-4o-mini"},
		{"", def},
		{"bogus", def},
	}
	for _, c := range cases {
		if got := ResolveModel(c.label, def); got != c.want {
			t.Errorf("ResolveModel(%q) = %q, want %q", c.label, got, c.want)
		}
	}
}

func TestValidModelTier(t *testing.T) {
	for _, ok := range []string{"free", "fast", "strong", "FREE", " strong "} {
		if !ValidModelTier(ok) {
			t.Errorf("ValidModelTier(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "bogus", "deepseek"} {
		if ValidModelTier(bad) {
			t.Errorf("ValidModelTier(%q) = true, want false", bad)
		}
	}
}

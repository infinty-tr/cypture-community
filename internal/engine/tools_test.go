package engine

import (
	"strings"
	"testing"
)

func TestToolDefsExposesBothNames(t *testing.T) {
	names := map[string]bool{}
	for _, d := range toolDefs() {
		if n, ok := d["name"].(string); ok {
			names[n] = true
		}
	}
	for _, want := range []string{
		"cyp_send_request", "send_request",
		"cyp_create_finding", "create_finding",
		"cyp_batch_send", "batch_send",
		"cyp_search_history", "search_history",
	} {
		if !names[want] {
			t.Errorf("toolDefs is missing exposed tool name %q", want)
		}
	}
}

func TestDispatchNormalizesAliases(t *testing.T) {
	s := NewServer(New([]string{"example.com"}, nil))

	want, isErr := s.dispatch("cyp_get_instance", nil)
	if isErr {
		t.Fatalf("cyp_get_instance returned error: %q", want)
	}
	for _, alias := range []string{"get_instance", "mcp__cyp__get_instance", "mcp__cyp__cyp_get_instance"} {
		got, isErr := s.dispatch(alias, nil)
		if isErr || got != want {
			t.Errorf("dispatch(%q) = (%q, err=%v); want (%q, false)", alias, got, isErr, want)
		}
	}

	if !strings.HasPrefix("cyp_", "cyp_") {
		t.Fatal("unreachable")
	}
}

func TestEvidenceGate(t *testing.T) {
	e := New([]string{"x.com"}, nil)

	e.history = append(e.history, &Entry{
		Host: "x.com", Method: "GET", Path: "/api/user",
		URL: "https://x.com/api/user?id=1", StatusCode: 200, RespBody: "ok",
	})
	cases := []struct {
		name string
		in   FindingInput
		want string
	}{
		{"no-evidence", FindingInput{Title: "a", Severity: "critical"}, "unverified"},
		{"evidence-unverified", FindingInput{Title: "b", Severity: "high", PoC: "id=1' OR 1=1-- diff 512B", Confidence: "confirmed"}, "likely"},

		{"evidence-verified", FindingInput{Title: "c", Severity: "critical", Endpoint: "https://x.com/api/user?id=1", PoC: "x", Confidence: "confirmed", Verified: true}, "confirmed"},

		{"verified-no-engine-proof", FindingInput{Title: "c2", Severity: "critical", Endpoint: "https://x.com/ghost", PoC: "uydurma", Confidence: "confirmed", Verified: true}, "unverified"},
		{"low-untouched", FindingInput{Title: "d", Severity: "low", Confidence: "confirmed"}, "confirmed"},
		{"info-untouched", FindingInput{Title: "e", Severity: "info"}, ""},
	}
	for _, c := range cases {
		f := e.AddFinding(c.in)
		if f.Confidence != c.want {
			t.Errorf("%s: Confidence = %q, want %q", c.name, f.Confidence, c.want)
		}
	}
}

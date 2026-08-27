package orchestrator

import (
	"encoding/json"
	"strings"
	"testing"
)

// mapLine unmarshals a raw opencode NDJSON line and runs it through mapEvents,
// mirroring what parseStream / tailAgentFile do at runtime.
func mapLine(t *testing.T, line string) []Event {
	t.Helper()
	var ev ocEvent
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return mapEvents(ev, map[string]bool{})
}

func TestMapEvents_SurfacesProviderError(t *testing.T) {
	// The exact shape recorded from a failed opencode sub-agent run.
	line := `{"type":"error","timestamp":1,"sessionID":"ses_x","error":` +
		`{"name":"UnknownError","data":{"message":"Unexpected server error. Check server logs for details.","ref":"err_073335b4"}}}`
	evs := mapLine(t, line)
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	e := evs[0]
	if e.Level != LevelWarning {
		t.Errorf("level = %q, want warning", e.Level)
	}
	if !strings.Contains(e.Message, "Unexpected server error") {
		t.Errorf("message did not carry the error text: %q", e.Message)
	}
	if !strings.Contains(e.Message, "err_073335b4") {
		t.Errorf("message did not carry the ref: %q", e.Message)
	}
}

func TestMapEvents_EscalatesFatalError(t *testing.T) {
	line := `{"type":"error","error":{"name":"Error","data":{"message":"Insufficient balance for this request"}}}`
	evs := mapLine(t, line)
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	if evs[0].Level != LevelError {
		t.Errorf("fatal error should map to LevelError, got %q", evs[0].Level)
	}
}

func TestMapEvents_EmptyErrorIgnored(t *testing.T) {
	if evs := mapLine(t, `{"type":"error","error":{}}`); len(evs) != 0 {
		t.Fatalf("empty error should produce no events, got %d", len(evs))
	}
}

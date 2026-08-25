package orchestrator

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
)

func TestClassifyFatal(t *testing.T) {
	fatal := []string{
		`{"type":"error","error":{"message":"Insufficient balance"}}`,
		"Error: insufficient_quota",
		"You have insufficient credit to run this model",
		"402 Payment Required",
		"quota exceeded for this account",
		"Invalid API key provided",
		"authentication failed: bad token",
	}
	for _, l := range fatal {
		if _, ok := classifyFatal(l); !ok {
			t.Errorf("expected FATAL for %q", l)
		}
	}

	ok := []string{
		`{"type":"tool_use","part":{"tool":"cyp_send_request"}}`,
		"HTTP/1.1 401 Unauthorized",
		"402 from the scanned host",
		`{"type":"step_finish","tokens":{"total":5}}`,
	}
	for _, l := range ok {
		if msg, hit := classifyFatal(l); hit {
			t.Errorf("false positive on %q → %q", l, msg)
		}
	}
}

func TestFatalScanWriter(t *testing.T) {
	var got string
	w := &fatalScanWriter{onLine: func(line string) {
		if _, ok := classifyFatal(line); ok {
			got = line
		}
	}}

	_, _ = w.Write([]byte("starting up\nInsufficient bal"))
	if got != "" {
		t.Fatal("should not trip on a partial line")
	}
	_, _ = w.Write([]byte("ance for account\n"))
	if got == "" {
		t.Fatal("expected the reassembled 'Insufficient balance' line to trip")
	}
}

type nopController struct{}

func (nopController) Emit(Event)          {}
func (nopController) Ask(Question) string { return "" }

func TestParseStreamFailFastGate(t *testing.T) {
	run := func(line string) bool {
		tripped := false
		var saw atomic.Bool
		parseStream(context.Background(), strings.NewReader(line+"\n"), nopController{}, &saw, func(string) { tripped = true })
		return tripped
	}

	targetResp := `{"type":"tool","part":{"tool":"cyp_send_request","state":{"status":"completed","output":"HTTP/1.1 401 Unauthorized\r\n\r\n{\"error\":\"invalid api key\",\"detail\":\"authentication failed\"}"}}}`
	if run(targetResp) {
		t.Error("FALSE POSITIVE: target auth response (tool event) tripped fail-fast")
	}

	providerErr := `{"type":"error","error":{"name":"APIError","data":{"message":"Insufficient balance. Manage your billing."}}}`
	if !run(providerErr) {
		t.Error("MISS: cypture-agent provider error (type:error) did not trip fail-fast")
	}
}

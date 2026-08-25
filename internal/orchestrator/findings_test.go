package orchestrator

import "testing"

type captureCtrl struct{ events []Event }

func (c *captureCtrl) Emit(e Event)        { c.events = append(c.events, e) }
func (c *captureCtrl) Ask(Question) string { return "" }

func TestEmitFinding_MapsFieldsAndAltKeys(t *testing.T) {
	c := &captureCtrl{}

	emitFinding(map[string]any{
		"name":             "SQL Injection",
		"severity":         "High",
		"url":              "http://t/showforum.asp?id=0",
		"method":           "GET",
		"type":             "SQLi",
		"description":      "AND 1=1 vs AND 1=2 diverged",
		"proof_of_concept": "id=0' OR '1'='1",
		"verified":         true,
	}, c)

	if len(c.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(c.events))
	}
	e := c.events[0]
	if e.Category != CatFinding || e.Level != LevelFinding {
		t.Errorf("wrong category/level: %q/%q", e.Category, e.Level)
	}
	if e.Data["title"] != "SQL Injection" {
		t.Errorf("title = %v", e.Data["title"])
	}
	if e.Data["severity"] != "high" {
		t.Errorf("severity = %v, want high", e.Data["severity"])
	}
	if e.Data["endpoint"] != "http://t/showforum.asp?id=0" {
		t.Errorf("endpoint (from url) = %v", e.Data["endpoint"])
	}
	if e.Data["vuln_type"] != "SQLi" {
		t.Errorf("vuln_type (from type) = %v", e.Data["vuln_type"])
	}
	if e.Data["poc"] == "" {
		t.Errorf("poc (from proof_of_concept) empty")
	}
}

func TestEmitFinding_CapsUnverifiedSeverity(t *testing.T) {
	cases := []struct {
		sev      string
		verified bool
		want     string
	}{
		{"critical", false, "medium"},
		{"high", false, "medium"},
		{"critical", true, "critical"},
		{"high", true, "high"},
		{"medium", false, "medium"},
		{"low", false, "low"},
	}
	for _, tc := range cases {
		c := &captureCtrl{}
		emitFinding(map[string]any{
			"title": "X", "severity": tc.sev, "verified": tc.verified,
		}, c)
		if len(c.events) != 1 {
			t.Fatalf("%s/%v: expected 1 event", tc.sev, tc.verified)
		}
		if got := c.events[0].Data["severity"]; got != tc.want {
			t.Errorf("severity(%s, verified=%v) = %v, want %v", tc.sev, tc.verified, got, tc.want)
		}
	}
}

func TestEmitFinding_SkipsTitleless(t *testing.T) {
	c := &captureCtrl{}
	emitFinding(map[string]any{"severity": "high", "endpoint": "http://t/"}, c)
	if len(c.events) != 0 {
		t.Fatalf("title-less finding must be skipped, got %d events", len(c.events))
	}
}

func TestEmitFinding_DefaultsSeverityToInfo(t *testing.T) {
	c := &captureCtrl{}
	emitFinding(map[string]any{"title": "Something"}, c)
	if len(c.events) != 1 || c.events[0].Data["severity"] != "info" {
		t.Fatalf("expected severity default info, got %+v", c.events)
	}
}

func TestUsageEvent_RealCyptureShape(t *testing.T) {

	line := `{"type":"message","info":{"id":"msg_abc","role":"assistant","cost":0.07828782,` +
		`"tokens":{"total":44719,"input":44445,"output":152,"reasoning":122,"cache":{"read":0,"write":0}},` +
		`"modelID":"gpt-4o","providerID":"openai"}}`
	e := usageEvent(line)
	if e == nil {
		t.Fatal("usageEvent returned nil on real engine event shape")
	}
	if e.Category != CatUsage {
		t.Fatalf("category = %q", e.Category)
	}
	if e.Data["msg_id"] != "msg_abc" {
		t.Errorf("msg_id = %v", e.Data["msg_id"])
	}
	if e.Data["cost_usd"].(float64) != 0.07828782 {
		t.Errorf("cost_usd = %v", e.Data["cost_usd"])
	}
	if e.Data["tokens_input"].(int64) != 44445 || e.Data["tokens_output"].(int64) != 152 {
		t.Errorf("tokens wrong: %+v", e.Data)
	}
	if e.Data["model"] != "gpt-4o" {
		t.Errorf("model = %v", e.Data["model"])
	}
}

func TestUsageEvent_TopLevelShape(t *testing.T) {

	line := `{"cost":0.5,"tokens":{"input":100,"output":50,"reasoning":10},"modelID":"m"}`
	e := usageEvent(line)
	if e == nil || e.Data["tokens_output"].(int64) != 50 {
		t.Fatalf("top-level usage not parsed: %+v", e)
	}
}

func TestUsageEvent_NoUsage(t *testing.T) {
	if usageEvent(`{"type":"text","part":{"text":"hi"}}`) != nil {
		t.Fatal("non-usage line should return nil")
	}
}

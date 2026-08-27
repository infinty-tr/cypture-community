package orchestrator

import "testing"

func TestDetectPhase(t *testing.T) {
	cases := []struct {
		msg  string
		want string
		ok   bool
	}{
		{"DALGA 0 — KEŞİF başlatılıyor", "Keşif Modülü", true},
		{"DALGA 1 — WEB ZAFİYETLERİ", "Web Değerlendirme Modülü", true},
		{"DALGA 2 — API & AUTH", "API Değerlendirme Modülü", true},
		{"DALGA 2 — FUZZING", "Fuzzing Modülü", true},
		{"DALGA 3 — ZİNCİR & RAPOR", "Raporlama Modülü", true},
		{"Faz 1: yüzey keşfi", "Keşif Modülü", true},
		{"web sayfasını gezdim", "", false},
		{"GET /robots.txt 200", "", false},

		{"Recon tamam. aşırı REST API açıklığı. --- DALGA 1 — WEB ZAFİYETLERİ Şimdi başlıyorum", "Web Değerlendirme Modülü", true},
	}
	for _, c := range cases {
		got, ok := detectPhase(c.msg)
		if ok != c.ok || got != c.want {
			t.Errorf("detectPhase(%q) = (%q,%v); want (%q,%v)", c.msg, got, ok, c.want, c.ok)
		}
	}
}

func TestPaneClassifyPhaseFlow(t *testing.T) {
	p := &paneController{byModule: map[string]string{}}

	id, mod, _ := p.classify(&Event{Category: CatPlanning, Module: "Akıl Yürütme", Message: "DALGA 0 — KEŞİF başlatılıyor"})
	if id != "system" || mod != "Çekirdek" {
		t.Fatalf("phase banner should route to the system strip: id=%q mod=%q", id, mod)
	}

	reconID, rmod, status := p.classify(&Event{Category: CatModule, Module: "Keşif Modülü", Message: "başladı"})
	if status != "open" || rmod != "Keşif Modülü" || reconID == "" || reconID == "system" {
		t.Fatalf("module event did not open recon tab: id=%q mod=%q status=%q", reconID, rmod, status)
	}

	id2, _, _ := p.classify(&Event{Category: CatModule, Module: "HTTP Probe", Message: "→ GET /robots.txt 200"})
	if id2 != reconID {
		t.Fatalf("probe routed to %q, want active recon tab %q", id2, reconID)
	}

	id3, mod3, status3 := p.classify(&Event{Category: CatModule, Module: "Web Değerlendirme Modülü", Message: "başladı"})
	if status3 != "open" || mod3 != "Web Değerlendirme Modülü" || id3 == reconID {
		t.Fatalf("web module did not open a new tab: id=%q mod=%q status=%q", id3, mod3, status3)
	}

	idHB, _, _ := p.classify(&Event{Category: CatModule, Module: "Çekirdek", Message: "⏳ sürüyor"})
	if idHB != "system" {
		t.Fatalf("heartbeat routed to %q, want system", idHB)
	}
}

// A lane-tagged event (as produced by tailAgentFile for a spawned specialist)
// must be routed into its own cockpit pane, not the shared system feed. This is
// the core of "agents showing up in the cockpit" for the live runner.
func TestWithPanes_LaneTaggedEventGetsPane(t *testing.T) {
	cap := &captureCtrl{}
	ctrl := withPanes(cap)

	ctrl.Emit(Event{Level: LevelThought, Category: CatPlanning, Module: "Akıl Yürütme",
		Lane: "GHOST · Keşif", Message: "recon running"})

	if len(cap.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(cap.events))
	}
	d := cap.events[0].Data
	if d == nil || d["pane_id"] == nil || d["pane_id"] == "system" {
		t.Fatalf("lane event was not given a real pane: %+v", d)
	}
	if d["pane_module"] != "GHOST · Keşif" {
		t.Errorf("pane_module = %v, want GHOST · Keşif", d["pane_module"])
	}
	if d["pane_status"] != "open" {
		t.Errorf("first event on a new pane should open it, got %v", d["pane_status"])
	}
}

// Core/system modules must stay in the shared feed and never spawn a pane.
func TestWithPanes_SystemModuleStaysSystem(t *testing.T) {
	cap := &captureCtrl{}
	ctrl := withPanes(cap)

	ctrl.Emit(Event{Level: LevelSystem, Category: CatSystem, Module: "Çekirdek",
		Message: "scan core started"})

	d := cap.events[0].Data
	if d != nil && d["pane_id"] != nil && d["pane_id"] != "system" {
		t.Fatalf("core module should stay in system feed, got pane %v", d["pane_id"])
	}
}

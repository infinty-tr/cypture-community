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

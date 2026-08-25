package orchestrator

import "testing"

func TestExtractFindingMarkers_BasicAndDedupShape(t *testing.T) {
	txt := `Test ettim ve SQLi doğruladım.
[CYP-FINDING]{"title":"SQL Injection in /search","severity":"high","endpoint":"/search?q=","poc":"q=1' OR '1'='1","confidence":"confirmed","verified":true}
Sonraki adıma geçiyorum.`
	cleaned, finds := extractFindingMarkers(txt)
	if len(finds) != 1 {
		t.Fatalf("want 1 finding, got %d", len(finds))
	}
	if finds[0]["title"] != "SQL Injection in /search" {
		t.Fatalf("title = %v", finds[0]["title"])
	}
	if got, ok := finds[0]["verified"].(bool); !ok || !got {
		t.Fatalf("verified not parsed as true: %v", finds[0]["verified"])
	}

	if containsCI(cleaned, "CYP-FINDING") || containsCI(cleaned, "OR '1'='1") {
		t.Fatalf("marker/JSON leaked into cleaned text: %q", cleaned)
	}
	if !containsCI(cleaned, "SQLi doğruladım") || !containsCI(cleaned, "Sonraki adıma") {
		t.Fatalf("surrounding prose was lost: %q", cleaned)
	}
}

func TestExtractFindingMarkers_MultipleAndEventShape(t *testing.T) {
	txt := `[CYP-FINDING]{"title":"IDOR on /orders","severity":"critical","verified":true} ` +
		`ara metin [CYP_FINDING]: {"title":"Open Redirect","severity":"medium"}`
	_, finds := extractFindingMarkers(txt)
	if len(finds) != 2 {
		t.Fatalf("want 2 findings, got %d", len(finds))
	}

	ev := findingEventFromMarker(finds[0])
	if ev.Category != CatFinding || ev.Level != LevelFinding {
		t.Fatalf("bad event category/level: %s/%s", ev.Category, ev.Level)
	}
	if ev.Data["title"] != "IDOR on /orders" || ev.Data["severity"] != "critical" {
		t.Fatalf("bad event data: %+v", ev.Data)
	}
	if ev.Data["verified"] != true {
		t.Fatalf("verified should be true bool, got %v", ev.Data["verified"])
	}
}

func TestExtractFindingMarkers_NoMarkerUntouched(t *testing.T) {
	txt := "Sadece normal akıl yürütme metni, CYP geçmiyor."
	cleaned, finds := extractFindingMarkers(txt)
	if len(finds) != 0 {
		t.Fatalf("unexpected findings: %+v", finds)
	}
	if cleaned != txt {
		t.Fatalf("text changed unexpectedly: %q", cleaned)
	}
}

func TestExtractFindingMarkers_TitlelessIgnored(t *testing.T) {

	txt := `[CYP-FINDING]{"severity":"high","note":"henüz başlık yok"}`
	_, finds := extractFindingMarkers(txt)
	if len(finds) != 0 {
		t.Fatalf("titleless marker should be ignored, got %+v", finds)
	}
}

func containsCI(s, sub string) bool {
	return len(s) >= len(sub) && indexCI(s, sub) >= 0
}

func indexCI(s, sub string) int {
	ls, lsub := []rune(toLowerASCII(s)), []rune(toLowerASCII(sub))
	for i := 0; i+len(lsub) <= len(ls); i++ {
		match := true
		for j := range lsub {
			if ls[i+j] != lsub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

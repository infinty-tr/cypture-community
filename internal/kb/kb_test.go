package kb

import (
	"encoding/json"
	"testing"

	"cypture/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.KBEntry{}, &models.TechPrior{}); err != nil {
		t.Fatal(err)
	}
	return New(db)
}

func TestHarvestThenSeed(t *testing.T) {
	s := newStore(t)
	const cli = "client-1"

	s.Harvest(cli, "example.com",
		[]KnownFinding{{VulnType: "SQLi", Endpoint: "showforum.asp?id", Severity: "critical"}},
		map[string]any{"tech": []any{"IIS 8.5", "ASP.NET"}, "dead_ends": []any{"/search XSS — kapalı"}})

	seed := s.Seed(cli, "example.com")
	if seed == nil {
		t.Fatal("seed should not be nil after a harvest")
	}
	var m map[string]any
	if err := json.Unmarshal(seed, &m); err != nil {
		t.Fatal(err)
	}
	if m["runs"].(float64) != 1 {
		t.Errorf("runs = %v, want 1", m["runs"])
	}
	if kf := m["known_findings"].([]any); len(kf) != 1 {
		t.Errorf("known_findings = %d, want 1", len(kf))
	}

	s.Harvest(cli, "example.com",
		[]KnownFinding{{VulnType: "LFI", Endpoint: "Templatize.asp?item", Severity: "high"}},
		map[string]any{"tech": []any{"IIS 8.5"}})
	seed2 := s.Seed(cli, "example.com")
	_ = json.Unmarshal(seed2, &m)
	if m["runs"].(float64) != 2 {
		t.Errorf("runs = %v, want 2", m["runs"])
	}
	if kf := m["known_findings"].([]any); len(kf) != 2 {
		t.Errorf("known_findings after 2 scans = %d, want 2 (union)", len(kf))
	}
}

func TestSeedNilForUnknown(t *testing.T) {
	s := newStore(t)
	if s.Seed("client-1", "never-scanned.com") != nil {
		t.Fatal("seed for unknown target should be nil")
	}
}

func TestKBTenantIsolation(t *testing.T) {
	s := newStore(t)
	const host = "shared-target.com"
	s.Harvest("alice", host,
		[]KnownFinding{{VulnType: "SQLi", Endpoint: "/alice-secret-endpoint", Severity: "critical"}},
		map[string]any{"tech": []any{"Laravel"}})
	s.Harvest("bob", host,
		[]KnownFinding{{VulnType: "XSS", Endpoint: "/bob-only", Severity: "high"}},
		map[string]any{"tech": []any{"Laravel"}})

	var bob map[string]any
	if err := json.Unmarshal(s.Seed("bob", host), &bob); err != nil {
		t.Fatal(err)
	}
	kf, _ := json.Marshal(bob["known_findings"])
	if containsSub(string(kf), "alice-secret-endpoint") {
		t.Fatalf("TENANT LEAK: Alice's endpoint appeared in Bob's seed: %s", kf)
	}
	if !containsSub(string(kf), "bob-only") {
		t.Fatalf("Bob's own finding missing from his seed: %s", kf)
	}
	if bob["runs"].(float64) != 1 {
		t.Fatalf("Bob's runs = %v, want 1 (Alice's scan must not count for Bob)", bob["runs"])
	}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

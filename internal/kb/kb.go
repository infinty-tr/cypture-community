package kb

import (
	"encoding/json"
	"strings"
	"time"

	"cypture/internal/models"

	"gorm.io/gorm"
)

type Store struct{ db *gorm.DB }

func New(db *gorm.DB) *Store { return &Store{db: db} }

type KnownFinding struct {
	VulnType string `json:"vuln_type"`
	Endpoint string `json:"endpoint"`
	Severity string `json:"severity"`
}

func hintsFor(tech []string) []string { return nil }

func kbKey(clientID, host string) string {
	h := normHost(host)
	if h == "" {
		return ""
	}
	return strings.TrimSpace(clientID) + "|" + h
}

func (s *Store) Load(clientID, host string) *models.KBEntry {
	key := kbKey(clientID, host)
	if key == "" {
		return nil
	}
	var e models.KBEntry
	if err := s.db.First(&e, "target_host = ?", key).Error; err != nil {
		return nil
	}
	return &e
}

func (s *Store) Seed(clientID, host string) []byte {
	out := map[string]any{}
	if e := s.Load(clientID, host); e != nil {
		tech := decodeStrs(e.ConfirmedTech)
		out["target"] = normHost(host)
		out["runs"] = e.Runs
		out["confirmed_tech"] = tech
		out["known_findings"] = decodeFindings(e.KnownFindings)
		out["dead_ends"] = decodeStrs(e.DeadEnds)
		out["notes"] = e.Notes
	}
	if len(out) == 0 {
		return nil
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return b
}

func (s *Store) Harvest(clientID, host string, findings []KnownFinding, update map[string]any) {
	key := kbKey(clientID, host)
	if key == "" {
		return
	}
	e := s.Load(clientID, host)
	if e == nil {
		e = &models.KBEntry{TargetHost: key}
	}

	tech := unionStrs(decodeStrs(e.ConfirmedTech), toStrs(update["tech"]), toStrs(update["confirmed_tech"]))
	dead := unionStrs(decodeStrs(e.DeadEnds), toStrs(update["dead_ends"]))
	known := unionFindings(decodeFindings(e.KnownFindings), findings)
	notes := strings.TrimSpace(toStr(update["notes"]))
	if notes == "" {
		notes = e.Notes
	}

	e.ConfirmedTech = encode(tech)
	e.DeadEnds = encode(dead)
	e.KnownFindings = encode(known)
	e.Notes = notes
	e.LastRun = time.Now()
	e.Runs++
	s.db.Save(e)

	s.LearnOutcomes(tech, findings)
}

func normHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
	if i := strings.IndexAny(h, "/:"); i >= 0 {
		h = h[:i]
	}
	return strings.TrimPrefix(h, "www.")
}

func decodeStrs(s string) []string {
	var out []string
	if strings.TrimSpace(s) != "" {
		_ = json.Unmarshal([]byte(s), &out)
	}
	return out
}
func decodeFindings(s string) []KnownFinding {
	var out []KnownFinding
	if strings.TrimSpace(s) != "" {
		_ = json.Unmarshal([]byte(s), &out)
	}
	return out
}
func encode(v any) string { b, _ := json.Marshal(v); return string(b) }

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
func toStrs(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func unionStrs(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, s := range l {
			k := strings.ToLower(strings.TrimSpace(s))
			if k == "" || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, strings.TrimSpace(s))
		}
	}
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

func unionFindings(a, b []KnownFinding) []KnownFinding {
	seen := map[string]bool{}
	var out []KnownFinding
	for _, f := range append(a, b...) {
		if strings.TrimSpace(f.VulnType) == "" && strings.TrimSpace(f.Endpoint) == "" {
			continue
		}
		k := strings.ToLower(f.VulnType + "|" + f.Endpoint)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}

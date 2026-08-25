package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"cypture/internal/models"
)

func (s *Server) synthesizeFindings(in []models.Finding) []models.Finding {
	base := normalizeForReport(in)
	if len(base) < 2 {
		return base
	}

	sort.SliceStable(base, func(i, j int) bool {
		if base[i].Title != base[j].Title {
			return base[i].Title < base[j].Title
		}
		return base[i].Endpoint < base[j].Endpoint
	})
	scanID := base[0].ScanSessionID
	h := synthHash(base)

	if groups := s.loadSynthCache(scanID, h); groups != nil {
		return applySynthGroups(base, groups)
	}

	s.triggerBackgroundSynth(scanID, h, base)
	return base
}

var synthInFlight sync.Map

func (s *Server) triggerBackgroundSynth(scanID, hash string, base []models.Finding) {
	if scanID == "" {
		return
	}
	if _, busy := synthInFlight.LoadOrStore(scanID, true); busy {
		return
	}

	snapshot := make([]models.Finding, len(base))
	copy(snapshot, base)
	go func() {
		defer synthInFlight.Delete(scanID)
		if groups, ok := s.llmSynthGroups(snapshot); ok {
			s.saveSynthCache(scanID, hash, groups)
		}
	}()
}

type synthCacheFile struct {
	Hash   string       `json:"hash"`
	Groups []synthGroup `json:"groups"`
}

func (s *Server) synthCacheDir() string {
	return filepath.Join(filepath.Dir(s.Cfg.DBPath), "synth_cache")
}

func synthHash(fs []models.Finding) string {
	h := sha256.New()
	for _, f := range fs {
		io.WriteString(h, f.Title+"|"+f.Severity+"|"+f.Endpoint+"\n")
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Server) loadSynthCache(scanID, hash string) []synthGroup {
	if scanID == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(s.synthCacheDir(), scanID+".json"))
	if err != nil {
		return nil
	}
	var c synthCacheFile
	if json.Unmarshal(b, &c) != nil || c.Hash != hash || len(c.Groups) == 0 {
		return nil
	}
	return c.Groups
}

func (s *Server) saveSynthCache(scanID, hash string, groups []synthGroup) {
	if scanID == "" {
		return
	}
	dir := s.synthCacheDir()
	if os.MkdirAll(dir, 0o755) != nil {
		return
	}
	if b, err := json.Marshal(synthCacheFile{Hash: hash, Groups: groups}); err == nil {
		_ = os.WriteFile(filepath.Join(dir, scanID+".json"), b, 0o644)
	}
}

func normalizeForReport(in []models.Finding) []models.Finding {
	cleaned := make([]models.Finding, len(in))
	copy(cleaned, in)
	for i := range cleaned {
		cleaned[i].Title = cleanFindingTitle(cleaned[i].Title)
	}

	return dedupeFindings(cleaned)
}

var reportTagWords = map[string]bool{
	"kritik": true, "critical": true,
	"high": true, "yuksek": true,
	"medium": true, "orta": true, "med": true,
	"low": true, "dusuk": true,
	"info": true, "bilgi": true, "informational": true, "info disclosure": true,
	"teorik": true, "theoretical": true,
	"dogrulandi": true, "verified": true, "confirmed": true,
	"probable": true, "muhtemel": true,
	"aday": true, "candidate": true, "unverified": true, "dogrulanmadi": true,
	"chain": true, "zincir": true,
	"kanit": true, "poc": true, "cvss": true,
}

var reportTagFolder = strings.NewReplacer(
	"̇", "", "ı", "i", "ş", "s", "ğ", "g", "ü", "u", "ö", "o", "ç", "c",
)

func foldTag(s string) string {
	return strings.TrimSpace(reportTagFolder.Replace(strings.ToLower(strings.TrimSpace(s))))
}

var reportCapsPrefixRe = regexp.MustCompile(`^(INFO DISCLOSURE|INFORMATION DISCLOSURE|SECURITY MISCONFIGURATION|SECURITY MISCONFIG|MISCONFIGURATION|SENSITIVE DATA EXPOSURE|BROKEN ACCESS CONTROL|VULNERABILITY|GÜVENLİK AÇIĞI)\s*[-—:]\s*`)

func cleanFindingTitle(raw string) string {
	t := strings.TrimSpace(raw)

	for strings.HasPrefix(t, "[") {
		end := strings.IndexByte(t, ']')
		if end < 0 {
			break
		}
		key := foldTag(strings.Trim(t[1:end], " \t!?.:-—"))
		if !reportTagWords[key] {
			break
		}
		t = strings.TrimSpace(t[end+1:])
	}
	if m := reportCapsPrefixRe.FindString(t); m != "" {
		t = strings.TrimSpace(t[len(m):])
	}
	if t == "" {
		return strings.TrimSpace(raw)
	}
	return t
}

const reportSynthSystem = `You normalize web-pentest findings into a professional client report. ` +
	`You are given a JSON array of findings, each with an integer "i" (index), "title", "type", "endpoint", "severity". ` +
	`Return ONLY a JSON array (no prose, no markdown) of groups. Each group: ` +
	`{"idx":[list of member indices],"title":"<clean professional finding title, no severity tags, no ALL-CAPS prefixes>",` +
	`"category":"<short vuln category e.g. Information Disclosure, Access Control, Injection>","observation":<true if this is a benign observation / not a real vulnerability>}. ` +
	`Rules: put findings that describe the SAME underlying issue (even if worded differently or on sibling hosts) into ONE group. ` +
	`Every input index must appear in exactly one group. Do NOT change or invent severities. Do NOT add commentary. Output JSON array only.`

type synthGroup struct {
	Idx         []int  `json:"idx"`
	Title       string `json:"title"`
	Category    string `json:"category"`
	Observation bool   `json:"observation"`
}

func (s *Server) llmSynthGroups(fs []models.Finding) ([]synthGroup, bool) {
	if len(fs) < 2 {
		return nil, false
	}
	endpoint, key, model := s.reportLLMEndpoint()
	if endpoint == "" {
		return nil, false
	}
	type inF struct {
		I        int    `json:"i"`
		Title    string `json:"title"`
		Type     string `json:"type"`
		Endpoint string `json:"endpoint"`
		Severity string `json:"severity"`
	}
	items := make([]inF, len(fs))
	for i, f := range fs {
		items[i] = inF{I: i, Title: f.Title, Type: f.VulnType, Endpoint: f.Endpoint, Severity: f.Severity}
	}
	inJSON, _ := json.Marshal(items)
	raw, err := callOpenAIChat(endpoint, key, model, reportSynthSystem, "Findings:\n"+string(inJSON), 280*time.Second)
	if err != nil {
		return nil, false
	}
	groups := parseSynthGroups(raw)
	if len(groups) == 0 {
		return nil, false
	}
	return groups, true
}

func (s *Server) reportLLMEndpoint() (endpoint, key, model string) {
	var keys []models.APIKeyPoolEntry
	if err := s.DB.Where("active = ? AND disabled = ?", true, false).
		Order("created_at asc").Find(&keys).Error; err != nil {
		return "", "", ""
	}
	for i := range keys {
		k := strings.TrimSpace(keys[i].KeyValue)

		if len(k) < 30 || strings.HasPrefix(strings.ToLower(k), "sk-test") {
			continue
		}
		if ep, m := openAICompatEndpoint(keys[i].Provider, keys[i].Model); ep != "" {
			return ep, k, m
		}
	}
	return "", "", ""
}

func openAICompatEndpoint(provider, model string) (endpoint, m string) {
	prov := strings.ToLower(strings.TrimSpace(provider))
	model = strings.TrimSpace(model)
	switch prov {
	case "openrouter":
		return "https://openrouter.ai/api/v1/chat/completions", strings.TrimPrefix(model, "openrouter/")
	case "openai":
		if model == "" {
			model = "gpt-4o-mini"
		}
		return "https://api.openai.com/v1/chat/completions", model
	case "deepseek":
		if model == "" {
			model = "deepseek-chat"
		}
		return "https://api.deepseek.com/chat/completions", strings.TrimPrefix(model, "deepseek/")
	case "groq":
		return "https://api.groq.com/openai/v1/chat/completions", strings.TrimPrefix(model, "groq/")
	}
	return "", ""
}

func callOpenAIChat(endpoint, key, model, system, user string, timeout time.Duration) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"model":       model,
		"temperature": 0,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
	})
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("llm http %d", resp.StatusCode)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Choices) == 0 {
		return "", fmt.Errorf("llm no content")
	}
	return out.Choices[0].Message.Content, nil
}

func parseSynthGroups(raw string) []synthGroup {
	raw = strings.TrimSpace(raw)
	if i := strings.IndexByte(raw, '['); i >= 0 {
		if j := strings.LastIndexByte(raw, ']'); j > i {
			raw = raw[i : j+1]
		}
	}
	var groups []synthGroup
	if err := json.Unmarshal([]byte(raw), &groups); err != nil {
		return nil
	}
	return groups
}

func applySynthGroups(fs []models.Finding, groups []synthGroup) []models.Finding {
	used := make([]bool, len(fs))
	out := make([]models.Finding, 0, len(groups))
	for _, g := range groups {
		var rep *models.Finding
		repStrength := -1
		for _, idx := range g.Idx {
			if idx < 0 || idx >= len(fs) || used[idx] {
				continue
			}
			used[idx] = true
			if st := findingStrength(fs[idx]); st > repStrength {
				repStrength = st
				f := fs[idx]
				rep = &f
			}
		}
		if rep == nil {
			continue
		}
		if t := strings.TrimSpace(g.Title); t != "" {
			rep.Title = t
		}
		if c := strings.TrimSpace(g.Category); c != "" && rep.VulnType == "" {
			rep.VulnType = c
		}
		out = append(out, *rep)
	}

	for i := range fs {
		if !used[i] {
			out = append(out, fs[i])
		}
	}
	return out
}

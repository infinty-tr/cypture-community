package orchestrator

import (
	"regexp"
	"strings"
)

func friendlyModule(tool string) string {
	t := strings.ToLower(tool)
	switch {
	case strings.Contains(t, "send_request"), strings.Contains(t, "replay"):
		return "HTTP Probe"
	case strings.Contains(t, "search_history"), strings.Contains(t, "list_requests"):
		return "Trafik Analizi"
	case strings.Contains(t, "get_request"), strings.Contains(t, "export_curl"):
		return "İstek İnceleyici"
	case strings.Contains(t, "sitemap"):
		return "Yüzey Haritalama"
	case strings.Contains(t, "intruder"), strings.Contains(t, "batch_send"),
		strings.Contains(t, "race_window"), strings.Contains(t, "macro"):
		return "Fuzzing Motoru"
	case strings.Contains(t, "finding"):
		return "Bulgu Motoru"
	case strings.Contains(t, "scope"):
		return "Kapsam Denetimi"
	case strings.Contains(t, "cyp"):
		return "Tarama Motoru"
	case t == "task":
		return "Modül Sevk"
	case t == "webfetch", strings.Contains(t, "google_search"), strings.Contains(t, "search"):
		return "Dış Kaynak Taraması"
	case t == "bash":
		return "Yerel Görev"
	case t == "read", t == "glob", t == "grep", t == "list", t == "lsp_diagnostics":
		return "Analiz"
	case t == "write", t == "edit", t == "todowrite":
		return "Planlayıcı"
	case strings.Contains(t, "skill"):
		return "Bilgi Tabanı"
	default:
		return "Tarama Motoru"
	}
}

func friendlySubagent(s string) string {
	t := strings.ToLower(s)
	switch {
	case strings.Contains(t, "recon"):
		return "GHOST · Keşif"
	case strings.Contains(t, "fuzz"):
		return "SWARM · Fuzzing"
	case strings.Contains(t, "graphql"):
		return "HYDRA · GraphQL"
	case strings.Contains(t, "secret") || strings.Contains(t, "hunter"):
		return "MAGPIE · Sırlar"
	case strings.Contains(t, "takeover"):
		return "USURPER · Devralma"
	case strings.Contains(t, "race"):
		return "TEMPO · Yarış"
	case strings.Contains(t, "auth"):
		return "SPECTER · Kimlik"
	case strings.Contains(t, "api"):
		return "CIPHER · API"
	case strings.Contains(t, "client"):
		return "PHANTOM · İstemci"
	case strings.Contains(t, "cloud") || strings.Contains(t, "infra"):
		return "NIMBUS · Bulut"
	case strings.Contains(t, "exploit") || strings.Contains(t, "chain"):
		return "DOMINO · Zincir"
	case strings.Contains(t, "valid"):
		return "ORACLE · Doğrulama"
	case strings.Contains(t, "connect"):
		return "NEXUS · Bağlantı"
	case strings.Contains(t, "black") || strings.Contains(t, "operator"):
		return "REAPER · Operatör"
	case strings.Contains(t, "web"):
		return "VIPER · Web"
	case strings.Contains(t, "gate"):
		return "WARDEN · Kapı"
	case strings.Contains(t, "report"):
		return "SCRIBE · Rapor"
	case strings.Contains(t, "orchestr") || strings.Contains(t, "meta") ||
		strings.Contains(t, "main") || strings.Contains(t, "parent") || strings.Contains(t, "koordin"):
		return "MAESTRO · Koordinasyon"
	default:
		return "NOMAD · Test"
	}
}

var (
	ansiEscape  = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")
	ansiRemnant = regexp.MustCompile(`\[[0-9;]+m`)
	wsCollapse  = regexp.MustCompile(`[ \t]{2,}`)
)

func Scrub(s string) string {
	s = ansiEscape.ReplaceAllString(s, "")
	s = ansiRemnant.ReplaceAllString(s, "")
	return strings.TrimSpace(wsCollapse.ReplaceAllString(s, " "))
}

var feedNoiseMarkers = []string{
	"paylaşılan hafıza", "paylasilan hafiza", "başlamadan oku", "baslamadan oku",
	"tekrar etme, zincirle", "zaten bulundu", "zaten test edildi",
	"boşluk arama", "bosluk arama", "gap hipotez", "gap done", "gap_done",
	"dahili alan", "dahili kayıt", "dahili kayit", "çekirdek modülü", "cekirdek modulu",
	"(shim", "shim:", "spawn:", "kapsama durumu", "coverage_status", "tested x",
	"önceliklendirildi", "onceliklendirildi", "decide_next", "chain_suggest",
	"gap_finder", "session_memory", "dispatch_plan", "prioritize", "class_select",
	"load_skills", "surface.json", "urls.txt", "findings.ndjson", "no such file",
	"kullanım:", "kullanim:", "usage:", "acive_target", "active_target",

	"ham http istemcisi", "curl tarama motoru", "curl/wget", "http probe ile gider",
	"test edildi' hafıza", "test edildi hafıza", "çalışma dizini dışında", "calisma dizini disinda",
	"yol izinli", "decide next", "session memory", "paylasilan hafiza", "peer bulgu",
	"exit: 5", "exit: exit status", "exit status 1", "record_finding", "auth_status",
	"coverage_status", "unit_loop", "mark_from_engine", "propagate_finding", "score_hypotheses",
	"out of the authorized scope", "out of scope", "authorized scope", "old_string", "old string",
	"send_request error", "new_string", "harvest_shape", "class_select", "auth_profile", "auth_inject",
}

func feedNoiseLine(s string) bool {
	l := strings.ToLower(s)
	for _, n := range feedNoiseMarkers {
		if strings.Contains(l, n) {
			return true
		}
	}
	return false
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// oneLine collapses whitespace/newlines into single spaces so a multi-line
// shell command renders as one readable cockpit line.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

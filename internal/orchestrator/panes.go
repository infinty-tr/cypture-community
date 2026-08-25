package orchestrator

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

type paneController struct {
	Controller
	mu        sync.Mutex
	seq       int
	activeID  string
	activeMod string
	byModule  map[string]string
	closed    map[string]bool
}

const maestroLane = "MAESTRO · Koordinasyon"

var hardCore = map[string]bool{
	"Çekirdek":        true,
	"Metre":           true,
	"Tarama Motoru":   true,
	"Kapsam Denetimi": true,
	"Operatör":        true,
	"Operatör Sorusu": true,
	"Bilgi Tabanı":    true,
}

var subagentModules = map[string]bool{
	"Keşif Modülü":             true,
	"Web Değerlendirme Modülü": true,
	"API Değerlendirme Modülü": true,
	"Fuzzing Modülü":           true,
	"Sömürü Modülü":            true,
	"Raporlama Modülü":         true,
	"Test Modülü":              true,
}

func withPanes(ctrl Controller) Controller {
	return &paneController{Controller: ctrl, byModule: map[string]string{}, closed: map[string]bool{}}
}

func (p *paneController) pane(module string) (id string, isNew bool) {
	if existing, ok := p.byModule[module]; ok {
		return existing, false
	}
	p.seq++
	id = fmt.Sprintf("p%d", p.seq)
	p.byModule[module] = id
	return id, true
}

func (p *paneController) Emit(ev Event) {

	if ev.Category == CatUsage || ev.Category == CatKB {
		p.Controller.Emit(ev)
		return
	}
	p.mu.Lock()
	id, mod, status := p.classify(&ev)

	var toClose [][2]string
	if isReporterPane(mod) {
		for m, pid := range p.byModule {
			if pid == id || p.closed[pid] || isMaestroPane(m) {
				continue
			}
			p.closed[pid] = true
			toClose = append(toClose, [2]string{pid, m})
		}
	}
	p.mu.Unlock()

	if ev.Data == nil {
		ev.Data = map[string]any{}
	}
	ev.Data["pane_id"] = id
	ev.Data["pane_module"] = mod
	if status != "" {
		ev.Data["pane_status"] = status
	}
	p.Controller.Emit(ev)

	for _, pc := range toClose {
		p.Controller.Emit(Event{
			Category: ev.Category,
			Module:   pc[1],
			Data:     map[string]any{"pane_id": pc[0], "pane_module": pc[1], "pane_status": "close"},
		})
	}
}

func isReporterPane(mod string) bool {
	m := strings.ToLower(mod)
	return strings.Contains(m, "rapor") || strings.Contains(m, "report") || strings.Contains(m, "scribe")
}

func isMaestroPane(mod string) bool {
	return strings.Contains(strings.ToUpper(mod), "MAESTRO")
}

func (p *paneController) classify(ev *Event) (id, mod, status string) {
	msg := strings.TrimSpace(ev.Message)

	if ev.Lane != "" {
		return p.paneFor(ev.Lane, msg)
	}

	if strings.Contains(ev.Module, " · ") {
		return p.paneFor(ev.Module, msg)
	}

	if _, ok := detectPhase(msg); ok {
		return "system", "Çekirdek", ""
	}

	if subagentModules[ev.Module] {
		return p.paneFor(ev.Module, msg)
	}

	if hardCore[ev.Module] {
		return "system", "Çekirdek", ""
	}

	if p.activeID != "" {
		return p.activeID, p.activeMod, ""
	}
	return "system", "Çekirdek", ""
}

func (p *paneController) paneFor(module, msg string) (id, mod, status string) {
	paneID, isNew := p.pane(module)
	p.activeID, p.activeMod = paneID, module
	switch {
	case strings.HasPrefix(msg, "✅") && strings.Contains(msg, "completed") && !isMaestroPane(module):

		status = "close"
		p.closed[paneID] = true
	case isNew:
		status = "open"
	case p.closed[paneID]:

		status = "open"
		p.closed[paneID] = false
	}
	return paneID, module, status
}

var phaseBannerRe = regexp.MustCompile(`(?i)(?:DALGA|TUR|ROUND|FAZ|AŞAMA|ASAMA|WAVE|PHASE)\s*\d*\s*[—\-:]\s*([\p{L} &/]+)`)

func detectPhase(msg string) (string, bool) {
	m := phaseBannerRe.FindStringSubmatch(msg)
	if m == nil {
		return "", false
	}
	up := strings.ToUpper(m[1])
	switch {
	case strings.Contains(up, "KEŞ") || strings.Contains(up, "RECON") || strings.Contains(up, "KESIF"):
		return "Keşif Modülü", true
	case strings.Contains(up, "SÖMÜR") || strings.Contains(up, "SOMUR") || strings.Contains(up, "EXPLOIT"):
		return "Sömürü Modülü", true
	case strings.Contains(up, "RAPOR") || strings.Contains(up, "REPORT") ||
		strings.Contains(up, "ZİNC") || strings.Contains(up, "ZINC") || strings.Contains(up, "CHAIN"):
		return "Raporlama Modülü", true
	case strings.Contains(up, "FUZZ"):
		return "Fuzzing Modülü", true
	case strings.Contains(up, "WEB"), strings.Contains(up, "DERİN"), strings.Contains(up, "DERIN"):
		return "Web Değerlendirme Modülü", true
	case strings.Contains(up, "API"):
		return "API Değerlendirme Modülü", true
	}
	return "", false
}

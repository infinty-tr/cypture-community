package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"

	"cypture/internal/models"
)

var (
	stDim  = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	stBar  = lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Bold(true)
	stStar = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	stCyan = lipgloss.NewStyle().Foreground(lipgloss.Color("48"))
	stOK   = lipgloss.NewStyle().Foreground(lipgloss.Color("48"))
	stWarn = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	stErr  = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	stFind = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true)
	stHead = lipgloss.NewStyle().Foreground(lipgloss.Color("51")).Bold(true)
	stSel  = lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("220")).Bold(true)
)

var spinner = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
var phaseNames = []string{"RECON", "ANALYSIS", "TEST", "DEEP", "REPORT"}

func phaseIndex(text string) int {
	w := strings.ToUpper(text)
	switch {
	case strings.Contains(w, "RAPOR") || strings.Contains(w, "TAMAMLAND") || strings.Contains(w, "SONLAND"):
		return 4
	case strings.Contains(w, "DERİN") || strings.Contains(w, "DERIN") || strings.Contains(w, "DEEP") || strings.Contains(w, "SÖMÜR"):
		return 3
	case strings.Contains(w, "TEST") || strings.Contains(w, "DALGA") || strings.Contains(w, "ZAFİYET") || strings.Contains(w, "ZAFIYET"):
		return 2
	case strings.Contains(w, "ANALİZ") || strings.Contains(w, "ANALIZ") || strings.Contains(w, "TRIAGE"):
		return 1
	case strings.Contains(w, "KEŞİF") || strings.Contains(w, "KESIF") || strings.Contains(w, "RECON") || strings.Contains(w, "YÜZEY"):
		return 0
	}
	return -1
}

var coreStrips = map[string]bool{
	"Çekirdek": true, "Metre": true, "Tarama Motoru": true, "Kapsam Denetimi": true,
	"Operatör": true, "Operatör Sorusu": true, "Bilgi Tabanı": true,
}

type subagent struct {
	name   string
	status string
	last   string
	lines  []string
}

type tickMsg time.Time

func tick() tea.Cmd {
	return tea.Tick(600*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

const (
	modeMain = iota
	modeChild
)

type model struct {
	db       *gorm.DB
	scanID   string
	target   string
	lastSeq  int
	main     []string
	subs     []*subagent
	subIndex map[string]int
	phaseIdx int
	findings int
	status   string
	mode     int
	sel      int
	scroll   int
	tickN    int
	w, h     int
}

func (m *model) Init() tea.Cmd {
	return tea.Batch(tick(), func() tea.Msg { return tickMsg(time.Now()) })
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = v.Width, v.Height
		return m, nil
	case tea.KeyMsg:
		return m, m.onKey(v)
	case tickMsg:
		m.tickN++
		m.refresh()
		return m, tick()
	}
	return m, nil
}

func (m *model) onKey(k tea.KeyMsg) tea.Cmd {
	if k.Type == tea.KeyCtrlC {
		return tea.Quit
	}
	s := k.String()
	if m.mode == modeMain {
		switch s {
		case "up", "k":
			if m.sel > 0 {
				m.sel--
			}
		case "down", "j":
			if m.sel < len(m.subs)-1 {
				m.sel++
			}
		case "enter", "right", "l":
			if len(m.subs) > 0 {
				m.mode = modeChild
				m.scroll = 0
			}
		}
		return nil
	}

	switch s {
	case "esc", "left", "h":
		m.mode = modeMain
	case "up", "k":
		m.scroll++
	case "down", "j":
		if m.scroll > 0 {
			m.scroll--
		}
	case "pgup":
		m.scroll += 10
	case "pgdown":
		m.scroll -= 10
		if m.scroll < 0 {
			m.scroll = 0
		}
	case "tab", "n", "]":
		if len(m.subs) > 0 {
			m.sel = (m.sel + 1) % len(m.subs)
			m.scroll = 0
		}
	case "shift+tab", "p", "[":
		if len(m.subs) > 0 {
			m.sel = (m.sel - 1 + len(m.subs)) % len(m.subs)
			m.scroll = 0
		}
	}
	return nil
}

func (m *model) refresh() {
	var evs []models.LogEvent
	m.db.Where("scan_session_id = ? AND seq > ?", m.scanID, m.lastSeq).Order("seq asc").Limit(500).Find(&evs)
	for i := range evs {
		e := evs[i]
		if e.Seq > m.lastSeq {
			m.lastSeq = e.Seq
		}
		mod := e.PaneModule
		if mod == "" {
			mod = e.Module
		}
		if p := phaseIndex(e.Message + " " + mod); p > m.phaseIdx {
			m.phaseIdx = p
		}
		if strings.TrimSpace(e.Message) == "" {
			continue
		}
		line := m.fmtLine(e.Level, mod, e.Message)
		m.main = append(m.main, line)
		if mod != "" && !coreStrips[mod] {
			idx, ok := m.subIndex[mod]
			if !ok {
				idx = len(m.subs)
				m.subIndex[mod] = idx
				m.subs = append(m.subs, &subagent{name: mod, status: "running"})
			}
			sa := m.subs[idx]
			sa.lines = append(sa.lines, line)
			sa.last = clip(stripStyle(e.Message), 60)
			if e.PaneStatus == "close" {
				sa.status = "done"
			} else if e.PaneStatus == "open" {
				sa.status = "running"
			}
		}
	}
	var fc int64
	m.db.Model(&models.Finding{}).Where("scan_session_id = ?", m.scanID).Count(&fc)
	m.findings = int(fc)
	var sess models.ScanSession
	if m.db.Select("status").First(&sess, "id = ?", m.scanID).Error == nil {
		m.status = string(sess.Status)
		if m.status == "completed" {
			m.phaseIdx = 4
		}
	}
	if len(m.main) > 3000 {
		m.main = m.main[len(m.main)-3000:]
	}
	if m.sel >= len(m.subs) {
		m.sel = len(m.subs) - 1
	}
	if m.sel < 0 {
		m.sel = 0
	}
}

func (m *model) fmtLine(level, mod, msg string) string {
	ts := stDim.Render(time.Now().Format("15:04:05"))
	var st lipgloss.Style
	switch level {
	case "success":
		st = stOK
	case "warning":
		st = stWarn
	case "error":
		st = stErr
	case "finding":
		st = stFind
	case "thought":
		st = stCyan
	default:
		st = lipgloss.NewStyle()
	}
	tag := ""
	if mod != "" && !coreStrips[mod] {
		tag = stStar.Render(mod) + " "
	}
	return ts + " " + tag + st.Render(msg)
}

func (m *model) phaseBar() string {
	var b strings.Builder
	for i, name := range phaseNames {
		switch {
		case i < m.phaseIdx:
			b.WriteString(stOK.Render("● " + name))
		case i == m.phaseIdx:
			b.WriteString(stStar.Render("◉ " + name))
		default:
			b.WriteString(stDim.Render("○ " + name))
		}
		if i < len(phaseNames)-1 {
			b.WriteString(stDim.Render("  ›  "))
		}
	}
	return b.String()
}

func (m *model) headerLine() string {
	spin := spinner[m.tickN%len(spinner)]
	live := stStar.Render(spin + " live")
	switch m.status {
	case "completed":
		live = stOK.Render("✓ completed")
	case "failed":
		live = stErr.Render("✗ failed")
	case "stopped":
		live = stWarn.Render("stopped")
	}
	return stHead.Render(" CYPTURE ") + stDim.Render(" live scan · ") + stBar.Render(m.target) +
		"   " + live + stDim.Render(fmt.Sprintf("   findings: %d   experts: %d", m.findings, len(m.subs)))
}

func (m *model) View() string {
	if m.w == 0 {
		m.w = 100
	}
	if m.h == 0 {
		m.h = 30
	}
	if m.mode == modeChild && len(m.subs) > 0 {
		return m.childView()
	}
	return m.mainView()
}

func (m *model) mainView() string {
	sep := stDim.Render(strings.Repeat("·", clampI(m.w, 10, 220)))

	var pb strings.Builder
	pb.WriteString(stBar.Render(" EXPERTS ") + stDim.Render("(↑/↓ select · Enter detail)") + "\n")
	if len(m.subs) == 0 {
		pb.WriteString(stDim.Render("   experts will appear here once dispatched…") + "\n")
	}
	maxList := 8
	start := 0
	if m.sel >= maxList {
		start = m.sel - maxList + 1
	}
	for i := start; i < len(m.subs) && i < start+maxList; i++ {
		sa := m.subs[i]
		g := "●"
		gs := stStar
		if sa.status == "done" {
			g, gs = "✓", stOK
		}
		row := fmt.Sprintf(" %s %-26s %s", gs.Render(g), clip(sa.name, 26), stDim.Render(clip(sa.last, m.w-40)))
		if i == m.sel {
			row = stSel.Render(fmt.Sprintf(" ▸ %-26s ", clip(sa.name, 26))) + " " + stDim.Render(clip(sa.last, m.w-40))
		}
		pb.WriteString(row + "\n")
	}
	if len(m.subs) > start+maxList {
		pb.WriteString(stDim.Render(fmt.Sprintf("   … +%d more experts", len(m.subs)-(start+maxList))) + "\n")
	}
	panel := strings.TrimRight(pb.String(), "\n")
	panelH := strings.Count(panel, "\n") + 1

	used := 2 + panelH + 2 + 1
	avail := m.h - used
	if avail < 3 {
		avail = 3
	}
	lines := m.main
	if len(lines) > avail {
		lines = lines[len(lines)-avail:]
	}
	body := strings.Join(styleLines(lines), "\n")
	for i := len(lines); i < avail; i++ {
		body += "\n"
	}
	footer := stDim.Render(" watch only · ↑/↓ select expert · Enter enter expert · process autonomous ")
	return m.headerLine() + "\n" + m.phaseBar() + "\n" + panel + "\n" + sep + "\n" + body + "\n" + sep + "\n" + footer
}

func (m *model) childView() string {
	sa := m.subs[m.sel]
	g := stStar.Render("● running")
	if sa.status == "done" {
		g = stOK.Render("✓ done")
	}
	pos := fmt.Sprintf("[%d/%d]", m.sel+1, len(m.subs))
	head := stBar.Render(" 🤖 "+sa.name+" ") + " " + g + stDim.Render("  "+pos)
	sep := stDim.Render(strings.Repeat("·", clampI(m.w, 10, 220)))
	avail := m.h - 4
	if avail < 3 {
		avail = 3
	}
	lines := sa.lines

	if len(lines) > avail {
		end := len(lines) - m.scroll
		if end < avail {
			end = avail
		}
		if end > len(lines) {
			end = len(lines)
		}
		start := end - avail
		if start < 0 {
			start = 0
		}
		lines = lines[start:end]
	}
	body := strings.Join(styleLines(lines), "\n")
	for i := len(lines); i < avail; i++ {
		body += "\n"
	}
	footer := stDim.Render(" ↑/↓ scroll · Tab/[ ] switch expert · Esc back ")
	return head + "\n" + sep + "\n" + body + "\n" + footer
}

var (
	mdBoldRe = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	mdCodeRe = regexp.MustCompile("`([^`]+)`")
	mdHeadRe = regexp.MustCompile(`(^|\s)(#{1,6})\s+(.+)$`)
)

func mdStyle(s string) string {
	s = mdHeadRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := mdHeadRe.FindStringSubmatch(m)
		return sub[1] + stHead.Render(sub[3])
	})
	s = mdBoldRe.ReplaceAllStringFunc(s, func(m string) string {
		return stBar.Render(mdBoldRe.FindStringSubmatch(m)[1])
	})
	s = mdCodeRe.ReplaceAllStringFunc(s, func(m string) string {
		return stCyan.Render(mdCodeRe.FindStringSubmatch(m)[1])
	})
	return s
}

func styleLines(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = mdStyle(l)
	}
	return out
}

func stripStyle(s string) string { return s }

func clip(s string, n int) string {
	r := []rune(s)
	if n < 1 {
		n = 1
	}
	if len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
func clampI(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func main() {
	scanID := flag.String("scan", "", "scan session id")
	dbPath := flag.String("db", "", "sqlite db path")
	flag.Parse()
	if *scanID == "" || *dbPath == "" {
		fmt.Fprintln(os.Stderr, "usage: cypture-tui --scan <id> --db <path>")
		os.Exit(2)
	}
	gdb, err := gorm.Open(sqlite.Open(*dbPath+"?_pragma=busy_timeout(5000)&mode=ro"), &gorm.Config{Logger: glogger.Discard})
	if err != nil {
		fmt.Fprintln(os.Stderr, "db:", err)
		os.Exit(1)
	}
	if sqlDB, e := gdb.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	m := &model{db: gdb, scanID: *scanID, subIndex: map[string]int{}, status: "running"}
	var sess models.ScanSession
	if gdb.First(&sess, "id = ?", *scanID).Error == nil {
		var eng models.Engagement
		if gdb.Select("seed").First(&eng, "id = ?", sess.EngagementID).Error == nil {
			m.target = eng.Seed
		}
	}
	if m.target == "" {
		m.target = "scan"
	}
	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		os.Exit(1)
	}
}

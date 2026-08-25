package server

import (
	"bytes"
	"html/template"
	"sort"
	"strings"
	"time"

	"cypture/internal/models"
	"cypture/internal/orchestrator"
)

type reportData struct {
	Brand       Branding
	Theme       reportTheme
	Client      string
	Scope       string
	Mode        string
	Date        string
	TestWindow  string
	Methodology string
	ToolsUsed   string
	Year        string

	Total       int
	Counts      []sevCount
	MaxCount    int
	RiskPosture string
	Summary     template.HTML

	Findings    []reportFinding
	Roadmap     []roadmapGroup
	HasFindings bool

	Unverified    []reportFinding
	HasUnverified bool
}

type sevCount struct {
	Sev   string
	Label string
	Count int
	Pct   int
}

type reportFinding struct {
	Index       int
	Title       string
	Severity    string
	SevClass    string
	CWE         string
	CWEName     string
	CVSSScore   string
	CVSSVector  string
	VulnType    string
	Method      string
	Endpoint    string
	Confidence  string
	Description string
	PoC         string
	Request     string
	Response    string
	Remediation string
	ImpactC     string
	ImpactI     string
	ImpactA     string
	Refs        []refLink
}

type roadmapGroup struct {
	Phase string
	Items []roadmapItem
}

type roadmapItem struct {
	Title    string
	Severity string
	SevClass string
	Action   string
}

var sevOrder = []string{"critical", "high", "medium", "low", "info"}
var sevLabels = map[string]string{
	"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info",
}

func boldHTML(s string) template.HTML {
	esc := template.HTMLEscapeString(s)
	for strings.Count(esc, "**") >= 2 {
		esc = strings.Replace(esc, "**", "<strong>", 1)
		esc = strings.Replace(esc, "**", "</strong>", 1)
	}
	return template.HTML(esc)
}

func clipText(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return strings.TrimSpace(s[:n]) + "…"
}

func (s *Server) buildReportData(sess *models.ScanSession, eng *models.Engagement) reportData {
	var all []models.Finding
	s.DB.Where("scan_session_id = ?", sess.ID).Find(&all)

	all = s.synthesizeFindings(all)
	sort.SliceStable(all, func(i, j int) bool {
		return severityRank[strings.ToLower(all[i].Severity)] < severityRank[strings.ToLower(all[j].Severity)]
	})

	var fs, candidates []models.Finding
	for _, f := range all {
		if f.Verified || findingHasEvidence(f) {
			fs = append(fs, f)
		} else {
			candidates = append(candidates, f)
		}
	}

	counts := map[string]int{}
	for _, f := range fs {
		counts[strings.ToLower(f.Severity)]++
	}
	maxCount := 1
	for _, c := range counts {
		if c > maxCount {
			maxCount = c
		}
	}
	var sc []sevCount
	for _, sev := range sevOrder {
		sc = append(sc, sevCount{
			Sev: sev, Label: sevLabels[sev], Count: counts[sev],
			Pct: counts[sev] * 100 / maxCount,
		})
	}

	scrub := orchestrator.Scrub
	rfs := make([]reportFinding, 0, len(fs))

	acil, kisa, orta := []roadmapItem{}, []roadmapItem{}, []roadmapItem{}
	for i, f := range fs {
		rfs = append(rfs, toReportFinding(scrub, i+1, f))
		sevc := strings.ToLower(f.Severity)
		item := roadmapItem{Title: scrub(f.Title), Severity: strings.ToUpper(f.Severity),
			SevClass: sevc, Action: clipText(scrub(f.Remediation), 220)}
		switch sevc {
		case "critical", "high":
			acil = append(acil, item)
		case "medium":
			kisa = append(kisa, item)
		default:
			orta = append(orta, item)
		}
	}

	ufs := make([]reportFinding, 0, len(candidates))
	for i, f := range candidates {
		ufs = append(ufs, toReportFinding(scrub, i+1, f))
	}
	var roadmap []roadmapGroup
	if len(acil) > 0 {
		roadmap = append(roadmap, roadmapGroup{"Immediate — First 24 Hours (Critical/High)", acil})
	}
	if len(kisa) > 0 {
		roadmap = append(roadmap, roadmapGroup{"Short Term — 1 Week (Medium)", kisa})
	}
	if len(orta) > 0 {
		roadmap = append(roadmap, roadmapGroup{"Medium Term — 1 Month (Low/Info)", orta})
	}

	top := ""
	if len(rfs) > 0 {
		top = rfs[0].Title
	}
	now := time.Now()

	return reportData{
		Brand:       defaultBranding(),
		Theme:       pickTheme(sess.ID),
		Client:      eng.Seed,
		Scope:       strings.Join(decodeList(eng.ScopeIncludes), ", "),
		Mode:        eng.Mode,
		Date:        now.Format("02.01.2006"),
		TestWindow:  reportWindow(sess, now),
		Methodology: "OWASP WSTG & PTES based, autonomous multi-agent black-box assessment",
		ToolsUsed:   "Cypture autonomous assessment engine (recon, web/API/fuzzing specialist modules, verification pass)",
		Year:        now.Format("2006"),
		Total:       len(fs),
		Counts:      sc,
		MaxCount:    maxCount,
		RiskPosture: riskPosture(counts),
		Summary:     boldHTML(execSummary(eng.Seed, len(fs), counts, top)),
		Findings:    rfs,
		Roadmap:     roadmap,
		HasFindings: len(fs) > 0,

		Unverified:    ufs,
		HasUnverified: len(ufs) > 0,
	}
}

func toReportFinding(scrub func(string) string, idx int, f models.Finding) reportFinding {
	conf := f.Confidence
	if f.Verified {
		conf = "verified"
	} else if conf == "" {
		conf = "not verified (candidate)"
	}
	sevc := strings.ToLower(f.Severity)
	cwe := cweFor(f.VulnType, f.Title)
	score, vector := cvssParts(f.CVSS)
	ic, ii, ia := impactFor(sevc)
	return reportFinding{
		Index: idx, Title: scrub(f.Title),
		Severity: strings.ToUpper(f.Severity), SevClass: sevc,
		CWE: cwe.ID, CWEName: cwe.Name,
		CVSSScore: score, CVSSVector: vector,
		VulnType: f.VulnType, Method: f.Method, Endpoint: scrub(f.Endpoint),
		Confidence: conf, Description: scrub(f.Evidence), PoC: scrub(f.PoC),
		Request: scrub(f.Request), Response: scrub(f.Response), Remediation: scrub(f.Remediation),
		ImpactC: ic, ImpactI: ii, ImpactA: ia, Refs: cweRefs(cwe),
	}
}

func reportWindow(sess *models.ScanSession, now time.Time) string {
	if sess.StartedAt != nil {
		end := now
		if sess.EndedAt != nil {
			end = *sess.EndedAt
		}
		return sess.StartedAt.Format("02.01.2006") + " – " + end.Format("02.01.2006")
	}
	return now.Format("02.01.2006")
}

func (s *Server) generateHTMLReport(sess *models.ScanSession, eng *models.Engagement) (string, error) {
	data := s.buildReportData(sess, eng)
	var buf bytes.Buffer
	if err := reportTmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

var reportTmpl = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Brand.Product}} Pentest Report — {{.Client}}</title>
<style>
{{.Theme.CSS}}
/* Fixed (theme-independent) palette: LIGHT background,
   dark text, dark-code-block-light-text → clean/readable both on screen and in print. */
:root{--crit:#c0392b;--high:#d35400;--med:#e67e22;--low:#27ae60;--info:#7f8c8d;
--mono:'Consolas','SFMono-Regular',Menlo,'Courier New',monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font-size:14px;line-height:1.65;
  font-family:'Helvetica Neue',Helvetica,Arial,sans-serif}
.wrap{max-width:940px;margin:0 auto;padding:0 28px 60px}
a{color:var(--accent2)}
h1{font-size:28px;margin:0 0 6px;color:#111}
h2{font-size:19px;color:var(--accent);border-bottom:2px solid var(--line);padding-bottom:7px;margin:38px 0 16px}
h3{font-size:15px;margin:0;color:#111}
.toolbar{position:sticky;top:0;z-index:5;background:var(--bg);padding:12px 0;display:flex;gap:10px;border-bottom:1px solid var(--line)}
.btn{background:var(--accent2);color:#fff;border:0;padding:9px 18px;border-radius:6px;cursor:pointer;font-size:13px}
/* Cover (dark banner — colored, preserved in print) */
.cover{background:var(--cover);color:var(--coverTxt);margin:0 -28px 8px;padding:54px 48px 46px;border-bottom:4px solid var(--accent)}
.cover .logo{height:46px;margin-bottom:26px}
.cover h1{color:#fff;font-size:32px;letter-spacing:.3px}
.cover .sub{color:var(--coverTxt);opacity:.9;font-size:15px;margin-top:4px}
.classif{display:inline-block;margin-top:22px;padding:5px 14px;background:var(--crit);color:#fff;
  border-radius:4px;font-weight:700;letter-spacing:2px;font-size:12px;text-transform:uppercase}
.cover-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px 30px;margin-top:26px;max-width:640px;font-size:13px}
.cover-grid .k{opacity:.75}.cover-grid .v{font-weight:600}
.preparedby{margin-top:24px;font-size:13px;opacity:.92}
.preparedby b{color:#fff}
/* TOC */
.toc{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 22px;margin-top:18px;columns:2;font-size:13px}
.toc a{display:block;color:var(--txt);text-decoration:none;padding:3px 0}
.toc a:hover{color:var(--accent2)}
/* Summary */
.summary{display:flex;flex-wrap:wrap;gap:24px;align-items:center;margin:6px 0 14px}
.total{font-size:46px;font-weight:800;color:var(--accent)}
.posture{font-size:13px;color:var(--mut)}
.bars{flex:1;min-width:300px}
.bar-row{display:flex;align-items:center;gap:10px;margin:5px 0;font-size:12px}
.bar-lab{width:58px;color:var(--mut)}
.bar-track{flex:1;height:11px;background:#eceef1;border:1px solid var(--line);border-radius:6px;overflow:hidden}
.bar-fill{height:100%}
.bar-n{width:26px;text-align:right;color:var(--mut)}
.sev-critical{background:var(--crit)}.sev-high{background:var(--high)}.sev-medium{background:var(--med)}
.sev-low{background:var(--low)}.sev-info{background:var(--info)}
.prose{color:var(--txt)}
/* Tables (zebra, dark header) */
table{width:100%;border-collapse:collapse;margin:10px 0;font-size:12.5px}
th,td{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}
th{background:#222;color:#fff;text-transform:uppercase;letter-spacing:.5px;font-size:11px}
tbody tr:nth-child(even){background:#f6f7f9}
.kv{margin:8px 0;font-size:13px}.kv .k{display:inline-block;min-width:130px;color:var(--mut)}
.matrix td:first-child{font-weight:700}
.pill{display:inline-block;padding:2px 9px;border-radius:4px;color:#fff;font-size:11px;font-weight:700}
.pill.critical{background:var(--crit)}.pill.high{background:var(--high)}.pill.medium{background:var(--med)}
.pill.low{background:var(--low)}.pill.info{background:var(--info)}
/* Findings */
.finding{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:20px 22px;margin:18px 0;border-left:5px solid var(--info)}
.finding.critical{border-left-color:var(--crit)}.finding.high{border-left-color:var(--high)}
.finding.medium{border-left-color:var(--med)}.finding.low{border-left-color:var(--low)}
.f-head{display:flex;justify-content:space-between;align-items:baseline;gap:12px}
.badge{font-size:11px;font-weight:700;padding:4px 11px;border-radius:4px;color:#fff;white-space:nowrap}
.badge.critical{background:var(--crit)}.badge.high{background:var(--high)}.badge.medium{background:var(--med)}
.badge.low{background:var(--low)}.badge.info{background:var(--info)}
.f-sub{color:var(--mut);font-size:12px;margin:6px 0 10px}
.f-sub code{background:#f0f0f0;padding:2px 6px;border-radius:3px;color:#1f2430;font-family:var(--mono)}
.f-sec{margin-top:14px}.f-sec h4{margin:0 0 5px;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--accent)}
/* Code blocks: DARK background + LIGHT text (always readable, in print too) */
pre{background:#1e1e1e;color:#d4d4d4;border-radius:6px;padding:12px;overflow-x:auto;font-size:12px;
  white-space:pre-wrap;word-break:break-word;font-family:var(--mono);line-height:1.5}
.impact span{display:inline-block;margin-right:16px;font-size:12px}
.refs a{display:inline-block;margin-right:14px;font-size:12px}
.roadmap-item{border-left:3px solid var(--info);padding:4px 0 4px 12px;margin:8px 0}
.roadmap-item.critical,.roadmap-item.high{border-left-color:var(--crit)}
.roadmap-item.medium{border-left-color:var(--med)}.roadmap-item.low{border-left-color:var(--low)}
.empty{color:var(--mut);padding:22px;text-align:center;border:1px dashed var(--line);border-radius:8px}
.foot{margin-top:48px;color:var(--mut);font-size:11.5px;text-align:center;border-top:1px solid var(--line);padding-top:18px}
/* Print: page header/footer + clean page breaks */
@page{margin:18mm 14mm;
  @top-right{content:"Cypture Security Assessment Report";font-size:8pt;color:#888}
  @bottom-left{content:"CONFIDENTIAL";font-size:7.5pt;color:#999}
  @bottom-right{content:"Page " counter(page) " / " counter(pages);font-size:8pt;color:#888}}
@page:first{margin:0}
@media print{
  .toolbar{display:none}.wrap{max-width:none;padding:0 14mm 14mm}
  .cover{margin:0 0 8px;padding:40px}
  h2{page-break-after:avoid}.finding{page-break-inside:avoid}
  .cover,.classif,.pill,.badge,.bar-fill,.bar-track,pre,th,tbody tr:nth-child(even){
    -webkit-print-color-adjust:exact;print-color-adjust:exact}
}
</style></head><body>
<div class="toolbar"><button class="btn" onclick="window.print()">🖨 Print / Save as PDF</button>
<a class="btn" style="text-decoration:none" href="?">↓ Markdown</a></div>

<div class="cover">
  {{if .Brand.LogoDataURI}}<img class="logo" src="{{.Brand.LogoDataURI}}" alt="{{.Brand.CompanyName}}">{{end}}
  <h1>Security Assessment Report</h1>
  <div class="sub">{{.Client}}</div>
  <div class="classif">{{.Brand.Classification}}</div>
  <div class="cover-grid">
    <div class="k">Target</div><div class="v">{{.Client}}</div>
    <div class="k">Test Window</div><div class="v">{{.TestWindow}}</div>
    <div class="k">Assessment Mode</div><div class="v">{{.Mode}}</div>
    <div class="k">Report Version</div><div class="v">v{{.Brand.Version}} · {{.Date}}</div>
    <div class="k">Overall Risk</div><div class="v">{{.RiskPosture}}</div>
    <div class="k">Total Findings</div><div class="v">{{.Total}}</div>
  </div>
  <div class="preparedby">Prepared by: <b>{{.Brand.CompanyName}}</b>{{if .Brand.CompanySite}} ({{.Brand.CompanySite}}){{end}}{{if .Brand.PartnerName}}
    &nbsp;·&nbsp; <b>{{.Brand.PartnerName}}</b>{{if .Brand.PartnerSite}} ({{.Brand.PartnerSite}}){{end}}{{end}}
    &nbsp;·&nbsp; <b>{{.Brand.Product}}</b></div>
</div>

<div class="wrap">
<div class="toc">
  <a href="#ozet">1. Executive Summary</a>
  <a href="#kapsam">2. Scope &amp; Methodology</a>
  <a href="#matris">3. Risk Rating Matrix</a>
  <a href="#tablo">4. Findings Summary Table</a>
  <a href="#detay">5. Detailed Findings</a>
  <a href="#yol">6. Remediation Roadmap</a>
  <a href="#sonuc">7. Conclusion</a>
</div>

<h2 id="ozet">1. Executive Summary</h2>
{{if .HasFindings}}
<div class="summary">
  <div><div class="total">{{.Total}}</div><div class="posture">verified findings · overall risk: <b>{{.RiskPosture}}</b></div></div>
  <div class="bars">
  {{range .Counts}}<div class="bar-row"><span class="bar-lab">{{.Label}}</span>
    <span class="bar-track"><span class="bar-fill sev-{{.Sev}}" style="width:{{if .Count}}{{.Pct}}{{else}}0{{end}}%"></span></span>
    <span class="bar-n">{{.Count}}</span></div>{{end}}
  </div>
</div>
{{end}}
<p class="prose">{{.Summary}}</p>

<h2 id="kapsam">2. Scope &amp; Methodology</h2>
<div class="kv"><span class="k">Target / Scope</span> <code>{{.Scope}}</code></div>
<div class="kv"><span class="k">Test Window</span> {{.TestWindow}}</div>
<div class="kv"><span class="k">Methodology</span> {{.Methodology}}</div>
<div class="kv"><span class="k">Tools Used</span> {{.ToolsUsed}}</div>
<div class="kv"><span class="k">Assessment Type</span> Black Box, authorized</div>

<h2 id="matris">3. Risk Rating Matrix</h2>
<table class="matrix"><thead><tr><th>Level</th><th>Description</th><th>Recommended Action Time</th></tr></thead><tbody>
<tr><td><span class="pill critical">CRITICAL</span></td><td>Directly exploitable, high impact (data breach / full access).</td><td>First 24 hours</td></tr>
<tr><td><span class="pill high">HIGH</span></td><td>Serious impact; exploitable under limited conditions or via chaining.</td><td>1 week</td></tr>
<tr><td><span class="pill medium">MEDIUM</span></td><td>Moderate impact; requires additional information/access.</td><td>1 month</td></tr>
<tr><td><span class="pill low">LOW</span></td><td>Limited impact; defense-in-depth recommendation.</td><td>Planned</td></tr>
<tr><td><span class="pill info">INFO</span></td><td>Informational / hardening opportunity.</td><td>Optional</td></tr>
</tbody></table>

{{if .HasFindings}}
<h2 id="tablo">4. Findings Summary Table</h2>
<table><thead><tr><th>#</th><th>CWE</th><th>Finding</th><th>Severity</th><th>CVSS</th><th>Asset</th></tr></thead><tbody>
{{range .Findings}}<tr>
  <td>{{.Index}}</td><td>{{.CWE}}</td><td>{{.Title}}</td>
  <td><span class="pill {{.SevClass}}">{{.Severity}}</span></td>
  <td>{{if .CVSSScore}}{{.CVSSScore}}{{else}}—{{end}}</td>
  <td><code>{{.Endpoint}}</code></td>
</tr>{{end}}
</tbody></table>

<h2 id="detay">5. Detailed Findings</h2>
{{range .Findings}}
<div class="finding {{.SevClass}}">
  <div class="f-head"><h3 class="f-title">{{.Index}}. {{.Title}}</h3>
    <span class="badge {{.SevClass}}">{{.Severity}}</span></div>
  <div class="f-sub">
    <b>{{.CWE}}</b>{{if .CWEName}} — {{.CWEName}}{{end}}
    {{if .CVSSScore}} · CVSS <b>{{.CVSSScore}}</b>{{end}}
    {{if .Confidence}} · Confidence: {{.Confidence}}{{end}}
    <br>Endpoint: <code>{{.Method}} {{.Endpoint}}</code>
    {{if .CVSSVector}}<br>Vector: <code>{{.CVSSVector}}</code>{{end}}
  </div>
  {{if .Description}}<div class="f-sec"><h4>Description</h4><pre>{{.Description}}</pre></div>{{end}}
  {{if .PoC}}<div class="f-sec"><h4>Evidence / PoC</h4><pre>{{.PoC}}</pre></div>{{end}}
  {{if .Request}}<div class="f-sec"><h4>Raw Request</h4><pre>{{.Request}}</pre></div>{{end}}
  {{if .Response}}<div class="f-sec"><h4>Raw Response</h4><pre>{{.Response}}</pre></div>{{end}}
  <div class="f-sec"><h4>Impact</h4><div class="impact">
    <span>Confidentiality: <b>{{.ImpactC}}</b></span><span>Integrity: <b>{{.ImpactI}}</b></span><span>Availability: <b>{{.ImpactA}}</b></span>
  </div></div>
  {{if .Remediation}}<div class="f-sec"><h4>Remediation</h4><pre>{{.Remediation}}</pre></div>{{end}}
  <div class="f-sec refs"><h4>References</h4>
    {{range .Refs}}<a href="{{.URL}}" target="_blank" rel="noopener">{{.Label}}</a>{{end}}
  </div>
</div>
{{end}}
{{else}}
<h2 id="tablo">4. Findings</h2>
<div class="empty">No verified findings were reported in this assessment.</div>
{{end}}

{{if .Roadmap}}
<h2 id="yol">6. Remediation Roadmap</h2>
{{range .Roadmap}}
<h3 style="margin:18px 0 6px;color:var(--accent)">{{.Phase}}</h3>
{{range .Items}}<div class="roadmap-item {{.SevClass}}"><b>{{.Title}}</b> <span class="pill {{.SevClass}}">{{.Severity}}</span>{{if .Action}}<br><span style="color:var(--mut)">{{.Action}}</span>{{end}}</div>{{end}}
{{end}}
{{end}}

{{if .HasUnverified}}
<h2 id="ek">Appendix — Unverified Candidate Findings</h2>
<p class="prose">The following candidates were flagged by specialist modules but did not pass the verification stage (false-positive elimination).
<b>These are not verified vulnerabilities</b>; they are listed for manual review only and are not included in the executive summary count.</p>
<table><thead><tr><th>#</th><th>Finding</th><th>Severity</th><th>Asset</th></tr></thead><tbody>
{{range .Unverified}}<tr>
  <td>{{.Index}}</td><td>{{.Title}}</td>
  <td><span class="pill {{.SevClass}}">{{.Severity}}</span></td>
  <td><code>{{.Method}} {{.Endpoint}}</code></td>
</tr>{{end}}
</tbody></table>
{{end}}

<h2 id="sonuc">7. Conclusion</h2>
<p class="prose">This report contains the results of the authorized security assessment carried out against {{.Client}}
by {{.Brand.CompanyName}} using the {{.Brand.Product}} platform. It is recommended that the identified findings be
prioritized and remediated according to the roadmap above, and that a verification test be performed after remediation.
This document is confidential ({{.Brand.Classification}}) and should only be shared with authorized parties.</p>

<div class="foot">© {{.Year}} {{.Brand.CompanyName}}{{if .Brand.PartnerName}} · {{.Brand.PartnerName}}{{end}} · generated with {{.Brand.Product}} · {{.Date}} · {{.Brand.Classification}}</div>
</div></body></html>`))

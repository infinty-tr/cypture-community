package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cypture/internal/auth"
	"cypture/internal/models"
	"cypture/internal/orchestrator"
)

func (s *Server) scanReportAllowed(r *http.Request, sess *models.ScanSession) bool {
	_, ok := auth.UserFrom(r.Context())
	return ok
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func (s *Server) handleScanReport(w http.ResponseWriter, r *http.Request) {
	sess, eng, ok := s.authorizeScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}

	if !s.scanReportAllowed(r, sess) {
		writeErr(w, http.StatusForbidden, "You are not authorized to view this report.")
		return
	}

	if strings.EqualFold(r.URL.Query().Get("format"), "html") {
		html, err := s.generateHTMLReport(sess, eng)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "could not generate report")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(html))
		return
	}

	md := s.reportFromFile(sess)
	if md == "" {
		md = s.generateReport(sess, eng)
	}

	filename := fmt.Sprintf("cypture-%s-report.md", clipHost(eng.Seed))
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(md))
}

func (s *Server) reportFromFile(sess *models.ScanSession) string {

	if sess.ReportPath != "" {
		if b, err := os.ReadFile(sess.ReportPath); err == nil && len(b) > 0 {
			return orchestrator.Scrub(string(b))
		}
	}
	if sess.WorkDir == "" {
		return ""
	}
	candidates := []string{
		filepath.Join(sess.WorkDir, "report.md"),
		filepath.Join(sess.WorkDir, "findings", "report.md"),
	}
	var newest string
	var newestMod int64 = -1
	for _, p := range candidates {
		fi, err := os.Stat(p)
		if err != nil || fi.Size() == 0 {
			continue
		}
		if fi.ModTime().Unix() > newestMod {
			newestMod = fi.ModTime().Unix()
			newest = p
		}
	}
	if newest == "" {
		return ""
	}
	if b, err := os.ReadFile(newest); err == nil && len(b) > 0 {
		return orchestrator.Scrub(string(b))
	}
	return ""
}

func (s *Server) generateReport(sess *models.ScanSession, eng *models.Engagement) string {
	var fs []models.Finding
	s.DB.Where("scan_session_id = ?", sess.ID).Find(&fs)

	fs = s.synthesizeFindings(fs)
	sort.SliceStable(fs, func(i, j int) bool {
		return severityRank[strings.ToLower(fs[i].Severity)] < severityRank[strings.ToLower(fs[j].Severity)]
	})

	var verified, candidates, lowInfo []models.Finding
	for _, f := range fs {
		switch strings.ToLower(strings.TrimSpace(f.Severity)) {
		case "low", "info", "informational", "":
			lowInfo = append(lowInfo, f)
		default:
			if f.Verified {
				verified = append(verified, f)
			} else {
				candidates = append(candidates, f)
			}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Cypture Security Test Report\n\n")
	fmt.Fprintf(&b, "**Target:** %s  \n", eng.Seed)
	fmt.Fprintf(&b, "**Scope:** %s  \n", strings.Join(decodeList(eng.ScopeIncludes), ", "))
	fmt.Fprintf(&b, "**Mode:** %s  \n", eng.Mode)
	fmt.Fprintf(&b, "**Date:** %s  \n\n", time.Now().Format("2006-01-02 15:04"))

	fmt.Fprintf(&b, "## Executive Summary\n\n")
	if len(verified) == 0 {
		fmt.Fprintf(&b, "No verified findings (medium or higher severity) were reported in this assessment.\n\n")
	} else {
		counts := map[string]int{}
		for _, f := range verified {
			counts[strings.ToLower(f.Severity)]++
		}
		fmt.Fprintf(&b, "%d verified findings in total: ", len(verified))
		parts := []string{}
		for _, sev := range []string{"critical", "high", "medium"} {
			if counts[sev] > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", counts[sev], sev))
			}
		}
		fmt.Fprintf(&b, "%s.\n\n", strings.Join(parts, ", "))
	}
	if len(lowInfo) > 0 {
		fmt.Fprintf(&b, "_Additionally, %d low-severity / informational observations are listed in the appendix (not included in the main risk table)._\n\n", len(lowInfo))
	}

	fmt.Fprintf(&b, "## Findings\n\n")
	if len(verified) == 0 {
		fmt.Fprintf(&b, "_No verified findings of medium or higher severity._\n\n")
	}
	for i, f := range verified {
		writeFindingMD(&b, i+1, f)
	}

	if len(candidates) > 0 {
		fmt.Fprintf(&b, "## Appendix — Unverified Candidate Findings\n\n")
		fmt.Fprintf(&b, "_The following candidates were flagged by specialist modules but did not pass the verification stage (false-positive elimination). **These are not verified vulnerabilities**; they are listed for manual review only._\n\n")
		for i, f := range candidates {
			writeFindingMD(&b, i+1, f)
		}
	}

	if len(lowInfo) > 0 {
		fmt.Fprintf(&b, "## Appendix — Low Severity & Informational\n\n")
		fmt.Fprintf(&b, "_The following observations are not significant security vulnerabilities on their own (security hardening / hygiene). They are listed for information; they may be valuable when chained with other findings._\n\n")
		for _, f := range lowInfo {
			sev := strings.ToUpper(strings.TrimSpace(f.Severity))
			if sev == "" {
				sev = "INFO"
			}
			fmt.Fprintf(&b, "- **[%s]** %s", sev, f.Title)
			if ep := strings.TrimSpace(f.Method + " " + f.Endpoint); ep != "" {
				fmt.Fprintf(&b, " — `%s`", ep)
			}
			fmt.Fprintf(&b, "\n")
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "---\n_This report was generated automatically by Cypture._\n")
	return orchestrator.Scrub(b.String())
}

func dedupeFindings(in []models.Finding) []models.Finding {
	out := make([]models.Finding, 0, len(in))
	for _, f := range in {

		if isNegativeFinding(f) || isTheoretical(f) {
			continue
		}

		f = recalibrateRecon(f)
		merged := false
		for i := range out {
			if sameFinding(out[i], f) {
				if findingStrength(f) > findingStrength(out[i]) {
					out[i] = f
				}
				merged = true
				break
			}
		}
		if !merged {
			out = append(out, f)
		}
	}
	return out
}

func findingStrength(f models.Finding) int {
	s := 0
	if f.Verified {
		s += 100
	}
	r, ok := severityRank[strings.ToLower(strings.TrimSpace(f.Severity))]
	if !ok {
		r = 5
	}
	s += (5 - r) * 10
	if strings.TrimSpace(f.Request) != "" && strings.TrimSpace(f.Response) != "" {
		s++
	}
	return s
}

func (s *Server) dedupedCountByScan(scanIDs []string) map[string]int64 {
	res := make(map[string]int64, len(scanIDs))
	if len(scanIDs) == 0 {
		return res
	}
	var all []models.Finding
	s.DB.Select("scan_session_id, title, vuln_type, endpoint, severity, verified").
		Where("scan_session_id IN ?", scanIDs).Find(&all)
	byScan := make(map[string][]models.Finding, len(scanIDs))
	for _, f := range all {
		byScan[f.ScanSessionID] = append(byScan[f.ScanSessionID], f)
	}
	for id, g := range byScan {

		res[id] = int64(len(normalizeForReport(g)))
	}
	return res
}

func findingHasEvidence(f models.Finding) bool {
	return strings.TrimSpace(f.PoC) != "" || strings.TrimSpace(f.Request) != "" ||
		strings.TrimSpace(f.Response) != "" || strings.TrimSpace(f.ExtractedEvidence) != "" ||
		strings.TrimSpace(f.Evidence) != ""
}

func writeFindingMD(b *strings.Builder, idx int, f models.Finding) {
	fmt.Fprintf(b, "### %d. %s\n\n", idx, f.Title)
	fmt.Fprintf(b, "- **Severity:** %s\n", strings.ToUpper(f.Severity))
	if f.CVSS != "" {
		fmt.Fprintf(b, "- **CVSS:** %s\n", f.CVSS)
	}
	if f.VulnType != "" {
		fmt.Fprintf(b, "- **Type:** %s\n", f.VulnType)
	}
	fmt.Fprintf(b, "- **Endpoint:** `%s %s`\n", f.Method, f.Endpoint)
	if f.DurationMs > 0 {
		fmt.Fprintf(b, "- **Response time:** %d ms\n", f.DurationMs)
	}
	conf := f.Confidence
	if f.Verified {
		conf = "verified"
	} else if conf == "" {
		conf = "not verified (candidate)"
	}
	fmt.Fprintf(b, "- **Confidence:** %s\n", conf)
	if f.Evidence != "" {
		fmt.Fprintf(b, "\n**Evidence:**\n\n%s\n", f.Evidence)
	}
	if f.PoC != "" {
		fmt.Fprintf(b, "\n**PoC:**\n\n%s\n", f.PoC)
	}
	if f.Request != "" {
		fmt.Fprintf(b, "\n**Raw Request:**\n\n```http\n%s\n```\n", f.Request)
	}
	if f.Response != "" {
		fmt.Fprintf(b, "\n**Raw Response:**\n\n```http\n%s\n```\n", f.Response)
	}
	if f.Remediation != "" {
		fmt.Fprintf(b, "\n**Remediation:** %s\n", f.Remediation)
	}
	b.WriteString("\n---\n\n")
}

func clipHost(target string) string {
	h := normalizeHost(target)
	if h == "" {
		return "scan"
	}
	return h
}

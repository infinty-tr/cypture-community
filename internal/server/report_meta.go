package server

import (
	"fmt"
	"hash/fnv"
	"html/template"
	"regexp"
	"strings"
)

type cweEntry struct{ ID, Name string }

var cweRules = []struct {
	key string
	cwe cweEntry
}{
	{"sql", cweEntry{"CWE-89", "SQL Injection"}},
	{"nosql", cweEntry{"CWE-943", "NoSQL Injection"}},
	{"xss", cweEntry{"CWE-79", "Cross-site Scripting"}},
	{"ssti", cweEntry{"CWE-1336", "Server-Side Template Injection"}},
	{"ssrf", cweEntry{"CWE-918", "Server-Side Request Forgery"}},
	{"xxe", cweEntry{"CWE-611", "XML External Entity"}},
	{"lfi", cweEntry{"CWE-22", "Path Traversal"}},
	{"path travers", cweEntry{"CWE-22", "Path Traversal"}},
	{"traversal", cweEntry{"CWE-22", "Path Traversal"}},
	{"command inj", cweEntry{"CWE-78", "OS Command Injection"}},
	{"rce", cweEntry{"CWE-94", "Code Injection"}},
	{"deserial", cweEntry{"CWE-502", "Insecure Deserialization"}},
	{"open redirect", cweEntry{"CWE-601", "Open Redirect"}},
	{"redirect", cweEntry{"CWE-601", "Open Redirect"}},
	{"idor", cweEntry{"CWE-639", "Insecure Direct Object Reference"}},
	{"bola", cweEntry{"CWE-639", "Broken Object Level Authorization"}},
	{"bfla", cweEntry{"CWE-285", "Improper Authorization"}},
	{"mass assign", cweEntry{"CWE-915", "Mass Assignment"}},
	{"auth bypass", cweEntry{"CWE-287", "Improper Authentication"}},
	{"authentication", cweEntry{"CWE-287", "Improper Authentication"}},
	{"jwt", cweEntry{"CWE-347", "Improper Verification of Cryptographic Signature"}},
	{"oauth", cweEntry{"CWE-287", "Improper Authentication"}},
	{"session", cweEntry{"CWE-384", "Session Fixation"}},
	{"csrf", cweEntry{"CWE-352", "Cross-Site Request Forgery"}},
	{"cors", cweEntry{"CWE-942", "Permissive Cross-domain Policy"}},
	{"clickjack", cweEntry{"CWE-1021", "Improper Restriction of Rendered UI Layers"}},
	{"prototype pollut", cweEntry{"CWE-1321", "Prototype Pollution"}},
	{"graphql", cweEntry{"CWE-200", "Information Exposure"}},
	{"rate limit", cweEntry{"CWE-770", "Allocation of Resources Without Limits"}},
	{"smuggl", cweEntry{"CWE-444", "HTTP Request Smuggling"}},
	{"cache", cweEntry{"CWE-525", "Web Cache Issues"}},
	{"crlf", cweEntry{"CWE-93", "CRLF Injection"}},
	{"file upload", cweEntry{"CWE-434", "Unrestricted File Upload"}},
	{"sensitive", cweEntry{"CWE-312", "Cleartext Storage of Sensitive Information"}},
	{"disclosure", cweEntry{"CWE-200", "Information Exposure"}},
	{"exposure", cweEntry{"CWE-200", "Information Exposure"}},
	{"header", cweEntry{"CWE-693", "Protection Mechanism Failure"}},
	{"verbose error", cweEntry{"CWE-209", "Information Exposure Through an Error Message"}},
	{"misconfig", cweEntry{"CWE-16", "Configuration"}},
}

func cweFor(vulnType, title string) cweEntry {
	hay := strings.ToLower(vulnType + " " + title)
	for _, r := range cweRules {
		if strings.Contains(hay, r.key) {
			return r.cwe
		}
	}
	return cweEntry{"CWE-Other", "Security Vulnerability"}
}

var cvssScoreRe = regexp.MustCompile(`\d{1,2}\.\d`)

func cvssParts(raw string) (score, vector string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if i := strings.Index(raw, "AV:"); i >= 0 {
		vector = strings.TrimRight(raw[i:], " )")
	} else if strings.HasPrefix(strings.ToUpper(raw), "CVSS:") {
		vector = raw
	}
	if m := cvssScoreRe.FindString(raw); m != "" {
		score = m
	}
	return score, vector
}

func impactFor(sev string) (c, i, a string) {
	switch strings.ToLower(sev) {
	case "critical":
		return "High", "High", "High"
	case "high":
		return "High", "High", "Medium"
	case "medium":
		return "Medium", "Medium", "Low"
	case "low":
		return "Low", "Low", "Low"
	default:
		return "Low", "None", "None"
	}
}

type refLink struct {
	Label string
	URL   template.URL
}

func cweRefs(cwe cweEntry) []refLink {
	refs := []refLink{}
	if num := strings.TrimPrefix(cwe.ID, "CWE-"); num != "" && num != "Other" {
		refs = append(refs, refLink{
			Label: cwe.ID + ": " + cwe.Name,
			URL:   template.URL("https://cwe.mitre.org/data/definitions/" + num + ".html"),
		})
	}
	refs = append(refs, refLink{Label: "OWASP Testing Guide", URL: "https://owasp.org/www-project-web-security-testing-guide/"})
	return refs
}

func riskPosture(counts map[string]int) string {
	switch {
	case counts["critical"] > 0:
		return "Critical"
	case counts["high"] > 0:
		return "High"
	case counts["medium"] > 0:
		return "Medium"
	case counts["low"]+counts["info"] > 0:
		return "Low"
	default:
		return "Informational"
	}
}

func execSummary(client string, total int, counts map[string]int, topFinding string) string {
	if total == 0 {
		return fmt.Sprintf("The authorized security assessment carried out against %s identified "+
			"no verified vulnerabilities within the defined scope. "+
			"This indicates that the tested surface has adequate defenses against known "+
			"common attack classes; periodic reassessment is recommended.", client)
	}
	var parts []string
	for _, s := range sevOrder {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], sevLabels[s]))
		}
	}
	sb := fmt.Sprintf("The authorized security assessment carried out against %s identified a total of "+
		"%d verified findings (%s). ", client, total, strings.Join(parts, ", "))
	if topFinding != "" {
		sb += fmt.Sprintf("Highest-priority finding: %s. ", topFinding)
	}
	sb += fmt.Sprintf("The overall risk posture is at the **%s** level. In the sections below, each "+
		"finding is detailed together with evidence, a CVSS assessment, and a remediation recommendation.",
		riskPosture(counts))
	return sb
}

type reportTheme struct {
	Key  string
	Name string
	CSS  template.CSS
}

var reportThemes = []reportTheme{
	{Key: "corporate", Name: "Kurumsal", CSS: template.CSS(`
:root{--bg:#ffffff;--card:#f7f9fc;--line:#dfe4ec;--txt:#1f2430;--mut:#5a6678;--accent:#1e3a8a;--accent2:#2563eb;
--cover:#16233f;--coverTxt:#eaf0fb;}`)},
	{Key: "crimson", Name: "Crimson", CSS: template.CSS(`
:root{--bg:#ffffff;--card:#faf7f7;--line:#e7dede;--txt:#241c1c;--mut:#6b5a5a;--accent:#a01b2b;--accent2:#c0392b;
--cover:#2a1012;--coverTxt:#ffe6e6;}`)},
	{Key: "slate", Name: "Slate", CSS: template.CSS(`
:root{--bg:#fbfbfc;--card:#f4f5f7;--line:#e2e5ea;--txt:#1e2228;--mut:#5b6470;--accent:#334155;--accent2:#475569;
--cover:#1e293b;--coverTxt:#eef2f7;}`)},
	{Key: "teal", Name: "Teal", CSS: template.CSS(`
:root{--bg:#fbfdfd;--card:#f1f7f6;--line:#dce8e6;--txt:#1b2422;--mut:#566863;--accent:#0f766e;--accent2:#0d9488;
--cover:#0b3b36;--coverTxt:#e6fffb;}`)},
}

func pickTheme(seed string) reportTheme {
	h := fnv.New32a()
	_, _ = h.Write([]byte(seed))
	return reportThemes[int(h.Sum32())%len(reportThemes)]
}

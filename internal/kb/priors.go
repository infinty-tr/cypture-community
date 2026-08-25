package kb

import (
	"regexp"
	"strings"
)

var classVocab = []struct {
	re  *regexp.Regexp
	tok string
}{
	{regexp.MustCompile(`(?i)sqli|sql.?inj`), "sqli"},
	{regexp.MustCompile(`(?i)nosql`), "nosqli"},
	{regexp.MustCompile(`(?i)\bxss\b|cross.?site.?script`), "xss"},
	{regexp.MustCompile(`(?i)ssrf`), "ssrf"},
	{regexp.MustCompile(`(?i)ssti|template.?inj`), "ssti"},
	{regexp.MustCompile(`(?i)\brce\b|command.?inj|\bos.?command`), "rce"},
	{regexp.MustCompile(`(?i)lfi|path.?travers|directory.?travers`), "lfi"},
	{regexp.MustCompile(`(?i)xxe`), "xxe"},
	{regexp.MustCompile(`(?i)idor|bola`), "idor"},
	{regexp.MustCompile(`(?i)bfla|function.?level`), "bfla"},
	{regexp.MustCompile(`(?i)mass.?assign`), "mass-assignment"},
	{regexp.MustCompile(`(?i)\bjwt\b`), "jwt"},
	{regexp.MustCompile(`(?i)oauth|openid`), "oauth"},
	{regexp.MustCompile(`(?i)csrf`), "csrf"},
	{regexp.MustCompile(`(?i)cors`), "cors"},
	{regexp.MustCompile(`(?i)open.?redirect`), "open-redirect"},
	{regexp.MustCompile(`(?i)deserial`), "deserialization"},
	{regexp.MustCompile(`(?i)prototype.?pollut`), "prototype-pollution"},
	{regexp.MustCompile(`(?i)race|toctou`), "race-condition"},
	{regexp.MustCompile(`(?i)smuggl`), "request-smuggling"},
	{regexp.MustCompile(`(?i)auth.?bypass|broken.?auth|privilege.?esc`), "auth-bypass"},
	{regexp.MustCompile(`(?i)business.?logic`), "business-logic"},
	{regexp.MustCompile(`(?i)upload`), "file-upload"},
}

func CanonClass(vulnType string) string {
	v := strings.TrimSpace(vulnType)
	if v == "" {
		return ""
	}

	vn := strings.ReplaceAll(strings.ReplaceAll(v, "_", " "), "-", " ")
	for _, c := range classVocab {
		if c.re.MatchString(v) || (vn != v && c.re.MatchString(vn)) {
			return c.tok
		}
	}
	return ""
}

type ClassPrior struct {
	Tech  string  `json:"tech"`
	Class string  `json:"class"`
	Rate  float64 `json:"rate"`
	Hits  int     `json:"hits"`
	Runs  int     `json:"runs"`
}

func (s *Store) LearnOutcomes(tech []string, findings []KnownFinding) {}

func (s *Store) PriorsFor(tech []string) []ClassPrior { return nil }

func (s *Store) PriorsDigest() map[string][]ClassPrior { return nil }

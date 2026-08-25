package engine

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

type SeqExtract struct {
	Var   string `json:"var"`
	From  string `json:"from"`
	Regex string `json:"regex"`
	JSON  string `json:"json"`
}

type SeqStep struct {
	Name    string       `json:"name"`
	Raw     string       `json:"raw"`
	Host    string       `json:"host"`
	Port    int          `json:"port"`
	TLS     *bool        `json:"tls"`
	Session string       `json:"session"`
	Extract []SeqExtract `json:"extract"`
}

func (e *Engine) RunSequence(steps []SeqStep, vars map[string]string) (map[string]any, error) {
	if vars == nil {
		vars = map[string]string{}
	}
	out := []map[string]any{}
	for idx, st := range steps {
		raw := substituteVars(st.Raw, vars)
		host := substituteVars(st.Host, vars)
		tlsOn := true
		if st.TLS != nil {
			tlsOn = *st.TLS
		}
		res, err := e.Send(raw, host, st.Port, tlsOn, st.Session, 0, false)
		stepOut := map[string]any{"step": idx, "name": firstNonEmpty(st.Name, "step_"+strconv.Itoa(idx))}
		if err != nil {
			stepOut["error"] = err.Error()
			out = append(out, stepOut)

			return map[string]any{"steps": out, "vars": vars, "stopped_at": idx}, nil
		}
		stepOut["requestId"] = res.RequestID
		stepOut["status"] = res.StatusCode
		extracted := map[string]string{}
		for _, ex := range st.Extract {
			if strings.TrimSpace(ex.Var) == "" {
				continue
			}
			val := extractValue(ex, res)
			vars[ex.Var] = val
			extracted[ex.Var] = val
		}
		if len(extracted) > 0 {
			stepOut["extracted"] = extracted
		}
		out = append(out, stepOut)
	}
	return map[string]any{"steps": out, "vars": vars}, nil
}

var seqVarRe = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_]+)\s*\}\}`)

func substituteVars(s string, vars map[string]string) string {
	if s == "" || !strings.Contains(s, "{{") {
		return s
	}
	return seqVarRe.ReplaceAllStringFunc(s, func(m string) string {
		name := strings.Trim(m, "{} ")
		if v, ok := vars[name]; ok {
			return v
		}
		return m
	})
}

func extractValue(ex SeqExtract, res *SendResult) string {
	var src string
	from := strings.ToLower(strings.TrimSpace(ex.From))
	switch {
	case from == "" || from == "body":
		src = res.Body
	case from == "status":
		src = strconv.Itoa(res.StatusCode)
	case from == "requestid":
		src = res.RequestID
	case from == "location":
		src = headerGet(res.Headers, "Location")
	case strings.HasPrefix(from, "header:"):
		src = headerGet(res.Headers, strings.TrimSpace(ex.From[len("header:"):]))
	default:
		src = res.Body
	}
	if strings.TrimSpace(ex.JSON) != "" {
		return jsonPath(src, ex.JSON)
	}
	if strings.TrimSpace(ex.Regex) != "" {
		re, err := regexp.Compile(ex.Regex)
		if err != nil {
			return ""
		}
		m := re.FindStringSubmatch(src)
		if len(m) >= 2 {
			return m[1]
		}
		if len(m) == 1 {
			return m[0]
		}
		return ""
	}
	return src
}

func jsonPath(body, path string) string {
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return ""
	}
	for _, seg := range strings.Split(path, ".") {
		if seg == "" {
			continue
		}
		switch cur := v.(type) {
		case map[string]any:
			v = cur[seg]
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(cur) {
				return ""
			}
			v = cur[idx]
		default:
			return ""
		}
	}
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

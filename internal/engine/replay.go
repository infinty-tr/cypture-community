package engine

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

type ReplayEdit struct {
	Method        string
	Path          string
	URL           string
	SetHeaders    map[string]string
	RemoveHeaders []string
	Body          *string
	SetParams     map[string]string
	Session       string
	TLS           *bool
	Port          int
	FollowRedirs  bool
	BodyLimit     int
}

func (e *Engine) Replay(id string, ed ReplayEdit) (map[string]any, error) {
	orig := e.Get(id)
	if orig == nil {
		return nil, fmt.Errorf("request id %q not found", id)
	}

	host := orig.Host
	port := orig.Port
	tlsOn := orig.TLS
	if ed.Port > 0 {
		port = ed.Port
	}
	if ed.TLS != nil {
		tlsOn = *ed.TLS
	}

	method := firstNonEmpty(ed.Method, orig.Method)

	pathQ := pathWithQuery(orig.URL, orig.Path)
	if ed.URL != "" {
		if u, err := url.Parse(ed.URL); err == nil {
			pathQ = u.RequestURI()
			if u.Host != "" {
				host = u.Hostname()
				tlsOn = u.Scheme == "https"
			}
		}
	} else if ed.Path != "" {
		pathQ = ed.Path
	}

	body := orig.ReqBody
	if ed.Body != nil {
		body = *ed.Body
	}
	if len(ed.SetParams) > 0 {
		pathQ = applyQueryParams(pathQ, ed.SetParams)

		if isFormish(body) {
			body = applyFormParams(body, ed.SetParams)
		}
	}

	headers := map[string]string{}
	for k, v := range orig.ReqHeaders {
		headers[k] = v
	}
	for _, rm := range ed.RemoveHeaders {
		for k := range headers {
			if strings.EqualFold(k, rm) {
				delete(headers, k)
			}
		}
	}
	for k, v := range ed.SetHeaders {

		for ek := range headers {
			if strings.EqualFold(ek, k) {
				delete(headers, ek)
			}
		}
		headers[k] = v
	}
	if headerGet(headers, "Host") == "" {
		headers["Host"] = host
	}

	raw := buildRawRequest(method, pathQ, headers, body)

	res, err := e.Send(raw, host, port, tlsOn, ed.Session, ed.BodyLimit, false)
	if err != nil {
		return nil, err
	}

	if ed.FollowRedirs {
		res = e.followRedirects(res, orig.URL, ed.Session, ed.BodyLimit)
	}

	out := map[string]any{
		"original_id": id,
		"result":      res,
		"diff":        e.Diff(id, res.RequestID),
	}
	return out, nil
}

func (e *Engine) followRedirects(res *SendResult, fromURL, session string, bodyLimit int) *SendResult {
	cur := res
	base := fromURL
	chain := []RedirectHop{}
	for hop := 0; hop < 10; hop++ {
		if cur.StatusCode < 300 || cur.StatusCode >= 400 {
			break
		}
		loc := headerGet(cur.Headers, "Location")
		if loc == "" {
			break
		}
		next := resolveURL(base, loc)
		u, err := url.Parse(next)
		if err != nil || !e.InScope(u.Hostname()) {
			chain = append(chain, RedirectHop{RequestID: cur.RequestID, StatusCode: cur.StatusCode, From: base, Location: loc})
			break
		}
		port := 80
		tlsOn := u.Scheme == "https"
		if tlsOn {
			port = 443
		}
		if p := u.Port(); p != "" {
			fmt.Sscanf(p, "%d", &port)
		}
		raw := buildRawRequest("GET", u.RequestURI(), map[string]string{"Host": u.Host}, "")
		nxt, err := e.Send(raw, u.Hostname(), port, tlsOn, session, bodyLimit, false)
		chain = append(chain, RedirectHop{RequestID: cur.RequestID, StatusCode: cur.StatusCode, From: base, Location: loc})
		if err != nil {
			break
		}
		cur = nxt
		base = next
	}
	cur.RedirectChain = chain
	return cur
}

func buildRawRequest(method, pathQ string, headers map[string]string, body string) string {
	if pathQ == "" {
		pathQ = "/"
	}
	var b strings.Builder
	b.WriteString(method + " " + pathQ + " HTTP/1.1\r\n")

	if h := headerGet(headers, "Host"); h != "" {
		b.WriteString("Host: " + h + "\r\n")
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(k + ": " + headers[k] + "\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}

func pathWithQuery(fullURL, fallbackPath string) string {
	if u, err := url.Parse(fullURL); err == nil && u.Path != "" {
		return u.RequestURI()
	}
	if fallbackPath == "" {
		return "/"
	}
	return fallbackPath
}

func applyQueryParams(pathQ string, params map[string]string) string {
	path := pathQ
	q := url.Values{}
	if i := strings.IndexByte(pathQ, '?'); i >= 0 {
		path = pathQ[:i]
		q, _ = url.ParseQuery(pathQ[i+1:])
	}
	for k, v := range params {
		q.Set(k, v)
	}
	if len(q) == 0 {
		return path
	}
	return path + "?" + q.Encode()
}

func applyFormParams(body string, params map[string]string) string {
	q, _ := url.ParseQuery(body)
	for k, v := range params {
		if _, ok := q[k]; ok {
			q.Set(k, v)
		}
	}
	return q.Encode()
}

func isFormish(body string) bool {
	body = strings.TrimSpace(body)
	return body != "" && !strings.HasPrefix(body, "{") && !strings.HasPrefix(body, "[") && strings.Contains(body, "=")
}

func resolveURL(base, loc string) string {
	bu, err := url.Parse(base)
	if err != nil {
		return loc
	}
	lu, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	return bu.ResolveReference(lu).String()
}

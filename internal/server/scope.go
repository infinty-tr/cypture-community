package server

import (
	"encoding/json"
	"net"
	"net/url"
	"os"
	"strings"
)

// allowInternalTargets lets a self-hosted operator scan internal/localhost/private
// targets (their own apps). It is OPT-IN via CYPTURE_ALLOW_INTERNAL_TARGETS=true —
// off by default, since reaching internal/metadata ranges is an SSRF risk on a
// shared/hosted deployment. On a single-operator self-host it is a normal use case.
func allowInternalTargets() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("CYPTURE_ALLOW_INTERNAL_TARGETS")))
	return v == "1" || v == "true" || v == "yes"
}

func normalizeHost(target string) string {
	t := strings.TrimSpace(strings.ToLower(target))
	if t == "" {
		return ""
	}
	if !strings.Contains(t, "://") {
		t = "//" + t
	}
	u, err := url.Parse(t)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	return strings.TrimPrefix(host, "www.")
}

func normalizeHostKeepPort(target string) string {
	t := strings.TrimSpace(strings.ToLower(target))
	if t == "" {
		return ""
	}
	if !strings.Contains(t, "://") {
		t = "//" + t
	}
	u, err := url.Parse(t)
	if err != nil {
		return ""
	}
	host := strings.TrimPrefix(u.Hostname(), "www.")
	if host == "" {
		return ""
	}
	if p := u.Port(); p != "" {
		return host + ":" + p
	}
	return host
}

func stripPort(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func normalizePattern(p string) string {
	p = strings.TrimSpace(strings.ToLower(p))
	if p == "" {
		return ""
	}
	if _, _, err := net.ParseCIDR(p); err == nil {
		return p
	}

	if strings.HasPrefix(p, "*") {
		base := normalizeHost(strings.TrimPrefix(strings.TrimPrefix(p, "*"), "."))
		if base == "" {
			return ""
		}
		return "*." + base
	}

	return normalizeHostKeepPort(p)
}

func normalizePatterns(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range in {
		n := normalizePattern(raw)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

func matchPattern(host, pattern string) bool {

	host = stripPort(host)
	pattern = stripPort(pattern)
	if host == "" || pattern == "" {
		return false
	}

	if ip := net.ParseIP(host); ip != nil {
		if _, ipnet, err := net.ParseCIDR(pattern); err == nil {
			return ipnet.Contains(ip)
		}
		return host == pattern
	}

	if strings.HasPrefix(pattern, "*") {
		base := strings.TrimPrefix(strings.TrimPrefix(pattern, "*"), ".")
		return host == base || strings.HasSuffix(host, "."+base)
	}

	return host == pattern
}

type ScopeSet struct {
	Includes []string
	Excludes []string
}

func (s ScopeSet) Allows(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	for _, ex := range s.Excludes {
		if matchPattern(host, ex) {
			return false
		}
	}
	for _, in := range s.Includes {
		if matchPattern(host, in) {
			return true
		}
	}
	return false
}

var selfIPs = func() map[string]bool {
	m := map[string]bool{}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				m[ipn.IP.String()] = true
			}
		}
	}
	return m
}()

var selfPublicIPs = map[string]bool{}

func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return true
	}
	if selfPublicIPs[ip.String()] {
		return true
	}
	return selfIPs[ip.String()]
}

func hostBlockedReason(host string) string {
	host = strings.TrimSpace(host)

	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return "internal/private/metadata address (" + host + ")"
		}
		return ""
	}
	host = normalizeHost(host)
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return "internal/private/metadata address (" + host + ")"
		}
		return ""
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return ""
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return host + " resolves to an internal/metadata address (" + ip.String() + ")"
		}
	}
	return ""
}

func blockedScopeReason(seed string, includes []string) string {
	if allowInternalTargets() {
		return ""
	}
	if r := hostBlockedReason(seed); r != "" {
		return r
	}
	for _, p := range includes {
		if _, ipnet, err := net.ParseCIDR(p); err == nil {
			if isBlockedIP(ipnet.IP) {
				return "internal/private network range cannot be scanned (" + p + ")"
			}
			continue
		}
		if r := hostBlockedReason(p); r != "" {
			return r
		}
	}
	return ""
}

func deriveSeedTarget(rawIncludes []string) string {
	for _, raw := range rawIncludes {
		p := strings.TrimSpace(strings.ToLower(raw))
		if p == "" || strings.HasPrefix(p, "*") {
			continue
		}
		if _, _, err := net.ParseCIDR(p); err == nil {
			continue
		}
		t := p
		if !strings.Contains(t, "://") {
			t = "//" + t
		}
		u, err := url.Parse(t)
		if err != nil || u.Hostname() == "" {
			continue
		}
		host := strings.TrimPrefix(u.Hostname(), "www.")
		if port := u.Port(); port != "" {
			host += ":" + port
		}
		path := u.EscapedPath()
		if u.RawQuery != "" {
			path += "?" + u.RawQuery
		}
		if path == "/" {
			path = ""
		}
		return host + path
	}
	return deriveSeed(normalizePatterns(rawIncludes))
}

func deriveSeed(includes []string) string {
	for _, p := range includes {
		if !strings.HasPrefix(p, "*.") && !strings.Contains(p, "/") {
			return p
		}
	}
	for _, p := range includes {
		if strings.HasPrefix(p, "*.") {
			return p[2:]
		}
	}
	for _, p := range includes {
		if _, _, err := net.ParseCIDR(p); err == nil {
			if ip, _, _ := net.ParseCIDR(p); ip != nil {
				return ip.String()
			}
		}
	}
	return ""
}

func decodeList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return []string{}
	}
	return out
}

func encodeList(items []string) string {
	b, _ := json.Marshal(normalizePatterns(items))
	return string(b)
}

package engine

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
)

// dialControlFn matches net.Dialer.Control; aliased so other files in this
// package can refer to it without importing syscall.
type dialControlFn = func(network, address string, c syscall.RawConn) error

// allowInternalTargets mirrors the server-side opt-in: when
// CYPTURE_ALLOW_INTERNAL_TARGETS is set, a single-operator self-host may reach
// internal/localhost/private ranges (their own apps). Off by default.
func allowInternalTargets() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("CYPTURE_ALLOW_INTERNAL_TARGETS")))
	return v == "1" || v == "true" || v == "yes"
}

// isBlockedIP reports whether ip is an internal/private/metadata address that an
// outbound scan request must not reach. Kept in sync with the server-side copy
// in internal/server/scope.go.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// CGNAT / shared address space 100.64.0.0/10 (covers many cloud metadata paths).
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return true
	}
	return false
}

// dialControl is installed as net.Dialer.Control on every client the engine
// dials with. It runs AFTER DNS resolution, on the concrete IP about to be
// connected to, so it is the authoritative SSRF enforcement point: it defeats
// DNS-rebinding, wildcard-scope abuse, and creation-time DNS fail-open that the
// host-pattern scope check (InScope) cannot catch. Unless internal targets are
// explicitly allowed, a connection to an internal/private/metadata IP is refused.
func (e *Engine) dialControl(_, address string, _ syscall.RawConn) error {
	if e.allowInternal {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("blocked: cannot parse dial address %q", address)
	}
	if isBlockedIP(ip) {
		return fmt.Errorf("blocked: %s is an internal/private/metadata address (SSRF guard)", ip)
	}
	return nil
}

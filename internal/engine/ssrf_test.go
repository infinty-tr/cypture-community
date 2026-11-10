package engine

import (
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"192.168.1.5", true},
		{"169.254.169.254", true}, // cloud metadata (link-local)
		{"100.64.0.1", true},      // CGNAT shared space
		{"0.0.0.0", true},
		{"::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}
	for _, c := range cases {
		got := isBlockedIP(net.ParseIP(c.ip))
		if got != c.blocked {
			t.Errorf("isBlockedIP(%s) = %v, want %v", c.ip, got, c.blocked)
		}
	}
}

// TestSSRFGuardBlocksInternal verifies that with the opt-in OFF, the engine
// refuses to connect to a loopback target even when it is in scope (the
// host-pattern check passes but the dial-time guard rejects the resolved IP).
func TestSSRFGuardBlocksInternal(t *testing.T) {
	srv := httptest.NewServer(nil)
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://") // 127.0.0.1:PORT

	e := New([]string{"127.0.0.1"}, nil) // in scope by host-pattern
	e.allowInternal = false              // explicit: opt-in OFF regardless of TestMain env

	_, err := e.Send("GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n", host, 0, false, "", 4096, false)
	if err == nil {
		t.Fatal("expected SSRF guard to block loopback target, got nil error")
	}
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("expected a 'blocked' SSRF error, got: %v", err)
	}
}

// TestSSRFGuardAllowsWhenOptedIn confirms the same request succeeds once internal
// targets are explicitly allowed.
func TestSSRFGuardAllowsWhenOptedIn(t *testing.T) {
	srv := httptest.NewServer(nil)
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	_, portStr, _ := net.SplitHostPort(host)
	port, _ := strconv.Atoi(portStr)

	e := New([]string{"127.0.0.1"}, nil)
	e.allowInternal = true

	if _, err := e.Send("GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n", host, port, false, "", 4096, false); err != nil {
		t.Fatalf("expected success with opt-in on, got: %v", err)
	}
}

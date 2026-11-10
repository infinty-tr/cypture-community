package engine

import (
	"os"
	"testing"
)

// TestMain enables internal-target scanning for the whole engine test package.
// The tests exercise engine mechanics against loopback httptest servers, which in
// production corresponds to CYPTURE_ALLOW_INTERNAL_TARGETS=true (an operator
// scanning their own internal app). Without it the dial-time SSRF guard correctly
// refuses 127.0.0.1 — see ssrf.go.
func TestMain(m *testing.M) {
	_ = os.Setenv("CYPTURE_ALLOW_INTERNAL_TARGETS", "1")
	os.Exit(m.Run())
}

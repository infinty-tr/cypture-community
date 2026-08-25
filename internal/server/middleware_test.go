package server

import (
	"testing"
	"time"
)

func TestIPLimiterBurstThenThrottle(t *testing.T) {

	l := newIPLimiter(60, 3)
	now := time.Unix(1_700_000_000, 0)

	for i := 0; i < 3; i++ {
		if !l.allow("1.2.3.4", now) {
			t.Fatalf("burst request %d should pass", i)
		}
	}

	if l.allow("1.2.3.4", now) {
		t.Fatal("4th instant request should be throttled")
	}

	if !l.allow("9.9.9.9", now) {
		t.Fatal("different IP should not be throttled")
	}

	if !l.allow("1.2.3.4", now.Add(time.Second)) {
		t.Fatal("after 1s one token should be available")
	}
	if l.allow("1.2.3.4", now.Add(time.Second)) {
		t.Fatal("only one token should have refilled")
	}
}

func TestIPLimiterDisabled(t *testing.T) {
	if newIPLimiter(0, 10) != nil {
		t.Fatal("perMin<=0 should disable the limiter (nil)")
	}
}

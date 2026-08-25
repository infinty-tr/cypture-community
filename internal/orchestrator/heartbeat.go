package orchestrator

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
)

type hbController struct {
	Controller
	last     atomic.Int64
	lastReal atomic.Int64
}

func (h *hbController) Emit(ev Event) {
	now := time.Now().UnixNano()
	h.last.Store(now)
	h.lastReal.Store(now)
	h.Controller.Emit(ev)
}

func (h *hbController) Ask(q Question) string {
	h.lastReal.Store(time.Now().UnixNano())
	h.last.Store(time.Now().UnixNano())
	res := h.Controller.Ask(q)
	h.lastReal.Store(time.Now().UnixNano())
	h.last.Store(time.Now().UnixNano())
	return res
}

func (h *hbController) StalledFor() time.Duration {
	return time.Since(time.Unix(0, h.lastReal.Load()))
}

func withHeartbeat(ctx context.Context, ctrl Controller) (Controller, func(), func() time.Duration) {
	hb := &hbController{Controller: ctrl}
	now := time.Now().UnixNano()
	hb.last.Store(now)
	hb.lastReal.Store(now)
	stopCh := make(chan struct{})
	go hb.loop(ctx, stopCh)
	var once int32
	stop := func() {
		if atomic.CompareAndSwapInt32(&once, 0, 1) {
			close(stopCh)
		}
	}
	return hb, stop, hb.StalledFor
}

func (h *hbController) loop(ctx context.Context, stop <-chan struct{}) {
	const quiet = 18 * time.Second
	start := time.Now()
	tick := time.NewTicker(6 * time.Second)
	defer tick.Stop()
	n := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-tick.C:
		}
		if time.Since(time.Unix(0, h.last.Load())) < quiet {
			continue
		}
		n++

		h.last.Store(time.Now().UnixNano())
		h.Controller.Emit(Event{Level: LevelInfo, Category: CatModule, Module: "Çekirdek",
			Message: heartbeatMsg(n, time.Since(start))})
	}
}

func heartbeatMsg(n int, elapsed time.Duration) string {
	msgs := []string{
		"Assessment in progress — modules are running in the background.",
		"Processing the target surface; collecting observations.",
		"Active analysis is ongoing; results are being compiled.",
		"Running the module chain; new observations will stream shortly.",
	}
	return fmt.Sprintf("⏳ %s (elapsed: %s)", msgs[n%len(msgs)], fmtElapsed(elapsed))
}

func fmtElapsed(d time.Duration) string {
	d = d.Round(time.Second)
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if m > 0 {
		return fmt.Sprintf("%dd %02dsn", m, s)
	}
	return fmt.Sprintf("%dsn", s)
}

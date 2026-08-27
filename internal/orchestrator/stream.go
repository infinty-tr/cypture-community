package orchestrator

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const startupSilence = 180 * time.Second

// ErrFatalModel — the scan died for a reason that is NOT the pool key's fault
// (unknown/invalid model, engine silence). The pool must NOT disable a key for it.
// ErrFatalKey — the provider rejected THIS key (bad key, no balance/quota). The
// failover loop may disable this key and rotate to another pool key.
var (
	ErrFatalModel = errors.New("model unavailable")
	ErrFatalKey   = errors.New("provider key rejected")
)

// classifyFatal reports whether a line signals a terminal condition, a
// human-readable reason, and whether the fault is key-specific (balance/auth) as
// opposed to model/engine-side.
func classifyFatal(line string) (msg string, fatal bool, keySpecific bool) {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "insufficient balance"),
		strings.Contains(l, "insufficient_quota"),
		strings.Contains(l, "insufficient funds"),
		strings.Contains(l, "insufficient credit"),
		strings.Contains(l, "out of credit"),
		strings.Contains(l, "no credit"),
		strings.Contains(l, "balance is too low"),
		strings.Contains(l, "payment required"),
		strings.Contains(l, "quota exceeded"),
		strings.Contains(l, "exceeded your current quota"),

		strings.Contains(l, "requires more credits"),
		strings.Contains(l, "add more credits"),
		strings.Contains(l, "more credits, or fewer max_tokens"),
		strings.Contains(l, "http 402"),
		strings.Contains(l, "\"code\":402"):
		return "Insufficient provider balance — scan stopped. Please add credit to the API key balance (OpenRouter: openrouter.ai/settings/credits).", true, true
	case strings.Contains(l, "invalid api key"),
		strings.Contains(l, "invalid_api_key"),
		strings.Contains(l, "incorrect api key"),
		strings.Contains(l, "no auth credentials"),
		strings.Contains(l, "authentication failed"),
		strings.Contains(l, "authentication error"),
		strings.Contains(l, "unauthorized") && strings.Contains(l, "key"):
		return "API key is invalid or missing — scan stopped. Check the provider key.", true, true
	case strings.Contains(l, "model not found"),
		strings.Contains(l, "no such model"),
		strings.Contains(l, "not a valid model"),
		strings.Contains(l, "invalid model"),
		strings.Contains(l, "unknown model"),
		strings.Contains(l, "model does not exist"),
		strings.Contains(l, "no endpoints found for"),
		strings.Contains(l, "is not a valid model id"):
		return "The selected model is invalid or not available at the provider — scan stopped. Check the model name in the admin panel.", true, false
	}
	return "", false, false
}

func streamNDJSON(ctx context.Context, cmd *exec.Cmd, ctrl Controller, onCancel func()) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	var (
		fatalOnce sync.Once
		fatalMsg  atomic.Pointer[string]
		fatalKey  atomic.Bool
		sawOutput atomic.Bool
	)
	trip := func(reason string, keySpecific bool) {
		fatalOnce.Do(func() {
			fatalMsg.Store(&reason)
			fatalKey.Store(keySpecific)
			if onCancel != nil {
				onCancel()
			}
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		})
	}

	cmd.Stderr = &fatalScanWriter{onLine: func(line string) {
		sawOutput.Store(true)
		if msg, ok, keySpecific := classifyFatal(line); ok {
			trip(msg, keySpecific)
		}
	}}

	if err := cmd.Start(); err != nil {
		return err
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			if onCancel != nil {
				onCancel()
			}
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		case <-done:
		}
	}()

	go func() {
		select {
		case <-time.After(startupSilence):
			if !sawOutput.Load() {
				trip("The engine did not respond (the model may be unreachable or out of balance) — scan stopped.", false)
			}
		case <-done:
		case <-ctx.Done():
		}
	}()

	parseStream(ctx, stdout, ctrl, &sawOutput, trip)

	waitErr := cmd.Wait()
	if r := fatalMsg.Load(); r != nil {
		ctrl.Emit(Event{Level: LevelError, Category: CatSystem, Module: "Çekirdek", Message: *r})
		if fatalKey.Load() {
			return ErrFatalKey
		}
		return ErrFatalModel
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return waitErr
}

type fatalScanWriter struct {
	mu     sync.Mutex
	buf    strings.Builder
	onLine func(string)
}

func (w *fatalScanWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	s := w.buf.String()
	for {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimSpace(s[:i])
		s = s[i+1:]
		if line != "" && w.onLine != nil {
			w.onLine(line)
		}
	}
	w.buf.Reset()
	w.buf.WriteString(s)
	return len(p), nil
}

func parseStream(ctx context.Context, r io.Reader, ctrl Controller, sawOutput *atomic.Bool, trip func(string, bool)) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	dispatched := map[string]bool{}

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}
		raw := scanner.Text()
		if sawOutput != nil {
			sawOutput.Store(true)
		}
		line := strings.TrimSpace(raw)
		if line == "" || !strings.HasPrefix(line, "{") {

			if msg, ok, keySpecific := classifyFatal(raw); ok && trip != nil {
				trip(msg, keySpecific)
			}
			continue
		}
		var ev ocEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		for _, e := range mapEvents(ev, dispatched) {

			switch e.Category {
			case CatFinding, CatUsage, CatKB, CatTraffic, CatQuestion, CatAnswer, CatComplete:

			default:
				if e.Lane == "" && !hardCore[e.Module] {
					e.Lane = maestroLane
				}
			}
			ctrl.Emit(e)
		}

		if trip != nil && ev.Type == "error" {
			if msg, ok, keySpecific := classifyFatal(line); ok {
				trip(msg, keySpecific)
			}
		}

		if strings.Contains(line, "\"tokens\"") {
			if u := usageEvent(line); u != nil {
				ctrl.Emit(*u)
			}
		}
	}
}

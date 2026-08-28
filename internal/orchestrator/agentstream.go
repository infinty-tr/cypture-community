package orchestrator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func tailAgents(ctx context.Context, dir string, ctrl Controller) {
	seen := map[string]bool{}
	tick := time.NewTicker(400 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".ndjson") || seen[name] {
				continue
			}
			seen[name] = true

			handle := strings.TrimSuffix(name, ".ndjson")
			lane := friendlySubagent(handle)
			go tailAgentFile(ctx, filepath.Join(dir, name), lane, ctrl)
			go watchAgentDone(ctx, filepath.Join(dir, handle+".status"), lane, ctrl)
		}
	}
}

// watchAgentDone polls a sub-agent's .status file and, when it finishes, emits a
// pane-close so the cockpit window flips from "awaiting response" to done even if
// the agent exited quietly without printing its own "✅ … completed" line
// (e.g. an api-test agent that found the surface auth-gated and stopped early).
func watchAgentDone(ctx context.Context, statusPath, lane string, ctrl Controller) {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		b, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}
		if s := strings.TrimSpace(string(b)); s == "done" || s == "error" {
			// "✅ … completed" is the marker paneFor() recognises to close a pane.
			ctrl.Emit(Event{Level: LevelSystem, Category: CatSystem, Lane: lane,
				Message: "✅ " + lane + " completed"})
			return
		}
	}
}

func tailAgentFile(ctx context.Context, path, lane string, ctrl Controller) {
	dispatched := map[string]bool{}

	var textBuf strings.Builder
	emitted := map[string]bool{}
	harvest := func() {
		if _, finds := extractFindingMarkers(textBuf.String()); len(finds) > 0 {
			for _, fd := range finds {
				title := firstString(fd, "title", "name")
				if title == "" || emitted[title] {
					continue
				}
				emitted[title] = true
				e := findingEventFromMarker(fd)
				e.Lane = lane
				ctrl.Emit(e)
			}
		}
	}
	tailLines(ctx, path, func(line string) {
		if !strings.HasPrefix(line, "{") {
			return
		}
		var ev ocEvent
		if json.Unmarshal([]byte(line), &ev) == nil {
			if (ev.Type == "text" || ev.Type == "reasoning") && ev.Part.Text != "" {
				textBuf.WriteString(ev.Part.Text)
				textBuf.WriteByte('\n')
				if textBuf.Len() > 65536 {
					tail := textBuf.String()
					tail = tail[len(tail)-32768:]
					textBuf.Reset()
					textBuf.WriteString(tail)
				}
				harvest()
			}
			for _, e := range mapEvents(ev, dispatched) {
				e.Lane = lane
				ctrl.Emit(e)
			}
		}

		if strings.Contains(line, "\"tokens\"") {
			if u := usageEvent(line); u != nil {
				ctrl.Emit(*u)
			}
		}
	})
}

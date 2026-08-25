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

			lane := friendlySubagent(strings.TrimSuffix(name, ".ndjson"))
			go tailAgentFile(ctx, filepath.Join(dir, name), lane, ctrl)
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

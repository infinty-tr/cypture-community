package engine

import (
	"fmt"
	"sort"
	"strings"
)

type ParamHit struct {
	Param      string `json:"param"`
	StatusCode int    `json:"status"`
	LenDelta   int    `json:"len_delta"`
	Reflected  bool   `json:"reflected"`
	Interest   string `json:"interest"`
}

func (e *Engine) ParamMine(id string, params []string, canary string) (map[string]any, error) {
	orig := e.Get(id)
	if orig == nil {
		return nil, fmt.Errorf("request id %q not found", id)
	}
	if strings.TrimSpace(canary) == "" {
		canary = "cypm9z7q"
	}
	interesting := []ParamHit{}
	tested := 0
	for _, p := range params {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		tested++
		out, err := e.Replay(id, ReplayEdit{SetParams: map[string]string{p: canary}})
		if err != nil {
			continue
		}
		res, _ := out["result"].(*SendResult)
		if res == nil {
			continue
		}
		reflected := strings.Contains(res.Body, canary)
		lenDelta := res.Length - orig.Length
		statusChanged := res.StatusCode != orig.StatusCode
		if reflected || statusChanged || absInt(lenDelta) > 24 {
			reasons := []string{}
			if reflected {
				reasons = append(reasons, "reflected")
			}
			if statusChanged {
				reasons = append(reasons, "status-change")
			}
			if absInt(lenDelta) > 24 {
				reasons = append(reasons, "length-change")
			}
			interesting = append(interesting, ParamHit{
				Param: p, StatusCode: res.StatusCode, LenDelta: lenDelta,
				Reflected: reflected, Interest: strings.Join(reasons, ","),
			})
		}
	}
	sort.Slice(interesting, func(i, j int) bool {
		return absInt(interesting[i].LenDelta) > absInt(interesting[j].LenDelta)
	})
	return map[string]any{
		"base_request": id, "tested": tested,
		"baseline_status": orig.StatusCode, "baseline_len": orig.Length,
		"interesting": interesting,
		"note":        "Interesting params are CANDIDATES — verify each manually (IDOR / mass-assignment / open-redirect).",
	}, nil
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

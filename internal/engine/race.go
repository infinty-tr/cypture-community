package engine

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type RaceRequest struct {
	Label string
	Raw   string
}

type RaceResult struct {
	Label        string `json:"label"`
	RequestID    string `json:"requestId,omitempty"`
	StatusCode   int    `json:"statusCode"`
	Length       int    `json:"length"`
	DurationMs   int64  `json:"durationMs"`
	FireOffsetNs int64  `json:"fireOffsetNs"`
	Body         string `json:"body,omitempty"`
	Error        string `json:"error,omitempty"`
}

func (e *Engine) RaceSend(reqs []RaceRequest, host string, port int, tlsOn bool, sessionID string, bodyLimit int) ([]RaceResult, error) {
	bareHost := normalizeHost(host)
	if !e.InScope(bareHost) {
		return nil, fmt.Errorf("host %q is out of the authorized scope", bareHost)
	}
	if bodyLimit <= 0 {
		bodyLimit = 65536
	}
	if port == 0 {
		if tlsOn {
			port = 443
		} else {
			port = 80
		}
	}
	n := len(reqs)
	results := make([]RaceResult, n)
	if n == 0 {
		return results, nil
	}
	addr := net.JoinHostPort(bareHost, strconv.Itoa(port))

	ready := make(chan struct{}, n)
	release := make(chan struct{})
	var firstFire atomic.Int64
	var wg sync.WaitGroup

	for i := range reqs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i].Label = reqs[i].Label

			raw := normalizeCRLF(reqs[i].Raw)

			if !strings.Contains(strings.ToLower(rawHeaderBlock(raw)), "\r\nhost:") &&
				!strings.HasPrefix(strings.ToLower(raw), "host:") {
				if j := strings.Index(raw, "\r\n"); j >= 0 {
					raw = raw[:j+2] + "Host: " + bareHost + "\r\n" + raw[j+2:]
				}
			}

			if !strings.Contains(strings.ToLower(rawHeaderBlock(raw)), "\r\nconnection:") {
				if j := strings.Index(raw, "\r\n"); j >= 0 {
					raw = raw[:j+2] + "Connection: close\r\n" + raw[j+2:]
				}
			}
			method, path := rawRequestLine(raw)

			dialer := &net.Dialer{Timeout: 15 * time.Second}
			var conn net.Conn
			var err error
			if tlsOn {
				conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: bareHost})
			} else {
				conn, err = dialer.Dial("tcp", addr)
			}
			if err != nil {
				results[i].Error = err.Error()
				ready <- struct{}{}
				return
			}
			defer conn.Close()

			body := []byte(raw)
			if len(body) < 2 {
				results[i].Error = "request too short for last-byte sync"
				ready <- struct{}{}
				return
			}
			head, last := body[:len(body)-1], body[len(body)-1:]
			_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
			if _, err := conn.Write(head); err != nil {
				results[i].Error = "write head: " + err.Error()
				ready <- struct{}{}
				return
			}
			ready <- struct{}{}
			<-release

			fired := time.Now()
			firstFire.CompareAndSwap(0, fired.UnixNano())
			if _, err := conn.Write(last); err != nil {
				results[i].Error = "write last byte: " + err.Error()
				return
			}
			respBytes, _ := io.ReadAll(io.LimitReader(conn, int64(bodyLimit)+8192))
			dur := time.Since(fired).Milliseconds()

			status, hdr, respBody := parseRawResponse(string(respBytes))
			if len(respBody) > bodyLimit {
				respBody = respBody[:bodyLimit]
			}
			entry := &Entry{
				ID: e.nextID("req"), Host: bareHost, Port: port, TLS: tlsOn,
				Method: method, Path: path, URL: schemeOf(tlsOn) + "://" + bareHost + path,
				SessionID: sessionID, At: time.Now(), DurationMs: dur,
				StatusCode: status, RespHeader: hdr, RespBody: clipStr(respBody, e.bodyCap),
				Length: len(respBody), ReqBody: clipStr(raw, e.bodyCap),
				ReqHeaders: map[string]string{},
			}
			e.store(entry)

			results[i].RequestID = entry.ID
			results[i].StatusCode = status
			results[i].Length = len(respBody)
			results[i].DurationMs = dur
			results[i].Body = respBody
			results[i].FireOffsetNs = fired.UnixNano()
		}(i)
	}

	go func() {
		for k := 0; k < n; k++ {
			<-ready
		}
		time.Sleep(40 * time.Millisecond)
		close(release)
	}()

	wg.Wait()

	base := firstFire.Load()
	for i := range results {
		if results[i].FireOffsetNs > 0 && base > 0 {
			results[i].FireOffsetNs -= base
		} else {
			results[i].FireOffsetNs = 0
		}
	}
	return results, nil
}
